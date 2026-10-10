"""Preserve, then separately quarantine, the three /tmp evidence symlinks in the application tree.

  preserve                 Step A: descriptor-bound archive + verification; writes ONLY a new root-only run directory.
  remove-links RUN_DIR     Step B: re-verify Step A, pin all three reviewed links, then atomically MOVE each link entry
                           out of the application directory into the root-only run directory (never unlink there).
  restore-links RUN_DIR    Recovery: after validating every guard, move quarantined links back (never overwriting).

Nothing under /tmp is ever modified. No deletion primitive exists in this tool.

Concurrency boundaries (see docs/codex/production-delivery/v2/README.md):
- /opt/msf-counter-bot is writable by its owner msf-counter-bot, every member of the established `media` group
  (2775 setgid; NOT changed by this work) and root. Writers cannot be excluded without changing `media` or stopping
  the service, so Step B relies on an atomic/descriptor protocol instead of writer exclusion:
  each reviewed link is pinned by an O_PATH|O_NOFOLLOW descriptor (a pinned inode cannot be freed, so its number
  cannot be reused), the entry is moved with renameat2(RENAME_NOREPLACE) into a root-only 0700 directory, and the
  moved object is accepted only if it IS the pinned inode. A substituted object (regular file, directory, other
  link) is never deleted: it is moved back with RENAME_NOREPLACE (or, if its name was re-occupied, left intact in
  the root-only quarantine and reported) and the operation STOPs without claiming success.
- The /tmp evidence trees are writable by their owner (papertankz) and root; they are not modified by this work.
  Step A uses verified stability instead of writer exclusion: every object is opened by descriptor (O_NOFOLLOW at
  every component), its fstat must equal the preceding lstat, file content is archived from that descriptor and
  re-fstat'ed after reading, and a complete second descriptor walk must reproduce every object's identity including
  ctime (which the kernel advances on any content or metadata change and which unprivileged users cannot set).
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile

# name, target, entries, link mtime ns, target mtime ns: as observed read-only by the vjserver gate diagnostic
# (2026-10-10T14:39:37Z). Step A STOPs if the evidence no longer matches what was reviewed.
LINKS = (
    ('combat_mod_evidence', '/tmp/friday-spatial-candidate.oYd8sS/evidence', 695, 1791467958352446231, 1791465966761582602),
    ('root_cause_evidence', '/tmp/friday-defense-root-cause.tFEDy8/evidence', 66, 1791462243443584804, 1791462175719879242),
    ('hulk_hydra_evidence', '/tmp/friday-hulk-hydra.TKg6u6/evidence', 245, 1791471428240964351, 1791471050642571298),
)
RUN_PATTERN = re.compile(r'tmp-evidence-links-\d{8}T\d{6}Z')
SEALED = ('links.json', 'source-manifest.json', 'archive-manifest.json')
QUARANTINE = 'quarantined-links'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
PRESERVATION_CONTRACT = {
    'preserved': ['directory, regular-file and symlink entries and names', 'regular-file content (SHA256 per file)',
                  'symlink target text (never followed)', 'permission bits', 'numeric uid/gid', 'mtime (ns, pax)'],
    'recorded_in_manifest_only': ['device', 'inode', 'nlink', 'ctime (ns)'],
    'verified_absent_or_rejected': ['hard links (nlink>1 regular files STOP)', 'xattrs incl. POSIX ACLs (STOP)',
                                    'special files (STOP)', 'mount points incl. bind mounts (STOP)',
                                    'symlinked ancestors (STOP)'],
    'not_preserved': ['atime', 'ctime/inode/device as live attributes (recorded only)'],
    'integrity_basis': 'descriptor-bound reads plus unchanged ctime/identity across a complete second walk; '
                       'this is verified stability during preservation, not a filesystem snapshot and not proof of '
                       'what the evidence contained before Step A began (bound to the reviewed diagnostic only by '
                       'entry count, target-directory mtime and link mtime)',
}


@dataclass(frozen=True)
class Spec:
    app: Path = Path('/opt/msf-counter-bot')
    evidence_root: Path = Path('/var/lib/friday-evidence')
    links: tuple = LINKS
    tar: str = '/usr/bin/tar'
    headroom: int = 64 * 1024 * 1024


PRODUCTION = Spec()


class Stop(Exception):
    def __init__(self, message):
        super().__init__('STOP: ' + message)


def require(ok, message):
    if not ok:
        raise Stop(message)


def emit(line):
    print(line, flush=True)


_libc = ctypes.CDLL(None, use_errno=True)
RENAME_NOREPLACE = 1


def renameat2(olddirfd, old, newdirfd, new):
    """rename(2) that never replaces an existing destination."""
    function = _libc.renameat2
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    if function(olddirfd, os.fsencode(old), newdirfd, os.fsencode(new), RENAME_NOREPLACE) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), old)


def fd_mount_id(fd):
    for line in Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines():
        if line.startswith('mnt_id:'):
            return int(line.split()[1])
    raise Stop('mount identity unavailable')


def ident(info):
    return {'type': stat.S_IFMT(info.st_mode), 'dev': info.st_dev, 'ino': info.st_ino, 'uid': info.st_uid,
            'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode), 'nlink': info.st_nlink, 'size': info.st_size,
            'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


def sealed_names(spec):
    return [name + '.tar' for name, *_ in spec.links] + list(SEALED)


def sha_file(path):
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def no_xattrs(target, label):
    try:
        names = os.listxattr(target) if isinstance(target, int) else os.listxattr(target, follow_symlinks=False)
    except OSError as error:
        if error.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            return
        raise Stop(f'xattr check failed for {label}: {error}')
    require(not names, f'xattrs/ACLs present on {label}: {names} (not covered by the preservation contract)')


def open_chain(path):
    """Open every component with O_NOFOLLOW; a symlinked or non-directory ancestor STOPs. Returns [(path, fd, info)]."""
    chain = [('/', os.open('/', DIR_FLAGS), None)]
    try:
        for part in Path(path).parts[1:]:
            try:
                fd = os.open(part, DIR_FLAGS, dir_fd=chain[-1][1])
            except OSError as error:
                raise Stop(f'source path component {part!r} of {path} is not a real directory: {error}')
            chain.append((str(Path(chain[-1][0]) / part), fd, None))
        return [(p, fd, os.fstat(fd)) for p, fd, _ in chain]
    except BaseException:
        for _, fd, _ in chain:
            os.close(fd)
        raise


def close_chain(chain):
    for _, fd, _ in chain:
        os.close(fd)


def chain_identity(chain, fresh=False):
    """Shared ancestors (/, /tmp) are compared without timestamps; the evidence holder and root fully."""
    out = []
    for index, (path, fd, info) in enumerate(chain):
        record = ident(os.fstat(fd) if fresh else info)
        record['mnt'] = fd_mount_id(fd)
        if index < len(chain) - 2:
            record = {k: record[k] for k in ('type', 'dev', 'ino', 'uid', 'gid', 'mode', 'mnt')}
        out.append((path, record))
    return out


class HashingReader:
    def __init__(self, stream):
        self.stream, self.digest, self.count = stream, hashlib.sha256(), 0

    def read(self, size=-1):
        block = self.stream.read(size)
        self.digest.update(block)
        self.count += len(block)
        return block


def tarinfo(rel, info, kind, linkname=''):
    member = tarfile.TarInfo(rel)
    member.type, member.mode, member.uid, member.gid = kind, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid
    member.uname = member.gname = ''
    member.mtime = info.st_mtime_ns // 10**9
    member.pax_headers = {'mtime': f'{info.st_mtime_ns // 10**9}.{info.st_mtime_ns % 10**9:09d}'}
    member.linkname = linkname
    member.size = info.st_size if kind == tarfile.REGTYPE else 0
    return member


def walk(dirfd, rel, top, records, archive=None):
    """Descriptor walk. With an archive, every object is archived from the descriptor that was verified."""
    for name in sorted(os.listdir(dirfd)):
        path = rel + '/' + name
        info = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        kind = stat.S_IFMT(info.st_mode)
        if kind == stat.S_IFLNK:
            pin = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dirfd)
            try:
                require(ident(os.fstat(pin)) == ident(info), 'symlink replaced while opening: ' + path)
                require(fd_mount_id(pin) == top['mnt'] and info.st_dev == top['dev'], 'mount boundary at ' + path)
                target = os.readlink('', dir_fd=pin)
                no_xattrs(f'/proc/self/fd/{dirfd}/{name}', path)  # llistxattr of the link itself, via its parent fd
            finally:
                os.close(pin)
            records[path] = dict(ident(info), linkname=target)
            if archive:
                archive.addfile(tarinfo(path, info, tarfile.SYMTYPE, target))
        elif kind == stat.S_IFDIR:
            fd = os.open(name, DIR_FLAGS, dir_fd=dirfd)
            try:
                opened = os.fstat(fd)
                require(ident(opened) == ident(info), 'directory replaced while opening: ' + path)
                require(fd_mount_id(fd) == top['mnt'] and info.st_dev == top['dev'], 'mount boundary (incl. bind mount) at ' + path)
                no_xattrs(fd, path)
                records[path] = ident(info)
                if archive:
                    archive.addfile(tarinfo(path, info, tarfile.DIRTYPE))
                walk(fd, path, top, records, archive)
                require(ident(os.fstat(fd)) == ident(info), 'directory changed while being read: ' + path)
            finally:
                os.close(fd)
        elif kind == stat.S_IFREG:
            require(info.st_nlink == 1, f'hard-linked file {path} (nlink={info.st_nlink}) is outside the preservation contract')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY, dir_fd=dirfd)
            with os.fdopen(fd, 'rb') as stream:
                opened = os.fstat(fd)
                require(ident(opened) == ident(info), 'file replaced while opening: ' + path)
                require(fd_mount_id(fd) == top['mnt'] and info.st_dev == top['dev'], 'mount boundary (incl. bind mount) at ' + path)
                no_xattrs(fd, path)
                if archive:
                    reader = HashingReader(stream)
                    archive.addfile(tarinfo(path, info, tarfile.REGTYPE), reader)
                    require(reader.count == info.st_size and ident(os.fstat(fd)) == ident(opened), 'file changed while reading: ' + path)
                    records[path] = dict(ident(info), sha256=reader.digest.hexdigest())
                else:
                    records[path] = ident(info)
        else:
            raise Stop('special file in evidence: ' + path)


def observe_tree(target, archive=None):
    """One descriptor-bound pass over a single evidence tree. Returns (chain identity, records)."""
    chain = open_chain(target)
    try:
        top_fd, top_info = chain[-1][1], chain[-1][2]
        top = {'mnt': fd_mount_id(top_fd), 'dev': top_info.st_dev}
        name = Path(target).name
        records = {name: ident(top_info)}
        no_xattrs(top_fd, name)
        if archive:
            archive.addfile(tarinfo(name, top_info, tarfile.DIRTYPE))
        walk(top_fd, name, top, records, archive)
        opened = chain_identity(chain)
        require(chain_identity(chain, fresh=True) == opened, 'evidence ancestors changed while being read: ' + str(target))
        return opened, records
    finally:
        close_chain(chain)


def comparable(records):
    """Fields a tar archive represents (manifest also records dev/ino/nlink/ctime for binding)."""
    out = {}
    for path, r in records.items():
        kind = {stat.S_IFDIR: 'd', stat.S_IFREG: 'f', stat.S_IFLNK: 'l'}[r['type']]
        item = {'type': kind, 'mode': r['mode'], 'uid': r['uid'], 'gid': r['gid'], 'mtime': r['mtime_ns'] // 10**9,
                'size': r['size'] if kind == 'f' else 0}
        if kind == 'f':
            item['sha256'] = r['sha256']
        if kind == 'l':
            item['linkname'] = r['linkname']
        out[path] = item
    return out


def tar_manifest(path):
    """Reads the archive without extracting it."""
    records = {}
    with tarfile.open(path, 'r:') as archive:
        for member in archive:
            require(member.name not in records, 'duplicate archive member: ' + member.name)
            record = {'mode': member.mode & 0o7777, 'uid': member.uid, 'gid': member.gid,
                      'mtime': int(member.mtime), 'size': 0}
            if member.isdir():
                record['type'] = 'd'
            elif member.isreg():
                stream = archive.extractfile(member)
                record.update(type='f', size=member.size, sha256=hashlib.sha256(stream.read()).hexdigest())
            elif member.issym():
                record.update(type='l', linkname=member.linkname)
            else:
                raise Stop('unexpected archive member type: ' + member.name)
            records[member.name] = record
    return records


def tool(spec, *args):
    result = subprocess.run([spec.tar, *args], capture_output=True, text=True, env=ENV, cwd='/', stdin=subprocess.DEVNULL)
    require((result.returncode, result.stdout, result.stderr) == (0, '', ''),
            f'tar {args[0]} rc={result.returncode} stdout={result.stdout[:500]!r} stderr={result.stderr[:500]!r}')


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'w') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def dump(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def evidence_root(spec):
    root = spec.evidence_root
    if os.path.lexists(root):
        info = os.lstat(root)
    else:
        parent = os.lstat(root.parent)
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not parent.st_mode & 0o022, 'unsafe evidence parent')
        os.mkdir(root, 0o700)
        os.chmod(root, 0o700)
        info = os.lstat(root)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
            'evidence root must be a real root-owned 0700 directory')
    return root


def app_fd(spec):
    fd = os.open(spec.app, DIR_FLAGS)
    require(stat.S_ISDIR(os.fstat(fd).st_mode), 'application root is not a real directory')
    return fd


def app_state(spec):
    info = os.lstat(spec.app)
    return [info.st_uid, info.st_gid, info.st_mode, info.st_ino]


def link_record(fd, name, target):
    """Pin and describe one reviewed link; returns (record, pinned O_PATH fd)."""
    try:
        pin = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    except FileNotFoundError:
        raise Stop('evidence link absent: ' + name)
    info = os.fstat(pin)
    if not stat.S_ISLNK(info.st_mode):
        os.close(pin)
        raise Stop('not a symlink: ' + name)
    actual = os.readlink('', dir_fd=pin)
    if actual != target:
        os.close(pin)
        raise Stop(f'link target changed: {name} -> {actual}')
    record = dict(ident(info), name=name, target=target)
    return record, pin


IDENTITY = ('type', 'dev', 'ino', 'uid', 'gid', 'mtime_ns', 'ctime_ns', 'nlink', 'target')
MOVED_IDENTITY = ('type', 'dev', 'ino', 'uid', 'gid', 'mtime_ns', 'nlink', 'target')  # rename(2) advances ctime


def same(current, record, keys):
    return all(current[k] == record[k] for k in keys)


def preserve(spec, stamp=None, out=emit):
    """Step A. Never touches the links or anything under /tmp; all output goes to a new root-only run directory."""
    require(os.geteuid() == 0, 'root required')
    fd = app_fd(spec)
    links, pins = [], []
    try:
        for name, target, _, link_mtime, _ in spec.links:
            record, pin = link_record(fd, name, target)
            pins.append(pin)
            require(record['mtime_ns'] == link_mtime, f'{name} link differs from the reviewed diagnostic (mtime)')
            links.append(record)
    finally:
        for pin in pins:
            os.close(pin)
        os.close(fd)
    first = {}
    for name, target, expected, _, target_mtime in spec.links:
        chain, records = observe_tree(target)
        require(records[Path(target).name]['mtime_ns'] == target_mtime, f'{name} evidence directory changed since review (mtime)')
        require(len(records) - 1 == expected, f'{name} entry count {len(records) - 1} != reviewed {expected}')
        first[name] = (chain, records)
    total = sum(r['size'] for _, records in first.values() for r in records.values())
    vfs = os.statvfs(spec.evidence_root if spec.evidence_root.exists() else spec.evidence_root.parent)
    require(vfs.f_bavail * vfs.f_frsize >= 2 * total + spec.headroom, 'insufficient space for verified preservation')
    stamp = stamp or datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    run = evidence_root(spec) / ('tmp-evidence-links-' + stamp)
    os.mkdir(run, 0o700)  # exclusive: an existing run directory STOPs, nothing is overwritten
    sources, archives = {}, {}
    for name, target, _, _, _ in spec.links:
        archive_path = run / (name + '.tar')
        afd = os.open(archive_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(afd, 'wb') as stream:
            with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as archive:
                chain, records = observe_tree(target, archive)
            stream.flush()
            os.fsync(stream.fileno())
        require(chain == first[name][0], f'{name} source path identity changed before archiving completed')
        require({p: {k: v for k, v in r.items() if k != 'sha256'} for p, r in records.items()} == first[name][1],
                f'{name} source changed between review observation and archiving')
        sources[name] = {'chain': chain, 'records': records}
        archives[name] = tar_manifest(archive_path)
        require(archives[name] == comparable(records), 'archive manifest differs from descriptor-read source: ' + name)
        tool(spec, '--compare', '--numeric-owner', '-C', str(Path(target).parent), '-f', str(archive_path))
    for name, target, _, _, _ in spec.links:  # complete second walk after every read and the independent tar compare
        chain, records = observe_tree(target)
        require(chain == sources[name]['chain'], f'{name} source ancestors changed during preservation')
        require(records == {p: {k: v for k, v in r.items() if k != 'sha256'} for p, r in sources[name]['records'].items()},
                f'{name} evidence changed during preservation (identity/ctime)')
    fd = app_fd(spec)
    try:
        for record in links:
            again, pin = link_record(fd, record['name'], record['target'])
            os.close(pin)
            require(same(again, record, IDENTITY), 'link changed during preservation: ' + record['name'])
    finally:
        os.close(fd)
    write_new(run / 'links.json', dump(links))
    write_new(run / 'source-manifest.json', dump(sources))
    write_new(run / 'archive-manifest.json', dump(archives))
    sums = ''.join(f'{sha_file(run / item)}  {item}\n' for item in sealed_names(spec))
    write_new(run / 'SHA256SUMS', sums)
    receipt = {'state': 'PRESERVED_VERIFIED', 'run_directory': str(run), 'sha256sums_sha256': sha_file(run / 'SHA256SUMS'),
               'evidence': {name: {'target': target, 'entries': len(sources[name]['records']) - 1,
                                   'file_bytes': sum(r['size'] for r in sources[name]['records'].values()
                                                     if r['type'] == stat.S_IFREG),
                                   'archive_sha256': sha_file(run / (name + '.tar')),
                                   'archive_bytes': os.lstat(run / (name + '.tar')).st_size}
                            for name, target, *_ in spec.links},
               'verification': ['links and evidence match the reviewed diagnostic (link mtime, directory mtime, entry count)',
                                'archive written from verified descriptors (fstat == lstat, re-fstat after read)',
                                'archive manifest == descriptor-read source manifest', 'GNU tar --compare clean',
                                'complete second descriptor walk: identities incl. ctime unchanged',
                                'links unchanged (pinned identity incl. ctime)'],
               'preservation_contract': PRESERVATION_CONTRACT,
               'links_modified': False, 'tmp_targets_modified': False, 'utc': stamp}
    write_new(run / 'RECEIPT.json', dump(receipt))
    for item in os.listdir(run):
        os.chmod(run / item, 0o400)
    os.chmod(run, 0o500)
    out(dump(receipt).rstrip())
    out(sums.rstrip())
    env = spec.app / '.env'
    if os.path.lexists(env):
        info = os.lstat(env)
        out(f'OBSERVATION .env owner={info.st_uid}:{info.st_gid} mode={oct(stat.S_IMODE(info.st_mode))} (metadata only)')
    out('PRESERVED_VERIFIED: links untouched; Step B requires separate authorization')
    return run


def verify_run(spec, run, sealed=True):
    """Step B cannot begin unless Step A's sealed, verified receipt still checks."""
    run = Path(run)
    require(run.parent == spec.evidence_root and RUN_PATTERN.fullmatch(run.name), 'not a Step A run directory')
    info = os.lstat(run)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0, 'run directory unsafe')
    if sealed:
        require(stat.S_IMODE(info.st_mode) == 0o500, 'run directory is not sealed (0500)')
        require(sorted(os.listdir(run)) == sorted(sealed_names(spec) + ['SHA256SUMS', 'RECEIPT.json']),
                'run directory contents differ from a sealed Step A run (prior removal attempt?)')
    for item in sealed_names(spec) + ['SHA256SUMS', 'RECEIPT.json']:
        f = os.lstat(run / item)
        require(stat.S_ISREG(f.st_mode) and f.st_uid == 0 and f.st_nlink == 1 and stat.S_IMODE(f.st_mode) == 0o400,
                'sealed file unsafe: ' + item)
    receipt = json.loads((run / 'RECEIPT.json').read_text())
    require(receipt.get('state') == 'PRESERVED_VERIFIED', 'preservation not verified')
    require(receipt.get('sha256sums_sha256') == sha_file(run / 'SHA256SUMS'), 'SHA256SUMS changed')
    lines = (run / 'SHA256SUMS').read_text().splitlines()
    require([line.split('  ', 1)[1] for line in lines] == sealed_names(spec), 'SHA256SUMS file list differs')
    for line in lines:
        digest, item = line.split('  ', 1)
        require(sha_file(run / item) == digest, 'sealed file hash mismatch: ' + item)
    links = json.loads((run / 'links.json').read_text())
    require([(l['name'], l['target']) for l in links] == [(n, t) for n, t, *_ in spec.links], 'recorded links differ')
    return links


def log(fd, text):
    os.write(fd, (datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') + ' ' + text + '\n').encode())
    os.fsync(fd)


def quarantined(qfd, name):
    try:
        info = os.stat(name, dir_fd=qfd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    record = ident(info)
    record['target'] = os.readlink(name, dir_fd=qfd) if stat.S_ISLNK(info.st_mode) else None
    return record


def remove_links(spec, run, out=emit, rename=None):
    """Step B. Move ONLY the three reviewed link entries into the root-only run directory; never delete anything."""
    rename = rename or renameat2
    require(os.geteuid() == 0, 'root required')
    run = Path(run)
    links = verify_run(spec, run)
    fd = app_fd(spec)
    pins = {}
    try:
        before = app_state(spec)
        for record in links:  # every guard is validated (and every link pinned) before anything moves
            current, pins[record['name']] = link_record(fd, record['name'], record['target'])
            require(same(current, record, IDENTITY), 'link replaced or modified since Step A: ' + record['name'])
        runfd = os.open(run, DIR_FLAGS)
        try:  # checked before anything changes: rename(2) cannot cross mounts, so fail closed early
            require(fd_mount_id(runfd) == fd_mount_id(fd),
                    'evidence run directory is not on the application mount; atomic move unavailable (nothing changed)')
        finally:
            os.close(runfd)
        os.chmod(run, 0o700)
        os.mkdir(run / QUARANTINE, 0o700)
        qfd = os.open(run / QUARANTINE, DIR_FLAGS)
        try:
            require(stat.S_IMODE(os.fstat(qfd).st_mode) == 0o700 and os.fstat(qfd).st_uid == 0, 'quarantine not root-only')
            require(fd_mount_id(qfd) == fd_mount_id(fd),
                    'quarantine is not on the application mount; atomic same-mount move unavailable (no link was moved)')
            logfd = os.open(run / 'REMOVAL-LOG', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            moved = []
            try:
                log(logfd, 'STARTED ' + ' '.join(r['name'] for r in links))
                for record in links:
                    name, pin = record['name'], pins[record['name']]
                    try:
                        rename(fd, name, qfd, name)
                    except OSError as error:
                        raise Stop(f'move of {name} failed before quarantine ({error}); entry left in place')
                    landed = quarantined(qfd, name)
                    pinned = os.fstat(pin)
                    exact = (landed is not None and landed['type'] == stat.S_IFLNK
                             and (landed['dev'], landed['ino']) == (pinned.st_dev, pinned.st_ino)
                             and same(landed, record, MOVED_IDENTITY))
                    if not exact:
                        log(logfd, f'SUBSTITUTION {name} type={landed and stat.filemode(landed["type"])}')
                        try:
                            rename(qfd, name, fd, name)
                            where = 'returned unmodified to the application directory'
                        except OSError as error:
                            where = f'retained unmodified in {run / QUARANTINE / name} ({error})'
                        log(logfd, f'SUBSTITUTE {name} {where}')
                        raise Stop(f'SUBSTITUTION_DETECTED: the object at {name} is not the reviewed link; it was {where}; '
                                   'nothing was deleted')
                    moved.append(name)
                    log(logfd, 'QUARANTINED ' + name)
                for record in links:
                    require(not os.path.lexists(spec.app / record['name']), 'link still present: ' + record['name'])
                require(app_state(spec) == before, 'application owner/group/mode/inode changed')
                receipt = {'state': 'LINKS_QUARANTINED', 'removed_from_application': moved,
                           'quarantine': str(run / QUARANTINE),
                           'quarantined_identity': {n: quarantined(qfd, n) for n in moved},
                           'tmp_targets_still_present': {r['name']: os.path.isdir(r['target']) for r in links},
                           'application_state_unchanged': True,
                           'remaining_symlinks': sorted(str(Path(d, n).relative_to(spec.app)) for d, ds, fs in os.walk(spec.app)
                                                        for n in ds + fs if os.path.islink(os.path.join(d, n)))}
                write_new(run / 'REMOVAL-RECEIPT.json', dump(receipt))
                log(logfd, 'COMPLETE')
            except Exception as error:
                rolled, stuck = [], []
                for name in reversed(moved):  # all-or-nothing: put verified links back, never overwriting
                    try:
                        rename(qfd, name, fd, name)
                        rolled.append(name)
                        log(logfd, 'ROLLED_BACK ' + name)
                    except OSError as rollback_error:
                        stuck.append(name)
                        log(logfd, f'ROLLBACK_FAILED {name} {rollback_error}')
                log(logfd, 'FAILED ' + str(error))
                raise Stop(f'STEP_B_FAILED ({error}); rolled_back={rolled} still_quarantined={stuck}; REMOVAL-LOG retained; '
                           f'no object was deleted; recover with restore-links {run}') from error
            finally:
                os.close(logfd)
        finally:
            os.close(qfd)
        for item in ('REMOVAL-LOG', 'REMOVAL-RECEIPT.json'):
            os.chmod(run / item, 0o400)
        os.chmod(run / QUARANTINE, 0o500)
        os.chmod(run, 0o500)
    finally:
        for pin in pins.values():
            os.close(pin)
        os.close(fd)
    out(dump(receipt).rstrip())
    out('LINKS_QUARANTINED: only the three reviewed link entries left the application directory; nothing deleted; /tmp untouched')
    return receipt


def restore_links(spec, run, out=emit, rename=None):
    """Validate EVERY guard first, then move quarantined links back with RENAME_NOREPLACE."""
    rename = rename or renameat2
    require(os.geteuid() == 0, 'root required')
    run = Path(run)
    links = verify_run(spec, run, sealed=False)
    require(os.path.isdir(run / QUARANTINE) and not os.path.islink(run / QUARANTINE), 'no quarantine in this run')
    fd = app_fd(spec)
    qfd = os.open(run / QUARANTINE, DIR_FLAGS)
    plan = []
    try:
        for record in links:
            name = record['name']
            in_app = os.path.lexists(spec.app / name)
            held = quarantined(qfd, name)
            if in_app:
                require(held is None, f'{name} present in both application and quarantine')
                current, pin = link_record(fd, name, record['target'])
                os.close(pin)
                require(same(current, record, MOVED_IDENTITY), f'{name} in application is not the recorded link')
                continue
            require(held is not None, f'{name} is in neither the application nor the quarantine')
            require(same(held, record, MOVED_IDENTITY), f'quarantined {name} is not the recorded link')
            plan.append(name)
        os.chmod(run, 0o700)
        os.chmod(run / QUARANTINE, 0o700)
        restored = []
        try:
            for name in plan:
                rename(qfd, name, fd, name)
                restored.append(name)
        except OSError as error:
            raise Stop(f'PARTIAL_RESTORE restored={restored} not_restored={[n for n in plan if n not in restored]} ({error})')
    finally:
        os.close(qfd)
        os.close(fd)
    write_new(run / f'RESTORE-{datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")}.json', dump({'state': 'LINKS_RESTORED', 'restored': restored}))
    out(dump({'state': 'LINKS_RESTORED', 'restored': restored}).rstrip())
    return restored


def main(argv, spec=PRODUCTION):
    try:
        if argv[1:] == ['preserve']:
            preserve(spec)
        elif len(argv) == 3 and argv[1] == 'remove-links':
            remove_links(spec, argv[2])
        elif len(argv) == 3 and argv[1] == 'restore-links':
            restore_links(spec, argv[2])
        else:
            raise Stop('usage: preserve | remove-links RUN_DIR | restore-links RUN_DIR')
        return 0
    except Stop as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception as error:
        print('STOP: unexpected error ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))

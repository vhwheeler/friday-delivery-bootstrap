"""Reviewed server-local bootstrap v2. Never invoke in Cloud; private keys are never read or printed.

Modes (exactly one argument):
  --preflight                  classify S0/S1 and evaluate the sudo and write/symlink gates; changes nothing.
  --execute                    create (S0) or resume (authorized, exactly validated S1), re-run all gates, install,
                               then re-establish every gate decision across the installation boundary.
  --authorize-incident-resume  write the root-only resume authorization for the ONE known v1 partial state, only
                               if the live state exactly matches the independently observed incident evidence.
Any other state, gate failure, change of security-relevant state or ambiguous probe result STOPs for review.
"""
from dataclasses import dataclass, field
import errno
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

HOST = 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n'
SSH_CONFIG = '''Host friday-artifacts
    HostName github.com
    HostKeyAlias github.com
    User git
    IdentityFile /var/lib/friday-delivery/.ssh/delivery_ed25519
    IdentitiesOnly yes
    IdentityAgent none
    BatchMode yes
    StrictHostKeyChecking yes
    UserKnownHostsFile /etc/friday-delivery/github_known_hosts
    GlobalKnownHostsFile /dev/null
    HostKeyAlgorithms ssh-ed25519
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    ForwardAgent no
    ClearAllForwardings yes
'''
TOOLS = {
    'systemctl': '/usr/bin/systemctl', 'useradd': '/usr/sbin/useradd', 'passwd': '/usr/bin/passwd',
    'runuser': '/usr/sbin/runuser', 'ssh-keygen': '/usr/bin/ssh-keygen', 'sudo': '/usr/bin/sudo',
    'cvtsudoers': '/usr/bin/cvtsudoers', 'python3': '/usr/bin/python3',
}
# Escalation-equivalent commands whose command-mode `sudo -l` answer is an exit status, not prose.
SPOT_COMMANDS = ('/usr/bin/bash', '/usr/bin/env', '/usr/bin/python3')
MAX_HOPS = 40
MAX_ENTRIES = 2_000_000
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}

# The ONE partial state this bootstrap may resume: the v1 run of 2026-10-10 that stopped at its sudo gate, as
# independently observed read-only on vjserver (docs/codex/production-delivery/v2/INCIDENT-AND-EVIDENCE.md).
# These values apply ONLY to incident resume behind an explicit root-owned authorization record; a fresh (S0)
# installation never consults them and lets useradd choose identifiers.
INCIDENT_RESUME = {
    'schema': 'friday-delivery-incident-resume/1',
    'incident': 'v1 bootstrap 757fe792298ca6f19e35f89e56642be224f42aac stopped at its sudo gate on 2026-10-10',
    'account': 'friday-delivery', 'uid': 989, 'gid': 986, 'group': 'friday-delivery',
    'home': '/var/lib/friday-delivery', 'shell': '/usr/sbin/nologin',
    'home_entries': ['.bash_logout', '.bashrc', '.profile', '.ssh'],
    'home_mtime_ns': 1791640959155206784, 'ssh_mtime_ns': 1791640959155206784,
    'v1_root_stage': '/var/tmp/friday-bootstrap-root-gr56v2gx',
    'v1_root_stage_files': {
        'bootstrap.py': 'df93e2739e75a746f585c961aa68d96b5e9926d594155bcad2b17337e53af201',
        'delivery.py': 'a84b66070ef4fd09daa48899a8c195943765ac3e3747af8f9394a859716ddbd0',
        'delivery_operator.py': 'f775c68c720af3afc8edc791f7b6d27638840108aaa6b99d199bac3764a4d083',
    },
}


@dataclass(frozen=True)
class Layout:
    account: str = 'friday-delivery'
    home: Path = Path('/var/lib/friday-delivery')
    app: Path = Path('/opt/msf-counter-bot')
    service: str = 'msf-counter-bot.service'
    etc: Path = Path('/etc/friday-delivery')
    tools_dir: Path = Path('/usr/local/libexec/friday-delivery')
    deploy: Path = Path('/var/lib/friday-deployment')
    # The delivery identity must never join these established non-FRIDAY groups.
    protected_groups: tuple = ('media',)
    skel: Path = Path('/etc/skel')
    shadow: Path = Path('/etc/shadow')
    nsswitch: Path = Path('/etc/nsswitch.conf')
    sudoers: Path = Path('/etc/sudoers')
    proc: Path = Path('/proc')
    linger: Path = Path('/var/lib/systemd/linger')
    crontabs: Path = Path('/var/spool/cron/crontabs')
    subuid: Path = Path('/etc/subuid')
    subgid: Path = Path('/etc/subgid')
    tools: dict = field(default_factory=lambda: dict(TOOLS))
    shell: str = '/usr/sbin/nologin'
    resume: dict = field(default_factory=lambda: dict(INCIDENT_RESUME))
    resume_record: Path = Path('/etc/friday-delivery-resume-authorization.json')


PRODUCTION = Layout()


class Stop(Exception):
    def __init__(self, message):
        super().__init__('STOP: ' + message)


def require(ok, message):
    if not ok:
        raise Stop(message)


def run(layout, tool, *args, input=None):
    """Fixed absolute tool, clean environment, closed stdin unless input is explicit."""
    kwargs = {'input': input} if input is not None else {'stdin': subprocess.DEVNULL}
    return subprocess.run([layout.tools[tool], *args], capture_output=True, text=isinstance(input, (str, type(None))),
                          env=ENV, cwd='/', **kwargs)


def checked(layout, tool, *args):
    result = run(layout, tool, *args)
    require(result.returncode == 0, f'{tool} failed rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}')
    return result.stdout


def lstat(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def mount_id(path):
    """Mount identity of the object at path itself (never following a final symlink); detects bind mounts."""
    fd = os.open(path, os.O_PATH | os.O_NOFOLLOW)
    try:
        for line in Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines():
            if line.startswith('mnt_id:'):
                return int(line.split()[1])
    finally:
        os.close(fd)
    raise Stop('mount identity unavailable for ' + str(path))


# ---------------------------------------------------------------- identity / S-state

def account_entry(layout):
    try:
        return pwd.getpwnam(layout.account)
    except KeyError:
        return None


def group_boundary(layout, account):
    """friday-delivery holds exactly its own private group and is outside every protected group."""
    require(grp.getgrgid(account.pw_gid).gr_name == layout.account, 'primary group is not the private account group')
    require(set(os.getgrouplist(layout.account, account.pw_gid)) == {account.pw_gid},
            'account holds supplementary group membership')
    require(grp.getgrgid(account.pw_gid).gr_mem == [], 'private group has members')
    require([g.gr_name for g in grp.getgrall() if g.gr_gid == account.pw_gid] == [layout.account], 'private GID is shared')
    require([p.pw_name for p in pwd.getpwall() if p.pw_uid == account.pw_uid] == [layout.account], 'UID is shared')
    require([p.pw_name for p in pwd.getpwall() if p.pw_gid == account.pw_gid] == [layout.account], 'private GID is another primary group')
    for name in layout.protected_groups:
        try:
            protected = grp.getgrnam(name)
        except KeyError:
            continue
        require(layout.account not in protected.gr_mem and account.pw_gid != protected.gr_gid,
                f'account must remain outside protected group {name}')


def shadow_locked(layout):
    lines = [line for line in layout.shadow.read_text().splitlines() if line.split(':', 1)[0] == layout.account]
    require(len(lines) == 1, 'shadow entry missing or duplicated')
    # Only the lock-field class is inspected; no password material is printed.
    require(re.fullmatch(r'!+\*?|\*', lines[0].split(':')[1]) is not None, 'password is not locked without a hash')


def process_credentials(text, pid):
    """Strictly parse Uid/Gid/Groups from /proc/<pid>/status; malformed or incomplete evidence STOPs."""
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition(':')
        if sep and key in ('Uid', 'Gid', 'Groups'):
            require(key not in fields, f'duplicate {key} in /proc/{pid}/status')
            fields[key] = value.split()
    require(set(fields) == {'Uid', 'Gid', 'Groups'}, f'incomplete credentials in /proc/{pid}/status')
    try:
        uids, gids, groups = ([int(x) for x in fields[k]] for k in ('Uid', 'Gid', 'Groups'))
    except ValueError:
        raise Stop(f'malformed credentials in /proc/{pid}/status')
    require(len(uids) == 4 and len(gids) == 4, f'malformed credential sets in /proc/{pid}/status')
    return set(uids), set(gids), set(groups)


def no_activity(layout, account):
    for entry in layout.proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            text = (entry / 'status').read_text()
        except (FileNotFoundError, ProcessLookupError):
            continue  # the process exited; it can no longer exercise any authority
        uids, gids, groups = process_credentials(text, entry.name)
        require(account.pw_uid not in uids, 'process running with delivery UID: pid ' + entry.name)
        require(account.pw_gid not in gids, 'process running with delivery GID: pid ' + entry.name)
        require(account.pw_gid not in groups, 'process holds delivery GID as a supplementary group: pid ' + entry.name)
    require(lstat(layout.linger / layout.account) is None, 'systemd linger exists')
    require(lstat(layout.crontabs / layout.account) is None, 'crontab exists')
    for path in (layout.subuid, layout.subgid):
        if path.exists():
            names = {line.split(':', 1)[0] for line in path.read_text().splitlines() if line.strip()}
            require(not names & {layout.account, str(account.pw_uid)}, 'subordinate ID range exists: ' + str(path))


def real_dir(path, uid, gid, mode, message):
    info = lstat(path)
    require(info is not None and stat.S_ISDIR(info.st_mode), message + ': not a real directory')
    require((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, mode),
            f'{message}: owner/mode {info.st_uid}:{info.st_gid} {oct(stat.S_IMODE(info.st_mode))}')
    return info


def later_paths(layout):
    ssh = layout.home / '.ssh'
    return [ssh / 'delivery_ed25519', ssh / 'delivery_ed25519.pub', ssh / 'config', layout.home / 'cache',
            layout.etc, layout.tools_dir, layout.deploy]


def validate_s1(layout):
    """Shape of the only reusable partial state (identity created by the reviewed bootstrap, no credential)."""
    a = account_entry(layout)
    require(a is not None, 'account absent')
    require(0 < a.pw_uid < 1000 and 0 < a.pw_gid < 1000, 'account is not a system account')
    require((a.pw_dir, a.pw_shell, a.pw_gecos) == (str(layout.home), layout.shell, ''), 'passwd home/shell/GECOS differ')
    group_boundary(layout, a)
    shadow_locked(layout)
    real_dir(layout.home, a.pw_uid, a.pw_gid, 0o700, 'home')
    ssh = layout.home / '.ssh'
    skel = {entry.name: entry for entry in os.scandir(layout.skel)}
    require(all(e.is_file(follow_symlinks=False) for e in skel.values()), 'skeleton contains non-regular entries')
    require(set(os.listdir(layout.home)) == set(skel) | {'.ssh'}, 'home contains unexpected entries')
    for name, source in skel.items():
        info = os.lstat(layout.home / name)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and (info.st_uid, info.st_gid) == (a.pw_uid, a.pw_gid),
                'skeleton copy unsafe: ' + name)
        require((layout.home / name).read_bytes() == Path(source.path).read_bytes(), 'skeleton copy modified: ' + name)
    real_dir(ssh, a.pw_uid, a.pw_gid, 0o700, '.ssh')
    require(os.listdir(ssh) == [], '.ssh is not empty')
    for path in later_paths(layout):
        require(lstat(path) is None, 'later bootstrap path exists: ' + str(path))
    no_activity(layout, a)
    return a


def canonical_record(layout):
    return json.dumps(layout.resume, indent=2, sort_keys=True) + '\n'


def incident_matches(layout, account):
    """Live state must equal the independently observed incident evidence, not merely its shape."""
    r = layout.resume
    require((r['account'], r['home'], r['shell']) == (layout.account, str(layout.home), layout.shell), 'record/layout mismatch')
    require((account.pw_uid, account.pw_gid) == (r['uid'], r['gid']), 'account UID/GID differ from the incident identity')
    require(grp.getgrgid(account.pw_gid).gr_name == r['group'], 'account group differs from the incident identity')
    require(sorted(os.listdir(layout.home)) == sorted(r['home_entries']), 'home entries differ from the incident evidence')
    require(os.lstat(layout.home).st_mtime_ns == r['home_mtime_ns'], 'home mtime differs from the incident evidence')
    require(os.lstat(layout.home / '.ssh').st_mtime_ns == r['ssh_mtime_ns'], '.ssh mtime differs from the incident evidence')
    stage = Path(r['v1_root_stage'])
    info = lstat(stage)
    require(info is not None and stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
            'v1 root staging (incident provenance) absent or unsafe: ' + str(stage))
    require(sorted(os.listdir(stage)) == sorted(r['v1_root_stage_files']), 'v1 root staging contents differ')
    for name, digest in r['v1_root_stage_files'].items():
        f = os.lstat(stage / name)
        require(stat.S_ISREG(f.st_mode) and f.st_uid == 0 and f.st_nlink == 1, 'v1 staging file unsafe: ' + name)
        require(hashlib.sha256((stage / name).read_bytes()).hexdigest() == digest, 'v1 staging file differs: ' + name)
        require(f.st_mtime_ns <= r['home_mtime_ns'], 'v1 staging is not older than the incident account')


def resume_authorized(layout):
    """Root-owned, exact, canonical authorization record; anything else is not an authorization."""
    info = lstat(layout.resume_record)
    if info is None:
        return False
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o400,
            'resume authorization record unsafe (must be a root-owned 0400 regular file)')
    fd = os.open(layout.resume_record, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        require(stream.read(65537) == canonical_record(layout).encode(), 'resume authorization record does not match the reviewed incident')
    return True


def classify(layout):
    """S0 = nothing exists and no authorization; S1 = authorized, exactly validated incident state; else STOP."""
    authorized = resume_authorized(layout)
    if account_entry(layout) is None:
        require(not authorized, 'resume authorization present but account absent')
        try:
            grp.getgrnam(layout.account)
            raise Stop('group exists without account')
        except KeyError:
            pass
        for path in [layout.home, *later_paths(layout)]:
            require(lstat(path) is None, 'path exists without account: ' + str(path))
        return 'S0', None
    require(authorized, 'existing account is not authorized for resume (no root-owned incident authorization record)')
    account = validate_s1(layout)
    incident_matches(layout, account)
    return 'S1', account


def authorize_incident_resume(layout, out):
    require(os.geteuid() == 0, 'run reviewed installer as root')
    require(lstat(layout.resume_record) is None, 'resume authorization already exists')
    account = validate_s1(layout)
    incident_matches(layout, account)
    parent = os.lstat(layout.resume_record.parent)
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not parent.st_mode & 0o022, 'unsafe record parent')
    exclusive_file(layout.resume_record, canonical_record(layout), 0o400)
    out('RESUME_AUTHORIZED: ' + str(layout.resume_record) + ' sha256=' + hashlib.sha256(canonical_record(layout).encode()).hexdigest())
    return 0


def create_s1(layout):
    checked(layout, 'useradd', '--system', '--user-group', '--create-home', '--home-dir', str(layout.home),
            '--shell', layout.shell, layout.account)
    checked(layout, 'passwd', '--lock', layout.account)
    a = pwd.getpwnam(layout.account)
    layout.home.chmod(0o700)
    ssh = layout.home / '.ssh'
    os.mkdir(ssh, 0o700)
    os.chown(ssh, a.pw_uid, a.pw_gid, follow_symlinks=False)
    os.chmod(ssh, 0o700)


# ---------------------------------------------------------------- sudo gate

def nsswitch_sources(path):
    sources = None
    for line in path.read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if line.startswith('sudoers:') or re.match(r'sudoers\s*:', line):
            require(sources is None, 'duplicate sudoers nsswitch entry')
            sources = line.split(':', 1)[1].split()
    return ['files'] if sources is None else sources


def sudo_gate(layout):
    """No sudo capability: structured policy, sudo's own evaluator and command-mode statuses must all agree."""
    require(account_entry(layout) is not None, 'sudo gate requires the account to exist')
    sources = nsswitch_sources(layout.nsswitch)
    require(sources == ['files'], f'sudoers sources {sources} are not local files only')
    c = run(layout, 'cvtsudoers', '-f', 'json', '-M', '-m', 'user=' + layout.account, str(layout.sudoers))
    try:
        specs = json.loads(c.stdout).get('User_Specs') if c.returncode == 0 and c.stderr == '' else 'ERROR'
    except (ValueError, AttributeError):
        specs = 'ERROR'
    require(specs in (None, []), f'cvtsudoers rc={c.returncode} specs={specs!r} stderr={c.stderr!r}')
    s = run(layout, 'sudo', '-n', '-l', '-U', layout.account)
    denial = re.fullmatch(r'User ' + re.escape(layout.account) + r' is not allowed to run sudo on [A-Za-z0-9._-]+\.\n?', s.stdout)
    # rc 0 is returned both for denial and for grants; it is never evidence on its own.
    require(s.returncode == 0 and s.stderr == '' and denial is not None,
            f'sudo denial not established rc={s.returncode} stdout={s.stdout!r} stderr={s.stderr!r}')
    for command in SPOT_COMMANDS:
        r = run(layout, 'sudo', '-n', '-l', '-U', layout.account, command)
        require((r.returncode, r.stdout, r.stderr) == (1, '', ''),
                f'command-mode sudo check {command} rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr!r}')
    return {'sudoers_sources': sources, 'user_specs': 0, 'denial': s.stdout.strip(), 'spot_commands': list(SPOT_COMMANDS)}


# ---------------------------------------------------------------- write / symlink gate

PROBE = r'''import os,sys
paths=sys.stdin.buffer.read().split(b"\0")[:-1]
out=[]
for p in paths:
    try:
        os.lstat(p)
    except PermissionError:
        out.append(b"U"); continue
    except OSError as e:
        out.append(b"E%d" % e.errno); continue
    out.append(b"W" if os.access(p, os.W_OK) else b"N")
sys.stdout.buffer.write(b"\0".join(out)+b"\0")
'''


def has_acl(path, info):
    if stat.S_ISLNK(info.st_mode):
        return False
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as error:
        if error.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            return False
        raise Stop(f'xattr probe failed {path}: {error}')
    return any(name.startswith('system.posix_acl_') for name in names)


class Identity:
    def __init__(self, account):
        self.uid = account.pw_uid
        self.groups = set(os.getgrouplist(account.pw_name, account.pw_gid))


def not_writable(path, info, who):
    """Static DAC rule: never owned by the identity, never world-writable, never group-writable by its groups."""
    require(info.st_uid != who.uid, 'owned by delivery account: ' + str(path))
    if stat.S_ISLNK(info.st_mode):
        return  # Linux ignores symlink mode; replacing a link requires write on its parent, which is checked.
    require(not info.st_mode & stat.S_IWOTH, 'world-writable: ' + str(path))
    require(not (info.st_mode & stat.S_IWGRP and info.st_gid in who.groups), 'group-writable by delivery identity: ' + str(path))
    require(not has_acl(path, info), 'POSIX ACL requires review: ' + str(path))


def external_safe(path, info):
    """Objects outside the application tree must be immutable system objects."""
    require(info.st_uid == 0, 'external path component not root-owned: ' + str(path))
    if not stat.S_ISLNK(info.st_mode):
        require(not info.st_mode & 0o022, 'external path component group/world-writable: ' + str(path))
        require(not has_acl(path, info), 'external path component has ACL: ' + str(path))


def resolve(link):
    """Component-wise physical resolution recording every object visited (no OS path following)."""
    visited = [(Path('/'), os.lstat('/'))]
    current, pending, hops = Path('/'), list(Path(link).parts[1:]), 0
    while pending:
        name = pending.pop(0)
        if name in ('', '.'):
            continue
        if name == '..':
            current = current.parent
            continue
        candidate = current / name
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            raise Stop(f'dangling symlink {link} (missing {candidate})')
        except OSError as error:
            raise Stop(f'symlink resolution error {link}: {error}')
        visited.append((candidate, info))
        if stat.S_ISLNK(info.st_mode):
            hops += 1
            require(hops <= MAX_HOPS, 'symlink loop or excessive hops: ' + str(link))
            target = os.readlink(candidate)
            require(target != '', 'empty symlink: ' + str(candidate))
            parts = list(Path(target).parts)
            if target.startswith('/'):
                current, parts = Path('/'), parts[1:]
            pending = parts + pending
            continue
        require(not pending or stat.S_ISDIR(info.st_mode), f'non-directory path component {candidate} for {link}')
        current = candidate
    return current, os.lstat(current), visited


def probe(layout, paths):
    """One fixed probe process as the delivery identity; any mismatch or error STOPs."""
    data = b''.join(os.fsencode(p) + b'\0' for p in paths)
    result = subprocess.run([layout.tools['runuser'], '-u', layout.account, '--', layout.tools['python3'], '-I', '-c', PROBE],
                            input=data, capture_output=True, env=ENV, cwd='/')
    require(result.returncode == 0 and result.stderr == b'', f'probe failed rc={result.returncode} stderr={result.stderr!r}')
    answers = result.stdout.split(b'\0')
    require(answers[-1:] == [b''] and len(answers) - 1 == len(paths), 'probe answer count mismatch')
    return dict(zip(paths, (a.decode() for a in answers[:-1])))


def security_key(path, info):
    """Every attribute that decides write authority or redirection; content timestamps are deliberately excluded."""
    kind = stat.S_IFMT(info.st_mode)
    return (kind, info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode),
            None if kind == stat.S_IFDIR else info.st_nlink, has_acl(path, info), mount_id(path),
            os.readlink(path) if kind == stat.S_IFLNK else None)


def observe(layout):
    """One complete observation: ancestors, physical walk, and every object on every symlink resolution chain."""
    app = layout.app
    info = lstat(app)
    require(app.is_absolute() and info is not None and stat.S_ISDIR(info.st_mode), 'application root missing or not a real directory')
    infos = {}
    for parent in reversed(app.parents):
        p = os.lstat(parent)
        require(stat.S_ISDIR(p.st_mode), 'application ancestor is not a real directory: ' + str(parent))
        infos[parent] = p
    ancestors = set(infos)
    app_mount = mount_id(app)
    root_dev, links, count, stack = info.st_dev, [], 0, [app]
    infos[app] = info
    while stack:
        directory = stack.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            raise Stop(f'walk error {directory}: {error}')
        for entry in entries:
            count += 1
            require(count <= MAX_ENTRIES, 'application tree exceeds entry budget')
            path = Path(entry.path)
            entry_info = entry.stat(follow_symlinks=False)
            infos[path] = entry_info
            if stat.S_ISLNK(entry_info.st_mode):
                links.append(path)
                continue
            require(entry_info.st_dev == root_dev and mount_id(path) == app_mount,
                    'mount point (including bind mount) inside application tree requires review: ' + str(path))
            if stat.S_ISDIR(entry_info.st_mode):
                stack.append(path)
    external, resolved = set(ancestors), []
    for link in sorted(links):
        final, final_info, visited = resolve(link)
        for path, visited_info in visited:
            if not (path == app or path.is_relative_to(app)):
                external.add(path)
            infos.setdefault(path, visited_info)
        if not final.is_relative_to(app):
            require(stat.S_ISREG(final_info.st_mode), f'out-of-tree link target is not a regular file: {link} -> {final}')
        resolved.append((str(link.relative_to(app)), os.readlink(link), str(final)))
    snapshot = {str(path): security_key(path, i) for path, i in infos.items()}
    return {'infos': infos, 'external': external, 'snapshot': snapshot, 'resolved': sorted(resolved), 'entries': count}


def evaluate(observation, who):
    for path in observation['external']:
        external_safe(path, observation['infos'][path])
    for path, info in observation['infos'].items():
        not_writable(path, info, who)


def require_same(first, later, when):
    a, b = first['snapshot'], later['snapshot']
    changed = sorted(p for p in set(a) | set(b) if a.get(p) != b.get(p))
    require(not changed and first['resolved'] == later['resolved'],
            f'security-relevant state changed {when}: {changed[:5]} (stability not established)')


def write_gate(layout, account):
    """No authority to modify the application tree, anything an allowed link reaches, or any redirecting component.

    Stability boundary: the decision covers the interval from the first observation to the post-probe
    observation (and, for --execute, the post-installation observation). Every security-relevant attribute of
    every object (type, dev, inode, uid, gid, mode, nlink, ACL presence, mount identity, link target and the full
    resolution) must be identical across observations, and the set of objects must be identical; any difference
    STOPs. No process runs as the delivery identity during the interval (S1 activity check) and it holds no
    registered credential, so it cannot act on a transient window that reverts between observations.
    """
    who = Identity(account)
    first = observe(layout)
    evaluate(first, who)
    paths = sorted(p for p, i in first['infos'].items() if not stat.S_ISLNK(i.st_mode))
    answers = probe(layout, [str(p) for p in paths])
    bad = {p: a for p, a in answers.items() if a not in ('N', 'U')}
    require(not bad, f'kernel probe reports writable/error: {dict(list(bad.items())[:5])}')
    second = observe(layout)
    evaluate(second, who)
    require_same(first, second, 'during the write gate')
    summary = {'entries': first['entries'], 'checked_objects': len(first['snapshot']), 'symlinks': first['resolved']}
    return summary, first


# ---------------------------------------------------------------- installation (only after S0/S1 + gates)

def app_state(layout):
    info = os.lstat(layout.app)
    return (info.st_uid, info.st_gid, info.st_mode)


def service_user(layout):
    user = checked(layout, 'systemctl', 'show', layout.service, '--property=User', '--value').strip()
    require(user != '', 'service User is empty')
    try:
        require(pwd.getpwnam(user).pw_uid != 0, 'bot runs as root; machine-key isolation requires human risk review')
    except KeyError:
        raise Stop('service user does not exist: ' + user)
    require(user != layout.account, 'service runs as delivery account')
    return user


def root_parent(path):
    info = os.lstat(Path(path).parent)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'creation parent is not a root-only directory: ' + str(Path(path).parent))


def exclusive_file(path, data, mode, uid=0, gid=0):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, data.encode() if isinstance(data, str) else data)
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def exclusive_dir(path, mode, uid=0, gid=0):
    os.mkdir(path, mode)
    os.chown(path, uid, gid, follow_symlinks=False)
    os.chmod(path, mode)


def install(layout, account, source_dir):
    """Exclusive creation only. Root-owned paths are created in root-only parents (no concurrent writer); the
    delivery-owned home has no process and no credential of its own until this step completes."""
    uid, gid = account.pw_uid, account.pw_gid
    ssh = layout.home / '.ssh'
    key = ssh / 'delivery_ed25519'
    for path in (key, Path(str(key) + '.pub')):
        require(lstat(path) is None, 'key path exists: ' + str(path))
    checked(layout, 'runuser', '-u', layout.account, '--', layout.tools['ssh-keygen'], '-q', '-t', 'ed25519', '-N', '',
            '-C', 'friday-vjserver-artifact-readonly', '-f', str(key))
    os.chmod(key, 0o600, follow_symlinks=False)
    os.chmod(str(key) + '.pub', 0o644, follow_symlinks=False)
    root_parent(layout.etc)
    exclusive_dir(layout.etc, 0o755)
    exclusive_file(layout.etc / 'github_known_hosts', HOST, 0o644)
    exclusive_file(ssh / 'config', SSH_CONFIG, 0o600, uid, gid)
    exclusive_dir(layout.home / 'cache', 0o700, uid, gid)
    exclusive_dir(layout.etc / 'approved', 0o700)
    root_parent(layout.deploy)
    exclusive_dir(layout.deploy, 0o700)
    parent = layout.tools_dir.parent
    if lstat(parent) is None:
        root_parent(parent)
        exclusive_dir(parent, 0o755)
    root_parent(layout.tools_dir)
    exclusive_dir(layout.tools_dir, 0o755)
    for name in ('delivery.py', 'delivery_operator.py'):
        exclusive_file(layout.tools_dir / name, (Path(source_dir) / name).read_bytes(), 0o644)


def validate_installed(layout, account):
    uid, gid = account.pw_uid, account.pw_gid
    ssh = layout.home / '.ssh'

    def regular(path, owner, mode):
        info = lstat(path)
        require(info is not None and stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'installed file missing/unsafe: ' + str(path))
        require((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (*owner, mode), 'installed file owner/mode: ' + str(path))
    real_dir(layout.home, uid, gid, 0o700, 'home')
    real_dir(ssh, uid, gid, 0o700, '.ssh')
    require(sorted(os.listdir(ssh)) == ['config', 'delivery_ed25519', 'delivery_ed25519.pub'], '.ssh contents')
    regular(ssh / 'delivery_ed25519', (uid, gid), 0o600)
    regular(ssh / 'delivery_ed25519.pub', (uid, gid), 0o644)
    regular(ssh / 'config', (uid, gid), 0o600)
    real_dir(layout.home / 'cache', uid, gid, 0o700, 'cache')
    real_dir(layout.etc, 0, 0, 0o755, '/etc/friday-delivery')
    regular(layout.etc / 'github_known_hosts', (0, 0), 0o644)
    real_dir(layout.etc / 'approved', 0, 0, 0o700, 'approved')
    require(os.listdir(layout.etc / 'approved') == [], 'approved is not empty')
    real_dir(layout.deploy, 0, 0, 0o700, 'deployment')
    require(os.listdir(layout.deploy) == [], 'deployment is not empty')
    real_dir(layout.tools_dir, 0, 0, 0o755, 'tools')
    for name in ('delivery.py', 'delivery_operator.py'):
        regular(layout.tools_dir / name, (0, 0), 0o644)
    group_boundary(layout, account)


def bootstrap(layout, mode, source_dir=None, out=None):
    out = out or emit
    require(mode in ('preflight', 'execute'), 'unknown mode')
    require(os.geteuid() == 0, 'run reviewed installer as root')
    service_user(layout)
    before = app_state(layout)
    state, account = classify(layout)
    out('STATE: ' + state)
    if state == 'S0':
        if mode == 'preflight':
            out('PREFLIGHT_INCOMPLETE: S0 has no account; sudo/write gates are evaluated only by --execute after creation')
            return 2
        create_s1(layout)
        account = validate_s1(layout)
        out('S1_CREATED_AND_VALIDATED (fresh installation)')
    else:
        out('S1_VALIDATED: authorized incident identity; complete S1 state and incident evidence matched')
    out('SUDO_GATE_PASS: ' + json.dumps(sudo_gate(layout), sort_keys=True))
    summary, decision = write_gate(layout, account)
    out('WRITE_GATE_PASS: ' + json.dumps(summary, sort_keys=True))
    require(app_state(layout) == before, 'application owner/group/mode changed')
    if mode == 'preflight':
        out('PREFLIGHT_PASS: no changes made; bootstrap --execute still requires separate authorization')
        return 0
    install(layout, account, source_dir or Path(__file__).resolve().parent)
    validate_installed(layout, account)
    # Re-establish every gate decision across the installation boundary.
    sudo_gate(layout)
    after = observe(layout)
    evaluate(after, Identity(account))
    require_same(decision, after, 'across the installation boundary')
    require(app_state(layout) == before, 'application owner/group/mode changed')
    out('POST_INSTALL_GATES_REESTABLISHED')
    pub = str(layout.home / '.ssh' / 'delivery_ed25519.pub')
    out(checked(layout, 'ssh-keygen', '-lf', pub).strip())
    out(Path(pub).read_text().strip())
    out('BOOTSTRAPPED_NOT_REGISTERED: private key remains local; no release fetched or activated')
    return 0


def emit(line):
    print(line, flush=True)  # keep progress ordered with STOP lines on stderr


def main(argv):
    try:
        require(len(argv) == 2 and argv[1] in ('--preflight', '--execute', '--authorize-incident-resume'),
                'exactly one of --preflight, --execute or --authorize-incident-resume is required')
        if argv[1] == '--authorize-incident-resume':
            return authorize_incident_resume(PRODUCTION, emit)
        return bootstrap(PRODUCTION, argv[1][2:])
    except Stop as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception as error:  # unexpected errors are STOP conditions too, never retries
        print('STOP: unexpected error ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))

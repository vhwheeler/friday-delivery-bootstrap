"""Registry-driven pinned artifact transport and quarantine (tooling schema 2); never deploys or mutates production Git.

Authority: a release is acceptable only through a root-installed registry entry (/etc/friday-delivery/approved/<id>.json,
schema friday-delivery-release/1) whose exact SHA256 the root operator restates on every run. Nothing inside the
delivery repository (provenance.json, README, other releases) and nothing inside the package is ever consulted to
decide what is approved: the package can only be checked AGAINST the entry, never authorize itself.
"""
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile

TOOLING_SCHEMA = 'friday-delivery-tooling/2'
ENTRY_SCHEMA = 'friday-delivery-release/1'
REPO = 'vhwheeler/friday-production-delivery'
APP_ROOT = '/opt/msf-counter-bot'
SCOPE = 'retrieval-preflight'
FULL_SHA = re.compile(r'[0-9a-f]{40}')
SHA256 = re.compile(r'[0-9a-f]{64}')
RELEASE_ID = re.compile(r'[a-z0-9][a-z0-9.-]{2,63}')
PATH_CHARS = re.compile(r'[A-Za-z0-9._/-]+')
MAX_PACKAGE = 10_000_000
MAX_ENTRY = 64_000
ENTRY_KEYS = ('schema', 'tooling_schema', 'id', 'scope', 'deployment_authorized', 'repository', 'delivery_commit',
              'artifact_path', 'package_sha256', 'package_bytes', 'manifest_sha256', 'manifest_release_id',
              'application_checkpoint', 'handoff_checkpoint', 'trust_anchor_sha256', 'canonical_staged_sha256',
              'approved_destinations')


@dataclass(frozen=True)
class Layout:
    account: str = 'friday-delivery'
    etc: Path = Path('/etc/friday-delivery')
    approved: Path = Path('/etc/friday-delivery/approved')
    tools: Path = Path('/usr/local/libexec/friday-delivery')
    home: Path = Path('/var/lib/friday-delivery')
    cache: Path = Path('/var/lib/friday-delivery/cache')
    quarantine: Path = Path('/var/lib/friday-deployment')
    python: str = '/usr/bin/python3'
    runuser: str = '/usr/sbin/runuser'


PRODUCTION = Layout()


def require(ok, message):
    if not ok:
        raise ValueError('STOP: ' + message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_relative(path):
    require(isinstance(path, str) and PATH_CHARS.fullmatch(path) is not None, f'unsupported path form: {path!r}')
    pure = PurePosixPath(path)
    require(not pure.is_absolute() and str(pure) == path and all(p not in ('', '.', '..') for p in pure.parts),
            f'unsafe or non-normal path: {path!r}')
    return path


def canonical_entry(entry):
    """The exact bytes an approved entry file holds; its SHA256 is what the control room approves."""
    return (json.dumps(entry, indent=2) + '\n').encode()


def validate_entry(entry, release_id=None):
    """Strict, complete registry entry. Partially specified, extended, retyped or deployment-claiming entries STOP."""
    require(isinstance(entry, dict) and list(entry) == list(ENTRY_KEYS), 'registry entry keys/order must be exactly ' + ', '.join(ENTRY_KEYS))
    require(entry['schema'] == ENTRY_SCHEMA, 'unknown or downgraded registry entry schema')
    require(entry['tooling_schema'] == TOOLING_SCHEMA, 'registry entry requires a different delivery-tooling schema')
    require(isinstance(entry['id'], str) and RELEASE_ID.fullmatch(entry['id']) is not None, 'invalid release id')
    require(release_id is None or entry['id'] == release_id, 'release id substitution')
    require(entry['scope'] == SCOPE and entry['deployment_authorized'] is False, 'entry may only authorize retrieval/preflight')
    require(entry['repository'] == REPO, 'repository mismatch')
    for key in ('delivery_commit', 'application_checkpoint', 'handoff_checkpoint'):
        require(isinstance(entry[key], str) and FULL_SHA.fullmatch(entry[key]) is not None, key + ' must be a full commit SHA')
    for key in ('package_sha256', 'manifest_sha256', 'canonical_staged_sha256'):
        require(isinstance(entry[key], str) and SHA256.fullmatch(entry[key]) is not None, key + ' must be a SHA256')
    require(entry['artifact_path'] == 'releases/sha256/' + entry['package_sha256'] + '/bundle.tar.gz', 'unapproved artifact path')
    require(type(entry['package_bytes']) is int and 0 < entry['package_bytes'] <= MAX_PACKAGE, 'invalid package size')
    require(entry['manifest_release_id'] is None or entry['manifest_release_id'] == entry['id'],
            'manifest release id must be null (unlabelled legacy package) or equal the entry id')
    require(entry['trust_anchor_sha256'] is None
            or (isinstance(entry['trust_anchor_sha256'], str) and SHA256.fullmatch(entry['trust_anchor_sha256']) is not None),
            'trust anchor must be null or a SHA256')
    dests = entry['approved_destinations']
    require(isinstance(dests, list) and dests and len(dests) == len(set(dests)), 'approved destinations must be a non-empty unique list')
    for d in dests:
        safe_relative(d)
    return entry


def parse_entry(raw, expected_sha256, release_id=None):
    require(isinstance(expected_sha256, str) and SHA256.fullmatch(expected_sha256) is not None,
            'control-room registry entry SHA256 is required')
    require(digest(raw) == expected_sha256, 'registry entry does not match the control-room SHA256')
    try:
        entry = json.loads(raw)
    except ValueError:
        raise ValueError('STOP: registry entry is not JSON')
    validate_entry(entry, release_id)
    require(canonical_entry(entry) == raw, 'registry entry is not in canonical form')
    return entry


def verify(raw, entry):
    """Check package bytes AGAINST the approved entry. Nothing in the package can widen or replace the entry."""
    validate_entry(entry)
    require(len(raw) == entry['package_bytes'], 'package size mismatch')
    require(digest(raw) == entry['package_sha256'], 'package hash mismatch')
    members = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for item in archive:
            name = PurePosixPath(item.name)
            require(item.isfile() and not item.issym() and not item.islnk(), 'non-regular archive member')
            require(not name.is_absolute() and '..' not in name.parts and str(name) == item.name, 'unsafe member path')
            require(item.name not in members and item.size <= MAX_PACKAGE, 'duplicate/oversized member')
            members[item.name] = archive.extractfile(item).read()
    require('manifest.json' in members, 'missing manifest')
    require(digest(members['manifest.json']) == entry['manifest_sha256'], 'manifest mismatch')
    m = json.loads(members['manifest.json'])
    require(m.get('release_id') == entry['manifest_release_id'], 'package release identity differs from the entry')
    require(m['source_checkpoint'] == entry['application_checkpoint'], 'source checkpoint mismatch')
    require(m['application_root'] == APP_ROOT, 'application root mismatch')
    anchor = (m.get('production_baseline') or {}).get('trust_anchor_sha256')
    require(anchor == entry['trust_anchor_sha256'], 'trust-anchor binding mismatch')
    require(set(members) == set(m['included_files']) | {'manifest.json'}, 'unexpected member')
    for name, info in m['included_files'].items():
        require(digest(members[name]) == info['sha256'] and len(members[name]) == info['bytes'], 'payload mismatch')
    require([e['path'] for e in m['entries']] == entry['approved_destinations'], 'destination allowlist mismatch')
    require(all(e['destination'] == APP_ROOT + '/' + e['path'] for e in m['entries']), 'destination outside the application root')
    staged = [members[e['payload']] for e in m['entries'] if e['path'].startswith('towers/dynamic/bundles/')]
    require(len(staged) == 1, 'staged bundle count')
    value = json.loads(staged[0]); claimed = value.pop('bundle_sha256')
    canonical = digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
    require(canonical == claimed == m['bundle_sha256'] == entry['canonical_staged_sha256'], 'canonical staged hash mismatch')
    return members


def read_regular(path, limit, owner=None, mode=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsafe input inode: ' + str(path))
        require(info.st_size <= limit, 'oversized input: ' + str(path))
        if owner is not None:
            require(info.st_uid == owner and not info.st_mode & 0o022, 'unsafe input owner/mode: ' + str(path))
        if mode is not None:
            require(stat.S_IMODE(info.st_mode) == mode, 'unexpected input mode: ' + str(path))
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            chunks.append(chunk); total += len(chunk)
            require(total <= limit, 'oversized input: ' + str(path))
        return b''.join(chunks)
    finally:
        os.close(fd)


def retrieve(entry, layout=PRODUCTION, run=subprocess.run, source=None):
    """Delivery identity only. Fetch the exact commit into a fresh bare repository and copy one blob out."""
    validate_entry(entry)
    cache = Path(layout.cache)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(layout.home), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_REPLACE_OBJECTS': '1', 'LC_ALL': 'C'}
    work = Path(tempfile.mkdtemp(prefix='pull-', dir=cache))

    def git(*args, capture=False):
        return run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.useReplaceRefs=false',
                    '-c', 'core.sshCommand=ssh -F ' + str(layout.home / '.ssh/config'),
                    '--git-dir=' + str(work / 'objects.git'), *args], env=env, check=True,
                   stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=subprocess.PIPE)
    git('init', '--bare')
    git('fetch', '--no-tags', '--depth=1', source or ('git@friday-artifacts:' + REPO + '.git'), entry['delivery_commit'])
    observed = git('rev-parse', 'FETCH_HEAD', capture=True).stdout.decode().strip()
    require(observed == entry['delivery_commit'], 'FETCH_HEAD mismatch')
    listing = git('ls-tree', '-z', observed, '--', entry['artifact_path'], capture=True).stdout.decode()
    meta, _, name = listing.rstrip('\0').partition('\t')
    require(name == entry['artifact_path'] and meta.split(' ')[:2] == ['100644', 'blob'], 'artifact is not a regular blob')
    raw = git('cat-file', 'blob', meta.split(' ')[2], capture=True).stdout
    require(len(raw) == entry['package_bytes'], 'retrieved size mismatch')
    target = work / 'bundle.tar.gz'
    with target.open('xb') as stream:
        stream.write(raw)
    return target


def quarantine(source, entry, layout=PRODUCTION):
    """Root only. Copy delivery-owned bytes into a root-only directory, then verify the ROOT copy against the entry."""
    require(os.geteuid() == 0, 'root verifier required')
    root = Path(layout.quarantine)
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077, 'unsafe quarantine root')
    source = Path(source)
    require(source.is_absolute() and '..' not in source.parts and source.is_relative_to(layout.cache), 'outside cache')
    for parent in [source.parent, *source.parents]:
        require(not parent.is_symlink(), 'symlink cache parent')
    raw = read_regular(source, entry['package_bytes'])
    destination = Path(tempfile.mkdtemp(prefix='verified-', dir=root))
    package = destination / 'bundle.tar.gz'
    with package.open('xb') as stream:
        stream.write(raw)
    package.chmod(0o600)
    members = verify(read_regular(package, entry['package_bytes'], owner=0), entry)
    payload = destination / 'package'; payload.mkdir(mode=0o700)
    for name, content in members.items():
        out = payload / name; out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with out.open('xb') as stream:
            stream.write(content)
        out.chmod(0o600)
    return payload

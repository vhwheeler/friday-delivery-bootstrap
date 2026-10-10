"""Pinned artifact transport and quarantine; never deploys or mutates production Git."""
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

REPO = 'vhwheeler/friday-production-delivery'
STATES = ('PUBLISHED', 'RETRIEVED_NOT_VERIFIED', 'RETRIEVED_VERIFIED', 'RETRIEVAL_FAILED',
          'PREFLIGHT_PASS', 'PREFLIGHT_FAIL', 'DEPLOYMENT_AUTHORIZED',
          'DEPLOYED_SMOKE_REQUIRED', 'PRODUCTION_READY')

def require(ok, message):
    if not ok:
        raise ValueError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def policy(p):
    require(p['repository'] == REPO, 'Repository mismatch')
    require(re.fullmatch('[0-9a-f]{40}', p['delivery_commit'] or '') is not None, 'Full delivery commit required')
    require(p['artifact_path'] == 'releases/sha256/' + p['package_sha256'] + '/bundle.tar.gz', 'Unapproved artifact path')
    require(re.fullmatch('[0-9a-f]{64}', p['package_sha256']) is not None, 'Invalid hash')
    return p

def verify(raw, p):
    policy(p)
    require(len(raw) == p['package_bytes'], 'Package size mismatch')
    require(digest(raw) == p['package_sha256'], 'Package hash mismatch')
    members = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for item in archive:
            name = PurePosixPath(item.name)
            require(item.isfile() and not item.issym() and not item.islnk(), 'Non-regular archive member')
            require(not name.is_absolute() and '..' not in name.parts and str(name) == item.name, 'Unsafe member path')
            require(item.name not in members and item.size <= 10_000_000, 'Duplicate/oversized member')
            members[item.name] = archive.extractfile(item).read()
    require('manifest.json' in members, 'Missing manifest')
    require(digest(members['manifest.json']) == p['manifest_sha256'], 'Manifest mismatch')
    m = json.loads(members['manifest.json'])
    require(m['source_checkpoint'] == p['application_checkpoint'], 'Source checkpoint mismatch')
    require(p['handoff_checkpoint'] == '44c3ed943821487f13adf9794bd272361af645e6', 'Handoff binding mismatch')
    require(set(members) == set(m['included_files']) | {'manifest.json'}, 'Unexpected member')
    for name, info in m['included_files'].items():
        require(digest(members[name]) == info['sha256'] and len(members[name]) == info['bytes'], 'Payload mismatch')
    require([e['path'] for e in m['entries']] == p['approved_destinations'], 'Destination allowlist mismatch')
    staged = [members[e['payload']] for e in m['entries'] if e['path'].startswith('towers/dynamic/bundles/')]
    require(len(staged) == 1, 'Staged bundle count')
    value = json.loads(staged[0]); claimed = value.pop('bundle_sha256')
    canonical = digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
    require(canonical == claimed == m['bundle_sha256'] == p['canonical_staged_sha256'], 'Canonical staged hash mismatch')
    return members

def read_regular(path, limit, owner=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Unsafe input inode')
        require(info.st_size <= limit, 'Oversized input')
        if owner is not None:
            require(info.st_uid == owner and not info.st_mode & 0o022, 'Unsafe input owner/mode')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            return stream.read(limit + 1)
    finally:
        os.close(fd)

def retrieve(p, cache, run=subprocess.run):
    policy(p)
    # Fresh bare repository, never production checkout; no inherited hooks/config/agent.
    cache = Path(cache)
    require(cache == Path('/var/lib/friday-delivery/cache'), 'Wrong cache root')
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/var/lib/friday-delivery',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
    work = Path(tempfile.mkdtemp(prefix='pull-', dir=cache))
    def git(*args, capture=False):
        return run(['git', '-c', 'core.hooksPath=/dev/null', '-c',
                    'core.sshCommand=ssh -F /var/lib/friday-delivery/.ssh/config',
                    '--git-dir=' + str(work / 'objects.git'), *args], env=env, check=True,
                   stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=subprocess.PIPE)
    git('init', '--bare')
    git('fetch', '--no-tags', '--depth=1', 'git@friday-artifacts:' + REPO + '.git', p['delivery_commit'])
    observed = git('rev-parse', 'FETCH_HEAD', capture=True).stdout.decode().strip()
    require(observed == p['delivery_commit'], 'FETCH_HEAD mismatch')
    raw = git('show', observed + ':' + p['artifact_path'], capture=True).stdout
    target = work / 'bundle.tar.gz'
    with target.open('xb') as stream:
        stream.write(raw)
    return target

def quarantine(source, p, root):
    require(os.geteuid() == 0, 'Root verifier required')
    root = Path(root)
    require(root == Path('/var/lib/friday-deployment'), 'Wrong quarantine root')
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077, 'Unsafe quarantine root')
    # Source parent must be trusted traversal: no symlink anywhere in cache path.
    source = Path(source)
    require(source.is_absolute() and '..' not in source.parts and source.is_relative_to('/var/lib/friday-delivery/cache'), 'Outside cache')
    for parent in [source.parent, *source.parents]:
        require(not parent.is_symlink(), 'Symlink cache parent')
    raw = read_regular(source, p['package_bytes'])
    destination = Path(tempfile.mkdtemp(prefix='verified-', dir=root))
    package = destination / 'bundle.tar.gz'
    with package.open('xb') as stream:
        stream.write(raw)
    package.chmod(0o600)
    # Re-open and hash the ROOT copy, never execute delivery-owned bytes.
    members = verify(read_regular(package, p['package_bytes'], owner=0), p)
    payload = destination / 'package'; payload.mkdir(mode=0o700)
    for name, content in members.items():
        out = payload / name; out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with out.open('xb') as stream:
            stream.write(content)
        out.chmod(0o600)
    return payload

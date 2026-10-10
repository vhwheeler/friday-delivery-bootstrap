"""Privileged retrieval/preflight only (tooling schema 2). No deployment command and no automatic authorization.

  --self-check                                         verify installed tooling, registry and locations; change nothing
  --approve <entry-file> --expect-entry-sha256 <sha>   root installs ONE control-room-approved registry entry (create-only)
  --revoke <release-id> --expect-entry-sha256 <sha>    root removes that exact registry entry
  --retrieve <release-id> --expect-entry-sha256 <sha>  retrieve as the delivery identity, verify the root copy, run the
                                                       package preflight; never deploys
  --retrieve-child                                     internal: delivery identity fetch (entry on stdin)

Every root mode re-states the control room's entry SHA256, so an old or substituted entry is never used implicitly.
delivery.py is executed only from bytes whose SHA256 matches the installed tooling.json, read without following links.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types

sys.dont_write_bytecode = True  # never create __pycache__ inside the root tooling directory
TOOLING_SCHEMA = 'friday-delivery-tooling/2'
TOOL_FILES = frozenset({'delivery.py', 'delivery_operator.py', 'tooling.json'})
ACL_XATTRS = ('system.posix_acl_access', 'system.posix_acl_default')


def fail(message):
    raise ValueError('STOP: ' + message)


def check(ok, message):
    if not ok:
        fail(message)


def no_acl(path):
    for name in ACL_XATTRS:
        try:
            os.getxattr(path, name, follow_symlinks=False)
        except OSError:
            continue
        fail('extended ACL present: ' + str(path))


def trusted_dir(path, trust_root, mode=None):
    """Root-owned real directory, not group/other writable, no ACL, with the same property up to trust_root."""
    path = Path(path)
    check(path.is_absolute() and path.is_relative_to(trust_root), 'path outside trust root: ' + str(path))
    for p in [path, *[q for q in path.parents if q.is_relative_to(trust_root)]]:
        info = os.lstat(p)
        check(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), 'not a real directory: ' + str(p))
        check(info.st_uid == 0 and not info.st_mode & 0o022, 'directory writable by non-root: ' + str(p))
        no_acl(p)
    if mode is not None:
        check(stat.S_IMODE(os.lstat(path).st_mode) == mode, 'unexpected directory mode: ' + str(path))


def read_tool(path, limit=1_000_000):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        fail('cannot open tooling file without following links: ' + str(path) + ' (' + error.strerror + ')')
    try:
        info = os.fstat(fd)
        check(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0 and info.st_gid == 0
              and stat.S_IMODE(info.st_mode) == 0o644 and info.st_size <= limit, 'unsafe tooling file: ' + str(path))
        raw = b''
        while chunk := os.read(fd, 1 << 16):
            raw += chunk
        no_acl(path)
        return raw
    finally:
        os.close(fd)


def load_tooling(layout_tools, trust_root=Path('/')):
    """Verify the installed tooling set and return (delivery module compiled from verified bytes, file hashes)."""
    tools = Path(layout_tools)
    trusted_dir(tools, trust_root, 0o755)
    check(set(os.listdir(tools)) == TOOL_FILES, 'tooling directory must contain exactly ' + ', '.join(sorted(TOOL_FILES)))
    raw = {name: read_tool(tools / name) for name in TOOL_FILES}
    meta = json.loads(raw['tooling.json'])
    check(meta.get('schema') == TOOLING_SCHEMA and set(meta) == {'schema', 'files'}, 'unknown tooling schema')
    check(set(meta['files']) == {'delivery.py', 'delivery_operator.py'}, 'tooling.json file set')
    for name, pin in meta['files'].items():
        check(hashlib.sha256(raw[name]).hexdigest() == pin['sha256'] and len(raw[name]) == pin['bytes'],
              'installed tooling differs from tooling.json: ' + name)
    module = types.ModuleType('delivery')
    module.__file__ = str(tools / 'delivery.py')
    sys.modules['delivery'] = module
    exec(compile(raw['delivery.py'], module.__file__, 'exec'), module.__dict__)
    check(module.TOOLING_SCHEMA == TOOLING_SCHEMA, 'delivery.py tooling schema mismatch')
    return module, {name: hashlib.sha256(raw[name]).hexdigest() for name in sorted(TOOL_FILES)}


class Locked:
    """Exclusive, non-blocking lock shared with tooling_transition.py; held for the whole root operation."""
    def __init__(self, etc):
        self.fd = os.open(etc, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def __enter__(self):
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            fail('another delivery operation or tooling transition holds the lock')
        return self

    def __exit__(self, *exc):
        os.close(self.fd)


def environment(d, layout, trust_root):
    check(os.geteuid() == 0, 'root operator required')
    trusted_dir(layout.etc, trust_root, 0o755)
    trusted_dir(layout.approved, trust_root, 0o700)
    trusted_dir(layout.quarantine, trust_root, 0o700)
    return d


def entry_path(d, layout, release_id):
    check(isinstance(release_id, str) and d.RELEASE_ID.fullmatch(release_id) is not None, 'invalid release id')
    return Path(layout.approved) / (release_id + '.json')


def self_check(d, layout, hashes):
    registry = sorted(os.listdir(layout.approved))
    return {'state': 'SELF_CHECK_PASS', 'tooling_schema': TOOLING_SCHEMA, 'tooling_sha256': hashes, 'registry': registry}


def approve(d, layout, staged, expected):
    raw = d.read_regular(staged, d.MAX_ENTRY)
    entry = d.parse_entry(raw, expected)
    target = entry_path(d, layout, entry['id'])
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchown(fd, 0, 0); os.fchmod(fd, 0o600)
        os.write(fd, raw); os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(layout.approved, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    d.parse_entry(d.read_regular(target, d.MAX_ENTRY, owner=0, mode=0o600), expected, entry['id'])
    return {'state': 'APPROVED_FOR_RETRIEVAL_PREFLIGHT', 'id': entry['id'], 'entry_sha256': expected,
            'deployment_authorized': False}


def load_entry(d, layout, release_id, expected):
    raw = d.read_regular(entry_path(d, layout, release_id), d.MAX_ENTRY, owner=0, mode=0o600)
    return d.parse_entry(raw, expected, release_id)


def revoke(d, layout, release_id, expected):
    load_entry(d, layout, release_id, expected)
    os.unlink(entry_path(d, layout, release_id))
    return {'state': 'REVOKED', 'id': release_id, 'entry_sha256': expected}


def child_command(layout):
    return [layout.runuser, '-u', layout.account, '--', layout.python, '-I', '-B',
            str(Path(layout.tools) / 'delivery_operator.py'), '--retrieve-child']


def retrieve_release(d, layout, release_id, expected, hashes, run_child=None, run_preflight=None):
    entry = load_entry(d, layout, release_id, expected)
    receipt = {'state': 'RETRIEVAL_FAILED', 'id': release_id, 'entry_sha256': expected, 'tooling_sha256': hashes,
               'repository': entry['repository'], 'delivery_commit': entry['delivery_commit'],
               'package_sha256': entry['package_sha256'], 'deployment_authorized': False}
    try:
        payload = None
        if run_child is None:
            result = subprocess.run(child_command(layout), input=d.canonical_entry(entry).decode(), text=True,
                                    capture_output=True, check=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
            source = result.stdout.strip()
        else:
            source = run_child(entry)
        receipt['state'] = 'RETRIEVED_NOT_VERIFIED'
        payload = d.quarantine(source, entry, layout)
        receipt['state'] = 'RETRIEVED_VERIFIED'
        receipt['quarantine'] = str(payload)
        command = [layout.python, '-I', '-B', str(payload / 'operator.py'), 'preflight']
        output = (run_preflight or (lambda c: subprocess.run(c, capture_output=True, text=True, cwd=payload.parent,
                                                              env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})))(command)
        receipt['state'] = 'PREFLIGHT_PASS' if output.returncode == 0 else 'PREFLIGHT_FAIL'
        receipt['preflight'] = json.loads(output.stdout) if output.returncode == 0 else {'error': output.stderr[-4000:]}
        receipt_path = payload.parent / 'receipt.json'
        with receipt_path.open('x') as stream:
            stream.write(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
        return receipt
    except Exception:
        with tempfile.NamedTemporaryFile(mode='w', prefix='failed-', suffix='.json', dir=layout.quarantine, delete=False) as stream:
            stream.write(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
        raise


def main(argv, layout=None, trust_root=Path('/')):
    tools = Path(os.path.abspath(__file__)).parent
    if argv == ['--retrieve-child']:
        import pwd
        d, _ = load_tooling(tools, trust_root)
        layout = layout or d.PRODUCTION
        check(tools == Path(layout.tools), 'operator is not running from the installed tooling directory')
        check(os.getuid() == pwd.getpwnam(layout.account).pw_uid and os.getuid() != 0, 'wrong retrieval identity')
        entry = d.validate_entry(json.load(sys.stdin))
        print(d.retrieve(entry, layout))
        return 0
    d, hashes = load_tooling(tools, trust_root)
    layout = layout or d.PRODUCTION
    check(tools == Path(layout.tools), 'operator is not running from the installed tooling directory')
    environment(d, layout, trust_root)
    modes = {'--self-check': 1, '--approve': 4, '--revoke': 4, '--retrieve': 4}
    check(argv and argv[0] in modes and len(argv) == modes[argv[0]] and (len(argv) == 1 or argv[2] == '--expect-entry-sha256'),
          'usage: --self-check | --approve FILE | --revoke ID | --retrieve ID, each with --expect-entry-sha256 SHA256')
    with Locked(layout.etc):
        if argv[0] == '--self-check':
            result = self_check(d, layout, hashes)
        elif argv[0] == '--approve':
            result = approve(d, layout, argv[1], argv[3])
        elif argv[0] == '--revoke':
            result = revoke(d, layout, argv[1], argv[3])
        else:
            result = retrieve_release(d, layout, argv[1], argv[3], hashes)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['state'] != 'PREFLIGHT_FAIL' else 3


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as error:
        print(str(error) if str(error).startswith('STOP') else 'STOP: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        sys.exit(1)

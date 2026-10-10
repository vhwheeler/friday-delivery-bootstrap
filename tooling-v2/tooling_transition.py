"""One-time, root-run transition of /usr/local/libexec/friday-delivery from bootstrap-v2 tooling (schema 1, V1-only) to
registry-driven tooling (schema 2). Never deploys, never touches the registry, the application or the delivery identity.

Run only from a verified ROOT copy (verify_tooling_kit.py). Modes:
  --preflight <root-copy>   observe and verify everything; change nothing
  --execute   <root-copy>   CURRENT -> TARGET with one atomic directory exchange
  --recover   <root-copy>   finish or undo an interrupted --execute / --rollback deterministically
  --rollback                TARGET -> previous exact tooling (atomic exchange back)
  --verify                  classify the installed state; change nothing

Every directory state is one of the named states below; anything else STOPs for human review. The lock is the same
exclusive flock on /etc/friday-delivery that the schema-2 operator holds, so no transition overlaps a retrieval.
"""
import ctypes
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys

# Installed by bootstrap v2 (docs/codex/production-delivery/v2/candidate-pins.json), byte-identical to bootstrap v1's.
CURRENT = {
    'delivery.py': ('a84b66070ef4fd09daa48899a8c195943765ac3e3747af8f9394a859716ddbd0', 6356),
    'delivery_operator.py': ('f775c68c720af3afc8edc791f7b6d27638840108aaa6b99d199bac3764a4d083', 3088),
}
# tools/production_delivery/tooling_v2/ (tests bind these pins to the reviewed sources).
TARGET = {
    'delivery.py': ('a98cee591a0dcd145765fbf673fdc20febda49014d425d7af231a50025181317', 12108),
    'delivery_operator.py': ('03adf98c2e0664f781ea636ea24d9fe13e95e0c13557bf1b28f48672a0f02bbb', 11078),
    'tooling.json': ('6228d6005a7aaaaf2e70bbf932856986ced9f451684364a2a4229ce25c082b61', 336),
}
ACL_XATTRS = ('system.posix_acl_access', 'system.posix_acl_default')
RENAME_NOREPLACE, RENAME_EXCHANGE, AT_FDCWD = 1, 2, -100


@dataclass(frozen=True)
class Layout:
    tools: Path = Path('/usr/local/libexec/friday-delivery')
    next: Path = Path('/usr/local/libexec/.friday-delivery-next')
    backup: Path = Path('/usr/local/libexec/friday-delivery.tooling-schema1-backup')
    retired: Path = Path('/usr/local/libexec/friday-delivery.tooling-schema2-retired')
    etc: Path = Path('/etc/friday-delivery')
    approved: Path = Path('/etc/friday-delivery/approved')
    quarantine: Path = Path('/var/lib/friday-deployment')
    account: str = 'friday-delivery'
    trust_root: Path = Path('/')
    proc: Path = Path('/proc')
    python: str = '/usr/bin/python3'


PRODUCTION = Layout()


class Stop(Exception):
    pass


def require(ok, message):
    if not ok:
        raise Stop('STOP: ' + message)


def no_acl(path):
    for name in ACL_XATTRS:
        try:
            os.getxattr(path, name, follow_symlinks=False)
        except OSError:
            continue
        raise Stop('STOP: extended ACL present: ' + str(path))


def lstat(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def trusted_dir(layout, path, mode=None):
    path = Path(path)
    require(path.is_relative_to(layout.trust_root), 'outside trust root: ' + str(path))
    for p in [path, *[q for q in path.parents if q.is_relative_to(layout.trust_root)]]:
        info = os.lstat(p)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'not a root-only real directory: ' + str(p))
        no_acl(p)
    if mode is not None:
        require(stat.S_IMODE(os.lstat(path).st_mode) == mode, 'unexpected mode: ' + str(path))


def read_file(path, owner_mode=(0, 0, 0o644), limit=1_000_000):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise Stop('STOP: cannot open without following links: ' + str(path) + ' (' + error.strerror + ')')
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit, 'unsafe inode: ' + str(path))
        if owner_mode is not None:
            require((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == owner_mode, 'owner/mode: ' + str(path))
        raw = b''
        while chunk := os.read(fd, 1 << 16):
            raw += chunk
        no_acl(path)
        return raw
    finally:
        os.close(fd)


def dir_state(path, allow_pycache=False):
    """None if absent; else {name: (sha256, bytes)} for a root:root real directory of root:root 0644 regular files.
    A root-owned __pycache__ written by an earlier schema-1 operator run is tolerated (and travels with its directory)."""
    info = lstat(path)
    if info is None:
        return None
    require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid) == (0, 0)
            and stat.S_IMODE(info.st_mode) in (0o755, 0o700), 'unexpected tooling directory: ' + str(path))
    no_acl(path)
    files = {}
    for name in sorted(os.listdir(path)):
        if name == '__pycache__' and allow_pycache:
            cache = Path(path) / name
            c = os.lstat(cache)
            require(stat.S_ISDIR(c.st_mode) and c.st_uid == 0 and not c.st_mode & 0o022, 'unsafe __pycache__')
            for item in os.listdir(cache):
                read_file(cache / item, owner_mode=None)
                require(os.lstat(cache / item).st_uid == 0 and item.endswith('.pyc'), 'unsafe __pycache__ member')
            continue
        raw = read_file(Path(path) / name)
        files[name] = (hashlib.sha256(raw).hexdigest(), len(raw))
    return files


def classify(layout):
    t = dir_state(layout.tools, allow_pycache=True)
    n = dir_state(layout.next, allow_pycache=True)  # holds CURRENT (and its cache) between exchange and rename
    b = dir_state(layout.backup, allow_pycache=True)
    r = dir_state(layout.retired)
    states = {
        'CURRENT': (t == CURRENT, n is None, b is None, r is None),
        'STAGED': (t == CURRENT, n is not None, b is None, r is None),
        'EXCHANGED': (t == TARGET, n == CURRENT, b is None, r is None),
        'TARGET': (t == TARGET, n is None, b == CURRENT, r is None),
        'ROLLBACK_EXCHANGED': (t == CURRENT, n is None, b == TARGET, r is None),
        'ROLLED_BACK': (t == CURRENT, n is None, b is None, r == TARGET),
    }
    found = [name for name, conditions in states.items() if all(conditions)]
    require(len(found) == 1, 'HUMAN_REQUIRED: unrecognized tooling state ' + json.dumps(
        {'tools': t, 'next': n, 'backup': b, 'retired': r}, sort_keys=True))
    return found[0]


def renameat2(old, new, flags):
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.renameat2
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    if function(AT_FDCWD, os.fsencode(str(old)), AT_FDCWD, os.fsencode(str(new)), flags) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(old))
    fsync_dir(Path(new).parent)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Locked:
    def __init__(self, layout):
        self.fd = os.open(layout.etc, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def __enter__(self):
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            raise Stop('STOP: a delivery operation or another transition holds the lock')
        return self

    def __exit__(self, *exc):
        os.close(self.fd)


def no_operator_running(layout):
    for pid in os.listdir(layout.proc):
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        try:
            cmdline = (Path(layout.proc) / pid / 'cmdline').read_bytes()
        except OSError:
            continue
        require(b'delivery_operator.py' not in cmdline, 'a delivery operator process is running (pid ' + pid + ')')


def boundaries(layout):
    """The delivery identity can modify neither the tooling nor the registry: every path is root-only."""
    require(os.geteuid() == 0, 'run the transition as root')
    account = pwd.getpwnam(layout.account)
    require(account.pw_uid != 0 and account.pw_gid != 0, 'delivery identity must not be root')
    trusted_dir(layout, layout.tools.parent)
    trusted_dir(layout, layout.etc, 0o755)
    trusted_dir(layout, layout.approved, 0o700)
    trusted_dir(layout, layout.quarantine, 0o700)


def registry_snapshot(layout):
    return {name: hashlib.sha256(read_file(Path(layout.approved) / name, owner_mode=None)).hexdigest()
            for name in sorted(os.listdir(layout.approved))}


def staged_target(stage):
    """Exact TARGET bytes from the verified root copy (root-owned, private, no links)."""
    stage = Path(stage)
    info = os.lstat(stage)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077, 'root copy is not private')
    raw = {}
    for name, (sha, size) in TARGET.items():
        data = read_file(stage / name, owner_mode=None)
        st = os.lstat(stage / name)
        require(st.st_uid == 0 and not st.st_mode & 0o077, 'root copy file is not private: ' + name)
        require(hashlib.sha256(data).hexdigest() == sha and len(data) == size, 'root copy differs from TARGET: ' + name)
        raw[name] = data
    return raw


def write_next(layout, raw):
    os.mkdir(layout.next, 0o700)
    os.chown(layout.next, 0, 0, follow_symlinks=False)
    for name, data in raw.items():
        fd = os.open(Path(layout.next) / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            os.fchown(fd, 0, 0); os.fchmod(fd, 0o644)
            os.write(fd, data); os.fsync(fd)
        finally:
            os.close(fd)
    fsync_dir(layout.next)
    require(dir_state(layout.next) == TARGET, 'staged tooling does not verify')
    os.chmod(layout.next, 0o755)


def post_check(layout, run_self_check):
    require(classify(layout) == 'TARGET', 'post-install state')
    result = run_self_check(layout)
    require(result.get('state') == 'SELF_CHECK_PASS', 'installed operator self-check failed')
    require(result.get('tooling_sha256') == {k: v[0] for k, v in sorted(TARGET.items())}, 'self-check tooling hashes')
    return result


def default_self_check(layout):
    out = subprocess.run([layout.python, '-I', '-B', str(Path(layout.tools) / 'delivery_operator.py'), '--self-check'],
                         capture_output=True, text=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    require(out.returncode == 0, 'installed operator self-check failed: ' + out.stderr.strip())
    return json.loads(out.stdout)


def run(mode, stage=None, layout=PRODUCTION, run_self_check=default_self_check):
    boundaries(layout)
    with Locked(layout):
        state = classify(layout)
        before = registry_snapshot(layout)
        report = {'mode': mode, 'state_before': state, 'registry': before}
        if mode == 'verify':
            pass
        elif mode == 'preflight':
            require(state == 'CURRENT', 'preflight requires the exact bootstrap-v2 tooling state, found ' + state)
            no_operator_running(layout)
            staged_target(stage)
            report['result'] = 'PREFLIGHT_PASS: no changes made'
        elif mode == 'execute':
            require(state == 'CURRENT', 'execute requires the exact bootstrap-v2 tooling state, found ' + state)
            no_operator_running(layout)
            write_next(layout, staged_target(stage))
            renameat2(layout.tools, layout.next, RENAME_EXCHANGE)
            renameat2(layout.next, layout.backup, RENAME_NOREPLACE)
            report['self_check'] = post_check(layout, run_self_check)
            report['result'] = 'TRANSITION_COMPLETE: tooling schema 2 installed; registry unchanged; nothing retrieved'
        elif mode == 'recover':
            if state == 'STAGED':
                target = staged_target(stage)
                for name in os.listdir(layout.next):
                    data = read_file(Path(layout.next) / name)
                    require(name in target and target[name].startswith(data), 'unknown staged content: ' + name)
                for name in os.listdir(layout.next):
                    os.unlink(Path(layout.next) / name)
                os.rmdir(layout.next)
                fsync_dir(Path(layout.next).parent)
                report['result'] = 'RECOVERED_TO_CURRENT: rerun --preflight then --execute'
            elif state == 'EXCHANGED':
                renameat2(layout.next, layout.backup, RENAME_NOREPLACE)
                report['self_check'] = post_check(layout, run_self_check)
                report['result'] = 'RECOVERED_TO_TARGET'
            elif state == 'ROLLBACK_EXCHANGED':
                renameat2(layout.backup, layout.retired, RENAME_NOREPLACE)
                report['result'] = 'RECOVERED_TO_ROLLED_BACK'
            else:
                report['result'] = 'NOTHING_TO_RECOVER'
        elif mode == 'rollback':
            require(state == 'TARGET', 'rollback requires the completed TARGET state, found ' + state)
            no_operator_running(layout)
            renameat2(layout.tools, layout.backup, RENAME_EXCHANGE)
            renameat2(layout.backup, layout.retired, RENAME_NOREPLACE)
            require(classify(layout) == 'ROLLED_BACK', 'rollback state')
            report['result'] = 'ROLLED_BACK: exact bootstrap-v2 tooling restored; schema-2 tooling retained at ' + str(layout.retired)
        else:
            raise Stop('STOP: unknown mode')
        require(registry_snapshot(layout) == before, 'registry changed during the transition')
        report['state_after'] = classify(layout)
        return report


def main(argv):
    modes = {'--preflight': 2, '--execute': 2, '--recover': 2, '--rollback': 1, '--verify': 1}
    try:
        require(argv and argv[0] in modes and len(argv) == modes[argv[0]], 'usage: ' + ' | '.join(modes))
        print(json.dumps(run(argv[0][2:], argv[1] if len(argv) == 2 else None), indent=2, sort_keys=True))
        return 0
    except Stop as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception as error:
        print('STOP: unexpected ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

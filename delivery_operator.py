"""Privileged retrieval/preflight only. No deployment command or automatic authorization."""
import json
import os
from pathlib import Path
import subprocess
import sys
from delivery import policy, read_regular, quarantine, require

def main():
    require(os.geteuid() == 0, 'Root operator required')
    require(len(sys.argv) == 2 and sys.argv[1] == 'code-blazes-627c0fc-v1', 'Exact approved release ID required')
    for path in [Path('/etc/friday-delivery'), Path('/etc/friday-delivery/approved'), Path('/usr/local/libexec/friday-delivery')]:
        info = path.lstat()
        require(not path.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022, 'Unsafe policy/tool directory')
    p = policy(json.loads(read_regular('/etc/friday-delivery/approved/code-blazes-627c0fc-v1.json', 100000, owner=0)))
    receipt = {'state': 'RETRIEVAL_FAILED', 'repository': p['repository'], 'delivery_commit': p['delivery_commit']}
    try:
        # Pass nonsecret policy via stdin; no production Git access and no sudo granted to delivery identity.
        result = subprocess.run(['runuser', '-u', 'friday-delivery', '--', '/usr/bin/python3',
                                  '/usr/local/libexec/friday-delivery/delivery_operator.py', '--retrieve-child'],
                                 input=json.dumps(p), text=True, capture_output=True, check=True)
        receipt['state'] = 'RETRIEVED_NOT_VERIFIED'
        payload = quarantine(result.stdout.strip(), p, '/var/lib/friday-deployment')
        receipt['state'] = 'RETRIEVED_VERIFIED'
        output = subprocess.run(['/usr/bin/python3', str(payload / 'operator.py'), 'preflight'],
                                capture_output=True, text=True)
        receipt['state'] = 'PREFLIGHT_PASS' if output.returncode == 0 else 'PREFLIGHT_FAIL'
        receipt['preflight'] = json.loads(output.stdout) if output.returncode == 0 else {'error': output.stderr}
        receipt['quarantine'] = str(payload)
        (payload.parent / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps(receipt, indent=2))
        return output.returncode
    except Exception:
        import tempfile
        root = Path('/var/lib/friday-deployment')
        info = root.lstat()
        require(not root.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o077, 'Unsafe failure receipt directory')
        with tempfile.NamedTemporaryFile(mode='w', prefix='failed-', suffix='.json', dir=root, delete=False) as stream:
            stream.write(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps(receipt), file=sys.stderr)
        raise

if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--retrieve-child']:
            import pwd
            from delivery import retrieve
            require(os.getuid() == pwd.getpwnam('friday-delivery').pw_uid, 'Wrong retrieval identity')
            print(retrieve(json.load(sys.stdin), '/var/lib/friday-delivery/cache'))
        else:
            sys.exit(main())
    except Exception as error:
        print(str(error), file=sys.stderr); sys.exit(1)

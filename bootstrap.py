"""Reviewed server-local bootstrap. Never invoke in Cloud; private keys never printed."""
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys

HOST = 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n'

def deny_sudo(result):
    # A policy lookup error is not evidence of denial. Locale is pinned by caller.
    message = result.stdout + result.stderr
    if result.returncode != 1 or not re.search(r"(?:User )?friday-delivery is not allowed to run sudo", message):
        raise ValueError('STOP: sudo denial not established; review policy/probe errors')


def deny_write(result, path):
    if result.returncode != 1 or result.stderr:
        raise ValueError('STOP: no-write permission not established: ' + str(path))


def bootstrap():
    if os.geteuid() != 0:
        raise ValueError('Run reviewed installer as root')
    def run(*args):
        return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()
    user = run('systemctl', 'show', 'msf-counter-bot.service', '--property=User', '--value')
    if not user or pwd.getpwnam(user).pw_uid == 0:
        raise ValueError('STOP: bot runs as root; machine-key isolation requires human risk review')
    try:
        pwd.getpwnam('friday-delivery')
    except KeyError:
        pass
    else:
        raise ValueError('STOP: account exists; never reuse unknown identity')
    for path in ['/var/lib/friday-delivery', '/etc/friday-delivery', '/usr/local/libexec/friday-delivery', '/var/lib/friday-deployment']:
        if os.path.lexists(path):
            raise ValueError('STOP: existing bootstrap path requires review: ' + path)
    # No credential generation until all checks pass; failure leaves partial setup for review, never reruns/overwrites.
    run('useradd', '--system', '--user-group', '--create-home', '--home-dir', '/var/lib/friday-delivery', '--shell', '/usr/sbin/nologin', 'friday-delivery')
    run('passwd', '--lock', 'friday-delivery')
    account = pwd.getpwnam('friday-delivery')
    home = Path(account.pw_dir); home.chmod(0o700)
    ssh = home / '.ssh'; ssh.mkdir(mode=0o700); os.chown(ssh, account.pw_uid, account.pw_gid)
    # Abort if any sudo authorization exists (sudo -l nonzero means no privileges).
    rights = subprocess.run(['sudo', '-l', '-U', 'friday-delivery'], capture_output=True, text=True, env=dict(os.environ, LC_ALL='C'))
    deny_sudo(rights)
    app = Path('/opt/msf-counter-bot')
    check = subprocess.run(['runuser', '-u', 'friday-delivery', '--', 'test', '-w', str(app)], capture_output=True, text=True)
    if not app.is_dir() or app.is_symlink():
        raise ValueError('STOP: application root missing or symlink')
    deny_write(check, app)
    for item in app.rglob('*'):
        result = subprocess.run(['runuser', '-u', 'friday-delivery', '--', 'test', '-w', str(item)], capture_output=True, text=True)
        if item.is_symlink():
            raise ValueError('STOP: application symlink requires scope review: ' + str(item))
        deny_write(result, item)
    key = ssh / 'delivery_ed25519'
    run('runuser', '-u', 'friday-delivery', '--', 'ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'friday-vjserver-artifact-readonly', '-f', str(key))
    key.chmod(0o600)
    etc = Path('/etc/friday-delivery'); etc.mkdir(mode=0o755)
    (etc / 'github_known_hosts').write_text(HOST); (etc / 'github_known_hosts').chmod(0o644)
    config = '''Host friday-artifacts
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
    (ssh / 'config').write_text(config); (ssh / 'config').chmod(0o600); os.chown(ssh / 'config', account.pw_uid, account.pw_gid)
    cache = home / 'cache'; cache.mkdir(mode=0o700); os.chown(cache, account.pw_uid, account.pw_gid)
    (etc / 'approved').mkdir(mode=0o700)
    Path('/var/lib/friday-deployment').mkdir(mode=0o700)
    tools = Path('/usr/local/libexec/friday-delivery'); tools.mkdir(parents=True, mode=0o755)
    for name in ['delivery.py', 'delivery_operator.py']:
        (tools / name).write_bytes(Path(__file__).with_name(name).read_bytes()); (tools / name).chmod(0o644)
    print(run('ssh-keygen', '-lf', str(key) + '.pub'))
    print(Path(str(key) + '.pub').read_text().strip())
    print('BOOTSTRAPPED_NOT_REGISTERED: private key remains local; no release fetched or activated')

if __name__ == '__main__':
    try:
        bootstrap()
    except Exception as error:
        print(str(error), file=sys.stderr); sys.exit(1)

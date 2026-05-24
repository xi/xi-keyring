import argparse
import os
import sys
from pathlib import Path

from cryptography.fernet import Fernet

from .dbus import DBusService
from .dumpable import pr_set
from .keyring import KeyringProxy
from .keyring import write_bytes


def get_data_home():
    path = os.getenv('XDG_DATA_HOME')
    if path:
        return Path(path)
    else:
        return Path.home() / '.local' / 'share'


def parse_args():
    parser = argparse.ArgumentParser('xikeyring')
    parser.add_argument(
        'action',
        choices=['dump', 'restore'],
        nargs='?',
    )
    parser.add_argument(
        '--store',
        '-s',
        help='path to the store file',
        type=Path,
        default=get_data_home() / 'xikeyring' / 'store',
    )
    parser.add_argument(
        '--key',
        '-k',
        help='path to the key file',
        type=Path,
        default=get_data_home() / 'xikeyring' / 'key',
    )
    parser.add_argument(
        '--bus', '-b', help='bus name', default='org.freedesktop.secrets'
    )
    return parser.parse_args()


pr_set(dumpable=False)

args = parse_args()
keyring = KeyringProxy(args.store, args.key)
if args.action == 'dump':
    encrypted = keyring.path.read_bytes()
    decrypted = Fernet(keyring.key.value).decrypt(encrypted)
    print(decrypted.decode('utf-8'))
elif args.action == 'restore':
    decrypted = sys.stdin.read().encode('utf-8')
    encrypted = Fernet(keyring.key.value).encrypt(decrypted)
    write_bytes(keyring.path, encrypted)
else:
    service = DBusService(keyring)
    service.run(args.bus)

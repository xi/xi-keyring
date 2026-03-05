import argparse
import os
import sys
from pathlib import Path

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
        '--dump',
        help='print the decryted file and exit',
        action='store_true',
    )
    parser.add_argument(
        '--restore',
        help='inverse of --dump',
        action='store_true',
    )
    parser.add_argument(
        '--store',
        '-s',
        help='path to the store file',
        default=get_data_home() / 'xikeyring.db',
    )
    parser.add_argument(
        '--bus', '-b', help='bus name', default='org.freedesktop.secrets'
    )
    return parser.parse_args()


pr_set(dumpable=False)

args = parse_args()
keyring = KeyringProxy(args.store)
if args.dump:
    with open(keyring.path, 'rb') as fh:
        encrypted = fh.read()
    decrypted = keyring.crypt.decrypt(encrypted)
    print(decrypted.decode('utf-8'))
elif args.restore:
    decrypted = sys.stdin.read().encode('utf-8')
    encrypted = keyring.crypt.encrypt(decrypted)
    write_bytes(keyring.path, encrypted)
else:
    service = DBusService(keyring)
    service.run(args.bus)

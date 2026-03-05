import argparse
import os
from pathlib import Path

from .dbus import DBusService
from .dumpable import pr_set
from .keyring import KeyringProxy


def get_data_home():
    path = os.getenv('XDG_DATA_HOME')
    if path:
        return Path(path)
    else:
        return Path.home() / '.local' / 'share'


def parse_args():
    parser = argparse.ArgumentParser('xikeyring')
    parser.add_argument(
        '--decrypt',
        '-d',
        help='print the decryted file and exit',
        action='store_true',
    )
    parser.add_argument(
        '--key',
        '-k',
        help='path to the key file',
        default=get_data_home() / 'xi' / 'keyring' / 'key',
    )
    parser.add_argument(
        '--store',
        '-s',
        help='path to the store file',
        default=get_data_home() / 'xi' / 'keyring' / 'keyring',
    )
    parser.add_argument(
        '--bus', '-b', help='bus name', default='org.freedesktop.secrets'
    )
    return parser.parse_args()


pr_set(dumpable=False)

args = parse_args()
keyring = KeyringProxy(args.key, args.store)
if args.decrypt:
    encrypted = keyring.path.read_bytes()
    decrypted = keyring.crypt.decrypt(encrypted)
    print(decrypted.decode('utf-8'))
else:
    service = DBusService(keyring)
    service.run(args.bus)

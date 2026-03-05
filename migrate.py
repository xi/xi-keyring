import json
import os
from pathlib import Path

from cryptography.fernet import Fernet

from xikeyring import crypto
from xikeyring.keyring import write_bytes
from xikeyring.prompt import PinentryPrompt as Prompt


def get_data_home():
    path = os.getenv('XDG_DATA_HOME')
    if path:
        return Path(path)
    else:
        return Path.home() / '.local' / 'share'


def read_legacy(password):
    legacy_path = get_data_home() / 'xikeyring.db'
    encrypted = legacy_path.read_bytes()
    return json.loads(crypto.decrypt_with_password(encrypted, password))


def migrate_data(data):
    result = {}
    for id, secret, attrs, app_id in data:
        if not app_id:
            result.setdefault('', [])
            result[''].append([id, secret, attrs])
        elif attrs == {'application': 'org.freedesktop.portal.Secret'}:
            result.setdefault('', [])
            result[''].append([id, secret, {**attrs, 'app_id': app_id}])
        else:
            result.setdefault(app_id, [])
            result[app_id].append([id, secret, attrs])
    return result


def write(keyrings, password):
    root = get_data_home() / 'xi' / 'keyring'
    root.mkdir(parents=True)

    key = Fernet.generate_key()
    encrypted = crypto.encrypt_with_password(key, password)
    write_bytes(root / 'key', encrypted, 0o600)
    fernet = Fernet(key)

    for app_id, data in keyrings.items():
        encrypted = fernet.encrypt(json.dumps(data).encode('utf-8'))
        if app_id:
            parent = root / app_id
            parent.mkdir()
        else:
            parent = root
        write_bytes(parent / 'keyring', encrypted, 0o600)


if __name__ == '__main__':
    password = Prompt().get_password(
        'Please enter your password to start the migration'
    )
    data = read_legacy(password)
    data = migrate_data(data)
    write(data, password)

    legacy_path = get_data_home() / 'xikeyring.db'
    print(f'You can now delete {legacy_path}')

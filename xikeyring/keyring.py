import base64
import json
import os
from dataclasses import dataclass

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .kernel_keyring import KernelKey
from .prompt import PinentryPrompt as Prompt

TRUSTED_MANAGERS = [
    '/usr/bin/seahorse',
]


class AccessDeniedError(Exception):
    pass


class NotFoundError(Exception):
    pass


@dataclass
class Item:
    secret: bytes
    attributes: dict[str, str]
    app_id: str


class Crypt:
    def __init__(self, password: bytes):
        self.password = KernelKey(password)

    def get_pkbf2(self, salt: bytes, iterations: int) -> bytes:
        if iterations < 100_000:
            raise ValueError('Too few iterations')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(self.password.value)
        return base64.urlsafe_b64encode(key)

    def encrypt(self, data: bytes) -> bytes:
        salt = os.urandom(16)
        params = [100_000]
        key = self.get_pkbf2(salt, *params)
        content = Fernet(key).encrypt(data)
        return b'$'.join(
            [
                b'fernet',
                base64.urlsafe_b64encode(salt),
                *[str(p).encode() for p in params],
                content,
            ]
        )

    def decrypt(self, data: bytes) -> bytes:
        algo, salt, *params, content = data.split(b'$')
        salt = base64.urlsafe_b64decode(salt)
        params = [int(p, 10) for p in params]
        if algo == b'fernet' and len(params) == 1:
            key = self.get_pkbf2(salt, *params)
        else:
            raise TypeError('Unknown encryption algorithm')
        return Fernet(key).decrypt(content)


class Keyring:
    def __init__(self, path: str):
        self.path = path
        self.prompt = Prompt()

        if os.path.exists(self.path):
            while True:
                self.crypt = self._get_crypt()
                try:
                    self._read()
                    break
                except InvalidToken:
                    pass
        else:
            self.crypt = self._get_crypt()
            self._write({})
            os.chmod(self.path, 0o600)

    def _get_crypt(self):
        # TODO: different messages for create|unlock|retry
        password = self.prompt.get_password(
            'An application wants access to your keyring, but it is locked'
        )
        if not password:
            raise AccessDeniedError
        return Crypt(password)

    def _read(self) -> dict[int, Item]:
        with open(self.path, 'rb') as fh:
            encrypted = fh.read()
        decrypted = self.crypt.decrypt(encrypted)
        raw = json.loads(decrypted)
        return {
            id: Item(base64.urlsafe_b64decode(secret), attributes, app_id)
            for id, secret, attributes, app_id in raw
        }

    def _write(self, items: dict[int, Item]):
        raw = [
            (
                id,
                base64.urlsafe_b64encode(item.secret).decode(),
                item.attributes,
                item.app_id,
            )
            for id, item in items.items()
        ]
        decrypted = json.dumps(raw).encode('utf-8')
        encrypted = self.crypt.encrypt(decrypted)
        with open(self.path, 'wb') as fh:
            fh.write(encrypted)

    def confirm_access(self, app_id: str) -> None:
        if not self.prompt.confirm(f'Allow {app_id or "host"} to access a secret from your keyring?'):
            raise AccessDeniedError

    def confirm_change(self, app_id: str) -> None:
        if not self.prompt.confirm(f'Allow {app_id or "host"} to make changes to your keyring?'):
            raise AccessDeniedError

    def has_access(self, app_id: str, item: Item) -> bool:
        return item.app_id == app_id or app_id in TRUSTED_MANAGERS

    def get(self, items: dict[int, Item], app_id: str, id: int) -> Item:
        try:
            item = items[id]
        except KeyError as e:
            raise NotFoundError from e
        if not self.has_access(app_id, item):
            raise NotFoundError
        return item

    def search_items(self, app_id: str, query: dict[str, str] = {}) -> list[int]:
        items = self._read()
        return [
            id for id, item in items.items()
            if self.has_access(app_id, item) and all(
                item.attributes.get(key) == value for key, value in query.items()
            )
        ]

    def get_attributes(self, app_id: str, id: int) -> dict[str, str]:
        items = self._read()
        return self.get(items, app_id, id).attributes

    def get_secret(self, app_id: str, id: int) -> bytes:
        items = self._read()
        item = self.get(items, app_id, id)
        self.confirm_access(app_id)
        return item.secret

    def create_item(self, app_id: str, attributes: dict[str, str], secret: bytes) -> int:
        items = self._read()
        id = max(items.keys(), default=0) + 1
        items[id] = Item(secret, attributes, app_id)
        self._write(items)
        return id

    def update_attributes(self, app_id: str, id: int, attributes: dict[str, str]) -> None:
        items = self._read()
        item = self.get(items, app_id, id)
        self.confirm_change(app_id)
        item.attributes = attributes
        self._write(items)

    def update_secret(self, app_id: str, id: int, secret: bytes) -> None:
        items = self._read()
        item = self.get(items, app_id, id)
        self.confirm_change(app_id)
        item.secret = secret
        self._write(items)

    def delete_item(self, app_id: str, id: int) -> None:
        items = self._read()
        self.get(items, app_id, id)  # trigger appropriate exceptions
        self.confirm_change(app_id)
        del items[id]
        self._write(items)


class KeyringProxy:
    def __init__(self, path):
        self.path = path
        self.keyring = None

    def lock(self):
        self.keyring = None

    def __getattr__(self, attr):
        if self.keyring is None:
            self.keyring = Keyring(self.path)
        return getattr(self.keyring, attr)


if __name__ == '__main__':
    k = KeyringProxy('keyring.db')
    id = k.create_item({'foo': 'bar'}, b'password')
    print(k.get_secret(id))
    k.delete_item(id)

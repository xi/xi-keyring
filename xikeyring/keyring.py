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
    exe: str


class Crypt:
    def __init__(self, password: bytes):
        self.password = KernelKey(password)

    def get_key(self, salt: bytes, iterations: int) -> bytes:
        if iterations < 100_000:
            raise ValueError('Too few iterations')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return base64.urlsafe_b64encode(kdf.derive(self.password.value))

    def encode(self, salt: bytes, iterations: int, content: bytes) -> bytes:
        return b'$'.join(
            [
                b'fernet',
                base64.urlsafe_b64encode(salt),
                str(iterations).encode(),
                content,
            ]
        )

    def decode(self, data: bytes) -> tuple[bytes, int, bytes]:
        algo, salt, iterations, content = data.split(b'$')
        if algo != b'fernet':
            raise TypeError('Unknown encryption algorithm')
        return (
            base64.urlsafe_b64decode(salt),
            int(iterations, 10),
            content,
        )

    def encrypt(self, data: bytes, iterations=100_000) -> bytes:
        salt = os.urandom(16)
        key = self.get_key(salt, iterations)
        content = Fernet(key).encrypt(data)
        return self.encode(salt, iterations, content)

    def decrypt(self, data: bytes) -> bytes:
        salt, iterations, content = self.decode(data)
        key = self.get_key(salt, iterations)
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
            id: Item(base64.urlsafe_b64decode(secret), attributes, exe)
            for id, secret, attributes, exe in raw
        }

    def _write(self, items: dict[int, Item]):
        raw = [
            (
                id,
                base64.urlsafe_b64encode(item.secret).decode(),
                item.attributes,
                item.exe,
            )
            for id, item in items.items()
        ]
        decrypted = json.dumps(raw).encode('utf-8')
        encrypted = self.crypt.encrypt(decrypted)
        with open(self.path, 'wb') as fh:
            fh.write(encrypted)

    def confirm_access(self, exe: str) -> None:
        if not self.prompt.confirm(f'Allow {exe} to access a secret from your keyring?'):
            raise AccessDeniedError

    def confirm_change(self, exe: str) -> None:
        if not self.prompt.confirm(f'Allow {exe} to make changes to your keyring?'):
            raise AccessDeniedError

    def has_access(self, exe: str, item: Item) -> bool:
        return item.exe == exe or exe in TRUSTED_MANAGERS

    def get(self, items: dict[int, Item], exe: str, id: int) -> Item:
        try:
            item = items[id]
        except KeyError as e:
            raise NotFoundError from e
        if not self.has_access(exe, item):
            raise NotFoundError
        return item

    def search_items(self, exe: str, query: dict[str, str] = {}) -> list[int]:
        items = self._read()
        return [
            id for id, item in items.items()
            if self.has_access(exe, item) and all(
                item.attributes.get(key) == value for key, value in query.items()
            )
        ]

    def get_attributes(self, exe: str, id: int) -> dict[str, str]:
        items = self._read()
        return self.get(items, exe, id).attributes

    def get_secret(self, exe: str, id: int) -> bytes:
        items = self._read()
        item = self.get(items, exe, id)
        self.confirm_access(exe)
        return item.secret

    def create_item(self, exe: str, attributes: dict[str, str], secret: bytes) -> int:
        items = self._read()
        id = max(items.keys(), default=0) + 1
        items[id] = Item(secret, attributes, exe)
        self._write(items)
        return id

    def update_attributes(self, exe: str, id: int, attributes: dict[str, str]) -> None:
        items = self._read()
        item = self.get(items, exe, id)
        self.confirm_change(exe)
        item.attributes = attributes
        self._write(items)

    def update_secret(self, exe: str, id: int, secret: bytes) -> None:
        items = self._read()
        item = self.get(items, exe, id)
        self.confirm_change(exe)
        item.secret = secret
        self._write(items)

    def delete_item(self, exe: str, id: int) -> None:
        items = self._read()
        self.get(items, exe, id)  # trigger appropriate exceptions
        self.confirm_change(exe)
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

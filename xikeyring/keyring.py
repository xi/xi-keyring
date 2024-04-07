import base64
import json
import os
from dataclasses import dataclass

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .prompt import PinentryPrompt as Prompt


class AccessDeniedError(Exception):
    pass


class NotFoundError(Exception):
    pass


@dataclass
class Item:
    secret: bytes
    attributes: dict[str, str]


class Crypt:
    def __init__(self, password: bytes):
        self.password = password

    def get_key(self, salt: bytes, iterations: int) -> bytes:
        if iterations < 100_000:
            raise ValueError('Too few iterations')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return base64.urlsafe_b64encode(kdf.derive(self.password))

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
    items: dict[int, Item]

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
            self.items = {}
            self.crypt = self._get_crypt()
            self._write()
            os.chmod(self.path, 0o600)

    def _get_crypt(self):
        # TODO: different messages for create|unlock|retry
        password = self.prompt.get_password(
            'An application wants access to your keyring, but it is locked'
        )
        if not password:
            raise AccessDeniedError
        return Crypt(password)

    def _read(self):
        with open(self.path, 'rb') as fh:
            encrypted = fh.read()
        decrypted = self.crypt.decrypt(encrypted)
        raw = json.loads(decrypted)
        self.items = {
            id: Item(base64.urlsafe_b64decode(secret), attributes)
            for id, secret, attributes in raw
        }

    def _write(self):
        raw = [
            (
                id,
                base64.urlsafe_b64encode(item.secret).decode(),
                item.attributes,
            )
            for id, item in self.items.items()
        ]
        decrypted = json.dumps(raw).encode('utf-8')
        encrypted = self.crypt.encrypt(decrypted)
        with open(self.path, 'wb') as fh:
            fh.write(encrypted)

    def confirm_access(self) -> None:
        if not self.prompt.confirm('Allow access to secret from keyring?'):
            raise AccessDeniedError

    def confirm_change(self) -> None:
        if not self.prompt.confirm('Allow changes to keyring?'):
            raise AccessDeniedError

    def __getitem__(self, id: int) -> Item:
        try:
            return self.items[id]
        except KeyError as e:
            raise NotFoundError from e

    def search_items(self, query: dict[str, str] = {}) -> list[int]:
        return [
            id for id, item in self.items.items()
            if not query or all(
                item.attributes.get(key) == value for key, value in query.items()
            )
        ]

    def get_attributes(self, id: int) -> dict[str, str]:
        return self[id].attributes

    def get_secret(self, id: int) -> bytes:
        self.confirm_access()
        return self[id].secret

    def create_item(self, attributes: dict[str, str], secret: bytes) -> int:
        id = max(self.items.keys(), default=0) + 1
        self.items[id] = Item(secret, attributes)
        self._write()
        return id

    def update_attributes(self, id: int, attributes: dict[str, str]) -> None:
        self.confirm_change()
        self[id].attributes = attributes
        self._write()

    def update_secret(self, id: int, secret: bytes) -> None:
        self.confirm_change()
        self[id].secret = secret
        self._write()

    def delete_item(self, id: int) -> None:
        self.confirm_change()
        try:
            del self.items[id]
        except KeyError as e:
            raise NotFoundError from e
        self._write()


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

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken

from . import crypto
from .kernel_keyring import KernelKey
from .pidfd import PID
from .prompt import PinentryPrompt as Prompt


class AccessDeniedError(Exception):
    pass


class NotFoundError(Exception):
    pass


@dataclass
class Item:
    secret: bytes
    attributes: dict[str, str]


def write_bytes(path: str | Path, data: bytes, mode: int) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode=mode)
    try:
        return os.write(fd, data)
    finally:
        os.close(fd)


class Crypt:
    def __init__(self, path: Path, password: bytes):
        if path.exists():
            encrypted = path.read_bytes()
            key = crypto.decrypt_with_password(encrypted, password)
        else:
            key = Fernet.generate_key()
            encrypted = crypto.encrypt_with_password(key, password)
            write_bytes(path, encrypted, 0o600)
        self.key = KernelKey(key)

    def encrypt(self, data: bytes) -> bytes:
        return Fernet(self.key.value).encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return Fernet(self.key.value).decrypt(data)


class Keyring:
    def __init__(self, path: Path):
        self.path = path
        self.prompt = Prompt()

        path.mkdir(parents=True, exist_ok=True)
        while True:
            try:
                self.crypt = self._get_crypt()
                break
            except InvalidToken:
                pass

    def _get_crypt(self):
        # TODO: different messages for create|unlock|retry
        password = self.prompt.get_password(
            'An application wants access to your keyring, but it is locked'
        )
        if not password:
            raise AccessDeniedError
        return Crypt(self.path / 'key', password)

    def _read(self, pid: PID) -> dict[int, Item]:
        path = pid.path(self.path / 'keyring')
        if not path.exists():
            return {}

        encrypted = path.read_bytes()
        pid.check_active()
        decrypted = self.crypt.decrypt(encrypted)
        raw = json.loads(decrypted)
        return {
            id: Item(base64.urlsafe_b64decode(secret), attributes)
            for id, secret, attributes in raw
        }

    def _write(self, pid: PID, items: dict[int, Item]):
        path = pid.path(self.path / 'keyring')

        # Raise an error instead of creating the directory because this
        # might be a tmpfs.
        if not path.parent.exists():
            raise NotFoundError

        raw = [
            (
                id,
                base64.urlsafe_b64encode(item.secret).decode(),
                item.attributes,
            )
            for id, item in items.items()
        ]
        decrypted = json.dumps(raw).encode('utf-8')
        encrypted = self.crypt.encrypt(decrypted)
        # FIXME: there is a small window for race conditions
        pid.check_active()
        write_bytes(path, encrypted, 0o600)

    def is_host(self, pid: PID) -> bool:
        host = self.path / 'keyring'
        path = pid.path(host)
        return path.exists() and host.exists() and path.samefile(host)

    def confirm_access(self) -> None:
        if not self.prompt.confirm('Allow access to a secret from your keyring?'):
            raise AccessDeniedError

    def confirm_change(self) -> None:
        if not self.prompt.confirm('Allow changes to your keyring?'):
            raise AccessDeniedError

    def get(self, items: dict[int, Item], id: int) -> Item:
        try:
            return items[id]
        except KeyError as e:
            raise NotFoundError from e

    def search_items(self, pid: PID, query: dict[str, str] = {}) -> list[int]:
        items = self._read(pid)
        return [
            id for id, item in items.items()
            if all(item.attributes.get(k) == v for k, v in query.items())
        ]

    def get_attributes(self, pid: PID, id: int) -> dict[str, str]:
        items = self._read(pid)
        return self.get(items, id).attributes

    def get_secret(self, pid: PID, id: int) -> bytes:
        items = self._read(pid)
        item = self.get(items, id)
        self.confirm_access()
        return item.secret

    def create_item(self, pid: PID, attributes: dict[str, str], secret: bytes) -> int:
        items = self._read(pid)
        id = max(items.keys(), default=0) + 1
        items[id] = Item(secret, attributes)
        self._write(pid, items)
        return id

    def update_attributes(self, pid: PID, id: int, attributes: dict[str, str]) -> None:
        items = self._read(pid)
        item = self.get(items, id)
        self.confirm_change()
        item.attributes = attributes
        self._write(pid, items)

    def update_secret(self, pid: PID, id: int, secret: bytes) -> None:
        items = self._read(pid)
        item = self.get(items, id)
        self.confirm_change()
        item.secret = secret
        self._write(pid, items)

    def delete_item(self, pid: PID, id: int) -> None:
        items = self._read(pid)
        self.get(items, id)  # trigger appropriate exceptions
        self.confirm_change()
        del items[id]
        self._write(pid, items)


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

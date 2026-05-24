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


def write_bytes(path: Path, data: bytes, pid: PID | None = None) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode=0o600)
    if pid:
        pid.check_active()
    try:
        return os.write(fd, data)
    finally:
        os.close(fd)


class Keyring:
    def __init__(self, store_path: Path, key_path: Path):
        self.path = store_path
        self.prompt = Prompt()

        if key_path.exists():
            self.key = self._get_key(key_path)
        else:
            self.key = self._create_key(key_path)

    def _get_key(self, path: Path) -> KernelKey:
        encrypted = path.read_bytes()
        while True:
            password = self.prompt.get_password(
                'An application wants access to your keyring, but it is locked.'
            )
            if not password:
                raise AccessDeniedError
            try:
                key = crypto.decrypt_with_password(encrypted, password)
                return KernelKey(key)
            except InvalidToken:
                pass

    def _create_key(self, path: Path) -> KernelKey:
        while True:
            password = self.prompt.get_password(
                'An application wants access to your keyring. '
                'Please enter a password to create a keyring.'
            )
            if not password:
                raise AccessDeniedError

            password2 = self.prompt.get_password(
                'Please enter the password again for confirmation.'
            )
            if password == password2:
                break

            again = self.prompt.confirm(
                'The passwords did not match. Do you want to try again?'
            )
            if not again:
                raise AccessDeniedError

        key = Fernet.generate_key()
        encrypted = crypto.encrypt_with_password(key, password)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_bytes(path, encrypted)
        return KernelKey(key)

    def _read(self, pid: PID) -> dict[int, Item]:
        path = pid.path(self.path)
        if not path.exists():
            return {}

        encrypted = path.read_bytes()
        pid.check_active()
        decrypted = Fernet(self.key.value).decrypt(encrypted)
        raw = json.loads(decrypted)
        return {
            id: Item(base64.urlsafe_b64decode(secret), attributes)
            for id, secret, attributes in raw
        }

    def _write(self, pid: PID, items: dict[int, Item]):
        path = pid.path(self.path)
        if not path.parent.exists():
            # Raise an error instead of creating the directory because this
            # might be a tmpfs.
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
        encrypted = Fernet(self.key.value).encrypt(decrypted)
        write_bytes(path, encrypted, pid)

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
    def __init__(self, *args):
        self.args = args
        self.keyring = None

    def lock(self):
        self.keyring = None

    def __getattr__(self, attr):
        if self.keyring is None:
            self.keyring = Keyring(*self.args)
        return getattr(self.keyring, attr)

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken

from . import crypto
from .kernel_keyring import KernelKey
from .prompt import PinentryPrompt as Prompt


class AccessDeniedError(Exception):
    pass


class NotFoundError(Exception):
    pass


@dataclass
class Item:
    secret: bytes
    attributes: dict[str, str]
    app_id: str


def write_bytes(path: Path, data: bytes) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode=0o600)
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

    def _read(self) -> dict[int, Item]:
        if not self.path.exists():
            return {}

        encrypted = self.path.read_bytes()
        decrypted = Fernet(self.key.value).decrypt(encrypted)
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
        encrypted = Fernet(self.key.value).encrypt(decrypted)
        write_bytes(self.path, encrypted)

    def confirm_access(self, app_id: str) -> None:
        if not self.prompt.confirm(f'Allow {app_id or "host"} to access a secret from your keyring?'):
            raise AccessDeniedError

    def confirm_change(self, app_id: str) -> None:
        if not self.prompt.confirm(f'Allow {app_id or "host"} to make changes to your keyring?'):
            raise AccessDeniedError

    def get(self, items: dict[int, Item], app_id: str, id: int) -> Item:
        try:
            item = items[id]
        except KeyError as e:
            raise NotFoundError from e
        if item.app_id != app_id:
            raise NotFoundError
        return item

    def search_items(self, app_id: str, query: dict[str, str] = {}) -> list[int]:
        items = self._read()
        return [
            id for id, item in items.items()
            if item.app_id == app_id and all(
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
    def __init__(self, *args):
        self.args = args
        self.keyring = None

    def lock(self):
        self.keyring = None

    def __getattr__(self, attr):
        if self.keyring is None:
            self.keyring = Keyring(*self.args)
        return getattr(self.keyring, attr)

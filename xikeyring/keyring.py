import base64
import json
import os
import sqlite3

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .prompt import PinentryPrompt as Prompt


class AccessDeniedError(Exception):
    pass


class NotFoundError(Exception):
    pass


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
    _crypt: Crypt | None

    def __init__(self, path: str):
        self._crypt = None
        self.db = sqlite3.connect(path)
        os.chmod(path, 0o600)
        self.prompt = Prompt()

        with self.db:
            self.db.execute(
                'CREATE TABLE IF NOT EXISTS items('
                'id INTEGER PRIMARY KEY, attributes JSON, secret BLOB)'
            )
            self.db.execute(
                'CREATE TABLE IF NOT EXISTS meta(id INTEGER PRIMARY KEY, value BLOB)'
            )

    def close(self):
        self._crypt = None
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def confirm_access(self) -> None:
        if not self.prompt.confirm('Allow access to secret from keyring?'):
            raise AccessDeniedError

    def confirm_change(self) -> None:
        if not self.prompt.confirm('Allow changes to keyring?'):
            raise AccessDeniedError

    @property
    def crypt(self) -> Crypt:
        while not self._crypt:
            password = self.prompt.get_password(
                'An application wants access to your keyring, but it is locked'
            )
            if not password:
                raise AccessDeniedError
            self._crypt = Crypt(password)
            try:
                self._validate_password()
            except ValueError:
                self._crypt = None
        return self._crypt

    def _validate_password(self) -> None:
        # SECURITY: we use the same mechanism to derive encryption keys.
        # Is this secure?
        res = self.db.execute('SELECT value FROM meta WHERE id=1')
        row = res.fetchone()
        if row:
            salt, iterations, content = self.crypt.decode(row[0])
            if self.crypt.get_key(salt, iterations) != content:
                raise ValueError('incorect password')
        else:
            iterations = 480_000
            salt = os.urandom(32)
            key = self.crypt.get_key(salt, iterations)
            data = self.crypt.encode(salt, iterations, key)
            with self.db:
                self.db.execute('INSERT INTO meta(id, value) VALUES (1, ?)', [data])

    def validate_password(self):
        # accessing the crypt will make sure that the password is validated
        # FIXME: not nice
        return self.crypt

    def lock(self) -> None:
        if not self._crypt:
            raise ValueError
        self._crypt = None

    def search_items(self, query: dict[str, str] = {}) -> list[int]:
        params = []
        sql = 'SELECT id FROM items'
        if query:
            for key, value in query.items():
                params.append(f'$.{key}')
                params.append(value)
            sql += ' WHERE ' + ' AND '.join(
                ['json_extract(attributes, ?) = ?' for _ in query]
            )
        res = self.db.execute(sql, params)
        return [row[0] for row in res.fetchall()]

    def get_attributes(self, id: int) -> dict[str, str]:
        res = self.db.execute('SELECT attributes FROM items WHERE id = ?', [id])
        row = res.fetchone()
        if not row:
            raise NotFoundError
        return json.loads(row[0])

    def get_secret(self, id: int) -> bytes:
        self.confirm_access()
        res = self.db.execute('SELECT secret FROM items WHERE id = ?', [id])
        row = res.fetchone()
        if not row:
            raise NotFoundError
        return self.crypt.decrypt(row[0])

    def create_item(self, attributes: dict[str, str], secret: bytes):
        self.validate_password()
        with self.db:
            cur = self.db.cursor()
            cur.execute(
                'INSERT INTO items(attributes, secret) VALUES (json(?), ?)',
                [
                    json.dumps(attributes),
                    self.crypt.encrypt(secret),
                ],
            )
            return cur.lastrowid

    def update_attributes(self, id: int, attributes: dict[str, str]) -> None:
        self.confirm_change()
        self.validate_password()
        with self.db:
            self.db.execute(
                'UPDATE items SET attributes=json(?) WHERE id=?',
                [json.dumps(attributes), id],
            )

    def update_secret(self, id: int, secret: bytes) -> None:
        self.confirm_change()
        self.validate_password()
        with self.db:
            self.db.execute(
                'UPDATE items SET secret=? WHERE id=?',
                [self.crypt.encrypt(secret), id],
            )

    def delete_item(self, id: int) -> None:
        self.confirm_change()
        self.validate_password()
        with self.db:
            self.db.execute('DELETE FROM items WHERE id=?', [id])


if __name__ == '__main__':
    with Keyring('keyring.db') as k:
        id = k.create_item({'foo': 'bar'}, b'password')
        print(k.get_secret(id))
        k.delete_item(id)

import base64
import os

import argon2
from cryptography.fernet import Fernet


def get_argon2(
    password: bytes,
    salt: bytes,
    time_cost: int,
    memory_cost: int,
    parallelism: int,
) -> bytes:
    # https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice
    key = argon2.low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=argon2.low_level.Type.ID,
    )
    return base64.urlsafe_b64encode(key)


def encrypt_with_password(data: bytes, password: bytes) -> bytes:
    salt = os.urandom(16)
    params = [3, 1 << 16, 4]
    key = get_argon2(password, salt, *params)
    content = Fernet(key).encrypt(data)
    return b'$'.join(
        [
            b'fernet-argon2',
            base64.urlsafe_b64encode(salt),
            *[str(p).encode() for p in params],
            content,
        ]
    )

def decrypt_with_password(data: bytes, password: bytes) -> bytes:
    algo, salt, *params, content = data.split(b'$')
    salt = base64.urlsafe_b64decode(salt)
    params = [int(p, 10) for p in params]
    if algo == b'fernet-argon2' and len(params) == 3:
        key = get_argon2(password, salt, *params)
    else:
        raise TypeError('Unknown encryption algorithm')
    return Fernet(key).decrypt(content)

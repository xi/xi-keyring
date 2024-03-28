import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# https://www.ietf.org/rfc/rfc2409.html#section-6.2
PRIME = int.from_bytes(
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xc9\x0f\xda\xa2\x21\x68\xc2\x34'
    b'\xc4\xc6\x62\x8b\x80\xdc\x1c\xd1\x29\x02\x4e\x08\x8a\x67\xcc\x74'
    b'\x02\x0b\xbe\xa6\x3b\x13\x9b\x22\x51\x4a\x08\x79\x8e\x34\x04\xdd'
    b'\xef\x95\x19\xb3\xcd\x3a\x43\x1b\x30\x2b\x0a\x6d\xf2\x5f\x14\x37'
    b'\x4f\xe1\x35\x6d\x6d\x51\xc2\x45\xe4\x85\xb5\x76\x62\x5e\x7e\xc6'
    b'\xf4\x4c\x42\xe9\xa6\x37\xed\x6b\x0b\xff\x5c\xb6\xf4\x06\xb7\xed'
    b'\xee\x38\x6b\xfb\x5a\x89\x9f\xa5\xae\x9f\x24\x11\x7c\x4b\x1f\xe6'
    b'\x49\x28\x66\x51\xec\xe6\x53\x81\xff\xff\xff\xff\xff\xff\xff\xff'
)


class PlainSession:
    @classmethod
    def create(cls, input):
        return b'', cls()

    def encode(self, path, msg):
        return (path, b'', msg, 'text/plain')

    def decode(self, secret):
        return secret[2]


class DHSession:
    # https://specifications.freedesktop.org/secret-service/latest/ch07s03.html

    @classmethod
    def bytes_to_key(cls, b, parameters):
        return dh.DHPublicNumbers(
            int.from_bytes(b),
            parameters.parameter_numbers(),
        ).public_key()

    @classmethod
    def key_to_bytes(cls, key):
        i = key.public_numbers().y
        return i.to_bytes(length=(i.bit_length() + 7) // 8)

    @classmethod
    def get_key(cls, peer_bytes):
        parameters = dh.DHParameterNumbers(p=PRIME, g=2).parameters()
        server_private_key = parameters.generate_private_key()
        peer_public_key = cls.bytes_to_key(bytes(peer_bytes), parameters)
        shared_key = server_private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=128 // 8,
            salt=None,
            info=b'',
        ).derive(shared_key)
        server_public_key = server_private_key.public_key()
        server_bytes = cls.key_to_bytes(server_public_key)
        return server_bytes, derived_key

    @classmethod
    def create(cls, input):
        output, key = cls.get_key(input)
        return output, cls(key)

    def __init__(self, key):
        self.key = key

    def encode(self, path, msg):
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(msg) + padder.finalize()
        cipher = Cipher(algorithms.AES128(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return (path, iv, ct, 'text/plain')

    def decode(self, secret):
        cipher = Cipher(algorithms.AES128(self.key), modes.CBC(bytes(secret[1])))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(bytes(secret[2])) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()


def create_session(algorithm: str, input: bytes) -> tuple[bytes, ...]:
    if algorithm == 'plain':
        return PlainSession.create(input)
    elif algorithm == 'dh-ietf1024-sha256-aes128-cbc-pkcs7':
        return DHSession.create(input)
    else:
        raise ValueError('unknown session algorithm')

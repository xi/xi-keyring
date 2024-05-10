import ctypes
import os

keyutils = ctypes.CDLL('libkeyutils.so.1')

THREAD_KEYRING = -1
PROCESS_KEYRING = -2
SESSION_KEYRING = -3
USER_KEYRING = -4
USER_SESSION_KEYRING = -5
GROUP_KEYRING = -6


def add_key(name: bytes, value: bytes, keyring: int) -> tuple[int, int]:
    size = len(value)
    id = keyutils.add_key(b'user', name, value, size, keyring)
    if id == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return id, size


def get_key(id: int, size: int) -> bytes:
    buf = ctypes.create_string_buffer(size)
    result = keyutils.keyctl_read(id, buf, size)
    if result == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return buf.value


class KernelKey:
    def __init__(self, value: bytes, keyring: int = PROCESS_KEYRING):
        name = f'kernel-key-{id(self)}'.encode()
        self.id, self.size = add_key(name, value, keyring)

    @property
    def value(self):
        return get_key(self.id, self.size)

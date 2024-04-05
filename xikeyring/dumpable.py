import ctypes
import ctypes.util
import os

libc_path = ctypes.util.find_library('c')
libc = ctypes.CDLL(libc_path, use_errno=True)

libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong)
libc.prctl.restype = ctypes.c_int

PR_SET_DUMPABLE = 4


def pr_set(*, dumpable: bool) -> None:
    """Prevent other processes from producing core dumps."""
    result = libc.prctl(PR_SET_DUMPABLE, 1 if dumpable else 0)
    if result != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

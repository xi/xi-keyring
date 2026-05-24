import selectors
import socket
import struct
from pathlib import Path

try:
    SO_PEERPIDFD = socket.SO_PEERPIDFD
except AttributeError:
    SO_PEERPIDFD = 77


class PID:
    def __init__(self, pid: int, pidfd: int):
        self.pid = pid
        self.pidfd = pidfd

    @classmethod
    def from_socket(cls, sock: socket.socket) -> 'PID':
        cred = sock.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')
        )
        pid, _uid, _gid = struct.unpack('3i', cred)
        pidfd = sock.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD)
        return cls(pid, pidfd)

    def check_active(self) -> None:
        with selectors.DefaultSelector() as sel:
            sel.register(self.pidfd, selectors.EVENT_READ)
            if sel.select(0) != []:
                raise ValueError('Calling process has quit')

    def path(self, path: str | Path) -> Path:
        root = (Path('/proc') / str(self.pid) / 'root').resolve()
        rel_path = Path(path).absolute().relative_to('/')
        result = (root / rel_path).resolve()

        # FIXME: symlinks are resoled relative to the host.
        #
        # A proper fix would involve openat2()
        # (see https://github.com/python/cpython/issues/141878).
        if root not in result.parents:
            raise ValueError('path escapes mount namespace')

        return result

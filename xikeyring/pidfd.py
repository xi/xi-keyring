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
        # openat2() is not available in python.
        #
        # Also, /proc/pid/root/ is a pseudo-symlink to /, so calling
        # resolve() will just return the host path.
        #
        # Instead, we have to carefully resolve the path ourselves.

        root = Path('/proc') / str(self.pid) / 'root'
        result = root
        parts = list(Path(path).absolute().relative_to('/').parts)
        visited_symlinks = set()

        while parts:
            part = parts.pop(0)
            result = result / part

            if part == '..':
                result = result.parent.parent
                if root not in result.parents:
                    raise ValueError('mount namespace escape')
            elif result.is_symlink():
                if result in visited_symlinks:
                    raise ValueError('circular symlinks')
                visited_symlinks.add(result)

                link = result.readlink()
                if link.is_absolute():
                    result = root
                    parts = [*link.relative_to('/').parts, *parts]
                else:
                    result = root.parent
                    parts = [*link.parts, *parts]

        return result

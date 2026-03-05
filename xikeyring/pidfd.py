import selectors
from pathlib import Path


class PID:
    def __init__(self, pid: int, pidfd: int):
        self.pid = pid
        self.pidfd = pidfd

    def check_active(self) -> None:
        with selectors.DefaultSelector() as sel:
            sel.register(self.pidfd, selectors.EVENT_READ)
            if sel.select(0) != []:
                raise ValueError('Calling process has quit')

    def path(self, path: str | Path) -> Path:
        root = Path('/proc') / str(self.pid) / 'root'
        rel_path = Path(path).absolute().relative_to('/')
        return root / rel_path

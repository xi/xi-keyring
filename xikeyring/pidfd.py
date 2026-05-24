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

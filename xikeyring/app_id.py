import configparser
import selectors
from pathlib import Path


def get_app_id(pid: int, pidfd: int) -> str:
    path = Path('/proc') / str(pid) / 'root' / '.flatpak-info'
    config = configparser.ConfigParser()
    try:
        with path.open() as fh:
            config.read_file(fh)
        app_id = config['Application']['name']
    except Exception:
        return ''

    with selectors.DefaultSelector() as sel:
        sel.register(pidfd, selectors.EVENT_READ)
        if sel.select() != []:
            raise ValueError('Calling process has quit')

    return app_id

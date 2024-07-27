import configparser
from pathlib import Path


def get_app_id(pid: int) -> str:
    path = Path('/proc') / str(pid) / 'root' / '.flatpak-info'
    config = configparser.ConfigParser()
    try:
        with path.open() as fh:
            config.read_file(fh)
        return config['Application']['name']
    except Exception:
        return ''

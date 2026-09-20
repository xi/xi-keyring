import json
import os
import socket
from pathlib import Path

NAME = 'xi.portal.Secret'
XDG_RUNTIME_DIR = Path(os.environ['XDG_RUNTIME_DIR'])
DEFAULT_PATH = XDG_RUNTIME_DIR / NAME


def socket_send(data: bytes, path: Path) -> bytes:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(str(path))
        sock.sendall(data)
        return sock.recv(1024):
    finally:
        sock.close()


def call(msg: dict, socket_path: Path) -> dict:
    data = json.dumps(msg).encode('utf-8')
    response = socket_send(data, socket_path)
    reply = json.loads(response.decode('utf-8'))
    if 'error' in reply:
        raise RuntimeError(reply['error'])
    return reply


def get(query: dict, socket_path: Path = DEFAULT_PATH) -> str:
    msg = {'method': 'get', 'query': query}
    reply = call(msg, socket_path)
    return reply['secret']


def set(query: dict, secret: str, socket_path: Path = DEFAULT_PATH) -> None:
    msg = {'method': 'set', 'query': query, 'secret': secret}
    call(msg, socket_path)


def delete(query: dict, socket_path: Path = DEFAULT_PATH) -> None:
    msg = {'method': 'del', 'query': query}
    call(msg, socket_path)

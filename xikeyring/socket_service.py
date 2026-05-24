import json
import socket
import sys
from contextlib import contextmanager
from pathlib import Path

from gi.repository import GLib

from .keyring import AccessDeniedError
from .keyring import Keyring
from .keyring import NotFoundError
from .pidfd import PID


class AmbiguousError(Exception):
    pass


def watch(sock: socket.socket, callback) -> int:
    sock.setblocking(False)  # noqa
    chan = GLib.IOChannel.unix_new(sock.fileno())
    flags = GLib.IO_IN|GLib.IO_HUP|GLib.IO_ERR
    return GLib.io_add_watch(chan, flags, callback, sock)


class Connection:
    def __init__(self, sock: socket.socket, keyring: Keyring):
        self.sock = sock
        self.keyring = keyring
        self.pid = PID.from_socket(sock)
        watch(sock, self.on_io)

    def get_id(self, query):
        ids = self.keyring.search_items(self.pid, query)
        if not ids:
            raise NotFoundError
        if len(ids) > 1:
            raise AmbiguousError
        return ids[0]

    def on_msg(self, msg):
        if msg['method'] == 'get':
            id = self.get_id(msg['query'])
            secret = self.keyring.get_secret(self.pid, id)
            return {'secret': secret.decode('utf-8')}
        elif msg['method'] == 'set':
            secret = msg['secret'].encode('utf-8')
            try:
                id = self.get_id(msg['query'])
                self.keyring.update_secret(self.pid, id, secret)
            except NotFoundError:
                self.keyring.create_item(self.pid, msg['query'], secret)
            return {}
        elif msg['method'] == 'del':
            id = self.get_id(msg['query'])
            self.keyring.delete_item(self.pid, id)
            return {}
        else:
            return {'error': 'invalid request'}

    def on_io(self, source, flags, sock):
        if flags & GLib.IO_ERR or flags & GLib.IO_HUP:
            sock.close()
            return False
        chunk = sock.recv(1024)
        if chunk:
            # TODO buffer
            try:
                msg = json.loads(chunk)
                reply = self.on_msg(msg)
            except AccessDeniedError:
                reply = {'error': 'access denied'}
            except NotFoundError:
                reply = {'error': 'not found'}
            except AmbiguousError:
                reply = {'error': 'ambiguous'}
            except Exception as e:
                print(e, file=sys.stderr)
                reply = {'error': 'server error'}
            sock.send(json.dumps(reply).encode('utf-8'))
            return True
        else:
            sock.close()
            return False


class SocketService:
    def __init__(self, keyring: Keyring):
        self.keyring = keyring

    def on_con(self, source, flags, sock: socket.socket):
        if flags & GLib.IO_ERR or flags & GLib.IO_HUP:
            return False
        conn, _addr = sock.accept()
        Connection(conn, self.keyring)
        return True

    @contextmanager
    def listen(self, path: Path | None):
        if path is None:  # systemd socket activation
            with socket.fromfd(3, socket.AF_INET, socket.SOCK_STREAM) as sock:
                watch(sock, self.on_con)
                yield
        else:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(str(path))
            sock.listen()
            print(f'listening on {path}')
            try:
                watch(sock, self.on_con)
                yield
            finally:
                sock.close()
                path.unlink()

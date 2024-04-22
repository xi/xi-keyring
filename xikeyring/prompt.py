import os
import subprocess
import sys


class PinentryPrompt:
    def __enter__(self):
        self._proc = subprocess.Popen(
            ['pinentry'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        resp = self._proc.stdout.readline()
        assert resp.startswith(b'OK')

        if sys.stdout.isatty():
            ttyname = os.ttyname(sys.stdout.fileno())
            self.call(b'OPTION ttyname=' + ttyname.encode())

        return self

    def __exit__(self, *args):
        self._proc.terminate()
        self._proc.communicate()

    def encode(self, s: str) -> bytes:
        result = ''
        for c in s:
            if ord(c) < 33:
                result += f'%{ord(c):02x}'
            else:
                result += c
        return result.encode()

    def call(self, cmd: bytes) -> tuple[bool, list[bytes]]:
        self._proc.stdin.write(cmd + b'\n')
        self._proc.stdin.flush()
        resp = []
        for line in self._proc.stdout:
            resp.append(line)
            if line.startswith(b'OK'):
                return True, resp
            elif line.startswith(b'ERR'):
                return False, resp
        raise AssertionError('unreachable')

    def setup(self, title: str, desc: str):
        self.call(b'SETTITLE ' + self.encode(title))
        self.call(b'SETPROMPT ' + self.encode(title))
        self.call(b'SETDESC ' + self.encode(desc))
        self.call(b'SETQUALITYBAR')

    def get_password(self, desc: str) -> bytes | None:
        with self:
            self.setup('Authentication required', desc)
            success, resp = self.call(b'GETPIN')
            if success:
                for line in resp:
                    if line.startswith(b'D '):
                        return line[2:-1]
            return None

    def confirm(self, desc: str) -> bool:
        with self:
            self.setup('Confirmation required', desc)
            success, resp = self.call(b'CONFIRM')
            return success


class DummyPrompt:
    def get_password(self, desc):
        return b'password'

    def confirm(self, desc):
        return True


if __name__ == '__main__':
    prompt = PinentryPrompt()
    print(prompt.get_password('please enter a password'))

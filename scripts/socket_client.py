#!/usr/bin/env python3

import argparse
import json
import os
import socket
import sys
from getpass import getpass
from pathlib import Path


def get_runtime_dir():
    return Path(os.environ['XDG_RUNTIME_DIR'])


def parse_args():
    parser = argparse.ArgumentParser('xikeyring')
    parser.add_argument('method', choices=['get', 'set', 'del'])
    parser.add_argument('service')
    parser.add_argument('username')
    parser.add_argument(
        '--socket',
        type=Path,
        default=get_runtime_dir() / 'xi.portal.Secret',
    )
    return parser.parse_args()


def call(sock, msg):
    sock.send(json.dumps(msg).encode('utf-8'))
    chunk = sock.recv(1024)  # TODO: buffer
    reply = json.loads(chunk)
    if 'error' in reply:
        print(reply['error'], file=sys.stderr)
        sys.exit(1)
    return reply


args = parse_args()
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(str(args.socket))
query = {
    'username': args.username,
    'service': args.service,
    'application': 'xikeyring',
}
try:
    if args.method == 'get':
        reply = call(sock, {'method': 'get', 'query': query})
        print(reply['secret'])
    elif args.method == 'set':
        secret = getpass()
        call(sock, {'method': 'set', 'query': query, 'secret': secret})
    elif args.method == 'del':
        call(sock, {'method': 'del', 'query': query})
finally:
    sock.close()

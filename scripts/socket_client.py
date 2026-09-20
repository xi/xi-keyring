#!/usr/bin/env python3

import argparse
from getpass import getpass
from pathlib import Path

from xikeyring import socket_client


def parse_args():
    parser = argparse.ArgumentParser('xikeyring')
    parser.add_argument('method', choices=['get', 'set', 'del'])
    parser.add_argument('service')
    parser.add_argument('username')
    parser.add_argument(
        '--socket',
        type=Path,
        default=socket_client.DEFAULT_PATH,
    )
    return parser.parse_args()


def main():
    args = parse_args()
    query = {
        'username': args.username,
        'service': args.service,
        'application': 'xikeyring',
    }
    if args.method == 'get':
        print(socket_client.get(query, args.socket))
    elif args.method == 'set':
        secret = getpass()
        socket_client.set(query, secret, args.socket)
    elif args.method == 'del':
        socket_client.delete(query, args.socket)


if __name__ == '__main__':
    main()

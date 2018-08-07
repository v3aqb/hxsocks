
# __main__.py - start hxsocks server

# Copyright (C) 2016 - 2018, v3aqb

# This file is a part of hxsocks.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import sys
import yaml
import asyncio
import argparse

from .server import HandlerFactory, HXsocksHandler, KeyManager, ECC

from concurrent.futures import ThreadPoolExecutor


def main():
    if sys.platform == 'win32':
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', required=True, help="config file")
    args = parser.parse_args()

    if not os.path.exists(args.c):
        sys.stderr.write('config file {} not exist!\n'.format(args.c))
        sys.exit()
    else:
        with open(args.c, 'r') as ymlfile:
            cfg = yaml.load(ymlfile)
        servers = cfg['servers']
        log_level = cfg['log_level'] if 'log_level' in cfg else 20

    # server cert
    cert_path = os.path.join(os.path.dirname(os.path.abspath(args.c)), 'cert.pem')

    if not os.path.exists(cert_path):
        sys.stderr.write('server cert not found, creating...\n')
        ECC(key_len=32).save(cert_path)

    kmgr = KeyManager(cert_path)

    # add user
    for user, pass_ in cfg['users'].items():
        kmgr.add_user(user, pass_)

    loop = asyncio.get_event_loop()
    loop.set_default_executor(ThreadPoolExecutor(20))

    for server in servers:
        handler = HandlerFactory(HXsocksHandler, server, kmgr, log_level)
        loop = asyncio.get_event_loop()
        coro = asyncio.start_server(handler.handle, handler.address[0], handler.address[1], loop=loop)
        server = loop.run_until_complete(coro)

    loop.run_forever()


if __name__ == '__main__':
    main()

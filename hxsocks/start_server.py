
import os
import sys
import hashlib
import asyncio
from concurrent.futures import ThreadPoolExecutor

import yaml

from .server import HandlerFactory, HXsocksHandler, UserManager, ECC


def start_hxs_server(confpath):
    with open(confpath, 'r') as ymlfile:
        cfg = yaml.safe_load(ymlfile)
    servers = cfg['servers']
    log_level = cfg['log_level'] if 'log_level' in cfg else 20

    # server cert
    cert_path = os.path.join(os.path.dirname(os.path.abspath(confpath)), 'cert.pem')

    if not os.path.exists(cert_path):
        sys.stderr.write('server cert not found, creating...\n')
        ECC(key_len=32).save(cert_path)

    user_mgr = UserManager(cert_path)
    cert = user_mgr.SERVER_CERT.get_pub_key()
    cert_hash = hashlib.sha256(cert).hexdigest()[:8]
    sys.stderr.write('load server cert %s\n' % cert_hash)

    # add user
    for user, passwd in cfg['users'].items():
        user_mgr.add_user(user, passwd)

    loop = asyncio.get_event_loop()
    loop.set_default_executor(ThreadPoolExecutor(20))

    for server in servers:
        handler = HandlerFactory(HXsocksHandler, server, user_mgr, log_level)
        coro = asyncio.start_server(handler.handle, handler.address[0], handler.address[1], loop=loop)
        server = loop.run_until_complete(coro)

    # loop.run_forever()


import os
import sys
import hashlib

from hxsocks.settings import Settings
from hxsocks.user_manager import UserManager, ECC
from hxsocks.server import Server, HXsocksHandler
from hxsocks.hxs3_server import hxs3_server

try:
    from hxsocks.udp_relay import UDPRelayServer
except ImportError:
    UDPRelayServer = None


def start_hxs_server(confpath):
    Settings.load(confpath)

    if Settings.udp_enable and not UDPRelayServer:
        sys.stderr.write('asyncio_dgram not found? disable udp\n')
        Settings.udp_enable = False

    # server cert
    cert_path = os.path.join(os.path.dirname(os.path.abspath(confpath)), 'cert.pem')

    if not os.path.exists(cert_path):
        sys.stderr.write('server cert not found, creating...\n')
        ECC(key_len=32).save(cert_path)

    user_mgr = UserManager(cert_path, Settings.conn_limit)
    cert = user_mgr.server_cert.get_pub_key()
    cert_hash = hashlib.sha256(cert).hexdigest()[:8]
    sys.stderr.write('load server cert %s\n' % cert_hash)

    servers = Settings.servers

    # add user
    for user, passwd in Settings.users.items():
        user_mgr.add_user(user, passwd)

    server_list = []
    for server in servers:
        if server.startswith(('ss', 'hxs2')):
            server_ = Server(HXsocksHandler, server, user_mgr, Settings)
            server_.start()
            server_list.append(server_)
            if Settings.udp_enable:
                udp_enable = Settings.udp_enable
                if isinstance(udp_enable, list) and server_.address[1] not in udp_enable:  # pylint: disable=E1135
                    continue
                if server_.method.startswith('2022'):
                    sys.stderr.write('2022-blake3 udp not supported yet.\n')
                    continue
                udp_server = UDPRelayServer(server_, Settings.udp_timeout, Settings.udp_mode)
                udp_server.start()
                server_list.append(udp_server)
        if server.startswith('hxs3'):
            server = hxs3_server(server, user_mgr, Settings)
            server.start_service()

    # loop.run_forever()
    return server_list


import os
import sys
import hashlib

import yaml

from hxsocks.server import Server, HXsocksHandler
from hxsocks.hxs3_server import hxs3_server
from hxsocks.user_manager import UserManager, ECC
try:
    from hxsocks.udp_relay import UDPRelayServer
except ImportError:
    UDPRelayServer = None


def start_hxs_server(confpath):
    with open(confpath, 'r') as ymlfile:
        cfg = yaml.safe_load(ymlfile)
    servers = cfg['servers']
    conn_limit = cfg.get('limit', 20)
    log_level = cfg.get('log_level', 20)

    tcp_nodelay = cfg.get('tcp_nodelay', False)
    tcp_timeout = cfg.get('tcp_timeout', 600)
    if not isinstance(tcp_timeout, int):
        tcp_timeout = 600

    udp_enable = cfg.get('udp_enable', False)
    if udp_enable and not UDPRelayServer:
        sys.stderr.write('asyncio_dgram not found? disable udp\n')
        udp_enable = False
    # boolean, port_number, [list of ports]
    if isinstance(udp_enable, int):
        if udp_enable <= 0:
            udp_enable = False
        elif udp_enable > 2:
            # False == 0, True == 1
            udp_enable = [udp_enable]
        else:
            udp_enable = True

    udp_timeout = cfg.get('udp_timeout', 600)
    if not isinstance(udp_timeout, int):
        udp_timeout = 600

    udp_mode = cfg.get('udp_mode', 2)
    # 0 for fullcone, 1 for restricted, 2 for port_restricted
    if not isinstance(udp_mode, int):
        udp_mode = 2

    # server cert
    cert_path = os.path.join(os.path.dirname(os.path.abspath(confpath)), 'cert.pem')

    if not os.path.exists(cert_path):
        sys.stderr.write('server cert not found, creating...\n')
        ECC(key_len=32).save(cert_path)

    user_mgr = UserManager(cert_path, conn_limit)
    cert = user_mgr.SERVER_CERT.get_pub_key()
    cert_hash = hashlib.sha256(cert).hexdigest()[:8]
    sys.stderr.write('load server cert %s\n' % cert_hash)

    # add user
    if cfg['users']:
        for user, passwd in cfg['users'].items():
            user_mgr.add_user(user, passwd)

    server_list = []
    for server in servers:
        if server.startswith(('ss', 'hxs2')):
            server_ = Server(HXsocksHandler, server, user_mgr, log_level, tcp_nodelay, tcp_timeout, udp_timeout)
            server_.start()
            server_list.append(server_)
            if udp_enable:
                if isinstance(udp_enable, list) and server_.address[1] not in udp_enable:
                    continue
                udp_server = UDPRelayServer(server_, udp_timeout, udp_mode)
                udp_server.start()
                server_list.append(udp_server)
        if server.startswith('hxs3'):
            server = hxs3_server(server, user_mgr, log_level, tcp_timeout, udp_timeout)
            server.start_service()

    # loop.run_forever()
    return server_list

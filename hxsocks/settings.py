
import yaml
import logging


class Settings:
    conn_limit = 20
    log_level = 20
    block_china = False

    tcp_nodelay = False
    tcp_idle_timeout = 600
    tcp_conn_timeout = 6

    udp_enable = False
    udp_timeout = 90
    udp_mode = 0
    prefer_ipv4 = 0

    users = {}

    @classmethod
    def load(cls, confpath):
        with open(confpath, 'r') as ymlfile:
            cfg = yaml.safe_load(ymlfile)

        cls.conn_limit = cfg.get('conn_limit', cls.conn_limit)
        cls.block_china = cfg.get('block_china', cls.block_china)
        cls.prefer_ipv4 = cfg.get('prefer_ipv4', cls.prefer_ipv4)
        log_level = cfg.get('log_level', cls.log_level)
        cls.log_level = log_level
        if isinstance(log_level, str):
            cls.log_level = getattr(logging, log_level.upper())

        cls.tcp_nodelay = cfg.get('tcp_nodelay', cls.tcp_nodelay)
        cls.tcp_idle_timeout = cfg.get('tcp_timeout', cls.tcp_idle_timeout)
        cls.tcp_conn_timeout = cfg.get('tcp_conn_timeout', cls.tcp_conn_timeout)
        if not isinstance(cls.tcp_idle_timeout, int):
            cls.tcp_idle_timeout = 600
        cls.tcp_idle_timeout = max(cls.tcp_idle_timeout, 60)

        cls.udp_enable = cfg.get('udp_enable', cls.udp_enable)
        # boolean, port_number, [list of ports]

        if isinstance(cls.udp_enable, int):
            if cls.udp_enable <= 0:
                cls.udp_enable = False
            elif cls.udp_enable > 2:
                # False == 0, True == 1
                cls.udp_enable = [cls.udp_enable]
            else:
                cls.udp_enable = True

        cls.udp_timeout = cfg.get('udp_timeout', cls.udp_timeout)
        if not isinstance(cls.udp_timeout, int):
            cls.udp_timeout = 600
        cls.udp_timeout = max(cls.udp_timeout, 60)

        cls.udp_mode = cfg.get('udp_mode', cls.udp_mode)
        # 0 for fullcone, 1 for restricted, 2 for port_restricted, 3 for symmetric
        if not isinstance(cls.udp_mode, int):
            cls.udp_mode = 0

        users = cfg['users']
        cls.users = users if users else cls.users

        cls.servers = cfg['servers']



import struct
import asyncio
import logging

from hxsocks.udp_relay import UDPRelay, parse_dgram
from hxsocks.udp_relay2 import get_relay2

logger = logging.getLogger('udp_relay3')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s')
hdr.setFormatter(formatter)
logger.addHandler(hdr)


def parse_dgram2(payload):
    '''parse hxsocks dgram'''
    client_id = payload.read(8)
    udp_sid = payload.read(4)
    data_len, = struct.unpack(b">H", payload.read(2))
    data = payload.read(data_len)
    return client_id, udp_sid, data


class HxsUDPRelayManager:
    relay_store = {}
    hxs_conn_store = {}
    logger = logger
    udp_mode = 2
    timeout = 90

    @classmethod
    def config(cls, settings):
        cls.udp_mode = settings.udp_mode
        cls.timeout = settings.udp_timeout

    @classmethod
    def on_dgram_recv(cls, hxs_conn, payload):
        logger.debug('on_dgram_recv')
        client_id, udp_sid, data = parse_dgram2(payload)
        asyncio.ensure_future(cls.send_dgram(client_id, udp_sid, data, hxs_conn))

    @classmethod
    async def send_dgram(cls, client_id, udp_sid, data, hxs_conn):
        logger.debug('send_dgram')
        client_addr = (client_id, udp_sid)
        if client_addr not in cls.relay_store:
            if cls.udp_mode in (0, 1, 2):
                relay = UDPRelay(cls, hxs_conn.udp_uid, client_addr, cls.timeout, cls.udp_mode)
                await relay.bind()
            else:
                relay = get_relay2(client_id)
            cls.relay_store[client_addr] = relay
        cls.hxs_conn_store[client_id] = hxs_conn
        relay = cls.relay_store[client_addr]
        addr, dgram = parse_dgram(data)
        await relay.send_dgram(addr, dgram, cls, client_addr)

    @classmethod
    async def on_remote_recv(cls, client_addr, buf):
        logger.debug('on_remote_recv')
        client_id, udp_sid = client_addr
        hxs_conn = cls.hxs_conn_store[client_id]
        await hxs_conn.send_dgram2(client_id, udp_sid, buf)

    @classmethod
    def close_relay(cls, client_addr):
        logger.debug('close_relay')
        del cls.relay_store[client_addr]

    @classmethod
    def conn_closed(cls, client_id, hxs_conn):
        logger.debug('conn_closed')
        if client_id not in cls.hxs_conn_store:
            return
        if hxs_conn == cls.hxs_conn_store[client_id]:
            del cls.hxs_conn_store[client_id]

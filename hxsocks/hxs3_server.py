'''
hxsocks3.py

Websocket version of hxsocks2.

'''
import io
import hashlib
import logging
import random
import struct
import time
import urllib.parse

import asyncio

import websockets.server
from websockets.exceptions import ConnectionClosed

from hxcrypto import InvalidTag

from hxsocks.util import parse_hostport
from hxsocks.hxs_common_server import HxsCommon, ReadFrameError

OPEN = 0
EOF_SENT = 1   # SENT END_STREAM
EOF_RECV = 2  # RECV END_STREAM
CLOSED = 3

REMOTE_WRITE_BUFFER = 524288

DATA = 0
HEADERS = 1
# PRIORITY = 2
RST_STREAM = 3
SETTINGS = 4
# PUSH_PROMISE = 5
PING = 6
GOAWAY = 7
WINDOW_UPDATE = 8
# CONTINUATION = 9
UDP_ASSOCIATE = 20

PONG = 1
END_STREAM_FLAG = 1


class hxs3_server:
    def __init__(self, server, user_mgr, settings):
        parse = urllib.parse.urlparse(server)
        query = urllib.parse.parse_qs(parse.query)
        self.address = parse_hostport(parse.netloc)
        self.user_mgr = user_mgr
        self.settings = settings
        self.logger = logging.getLogger('hxs3_%d' % self.address[1])
        self.logger.setLevel(settings.log_level)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)
        proxy = query.get('proxy', [''])[0]
        self.proxy = parse_hostport(proxy) if proxy else None

        self.handller_class = hxs3_handler
        self.server = None

    def start_service(self):
        self.logger.info('starting hxs3 server at %r', self.address)
        asyncio.ensure_future(websockets.server.serve(self.handle,
                                                      host=self.address[0],
                                                      port=self.address[1],
                                                      ping_interval=10,
                                                      ping_timeout=None,
                                                      read_limit=2 ** 18,
                                                      write_limit=2 ** 18,
                                                      ))

    async def handle(self, websocket, path):
        handler = self.handller_class(self)
        await handler.handle(websocket, path)


class hxs3_handler(HxsCommon):

    def __init__(self, server):
        super().__init__()
        self.logger = server.logger
        self.user_mgr = server.user_mgr
        self.server_addr = server.address
        self._proxy = server.proxy

        self.settings = server.settings

        self.websocket = None

    async def handle(self, websocket, path):
        self.websocket = websocket

        self.client_address = self.websocket.remote_address
        xff = self.websocket.request_headers.get_all('X-Forwarded-For')
        if xff:
            self.client_address = (xff[0], 0)

        fut = self.websocket.recv()
        try:
            client_auth = await asyncio.wait_for(fut, timeout=6)
        except asyncio.TimeoutError:
            self.logger.error('read client auth failed. client: %s', self.client_address)
            return
        data = io.BytesIO(client_auth)

        ver = data.read(1)[0]
        if ver != 0:
            self.logger.error('version %d not recognised', ver, self.client_address)
            return
        pklen = data.read(1)[0]
        client_pkey = data.read(pklen)
        client_auth = data.read(32)
        self._mode = data.read(1)[0]

        try:
            client, reply, self._skey = self.user_mgr.hxs2_auth(client_pkey, client_auth)
            self.logger.info('new key exchange. client: %s %s', client, self.client_address)
            self.user = client
        except ValueError as err:
            self.logger.error('key exchange failed. %s %s', err, self.client_address)
            await self.play_dead()
            return

        reply = reply + chr(self._mode).encode() + bytes(random.randint(64, 2048))
        await self.websocket.send(reply)

        await self.handle_connection()
        client_pkey = hashlib.md5(client_pkey).digest()
        self.user_mgr.del_key(client_pkey)
        await self.websocket.close()
        return

    async def play_dead(self):
        count = random.randint(12, 30)
        for _ in range(count):
            timeout = random.random()
            fut = self.websocket.recv()
            try:
                await asyncio.wait_for(fut, timeout)
            except asyncio.TimeoutError:
                continue
            except (OSError, RuntimeError, ConnectionClosed):
                return

    async def read_frame(self, timeout=30):
        try:
            fut = self.websocket.recv()
            frame_data = await asyncio.wait_for(fut, timeout=timeout)
            frame_data = self.decrypt_frame(frame_data)
            return frame_data
        except (ConnectionClosed, RuntimeError, InvalidTag) as err:
            raise ReadFrameError(err) from err

    async def send_frame(self, type_, flags, stream_id, payload):
        self.logger.debug('send frame_type: %d, stream_id: %d', type_, stream_id)
        if self._connection_lost:
            return
        if type_ in (DATA, HEADERS):
            self._last_active = time.monotonic()

        header = struct.pack('>BBH', type_, flags, stream_id)
        data = header + payload
        ct_ = self._cipher.encrypt(data)
        try:
            await self.websocket.send(ct_)
        except ConnectionClosed:
            self._connection_lost = True
            raise

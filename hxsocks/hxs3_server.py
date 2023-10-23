'''
hxsocks3.py

Websocket version of hxsocks2.

'''
import io
import hashlib
import logging
import random
import urllib.parse

import asyncio

import websockets.server
from websockets.exceptions import ConnectionClosed

from hxcrypto import InvalidTag

from hxsocks.util import parse_hostport
from hxsocks.hxs_common_server import HxsCommon, ReadFrameError
from hxsocks.hxs_common_server import HANDSHAKE_SIZE, READ_AUTH_TIMEOUT, CLIENT_WRITE_BUFFER


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
        self.logger.warning('starting hxs3 server at %r', self.address)
        asyncio.ensure_future(websockets.server.serve(self.handle,
                                                      host=self.address[0],
                                                      port=self.address[1],
                                                      ping_interval=None,
                                                      ping_timeout=None,
                                                      max_size=2 ** 17,
                                                      max_queue=2,
                                                      read_limit=2 ** 18,
                                                      write_limit=CLIENT_WRITE_BUFFER,
                                                      ))

    async def handle(self, websocket, path):
        handler = self.handller_class(self)
        try:
            await handler.handle(websocket, path)
        except ConnectionClosed:
            self.logger.error('ConnectionClosed')
        try:
            await handler.websocket.close()
        except ConnectionClosed:
            pass


class hxs3_handler(HxsCommon):

    def __init__(self, server):
        super().__init__(0)
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

        try:
            fut = self.websocket.recv()
            client_auth = await asyncio.wait_for(fut, timeout=READ_AUTH_TIMEOUT)
        except (asyncio.TimeoutError, ConnectionClosed) as err:
            self.logger.error('read client auth failed. client: %s, %r', self.client_address, err)
            return
        data = io.BytesIO(client_auth)

        ver = data.read(1)[0]
        if ver != 0:
            self.logger.error('version %d not recognised, %s', ver, self.client_address)
            return
        pklen = data.read(1)[0]
        client_pkey = data.read(pklen)
        client_auth = data.read(32)
        mode = data.read(1)[0]

        self._mode = 0
        if mode & 1:
            self._mode |= 1

        try:
            client, reply, self._skey = self.user_mgr.hxs2_auth(client_pkey, client_auth)
            self.logger.info('new key exchange. client: %s %s', client, self.client_address)
            self.user = client
        except ValueError as err:
            self.logger.error('key exchange failed. %s %s', err, self.client_address)
            await self.play_dead()
            return

        reply = reply + chr(self._mode).encode() + \
            bytes(random.randint(HANDSHAKE_SIZE // 2, HANDSHAKE_SIZE))
        try:
            await self.websocket.send(reply)
        except ConnectionClosed:
            self.logger.error('send auth reply fail.')
            self._connection_lost = True
        await self.handle_connection()
        client_pkey = hashlib.md5(client_pkey).digest()
        self.user_mgr.del_key(client_pkey)
        return

    async def play_dead(self):
        self.logger.info('enter play_dead')
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

    async def _send_frame(self, ct_):
        try:
            await self.websocket.send(ct_)
        except ConnectionClosed as err:
            self.logger.error('send_frame fail: %r', err)
            self._connection_lost = True

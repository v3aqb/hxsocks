
# server.py - hxsocks server

# Copyright (C) 2023, v3aqb

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

import socket
import io
import random
import hashlib
import base64
import math

import asyncio
import asyncio.streams

from hxcrypto import InvalidTag, IVError, AEncryptor, method_supported
from hxsocks.hxs2_conn import Hxs2Connection
from hxsocks.hxs_common_server import HANDSHAKE_SIZE, CTX, CLIENT_WRITE_BUFFER, READ_AUTH_TIMEOUT


class HXsocks4Handler:
    bufsize = 65535
    table = {}
    for i in range(256):
        table[i] = i & 0b01111111

    def __init__(self, server):
        self.server = server
        self.logger = server.logger
        self.user_mgr = self.server.user_mgr
        self.address = self.server.address
        self.settings = server.settings

        self.encryptor = AEncryptor(self.server.psk.encode(), self.server.method, CTX, check_iv=True, role=1)
        self._buf = b''

        self.client_address = None
        self.client_reader = None
        self.client_writer = None

    async def handle(self, client_reader, client_writer):
        client_writer.transport.set_write_buffer_limits(CLIENT_WRITE_BUFFER)
        if self.settings.tcp_nodelay:
            soc = client_writer.transport.get_extra_info('socket')
            soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        try:
            await self._handle(client_reader, client_writer)
        except Exception as err:
            self.logger.error('_handle error %r', err, exc_info=True)
        if not client_writer.is_closing():
            client_writer.close()
        try:
            await client_writer.wait_closed()
        except OSError:
            pass

    async def read_request_headers(self):
        '''return (header: io.BytesIO, b85encode: Boolean)
        '''
        data = b''
        for _ in range(10):
            try:
                fut = self.client_reader.read(self.bufsize)
                data += await asyncio.wait_for(fut, timeout=4)
                if len(data) > self.encryptor.iv_len:
                    header = self.encryptor.decrypt(data)
                    header = io.BytesIO(header)
                    return (header, False)
            except InvalidTag:
                if len(data) > self.encryptor.iv_len * 2:
                    try:
                        data_b85decode = base64.b85decode(data)
                        header = self.encryptor.decrypt(data_b85decode)
                        header = io.BytesIO(header)
                        return (header, True)
                    except (ValueError, InvalidTag):
                        pass
        raise ValueError('unable to decrypt request')

    async def _handle(self, client_reader, client_writer):
        self.client_address = client_writer.get_extra_info('peername')
        self.client_reader = client_reader
        self.client_writer = client_writer
        self.logger.debug('incoming connection %s', self.client_address)

        try:
            fut = self.read_request_headers()
            header, b85encode = await asyncio.wait_for(fut, timeout=READ_AUTH_TIMEOUT)
        except (IVError, ValueError) as err:
            self.logger.error('read request header error, %s %r', self.client_address, err)
            await self.play_dead()
            return
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, IndexError) as err:
            self.logger.warning('read request header error, %s, %r', self.client_address, err)
            return

        self.logger.debug('client_address: %s', self.client_address)

        pklen = header.read(1)[0]  # 158
        client_pkey = header.read(pklen)
        client_auth = header.read(32)
        mode = header.read(1)[0]

        try:
            client, reply, shared_secret = self.user_mgr.hxs2_auth(client_pkey, client_auth)
            self.logger.info('new key exchange. client: %s %s, b85: %r', client, self.client_address, b85encode)
        except ValueError as err:
            self.logger.error('key exchange failed. %s %s, b85: %r', err, self.client_address, b85encode)
            await self.play_dead()
            return

        mode_s = 0
        if mode & 1:
            mode_s |= 1
        if mode & 2 and 'rc4' in method_supported:
            mode_s |= 2
        reply += bytes((mode_s, ))
        if b85encode:
            padding_len_low = math.ceil((HANDSHAKE_SIZE // 2 - len(reply) * 0.25 - 8) * 0.8)
            padding_len_high = math.ceil((HANDSHAKE_SIZE - len(reply) * 0.25 - 8) * 0.8)
        else:
            padding_len_low = HANDSHAKE_SIZE // 2
            padding_len_high = HANDSHAKE_SIZE
        reply += bytes(random.randint(max(padding_len_low, 0), max(padding_len_high, 0)))
        reply = self.encryptor.encrypt(reply)
        if b85encode:
            reply = base64.b85encode(reply)
        client_writer.write(reply)

        conn = Hxs2Connection(client_reader,
                              client_writer,
                              client,
                              shared_secret,
                              mode_s,
                              self.server.proxy,
                              self.user_mgr,
                              self.address,
                              self.logger,
                              self.settings)
        result = await conn.handle_connection()
        client_pkey = hashlib.md5(client_pkey).digest()
        self.user_mgr.del_key(client_pkey)
        if result:
            await self.play_dead()
        return

    async def play_dead(self):
        count = random.randint(12, 30)
        for _ in range(count):
            timeout = random.random()
            fut = self.client_reader.read(self.bufsize)
            try:
                await asyncio.wait_for(fut, timeout)
            except asyncio.TimeoutError:
                continue
            except OSError:
                return

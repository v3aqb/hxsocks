
# server.py - hxsocks server

# Copyright (C) 2016 - 2023, v3aqb

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
import struct
import logging
import io
import time
import urllib.parse
import random
import hashlib

import asyncio
import asyncio.streams

from hxcrypto import BufEmptyError, InvalidTag, IVError, is_aead, Encryptor
from hxsocks.hxs2_conn import Hxs2Connection
from hxsocks.hxs_common_server import HANDSHAKE_SIZE
from hxsocks.hxs4_handler import HXsocks4Handler
from hxsocks.util import open_connection, parse_hostport

SS_SUBKEY = "ss-subkey"
SS_SUBKEY_2022 = 'shadowsocks 2022 session subkey'

DEFAULT_METHOD = 'chacha20-ietf-poly1305'  # for hxsocks2 handshake


class ForwardContext:
    def __init__(self):
        self.last_active = time.monotonic()
        # eof recieved
        self.remote_eof = False
        self.local_eof = False
        # traffic
        self.traffic_from_client = 0
        self.traffic_from_remote = 0


class HxsServer:
    def __init__(self, serverinfo, user_mgr, settings):
        self.serverinfo = serverinfo
        self.user_mgr = user_mgr
        self.settings = settings

        self.server = None
        self._handler_class = None
        self.ss_enable = False

        parse = urllib.parse.urlparse(serverinfo)
        query = urllib.parse.parse_qs(parse.query)
        if parse.scheme == 'ss':
            self.psk, self.method = parse.password, parse.username
            self.ss_enable = True
            self._handler_class = HXsocksHandler
        elif parse.scheme == 'hxs2':
            self.psk = query.get('PSK', [''])[0]
            self.method = query.get('method', [DEFAULT_METHOD])[0]
            self.ss_enable = self.psk and int(query.get('ss', ['0'])[0])
            self._handler_class = HXsocksHandler
        elif parse.scheme == 'hxs4':
            self.psk = query.get('PSK', [''])[0]
            self.method = query.get('method', [DEFAULT_METHOD])[0]
            self.ss_enable = self.psk and int(query.get('ss', ['0'])[0])
            self._handler_class = HXsocks4Handler
        else:
            raise ValueError(f'bad serverinfo: {self.serverinfo}')

        self.aead = is_aead(self.method)

        # HTTP proxy only
        proxy = query.get('proxy', [''])[0]
        self.proxy = parse_hostport(proxy) if proxy else None

        self.address = (parse.hostname, parse.port)

        self.logger = logging.getLogger(f'hxs_{self.address[1]}')
        self.logger.setLevel(self.settings.log_level)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

        self.logger.warning('starting server: %s', serverinfo)

    async def handle(self, reader, writer):
        _handler = self._handler_class(self)
        await _handler.handle(reader, writer)

    def start(self):
        asyncio.ensure_future(self._start())

    async def _start(self):
        self.server = await asyncio.start_server(self.handle,
                                                 self.address[0],
                                                 self.address[1],
                                                 limit=262144)


class HXsocksHandler:
    bufsize = 16383

    def __init__(self, server):
        self.server = server
        self.logger = server.logger
        self.user_mgr = self.server.user_mgr
        self.address = self.server.address
        self.settings = server.settings

        self.encryptor = Encryptor(self.server.psk, self.server.method, check_iv=True, role=1)
        self._buf = b''

        self.client_address = None
        self.client_reader = None

    async def _read(self):
        if self.server.aead:
            _len = await self.client_reader.readexactly(18)
            _len = self.encryptor.decrypt(_len)
            _len, = struct.unpack("!H", _len)
            ct_ = await self.client_reader.readexactly(_len + 16)
        else:
            ct_ = await self.client_reader.read(self.bufsize)
        return self.encryptor.decrypt(ct_)

    async def read(self, size=None):
        # compatible with shadowsocks aead
        if not size:
            if self._buf:
                buf, self._buf = self._buf, b''
                return buf
            return await self._read()

        while len(self._buf) < size:
            self._buf += await self._read()
        _buf, self._buf = self._buf[:size], self._buf[size:]
        return _buf

    async def handle(self, client_reader, client_writer):
        client_writer.transport.set_write_buffer_limits(262144)
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
        if self.server.method.startswith('2022'):
            fix_len_header = await self.client_reader.readexactly(self.encryptor.iv_len + 11 + 16)
            fix_len_header = self.encryptor.decrypt(fix_len_header)
            type_, timestamp, length = struct.unpack('!BQH', fix_len_header)
            if type_ != 0:
                raise ValueError('header_type=1, except 0')
            diff = time.time() - timestamp
            if abs(diff) > 30:
                raise ValueError('timestamp error, diff: %.4fs' % diff)
            header = await self.client_reader.readexactly(length + 16)
        elif self.server.aead:
            _len = await self.client_reader.readexactly(self.encryptor.iv_len + 18)
            _len = self.encryptor.decrypt(_len)
            _len, = struct.unpack("!H", _len)
            header = await self.client_reader.readexactly(_len + 16)
        else:
            # stream cipher
            header = await self.client_reader.read(self.bufsize)
        header = self.encryptor.decrypt(header)
        header = io.BytesIO(header)
        addr_type = header.read(1)[0]
        if addr_type in (1, 3, 4):
            if addr_type == 1:
                addr = header.read(4)
                addr = socket.inet_ntoa(addr)
            elif addr_type == 3:
                data = header.read(1)
                addr = header.read(data[0])
                addr = addr.decode('ascii')
            elif addr_type == 4:
                data = header.read(16)
                addr = socket.inet_ntop(socket.AF_INET6, data)
            port = header.read(2)
            port, = struct.unpack('>H', port)
            if self.encryptor.ctx == SS_SUBKEY_2022:
                padding_len = header.read(2)
                padding_len, = struct.unpack('>H', padding_len)
                header.read(padding_len)
        else:
            addr = ''
            port = 0
        return addr_type, addr, port, header

    async def _handle(self, client_reader, client_writer):
        self.client_address = client_writer.get_extra_info('peername')
        self.client_reader = client_reader
        self.logger.debug('incoming connection %s', self.client_address)

        try:
            fut = self.read_request_headers()
            addr_type, addr, port, payload = await asyncio.wait_for(fut, timeout=12)
        except (IVError, InvalidTag, ValueError) as err:
            self.logger.error('read request header error, %s %r', self.client_address, err)
            await self.play_dead()
            return
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, IndexError) as err:
            self.logger.warning('read request header error, %s, %r', self.client_address, err)
            return

        self.logger.debug('addr_type: %s %s', addr_type, self.client_address)

        if addr_type in (1, 3, 4):
            # A shadowsocks request
            result = await self.handle_ss(client_writer, addr, port, payload)
            if result:
                await self.play_dead()
            return
        if addr_type == 20:  # hxsocks2 client key exchange
            req_len = payload.read(2)
            req_len, = struct.unpack('>H', req_len)
            data = payload.read(req_len)
            data = io.BytesIO(data)

            pklen = data.read(1)[0]  # 158
            client_pkey = data.read(pklen)
            client_auth = data.read(32)
            mode = data.read(1)[0]

            try:
                client, reply, shared_secret = self.user_mgr.hxs2_auth(client_pkey, client_auth)
                self.logger.info('new key exchange. client: %s %s', client, self.client_address)
            except ValueError as err:
                self.logger.error('key exchange failed. %s %s', err, self.client_address)
                await self.play_dead()
                return

            reply = reply + bytes((mode, )) + \
                bytes(random.randint(HANDSHAKE_SIZE // 2, HANDSHAKE_SIZE))
            reply = struct.pack('>H', len(reply)) + reply
            client_writer.write(self.encryptor.encrypt(reply))

            conn = Hxs2Connection(client_reader,
                                  client_writer,
                                  client,
                                  shared_secret,
                                  mode,
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

        # TODO: security log
        self.logger.error('bad addr_type: %s, %s', addr_type, self.client_address)
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

    async def handle_ss(self, client_writer, addr, port, payload):
        # if error, return 1
        if not self.server.ss_enable:
            return True
        # access control
        try:
            self.user_mgr.user_access_ctrl(self.address[1], (addr, port), self.client_address, self.server.psk, 0)
        except ValueError as err:
            self.logger.warning('access denied! %s:%s, %s %s', addr, port, err)
            return

        # create connection
        self.logger.info('connect to %s:%d %r', addr, port, self.client_address)

        try:
            remote_reader, remote_writer = await open_connection(addr,
                                                                 port,
                                                                 self.server.proxy,
                                                                 self.settings)
        except (ConnectionError, asyncio.TimeoutError, socket.gaierror) as err:
            self.logger.error('connect to %s:%s failed! %r', addr, port, err)
            return

        # forward
        context = ForwardContext()

        payload = payload.read()
        if payload:
            remote_writer.write(payload)

        tasks = [asyncio.create_task(self.ss_forward_a(remote_writer, context)),
                 asyncio.create_task(self.ss_forward_b(remote_reader,
                                                       client_writer,
                                                       context)),
                 ]
        await asyncio.wait(tasks)

        # access log
        traffic = (context.traffic_from_client, context.traffic_from_remote)
        self.user_mgr.user_access_log(self.address[1], (addr, port), traffic, self.client_address, self.server.psk, 0)
        if not remote_writer.is_closing():
            remote_writer.close()
        try:
            await remote_writer.wait_closed()
        except ConnectionError:
            pass

    async def ss_forward_a(self, write_to, context):
        # data from ss client, decrypt, sent to remote
        while True:
            try:
                fut = self.read()
                data = await asyncio.wait_for(fut, timeout=6)
                context.last_active = time.monotonic()
            except asyncio.TimeoutError:
                idle_time = time.monotonic() - context.last_active
                if context.local_eof and idle_time > 60:
                    break
                if idle_time > self.settings.tcp_idle_timeout:
                    break
                continue
            except (BufEmptyError, asyncio.IncompleteReadError, InvalidTag, OSError):
                break

            if not data:
                break
            context.traffic_from_client += len(data)
            try:
                write_to.write(data)
                await write_to.drain()
            except ConnectionError:
                context.local_eof = True
                return
        context.local_eof = True
        try:
            write_to.write_eof()
        except OSError:
            pass

    async def ss_forward_b(self, read_from, write_to, context):
        # data from remote, encrypt, sent to client
        while True:
            try:
                fut = read_from.read(self.bufsize)
                data = await asyncio.wait_for(fut, timeout=6)
                context.last_active = time.monotonic()
            except asyncio.TimeoutError:
                idle_time = time.monotonic() - context.last_active
                if context.local_eof and idle_time > 60:
                    break
                if idle_time > self.settings.tcp_idle_timeout:
                    break
                continue
            except OSError:
                break

            if not data:
                break

            context.traffic_from_remote += len(data)

            data = self.encryptor.encrypt(data)
            try:
                write_to.write(data)
                await write_to.drain()
            except (ConnectionError, RuntimeError):
                context.remote_eof = True
                return
        context.remote_eof = True
        try:
            write_to.write_eof()
        except (OSError, RuntimeError):
            pass

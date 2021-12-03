
# hxs2_conn.py - hxsocks2 protocol

# Copyright (C) 2018, v3aqb

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

import asyncio
import struct
import io
import time
import random
import socket
import traceback

from hxcrypto import InvalidTag, AEncryptor
from hxsocks.util import open_connection
from .udp_relay import UDPRelay


CTX = b'hxsocks2'

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

HXS2_METHOD = [
    'chacha20-ietf-poly1305',
    'aes-128-gcm',
    'aes-192-gcm',
    'aes-256-gcm',
]


class ForwardContext:
    def __init__(self, host, logger):
        self.host = host
        self.logger = logger
        self.drain_lock = asyncio.Lock()
        self.last_active = time.monotonic()
        self.resume_reading = asyncio.Event()
        self.resume_reading.set()

        # eof recieved
        self.stream_status = OPEN
        # traffic
        self.traffic_from_client = 0
        self.traffic_from_remote = 0

        self._sent_counter = 0
        self._sent_rate = 0
        # start monitor
        self.monitor_task = asyncio.ensure_future(self.monitor())

    def data_sent(self, data_len):
        # sending data to hxs connection
        self.traffic_from_remote += data_len
        self.last_active = time.monotonic()
        self._sent_counter += data_len // 8192 + 1

    def data_recv(self, data_len):
        self.traffic_from_client += data_len
        self.last_active = time.monotonic()

    def is_heavy(self):
        return self._sent_counter and self._sent_rate > 10

    async def monitor(self):
        while self.stream_status is OPEN:
            await asyncio.sleep(1)
            self._sent_rate = 0.2 * self._sent_counter + self._sent_rate * 0.8
            if self._sent_counter or self._sent_rate > 5:
                self.logger.debug('%20s rate: %.2f, count %s', self.host, self._sent_rate, self._sent_counter)
            self._sent_counter = 0


class Hxs2Connection():
    bufsize = 65535 - 22

    def __init__(self, reader, writer, user, skey, proxy, user_mgr, server_addr, logger, tcp_nodelay, timeout):
        self.__cipher = None  # AEncryptor(skey, method, CTX)
        self.__skey = skey
        self._client_reader = reader
        self._client_writer = writer
        self._client_address = writer.get_extra_info('peername')
        self._client_writer.transport.set_write_buffer_limits(524288)
        # suppose client support async drain
        self._settings_async_drain = False
        self._proxy = proxy
        self.server_addr = server_addr
        self._s_port = server_addr[1]
        self.logger = logger
        self._tcp_nodelay = tcp_nodelay
        self.timeout = timeout
        self.user = user
        self.user_mgr = user_mgr
        self._connection_lost = False

        self._init_time = time.monotonic()
        self._last_active = self._init_time
        self._gone = False
        self._next_stream_id = 1

        self._stream_writer = {}
        self._stream_task = {}
        self._stream_context = {}

        self._client_writer_lock = asyncio.Lock()

    async def handle_connection(self):
        self.logger.debug('start recieving frames...')
        timeout_count = 0

        while not self._connection_lost:
            try:
                if self._gone and not self._stream_writer:
                    break

                if time.monotonic() - self._last_active > self.timeout * 2:
                    break

                # read frame_len
                try:
                    fut = self._client_reader.readexactly(2)
                    frame_len = await asyncio.wait_for(fut, timeout=10)
                    frame_len, = struct.unpack('>H', frame_len)
                    timeout_count = 0
                except (asyncio.IncompleteReadError, ValueError, InvalidTag,
                        ConnectionError) as err:
                    self.logger.debug('read frame_len error: %r', err)
                    break
                except asyncio.TimeoutError:
                    timeout_count += 1
                    if timeout_count > 10:
                        # client should sent ping to keep_alive
                        self.logger.debug('read frame_len timed out.')
                        break
                    continue

                # read chunk_data
                try:
                    fut = self._client_reader.readexactly(frame_len)
                    # chunk size shoule be smaller than 32kB
                    frame_data = await asyncio.wait_for(fut, timeout=8)
                    if self.__cipher:
                        frame_data = self.__cipher.decrypt(frame_data)
                    else:
                        error = None
                        for method in HXS2_METHOD:
                            try:
                                cipher = AEncryptor(self.__skey, method, CTX, check_iv=False)
                                frame_data = cipher.decrypt(frame_data)
                                self.__cipher = cipher
                                self.__skey = None
                                break
                            except InvalidTag as err:
                                error = err
                                continue
                        else:
                            raise error
                except (ConnectionError, InvalidTag, asyncio.TimeoutError,
                        asyncio.IncompleteReadError) as err:
                    # something went wrong...
                    self.logger.debug('read frame error: %r', err)
                    break

                # parse chunk_data
                # +------+-------------------+----------+
                # | type | flags | stream_id | payload  |
                # +------+-------------------+----------+
                # |  1   |   1   |     2     | Variable |
                # +------+-------------------+----------+
                frame_data = io.BytesIO(frame_data)
                header = frame_data.read(4)
                frame_type, frame_flags, stream_id = struct.unpack('>BBH', header)

                if frame_type in (DATA, HEADERS):
                    self._last_active = time.monotonic()

                self.logger.debug('recv frame_type: %d, stream_id: %d', frame_type, stream_id)
                if frame_type == DATA:  # 0
                    # check if remote socket writable
                    if self._stream_context[stream_id].stream_status & EOF_RECV:
                        self.logger.warning('data recv while stream closed.')
                        continue
                    # first 2 bytes of payload indicates data_len
                    data_len, = struct.unpack('>H', frame_data.read(2))
                    data = frame_data.read(data_len)
                    if len(data) != data_len:
                        # something went wrong, destory connection
                        self.logger.error('data_len mismatch')
                        break
                    # sent data to stream
                    try:
                        if isinstance(self._stream_writer[stream_id], UDPRelay):
                            await self._stream_writer[stream_id].send(data)
                        else:
                            self._stream_writer[stream_id].write(data)
                            self._stream_context[stream_id].data_recv(len(data))
                            await self.stream_writer_drain(stream_id)
                    except ConnectionError:
                        # remote closed, reset stream
                        asyncio.ensure_future(self.close_stream(stream_id))
                elif frame_type == HEADERS:  # 1
                    if self._next_stream_id == stream_id:
                        # open new stream
                        self._next_stream_id += 1

                        host_len = frame_data.read(1)[0]
                        host = frame_data.read(host_len).decode('ascii')
                        port, = struct.unpack('>H', frame_data.read(2))
                        # rest of the payload is discarded
                        asyncio.ensure_future(self.create_connection(stream_id, host, port))

                    elif stream_id < self._next_stream_id:
                        self.logger.debug('sid %s END_STREAM. status %s',
                                          stream_id,
                                          self._stream_context[stream_id].stream_status)
                        if frame_flags & END_STREAM_FLAG:
                            self._stream_context[stream_id].stream_status |= EOF_RECV
                            if stream_id in self._stream_writer:
                                try:
                                    self._stream_writer[stream_id].write_eof()
                                except OSError:
                                    self._stream_context[stream_id].stream_status = CLOSED
                            if self._stream_context[stream_id].stream_status == CLOSED:
                                asyncio.ensure_future(self.close_stream(stream_id))
                    else:
                        self.logger.error('frame_type == HEADERS, wrong stream_id!')
                elif frame_type == RST_STREAM:  # 3
                    asyncio.ensure_future(self.close_stream(stream_id))
                elif frame_type == SETTINGS:
                    if stream_id == 1:
                        self._settings_async_drain = True
                        self.send_frame(SETTINGS, 0, 1, bytes(random.randint(64, 256)))
                elif frame_type == PING:  # 6
                    if frame_flags == 0:
                        self.send_frame(PING, PONG, 0, bytes(random.randint(64, 256)))
                elif frame_type == GOAWAY:  # 7
                    # GOAWAY
                    # no more new stream
                    # make no sense when client sending this...
                    self._gone = True
                elif frame_type == WINDOW_UPDATE:  # 8
                    if frame_flags == 1:
                        self._stream_context[stream_id].resume_reading.clear()
                    else:
                        self._stream_context[stream_id].resume_reading.set()
                elif frame_type == UDP_ASSOCIATE:  # 20
                    if stream_id == 0:
                        self.send_frame(UDP_ASSOCIATE, OPEN, 0, bytes(random.randint(64, 256)))
                    elif stream_id == self._next_stream_id:
                        self._next_stream_id += 1
                        # get a udp relay
                        self._stream_writer[stream_id] = UDPRelay(self, stream_id, 300, 0)
                        self._stream_context[stream_id] = ForwardContext('udp', self.logger)
            except Exception as err:
                self.logger.error('read from connection error: %r', err)
                self.logger.error(traceback.format_exc())
                break
        self._connection_lost = True
        # exit loop, close all streams...
        self.logger.info('recv from hxs2 connect ended')

        task_list = []
        for stream_id in self._stream_writer:
            self._stream_context[stream_id].stream_status = CLOSED
            if not self._stream_writer[stream_id].is_closing():
                self._stream_writer[stream_id].close()
                if stream_id in self._stream_writer:
                    task_list.append(self._stream_writer[stream_id])

        self._stream_writer = {}
        task_list = [asyncio.create_task(w.wait_closed()) for w in task_list]
        if task_list:
            await asyncio.wait(task_list)

    async def create_connection(self, stream_id, host, port):
        self.logger.info('connecting %s:%s %s %s', host, port, self.user, self._client_address)
        timelog = time.monotonic()

        try:
            self.user_mgr.user_access_ctrl(self._s_port, host, self._client_address, self.user)
            reader, writer = await open_connection(host, port, self._proxy, self._tcp_nodelay)
            writer.transport.set_write_buffer_limits(REMOTE_WRITE_BUFFER)
        except (ConnectionError, asyncio.TimeoutError, socket.gaierror) as err:
            # tell client request failed.
            self.logger.error('connect %s:%s failed: %r', host, port, err)
            data = b'\x01' * random.randint(64, 256)
            self.send_frame(RST_STREAM, 0, stream_id, data)
        else:
            # tell client request success, header frame, first byte is \x00
            timelog = time.monotonic() - timelog
            if timelog > 1:
                self.logger.info('connect %s:%s connected, %.3fs', host, port, timelog)
            # client may reset the connection
            # TODO: maybe keep this connection for later?
            if stream_id in self._stream_context and \
                    self._stream_context[stream_id].stream_status == CLOSED:
                writer.close()
                return
            data = bytes(random.randint(64, 256))
            # registor stream
            self._stream_writer[stream_id] = writer
            self._stream_context[stream_id] = ForwardContext(host, self.logger)
            # start forward from remote_reader to client_writer
            self.send_frame(HEADERS, OPEN, stream_id, data)
            task = asyncio.ensure_future(self.read_from_remote(stream_id, reader))
            self._stream_task[stream_id] = task

    def send_frame(self, type_, flags, stream_id, payload):
        self.logger.debug('send frame_type: %d, stream_id: %d', type_, stream_id)
        if self._connection_lost:
            return
        if type_ in (DATA, HEADERS):
            self._last_active = time.monotonic()

        header = struct.pack('>BBH', type_, flags, stream_id)
        data = header + payload
        ct = self.__cipher.encrypt(data)
        self._client_writer.write(struct.pack('>H', len(ct)) + ct)

    def send_one_data_frame(self, stream_id, data):
        payload = struct.pack('>H', len(data)) + data
        diff = self.bufsize - len(data)
        payload += bytes(random.randint(min(diff, 8), min(diff, 255)))
        self.send_frame(DATA, 0, stream_id, payload)

    async def send_data_frame(self, stream_id, data):
        self._stream_context[stream_id].data_sent(len(data))
        if isinstance(self._stream_writer[stream_id], UDPRelay):
            self.send_one_data_frame(stream_id, data)
        elif len(data) > 16386 and random.random() < 0.1:
            data = io.BytesIO(data)
            data_ = data.read(random.randint(256, 16386 - 22))
            while data_:
                self.send_one_data_frame(stream_id, data_)
                if random.random() < 0.2:
                    self.send_frame(PING, 0, 0, bytes(random.randint(256, 1024)))
                data_ = data.read(random.randint(256, 8192 - 22))
                await asyncio.sleep(0)
        else:
            self.send_one_data_frame(stream_id, data)
        async with self._client_writer_lock:
            try:
                await self._client_writer.drain()
            except ConnectionError:
                self._connection_lost = True

    on_remote_recv = send_data_frame

    async def read_from_remote(self, stream_id, remote_reader):
        self.logger.debug('start read from stream')
        while True:
            await self._stream_context[stream_id].resume_reading.wait()
            fut = remote_reader.read(self.bufsize)
            try:
                data = await asyncio.wait_for(fut, timeout=6)
            except OSError:
                await self.close_stream(stream_id)
                break
            except asyncio.TimeoutError:
                if time.monotonic() - self._stream_context[stream_id].last_active < self.timeout and \
                        self._stream_context[stream_id].stream_status == OPEN:
                    continue
                data = b''

            if not data:
                self.send_frame(HEADERS, END_STREAM_FLAG, stream_id,
                                bytes(random.randint(8, 256)))
                self._stream_context[stream_id].stream_status |= EOF_SENT
                if self._stream_context[stream_id].stream_status == CLOSED:
                    await self.close_stream(stream_id)
                break
            if self._stream_context[stream_id].stream_status & EOF_SENT:
                break
            if self._stream_context[stream_id].is_heavy():
                await asyncio.sleep(0)
            await self.send_data_frame(stream_id, data)

        self.logger.debug('sid %s read_from_remote end. status %s',
                          stream_id,
                          self._stream_context[stream_id].stream_status)

        while time.monotonic() - self._stream_context[stream_id].last_active < 12:
            await asyncio.sleep(6)
        await self.close_stream(stream_id)

    def log_access(self, stream_id):
        traffic = (self._stream_context[stream_id].traffic_from_client,
                   self._stream_context[stream_id].traffic_from_remote)
        self.user_mgr.user_access_log(self._s_port,
                                      self._stream_context[stream_id].host,
                                      traffic,
                                      self._client_address,
                                      self.user)

    async def close_stream(self, stream_id):
        if not self._stream_context[stream_id].resume_reading.is_set():
            self._stream_context[stream_id].resume_reading.set()
        if self._stream_context[stream_id].stream_status != CLOSED:
            self.send_frame(RST_STREAM, 0, stream_id, bytes(random.randint(64, 256)))
            self._stream_context[stream_id].stream_status = CLOSED
        if stream_id in self._stream_writer:
            writer = self._stream_writer[stream_id]
            del self._stream_writer[stream_id]
            self.log_access(stream_id)
            try:
                if not writer.is_closing():
                    writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    def close_relay(self, stream_id):
        if self._stream_context[stream_id].stream_status == OPEN:
            self._stream_context[stream_id].stream_status = CLOSED
            self.send_frame(RST_STREAM, 0, stream_id, bytes(random.randint(64, 256)))
        if stream_id in self._stream_writer:
            del self._stream_writer[stream_id]

    async def stream_writer_drain(self, stream_id):
        if self._settings_async_drain:
            asyncio.ensure_future(self.async_drain(stream_id))
        else:
            await self._stream_writer[stream_id].drain()

    async def async_drain(self, stream_id):
        if isinstance(self._stream_writer[stream_id], UDPRelay):
            return
        wbuffer_size = self._stream_writer[stream_id].transport.get_write_buffer_size()
        if wbuffer_size <= REMOTE_WRITE_BUFFER:
            return
        if wbuffer_size > REMOTE_WRITE_BUFFER * 16:
            self.logger.error('wbuffer_size > REMOTE_WRITE_BUFFER * 16')

        with self._stream_context[stream_id].drain_lock:
            try:
                # tell client to stop reading
                self.send_frame(WINDOW_UPDATE, 1, stream_id, bytes(random.randint(64, 256)))
                await self._stream_writer[stream_id].drain()
                # tell client to resume reading
                self.send_frame(WINDOW_UPDATE, 0, stream_id, bytes(random.randint(64, 256)))
            except OSError:
                await self.close_stream(stream_id)
                return

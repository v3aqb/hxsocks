'''
hxsocks3.py

A not encrypted version of hxsocks2, works on websocket.

'''
import io
import hashlib
import logging
import random
import struct
import socket
import time
import traceback
import urllib.parse

import asyncio

import websockets.server
from websockets.exceptions import ConnectionClosed

from hxcrypto import InvalidTag, AEncryptor
from hxcrypto.encrypt import EncryptorStream
from hxsocks.util import open_connection, parse_hostport
from hxsocks.hxs2_conn import ForwardContext, HXS2_METHOD
from hxsocks.udp_relay import UDPRelay


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


class hxs3_server:
    def __init__(self, server, user_mgr, log_level, timeout=120):
        parse = urllib.parse.urlparse(server)
        query = urllib.parse.parse_qs(parse.query)
        self.address = parse_hostport(parse.netloc)
        self.user_mgr = user_mgr
        self.logger = logging.getLogger('hxs3_%d' % self.address[1])
        self.logger.setLevel(log_level)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)
        self.proxy = query.get('proxy', [''])[0]
        self.timeout = timeout

        self.handller_class = hxs3_handler
        self.server = None

    def start_service(self):
        self.logger.info('starting hxs3 server at %r', self.address)
        asyncio.ensure_future(websockets.server.serve(self.handle,
                                                      host=self.address[0],
                                                      port=self.address[1],
                                                      ping_interval=None,
                                                      read_limit=2 ** 18,
                                                      write_limit=2 ** 18,
                                                      ))

    async def handle(self, websocket, path):
        handler = self.handller_class(self)
        await handler.handle(websocket, path)


class hxs3_handler:
    bufsize = 65535 - 22

    def __init__(self, server):
        self.logger = server.logger
        self.user_mgr = server.user_mgr
        self.address = server.address
        self.server_addr = server.address
        self._proxy = server.proxy
        self.websocket = None
        self.client_address = None
        self._connection_lost = False
        self.__cipher = None
        self.__skey = None
        self._mode = 0
        self.user = None

        self.timeout = server.timeout
        self._init_time = time.monotonic()
        self._last_active = self._init_time
        self._gone = False
        self._next_stream_id = 1
        self._settings_async_drain = False

        self._stream_writer = {}
        self._stream_task = {}
        self._stream_context = {}

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
            client, reply, self.__skey = self.user_mgr.hxs2_auth(client_pkey, client_auth)
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
            except OSError:
                return

    async def handle_connection(self):
        self.logger.debug('start recieving frames...')
        timeout_count = 0

        while not self._connection_lost:
            try:
                if self._gone and not self._stream_writer:
                    break

                if time.monotonic() - self._last_active > self.timeout * 2:
                    break

                try:
                    fut = self.websocket.recv()
                    # chunk size shoule be smaller than 32kB
                    frame_data = await asyncio.wait_for(fut, timeout=6)
                    frame_data = self.decrypt_frame(frame_data)
                    timeout_count = 0
                except (ValueError, InvalidTag,
                        ConnectionError, ConnectionClosed) as err:
                    self.logger.debug('read frame_len error: %r', err)
                    break
                except asyncio.TimeoutError:
                    timeout_count += 1
                    if timeout_count > 10:
                        # client should sent ping to keep_alive
                        self.logger.debug('read frame_len timed out.')
                        break
                    continue

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
                            await self._stream_writer[stream_id].send_raw(data)
                        else:
                            self._stream_writer[stream_id].write(data)
                            await self.stream_writer_drain(stream_id)
                        self._stream_context[stream_id].data_recv(len(data))
                    except ConnectionError:
                        # remote closed, reset stream
                        self.logger.info('close_stream %d', stream_id)
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
                        await self.send_frame(SETTINGS, 0, 1, bytes(random.randint(64, 256)))
                elif frame_type == PING:  # 6
                    if frame_flags == 0:
                        await self.send_frame(PING, PONG, 0, bytes(random.randint(64, 256)))
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
                        await self.send_frame(UDP_ASSOCIATE, OPEN, 0, bytes(random.randint(64, 256)))
                    elif stream_id == self._next_stream_id:
                        self._next_stream_id += 1
                        # get a udp relay
                        relay = UDPRelay(self, self.user, stream_id, 300, 0)
                        await relay.bind()
                        self._stream_writer[stream_id] = relay
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
        return self._next_stream_id == 1

    async def create_connection(self, stream_id, host, port):
        self.logger.info('connecting %s:%s %s %s', host, port, self.user, self.client_address)
        timelog = time.monotonic()

        try:
            self.user_mgr.user_access_ctrl(self.address[1], host, self.client_address, self.user)
            reader, writer = await open_connection(host, port, self._proxy, True)
            writer.transport.set_write_buffer_limits(REMOTE_WRITE_BUFFER)
        except (OSError, asyncio.TimeoutError, socket.gaierror) as err:
            # tell client request failed.
            self.logger.error('connect %s:%s failed: %r', host, port, err)
            data = b'\x01' * random.randint(64, 256)
            await self.send_frame(RST_STREAM, 0, stream_id, data)
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
            await self.send_frame(HEADERS, OPEN, stream_id, data)
            task = asyncio.ensure_future(self.read_from_remote(stream_id, reader))
            self._stream_task[stream_id] = task

    def decrypt_frame(self, frame_data):
        if self.__cipher:
            frame_data = self.__cipher.decrypt(frame_data)
        else:
            error = None
            if self._mode == 1:
                self.bufsize += 16
                self.__cipher = EncryptorStream(self.__skey, 'rc4-md5', check_iv=False)
                self.__skey = None
                frame_data = self.__cipher.decrypt(frame_data)
                return frame_data
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
        return frame_data

    async def send_frame(self, type_, flags, stream_id, payload):
        self.logger.debug('send frame_type: %d, stream_id: %d', type_, stream_id)
        if self._connection_lost:
            return
        if type_ in (DATA, HEADERS):
            self._last_active = time.monotonic()

        header = struct.pack('>BBH', type_, flags, stream_id)
        data = header + payload
        ct_ = self.__cipher.encrypt(data)
        try:
            await self.websocket.send(ct_)
        except ConnectionClosed:
            self._connection_lost = True

    async def send_one_data_frame(self, stream_id, data):
        payload = struct.pack('>H', len(data)) + data
        diff = self.bufsize - len(data)
        payload += bytes(random.randint(min(diff, 8), min(diff, 255)))
        await self.send_frame(DATA, 0, stream_id, payload)

    async def send_data_frame(self, stream_id, data):
        self._stream_context[stream_id].data_sent(len(data))
        if isinstance(self._stream_writer[stream_id], UDPRelay):
            await self.send_one_data_frame(stream_id, data)
        elif len(data) > 16386 and random.random() < 0.1:
            data = io.BytesIO(data)
            data_ = data.read(random.randint(256, 16386 - 22))
            while data_:
                await self.send_one_data_frame(stream_id, data_)
                if random.random() < 0.2:
                    await self.send_frame(PING, 0, 0, bytes(random.randint(256, 1024)))
                data_ = data.read(random.randint(256, 8192 - 22))
                await asyncio.sleep(0)
        else:
            await self.send_one_data_frame(stream_id, data)

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
                await self.send_frame(HEADERS, END_STREAM_FLAG, stream_id,
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
        self.user_mgr.user_access_log(self.address[1],
                                      self._stream_context[stream_id].host,
                                      traffic,
                                      self.client_address,
                                      self.user)

    async def close_stream(self, stream_id):
        if not self._stream_context[stream_id].resume_reading.is_set():
            self._stream_context[stream_id].resume_reading.set()
        if self._stream_context[stream_id].stream_status != CLOSED:
            await self.send_frame(RST_STREAM, 0, stream_id, bytes(random.randint(64, 256)))
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
            asyncio.ensure_future(self.send_frame(RST_STREAM, 0, stream_id, bytes(random.randint(64, 256))))
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
                await self.send_frame(WINDOW_UPDATE, 1, stream_id, bytes(random.randint(64, 256)))
                await self._stream_writer[stream_id].drain()
                # tell client to resume reading
                await self.send_frame(WINDOW_UPDATE, 0, stream_id, bytes(random.randint(64, 256)))
            except OSError:
                await self.close_stream(stream_id)
                return

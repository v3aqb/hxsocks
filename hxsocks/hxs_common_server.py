
import io
import time
import random
import socket
import struct
import asyncio

from hxcrypto import InvalidTag, AEncryptor
from hxcrypto.encrypt import EncryptorStream
from hxsocks.util import open_connection
from hxsocks.hxs_udp_relay import HxsUDPRelayManager, parse_dgram2

CTX = 'hxsocks2'

OPEN = 0
EOF_SENT = 1  # SENT END_STREAM
EOF_RECV = 2  # RECV END_STREAM
CLOSED = 3

HANDSHAKE_SIZE = 512
_HEADER_SIZE = 512
CLIENT_WRITE_BUFFER = 262144
REMOTE_WRITE_BUFFER = 262144
READ_AUTH_TIMEOUT = 12
READ_FRAME_TIMEOUT = 8
_PING_SIZE = 128
_PONG_SIZE = 512
_PONG_FREQ = 0.3
_FRAME_SIZE_LIMIT = 16386
_FRAME_SPLIT_FREQ = 0.3
_STREAM_TIMEOUT = 60

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
UDP_DGRAM2 = 21

PONG = 1
END_STREAM_FLAG = 1

HXS2_METHOD = [
    'chacha20-ietf-poly1305',
    'aes-128-gcm',
    'aes-256-gcm',
]


class ForwardContext:
    def __init__(self, host, logger):
        self.host = host  # (host, port)
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


class ReadFrameError(Exception):
    def __init__(self, err):
        super().__init__()
        self.err = err


class HxsCommon:
    bufsize = 65535 - 22
    HEADER_SIZE = _HEADER_SIZE
    PING_SIZE = _PING_SIZE
    PONG_SIZE = _PONG_SIZE
    PONG_FREQ = _PONG_FREQ
    FRAME_SIZE_LIMIT = _FRAME_SIZE_LIMIT
    FRAME_SPLIT_FREQ = _FRAME_SPLIT_FREQ
    STREAM_TIMEOUT = _STREAM_TIMEOUT

    def __init__(self):
        self._mode = 0
        self._skey = b''
        self._cipher = None
        self.logger = None

        self._proxy = None
        self.settings = None
        self._settings_async_drain = False

        self.user_mgr = None
        self.server_addr = None
        self.client_address = None
        self.user = ''
        self.udp_uid = ''
        self.client_id = ''

        self._init_time = time.monotonic()
        self._last_active = self._init_time
        self._gone = False
        self._next_stream_id = 1
        self._connection_lost = False

        self._stream_writer = {}
        self._stream_task = {}
        self._stream_context = {}

    def decrypt_frame(self, frame_data):
        if self._cipher:
            frame_data = self._cipher.decrypt(frame_data)
        else:
            error = None
            if self._mode == 1:
                self.bufsize += 16
                self._cipher = EncryptorStream(self._skey, 'rc4-md5', check_iv=False)
                self._skey = None
                frame_data = self._cipher.decrypt(frame_data)
                return frame_data
            for method in HXS2_METHOD:
                try:
                    cipher = AEncryptor(self._skey, method, CTX, check_iv=False)
                    frame_data = cipher.decrypt(frame_data)
                    self._cipher = cipher
                    self._skey = None
                    break
                except InvalidTag as err:
                    error = err
                    continue
            else:
                self.logger.error('skey: %r', self._skey)
                raise error
        return frame_data

    async def handle_connection(self):
        self.logger.debug('start recieving frames...')
        HxsUDPRelayManager.config(self.settings)

        self.udp_uid = '%s:%s' % (self.client_address[0], self.user)
        while not self._connection_lost:
            try:
                if self._gone and not self._stream_writer:
                    break

                try:
                    frame_data = await self.read_frame(timeout=30)
                except ReadFrameError as err:
                    # destroy connection
                    self.logger.error('read frame error: %r', err.err)
                    break
                except asyncio.TimeoutError:
                    if self._stream_writer:
                        self.logger.debug('TimeoutError, active stream exist, continue')
                        continue
                    if time.monotonic() - self._last_active > self.settings.tcp_idle_timeout:
                        self.logger.info('connection idle.')
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

                if frame_type in (DATA, HEADERS, RST_STREAM, UDP_DGRAM2):
                    self._last_active = time.monotonic()
                    if random.random() < self.PONG_FREQ:
                        await self.send_pong()

                self.logger.debug('recv frame_type: %d, stream_id: %d', frame_type, stream_id)
                if frame_type == DATA:  # 0
                    # check if remote socket writable
                    if self._stream_context[stream_id].stream_status & EOF_RECV:
                        self.logger.warning('data recv while stream closed. sid %d', stream_id)
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
                        self._stream_writer[stream_id].write(data)
                        await self.stream_writer_drain(stream_id)
                        self._stream_context[stream_id].data_recv(len(data))
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

                    elif stream_id in self._stream_writer:
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
                        self.logger.error('frame_type == HEADERS, stream_id %s, flags: %s', stream_id, frame_flags)
                elif frame_type == RST_STREAM:  # 3
                    asyncio.ensure_future(self.close_stream(stream_id))
                elif frame_type == SETTINGS:
                    if stream_id == 1:
                        self._settings_async_drain = True
                        await self.send_frame(SETTINGS, 0, 1)
                elif frame_type == PING:  # 6
                    if frame_flags == 0:
                        await self.send_pong(stream_id=stream_id)
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
                elif frame_type == UDP_DGRAM2:  # 21
                    client_id, udp_sid, data = parse_dgram2(frame_data)
                    if not self.client_id:
                        self.client_id = client_id
                    await HxsUDPRelayManager.send_dgram(udp_sid, data, self)
            except Exception as err:
                self.logger.error('read from connection error: %r', err, exc_info=True)
                break
        self._connection_lost = True
        # exit loop, close all streams...
        self.logger.info('recv from hxsocks connect ended')

        HxsUDPRelayManager.conn_lost(self)
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
        self._stream_context[stream_id] = ForwardContext(host, self.logger)
        try:
            self.user_mgr.user_access_ctrl(self.server_addr[1], (host, port), self.client_address, self.user, 0)
            reader, writer = await open_connection(host, port, self._proxy,
                                                   self.settings)
            writer.transport.set_write_buffer_limits(REMOTE_WRITE_BUFFER)
        except (OSError, asyncio.TimeoutError, socket.gaierror) as err:
            # tell client request failed.
            self.logger.error('connect %s:%s failed: %r, proxy %r', host, port, err, self._proxy)
            data = b'\x01' * random.randint(self.HEADER_SIZE // 4, self.HEADER_SIZE)
            await self.send_frame(RST_STREAM, 0, stream_id, data)
        else:
            # tell client request success, header frame, first byte is \x00
            timelog = time.monotonic() - timelog
            if timelog > 1:
                self.logger.warning('connect %s:%s connected, %.3fs', host, port, timelog)
            # client may reset the connection
            # TODO: maybe keep this connection for later?
            if self._stream_context[stream_id].stream_status == CLOSED:
                self.logger.warning('connect %s:%s connected, client closed', host, port)
                writer.close()
                await writer.wait_closed()
                return
            # registor stream
            self._stream_writer[stream_id] = writer
            # start forward from remote_reader to client_writer
            await self.send_frame(HEADERS, OPEN, stream_id)
            task = asyncio.ensure_future(self.read_from_remote(stream_id, reader))
            self._stream_task[stream_id] = task

    async def send_frame(self, type_, flags, stream_id, payload=None):
        self.logger.debug('send frame_type: %d, stream_id: %d', type_, stream_id)
        if self._connection_lost:
            self.logger.debug('send_frame, connection lost')
            return
        if type_ in (DATA, HEADERS, UDP_DGRAM2):
            self._last_active = time.monotonic()
        if not payload:
            payload = bytes(random.randint(self.HEADER_SIZE // 4, self.HEADER_SIZE))

        header = struct.pack('>BBH', type_, flags, stream_id)
        data = header + payload
        ct_ = self._cipher.encrypt(data)

        await self._send_frame(ct_)

    async def send_one_data_frame(self, stream_id, data, more_padding=False):
        payload = struct.pack('>H', len(data)) + data
        diff = self.FRAME_SIZE_LIMIT - len(data)
        if 0 <= diff < self.FRAME_SIZE_LIMIT * 0.05:
            padding = bytes(diff)
        elif self.bufsize - len(data) < 255:
            padding = bytes(self.bufsize - len(data))
        else:
            diff = 1024 - len(data)
            if diff > 0 and more_padding:
                padding_len = random.randint(max(diff - 100, 0), diff + 512)
            else:
                padding_len = random.randint(8, 255)
            padding = bytes(padding_len)
        payload += padding
        await self.send_frame(DATA, 0, stream_id, payload)

    async def send_data_frame(self, stream_id, data, more_padding=False):
        self._stream_context[stream_id].data_sent(len(data))
        if not isinstance(self._stream_writer[stream_id], asyncio.StreamWriter):
            await self.send_one_data_frame(stream_id, data)
            return
        if len(data) > self.FRAME_SIZE_LIMIT and random.random() < self.FRAME_SPLIT_FREQ:
            data = io.BytesIO(data)
            data_ = data.read(random.randint(64, self.FRAME_SIZE_LIMIT))
            while data_:
                await self.send_one_data_frame(stream_id, data_)
                data_ = data.read(random.randint(64, self.FRAME_SIZE_LIMIT))
                await asyncio.sleep(0)
        else:
            await self.send_one_data_frame(stream_id, data, more_padding)

    async def send_pong(self, stream_id=0, size=None):
        if not size:
            size = self.PONG_SIZE
        await self.send_frame(PING, PONG, stream_id, bytes(random.randint(size // 4, size)))

    async def send_ping(self, stream_id=0, size=None):
        if not size:
            size = self.PING_SIZE
        await self.send_frame(PING, 0, stream_id, bytes(random.randint(size // 4, size)))

    async def on_remote_recv(self, stream_id, data):
        await self.send_data_frame(stream_id, data)

    async def read_from_remote(self, stream_id, remote_reader):
        self.logger.debug('start read from stream')
        count = 0
        while True:
            await self._stream_context[stream_id].resume_reading.wait()
            fut = remote_reader.read(self.bufsize)
            try:
                data = await asyncio.wait_for(fut, timeout=6)
            except OSError:
                await self.close_stream(stream_id)
                break
            except asyncio.TimeoutError:
                time_since_lastactive = time.monotonic() - self._stream_context[stream_id].last_active
                if time_since_lastactive < self.STREAM_TIMEOUT:
                    continue
                if self._stream_context[stream_id].stream_status == OPEN and \
                        time_since_lastactive < self.settings.tcp_idle_timeout:
                    continue
                await self.close_stream(stream_id)
                break

            if not data:
                await self.send_frame(HEADERS, END_STREAM_FLAG, stream_id)
                self._stream_context[stream_id].stream_status |= EOF_SENT
                if self._stream_context[stream_id].stream_status == CLOSED:
                    await self.close_stream(stream_id)
                break
            if self._stream_context[stream_id].stream_status & EOF_SENT:
                break
            if self._stream_context[stream_id].is_heavy():
                await asyncio.sleep(0)
            if count < 3:
                await self.send_data_frame(stream_id, data, more_padding=True)
                count += 1
            else:
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
        self.user_mgr.user_access_log(self.server_addr[1],
                                      self._stream_context[stream_id].host,
                                      traffic,
                                      self.client_address,
                                      self.user,
                                      0)

    async def close_stream(self, stream_id):
        if not self._stream_context[stream_id].resume_reading.is_set():
            self._stream_context[stream_id].resume_reading.set()
        if self._stream_context[stream_id].stream_status != CLOSED:
            await self.send_frame(RST_STREAM, 0, stream_id)
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
            asyncio.ensure_future(self.send_frame(RST_STREAM, 0, stream_id))
        if stream_id in self._stream_writer:
            del self._stream_writer[stream_id]

    async def stream_writer_drain(self, stream_id):
        if self._settings_async_drain:
            asyncio.ensure_future(self.async_drain(stream_id))
        else:
            await self._stream_writer[stream_id].drain()

    async def async_drain(self, stream_id):
        if not isinstance(self._stream_writer[stream_id], asyncio.StreamWriter):
            return
        wbuffer_size = self._stream_writer[stream_id].transport.get_write_buffer_size()
        if wbuffer_size <= REMOTE_WRITE_BUFFER:
            return
        if wbuffer_size > REMOTE_WRITE_BUFFER * 16:
            self.logger.error('wbuffer_size > REMOTE_WRITE_BUFFER * 16')

        async with self._stream_context[stream_id].drain_lock:
            try:
                # tell client to stop reading
                await self.send_frame(WINDOW_UPDATE, 1, stream_id)
                await self._stream_writer[stream_id].drain()
                # tell client to resume reading
                await self.send_frame(WINDOW_UPDATE, 0, stream_id)
            except OSError:
                await self.close_stream(stream_id)
                return

    async def send_dgram2(self, client_id, udp_sid, data):
        # remote addr included in data, as shadowsocks format
        payload = client_id + udp_sid
        payload += struct.pack(b'!H', len(data))
        payload += data
        payload += bytes(random.randint(self.PING_SIZE // 4, self.PING_SIZE))
        await self.send_frame(UDP_DGRAM2, 0, 0, payload)

    async def _send_frame(self, ct_):
        raise NotImplementedError

    async def read_frame(self, timeout):
        raise NotImplementedError

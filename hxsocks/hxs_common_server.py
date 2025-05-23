
import io
import time
import random
import socket
import struct
import asyncio

from hxcrypto import InvalidTag, AEncryptor
from hxcrypto.encrypt import EncryptorStream
from hxsocks.util import create_connection
from hxsocks.hxs_udp_relay import HxsUDPRelayManager, parse_dgram2

CTX = 'hxsocks2'

OPEN = 0
EOF_FROM_ENDPOINT = 1
EOF_FROM_CONN = 2
CLOSED = 3

HANDSHAKE_SIZE = 256
CLIENT_WRITE_BUFFER = 131072
REMOTE_WRITE_BUFFER = 131072
READ_AUTH_TIMEOUT = 12
READ_FRAME_TIMEOUT = 8
RECV_WINDOW_SIZE = 2 ** 31 - 1

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
FLOW_CONTROL = 128

HXS2_METHOD = [
    'chacha20-ietf-poly1305',
    'aes-128-gcm',
    'aes-256-gcm',
]


class HxsStreamContext(asyncio.Protocol):
    def __init__(self, conn, stream_id, host):
        self._conn = conn
        self._stream_id = stream_id
        self.host = host  # (host, port)

        self.last_active = time.monotonic()
        self.drain_lock = asyncio.Lock()

        # eof recieved
        self.stream_status = OPEN
        self._from_endpoint_count = 0

        self._recv_buffer = bytearray()
        self._send_buffer = bytearray()
        self._writing = False
        self._eof_pending = False
        self._closing = False
        self._reading = asyncio.Event()  # reading form conn, write to endpoint
        self._reading.set()
        self._transport = None
        self._connected = False
        self._connection_lost = False

    def connection_made(self, transport):
        self._transport = transport
        self._connection_made()

    def _connection_made(self):
        self._connected = True
        if self._send_buffer:
            data = bytes(self._send_buffer)
            self._send_buffer.clear()
            self.write(data)
            self._send_buffer = None

    def connection_lost(self, _):
        self._connection_lost = True
        self.close()

    def pause_writing(self):
        self._reading.clear()

    def resume_writing(self):
        self._reading.set()

    def data_received(self, data):
        '''data recieved from endpoint, send to connection'''
        if self.stream_status & EOF_FROM_ENDPOINT:
            return
        self._from_endpoint_count += 1
        self._recv_buffer.extend(data)
        if len(self._recv_buffer) > self._conn.bufsize * 2:
            self._transport.pause_reading()
        asyncio.ensure_future(self._maybe_start_writing())

    async def _maybe_start_writing(self):
        if self._writing:
            return
        self._writing = True
        while self._recv_buffer:
            # write buffer to conn
            more_padding = self._from_endpoint_count < self._conn.MORE_PADDING_COUNT
            data_len = len(self._recv_buffer)
            frame_size_limit = self._conn.MORE_PADDING_SIZE if more_padding else self._conn.FRAME_SPLIT_LIMIT
            if data_len > frame_size_limit and (more_padding or random.random() < self._conn.FRAME_SPLIT_FREQ):
                data = self._buf_read(random.randint(64, frame_size_limit))
                await self.send_one_data_frame(data, more_padding, frag=len(data) < data_len)
                await asyncio.sleep(0.01)
            else:
                data = self._buf_read()
                await self.send_one_data_frame(data, more_padding)
        if self._eof_pending:
            self._eof_received()
        if self._closing:
            self._close()
        # after self._recv_buffer is empty
        self._writing = False
        self._transport.resume_reading()

    def _buf_read(self, n=None):
        if not n:
            n = self._conn.bufsize
        if len(self._recv_buffer) <= n:
            data = bytes(self._recv_buffer)
            self._recv_buffer.clear()
        else:
            data = bytes(self._recv_buffer[:n])
            del self._recv_buffer[:n]
        return data

    async def send_one_data_frame(self, data, more_padding, frag=False):
        if self.stream_status & EOF_FROM_ENDPOINT:
            return
        await self._conn.acquire(len(data))
        self._conn.send_one_data_frame(self._stream_id, data, more_padding, frag=frag)

    def get_write_buffer_size(self):
        return len(self._recv_buffer)

    def eof_received(self):
        if self._recv_buffer:
            self._eof_pending = True
            return not self.stream_status & EOF_FROM_CONN
        self._eof_received()
        return not self.stream_status & EOF_FROM_CONN

    def _eof_received(self):
        if not self.stream_status & EOF_FROM_ENDPOINT:
            self.stream_status |= EOF_FROM_ENDPOINT
            self._conn.send_frame(HEADERS, END_STREAM_FLAG, self._stream_id)
        if self.stream_status == CLOSED:
            self._conn.close_stream(self._stream_id)

    def close(self):
        if self._closing:
            return
        self._closing = True
        if self._recv_buffer:
            return
        self._close()

    def _close(self):
        if self.stream_status != CLOSED:
            self._conn.send_frame(RST_STREAM, 0, self._stream_id)
            self.stream_status = CLOSED
        self._reading.set()
        if self._transport:
            self._transport.close()
        self._conn.close_stream(self._stream_id)

    def is_closing(self):
        return self._closing

    def write(self, data):
        if self._connection_lost:
            return
        if self._connected:
            self._transport.write(data)
        else:
            self._send_buffer.extend(data)

    def write_eof(self):
        self._transport.write_eof()

    async def drain(self):
        if self.is_closing():
            raise ConnectionResetError
        await self._reading.wait()


class HxsForwardContext(HxsStreamContext):
    def __init__(self, conn, stream_id, host, send_w, recv_w):
        super().__init__(conn, stream_id, host)

        self._fc_enable = bool(send_w)
        if send_w or stream_id == 0:
            self._monitor_task = asyncio.ensure_future(self.monitor())
        self.send_w = send_w or float('inf')
        self.recv_w = recv_w

        # traffic, for log
        self.traffic_from_endpoint = 0
        self.traffic_from_conn = 0

        # traffic, for flow control
        self.sent_rate = 0
        self.sent_rate_max = 0
        self.sent_counter = 0
        self.recv_rate = 0
        self.recv_rate_max = 0
        self.recv_counter = 0

        self._monitor_task = None

        self._lock = asyncio.Lock()
        self._window_open = asyncio.Event()  # blocked when cannot send to connection
        self._window_open.set()
        self.notify_data_recv_job = None

        self._recv_w_max = recv_w
        self._recv_w_min = recv_w
        self._recv_w_counter = 0

    async def send_one_data_frame(self, data, more_padding, frag=False):
        if self.stream_status & EOF_FROM_ENDPOINT:
            return
        await self._conn.acquire(len(data))
        await self.acquire(len(data))
        self._conn.send_one_data_frame(self._stream_id, data, more_padding, frag=frag)

    async def acquire(self, size):
        ''' called before send data to connection, or maybe after'''
        async with self._lock:
            await self._window_open.wait()
            self.traffic_from_endpoint += size
            self.sent_counter += size
            self.last_active = time.monotonic()
            self.send_w -= size
            if self.send_w <= 0:
                self._window_open.clear()

    def acquire_nowait(self, size):
        if not self._window_open.is_set():
            raise ValueError('windows not open')
        self.traffic_from_endpoint += size
        self.sent_counter += size
        self.last_active = time.monotonic()
        self.send_w -= size
        if self.send_w <= 0:
            self._window_open.clear()

    def data_recv(self, size):
        '''data recv from connection, maybe update window'''
        self.traffic_from_conn += size
        self.recv_counter += size
        self.last_active = time.monotonic()
        if self.fc_enable:
            self._recv_w_counter += size
            # update window later
            if self._recv_w_counter > self.recv_w // 4:
                self.notify_data_recv()
            else:
                if not self.notify_data_recv_job:
                    loop = asyncio.get_event_loop()
                    self.notify_data_recv_job = loop.call_later(0.2, self.notify_data_recv, (True, ))

    def notify_data_recv(self, sched=False):
        if not sched and self.notify_data_recv_job:
            self.notify_data_recv_job.cancel()
        w_counter = self._recv_w_counter
        self._recv_w_counter = 0
        payload = struct.pack('>I', w_counter)
        payload += bytes(random.randint(self._conn.HEADER_SIZE // 4 - 4, self._conn.HEADER_SIZE - 4))
        self._conn.send_frame(WINDOW_UPDATE, 0, self._stream_id, payload)
        self.notify_data_recv_job = None

    def enable_fc(self, send_w, recv_w):
        if self.fc_enable:
            raise ValueError('fc already enabled')
        self._fc_enable = bool(send_w)
        self.send_w = send_w
        self.recv_w = recv_w
        self._recv_w_max = recv_w
        self._recv_w_min = recv_w
        if not self._monitor_task:
            self._monitor_task = asyncio.ensure_future(self.monitor())

    @property
    def fc_enable(self):
        return self._fc_enable

    def new_recv_window(self, new_window):
        # change recv window
        new_window = int(new_window)
        new_window = max(new_window, self._conn.WINDOW_SIZE[0])
        new_window = min(new_window, self._conn.WINDOW_SIZE[2])
        old_size = self.recv_w
        self.recv_w = new_window
        self._recv_w_counter += new_window - old_size
        if self._recv_w_counter > self.recv_w // 2:
            w_counter = self._recv_w_counter
            self._recv_w_counter = 0
            payload = struct.pack('>I', w_counter)
            payload += bytes(random.randint(self._conn.HEADER_SIZE // 4 - 4, self._conn.HEADER_SIZE - 4))
            self._conn.send_frame(WINDOW_UPDATE, 0, self._stream_id, payload)
        self._conn.logger.debug(f'{self._conn.name}: update window form {old_size} to {self.recv_w}')

    def reduce_window(self, rtt):
        if self.fc_enable:
            if self.recv_rate * rtt * 2.7 < self.recv_w:
                return
            self._recv_w_max = self.recv_w
            new_window = self.recv_rate * rtt * 1.5
            new_window = max(new_window, self.recv_w * 0.75)
            if new_window < self.recv_w:
                self.new_recv_window(new_window)

    def increase_window(self, rtt):
        if self.fc_enable:
            if self.recv_rate * rtt * 2.7 < self.recv_w:
                return
            self._recv_w_min = self.recv_w
            if self._recv_w_max > self.recv_w:
                new_window = (self.recv_w + self._recv_w_max) // 2
                new_window = max(new_window, self.recv_w + self._conn.WINDOW_SIZE[0])
                self.new_recv_window(new_window)
            else:
                new_window = self.recv_rate * rtt * 2.7
                new_window = min(new_window, self.recv_w * 1.25)
                self.new_recv_window(new_window)

    def window_update(self, size):
        if size < 0:
            self.send_w = size
            self._window_open.clear()
            return
        self.send_w += size
        if self.send_w > 0:
            self._window_open.set()

    async def monitor(self):
        while self.stream_status is OPEN:
            await asyncio.sleep(1)
            self.sent_rate_max = max(self.sent_rate_max, self.sent_counter)
            self.sent_rate = 0.2 * self.sent_counter + self.sent_rate * 0.8
            self.sent_counter = 0
            self.recv_rate_max = max(self.recv_rate_max, self.recv_counter)
            self.recv_rate = 0.2 * self.recv_counter + self.recv_rate * 0.8
            self.recv_counter = 0
            if time.monotonic() - self.last_active > self._conn.STREAM_TIMEOUT:
                self.close()

    def close(self):
        super().close()
        self.window_update(float('+inf'))


class ReadFrameError(Exception):
    def __init__(self, err):
        super().__init__()
        self.err = err


class HC:
    MAX_STREAM_ID = 32767
    MAX_CONNECTION = 2
    CLIENT_WRITE_BUFFER = 131072
    CONNECTING_LIMIT = 3
    STREAM_TIMEOUT = 60

    READ_FRAME_TIMEOUT = 8
    PING_TIMEOUT = 8
    IDLE_TIMEOUT = 300
    PING_INTV = 3
    PING_INTV_2 = 20

    CLIENT_AUTH_PADDING = 256
    HEADER_SIZE = 256
    PING_SIZE = 256
    PONG_SIZE = 256
    PONG_FREQ = 0.2
    MORE_PADDING_COUNT = 5
    MORE_PADDING_SIZE = 1024 - 22
    MORE_PADDING_RANGE = 512
    FRAME_SPLIT_FREQ = 0.3
    FRAME_SPLIT_LIMIT = 4096 - 22
    WINDOW_SIZE = (4096, 65536, 1048576 * 4)


class HxsCommon(HC):
    bufsize = 65535 - 22

    def __init__(self, mode):
        self._mode = mode
        self._skey = b''
        self._cipher = None
        self.logger = None

        self._proxy = None
        self.settings = None
        self._settings_async_drain = False

        self.user_mgr = None
        self.server_addr = None
        self.client_address = None
        self.name = None
        self.user = ''
        self.udp_uid = ''
        self.client_id = ''

        self.connection_lost = False
        self._init_time = time.monotonic()
        self._last_recv = time.monotonic()
        self._last_send = time.monotonic()
        self._last_ping = 0
        self._ping_id = 0
        self._ping_time = 0
        self._rtt = 5
        self._rtt_ewma = 0.2

        self._gone = False
        self._next_stream_id = 1
        self._connection_lost = False

        self._stream_ctx = {}
        self.monitor_task = None

    def decrypt_frame(self, frame_data):
        if self._cipher:
            frame_data = self._cipher.decrypt(frame_data)
        else:
            error = None
            if self._mode & 1:
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
                self.logger.error('unable to decrypt frame. user: %r', self.user)
                raise error
        return frame_data

    @property
    def _last_active(self):
        return max(self._last_recv, self._last_send)

    async def handle_connection(self):
        self.logger.debug('start recieving frames...')
        HxsUDPRelayManager.config(self.settings)
        self.monitor_task = asyncio.ensure_future(self.monitor())
        self._stream_ctx[0] = HxsForwardContext(self, 0, ('', 0), 0, 0)

        self.udp_uid = '%s:%s' % (self.client_address[0], self.user)
        while not self._connection_lost:
            try:
                if self._gone and not self._stream_ctx:
                    break

                try:
                    frame_data = await self.read_frame(timeout=30)
                except ReadFrameError as err:
                    # destroy connection
                    self.logger.error('read frame error: %r', err.err)
                    break
                except asyncio.TimeoutError:
                    if self._stream_ctx:
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
                header, payload = frame_data[:4], frame_data[4:]
                frame_type, frame_flags, stream_id = struct.unpack('>BBH', header)
                payload = io.BytesIO(payload)

                if frame_type in (DATA, HEADERS, RST_STREAM, UDP_DGRAM2):
                    self._last_recv = time.monotonic()

                self.logger.debug('recv frame_type: %d, stream_id: %d', frame_type, stream_id)
                if frame_type == DATA:  # 0
                    # first 2 bytes of payload indicates data_len
                    data_len, = struct.unpack('>H', payload.read(2))
                    data = payload.read(data_len)
                    self._stream_ctx[0].data_recv(len(data))

                    if len(data) != data_len:
                        # something went wrong, destory connection
                        self.logger.error('len(data) != data_len')
                        break

                    if frame_flags & 1:
                        self.send_pong()
                    elif random.random() < self.PONG_FREQ:
                        self.send_pong()

                    # sent data to stream
                    if stream_id not in self._stream_ctx or\
                            self._stream_ctx[stream_id].stream_status & EOF_FROM_CONN:
                        self.logger.warning('DATA recv Stream CLOSED, sid %d', stream_id)
                        continue

                    try:
                        self._stream_ctx[stream_id].write(data)
                        await self.stream_writer_drain(stream_id, len(data))
                    except ConnectionError:
                        # remote closed, reset stream
                        self.close_stream(stream_id)
                elif frame_type == HEADERS:  # 1
                    if self._next_stream_id == stream_id:
                        # open new stream
                        self._next_stream_id += 1

                        host_len = payload.read(1)[0]
                        host = payload.read(host_len).decode('ascii')
                        port = struct.unpack('>H', payload.read(2))[0]
                        # rest of the payload is discarded
                        send_w = 0
                        if frame_flags & FLOW_CONTROL:  # client want per stream flow control
                            send_w = struct.unpack('>I', payload.read(4))[0]
                        asyncio.ensure_future(self.create_connection(stream_id, host, port, send_w))

                    elif stream_id in self._stream_ctx:
                        self.logger.debug('sid %s END_STREAM. status %s',
                                          stream_id,
                                          self._stream_ctx[stream_id].stream_status)
                        if frame_flags & END_STREAM_FLAG:
                            self._stream_ctx[stream_id].stream_status |= EOF_FROM_CONN
                            try:
                                self._stream_ctx[stream_id].write_eof()
                            except OSError:
                                self._stream_ctx[stream_id].stream_status = CLOSED
                            if self._stream_ctx[stream_id].stream_status == CLOSED:
                                self.close_stream(stream_id)
                    else:
                        self.logger.error('frame_type == HEADERS, stream_id %s, flags: %s. stream already closed?', stream_id, frame_flags)
                elif frame_type == RST_STREAM:  # 3
                    if stream_id not in self._stream_ctx:
                        continue
                    self._stream_ctx[stream_id].stream_status = CLOSED
                    self.close_stream(stream_id)
                elif frame_type == SETTINGS:
                    settings = 0
                    payload_ = b''
                    if stream_id & 1:
                        self._settings_async_drain = True
                        settings |= 1
                    if stream_id & FLOW_CONTROL and self._next_stream_id == 1:
                        send_w = struct.unpack('>I', payload.read(4))[0]
                        if 4096 <= send_w <= 2 ** 31 - 1:
                            self._stream_ctx[0].enable_fc(send_w, self.WINDOW_SIZE[1])
                            payload_ += struct.pack('>I', self.WINDOW_SIZE[1])
                            settings |= FLOW_CONTROL
                    payload_ += bytes(random.randint(self.HEADER_SIZE // 4 - len(payload_),
                                                     self.HEADER_SIZE - len(payload_)))
                    self.send_frame(SETTINGS, 1, settings, payload_)
                elif frame_type == PING:  # 6
                    if frame_flags == 0:
                        self.send_pong(stream_id)
                    elif self._ping_time and self._ping_id == stream_id:
                        resp_time = time.monotonic() - self._ping_time
                        self._rtt_ewma = resp_time * 0.2 + self._rtt_ewma * 0.8
                        self._rtt = min(self._rtt, resp_time)
                        self._ping_time = 0
                        if max(resp_time, self._rtt_ewma) < self._rtt * 1.5:
                            self._stream_ctx[0].increase_window(self._rtt)
                        if self._rtt_ewma > self._rtt * 2.5:
                            self._stream_ctx[0].reduce_window(self._rtt)
                elif frame_type == GOAWAY:  # 7
                    # GOAWAY
                    # no more new stream
                    # make no sense when client sending this...
                    self._gone = True
                elif frame_type == WINDOW_UPDATE:  # 8
                    if not self._stream_ctx[stream_id].fc_enable:
                        self._settings_async_drain = True
                        if frame_flags == 0:
                            self._stream_ctx[stream_id].resume_writing()
                        else:
                            self._stream_ctx[stream_id].pause_writing()
                    else:
                        size = struct.unpack('>I', payload.read(4))[0]
                        self._stream_ctx[stream_id].window_update(size)
                elif frame_type == UDP_DGRAM2:  # 21
                    client_id, udp_sid, data = parse_dgram2(payload)
                    if not self.client_id:
                        self.client_id = client_id
                    self._stream_ctx[0].data_recv(len(data))
                    await HxsUDPRelayManager.send_dgram(udp_sid, data, self)
            except Exception as err:
                self.logger.error('read from connection error: %r', err, exc_info=True)
                break
        self._connection_lost = True
        # exit loop, close all streams...
        self.logger.info('recv from hxsocks connect ended')

        HxsUDPRelayManager.conn_lost(self)

        for stream_id in self._stream_ctx:
            self.close_stream(stream_id)

        await asyncio.sleep(1)
        return self._next_stream_id == 1

    async def create_connection(self, stream_id, host, port, send_w=0):
        self.logger.info('connecting %s:%s %s %s', host, port, self.user, self.client_address)
        timelog = time.monotonic()
        # DISABLE PER_STREAM FLOW CONTROL
        send_w = 0
        recv_w = RECV_WINDOW_SIZE if send_w else 0
        self._stream_ctx[stream_id] = HxsForwardContext(self, stream_id, (host, port), send_w, recv_w)
        self.name = self.server_addr[1]
        try:
            self.user_mgr.user_access_ctrl(self.server_addr[1], (host, port), self.client_address, self.user, 0)
            transport = await create_connection(self._stream_ctx[stream_id], host, port,
                                                self._proxy, self.settings)
            transport.set_write_buffer_limits(REMOTE_WRITE_BUFFER)
        except (OSError, asyncio.TimeoutError, socket.gaierror, ValueError) as err:
            # tell client request failed.
            self.logger.error('connect %s:%s failed: %r, proxy %r', host, port, err, self._proxy)
            data = b'\x01' * random.randint(self.HEADER_SIZE // 4, self.HEADER_SIZE)
            self.send_frame(RST_STREAM, 0, stream_id, data)
        else:
            # block china?
            try:
                addr = transport.get_extra_info('peername')
                self.user_mgr.user_access_ctrl(self.server_addr[1], addr, self.client_address, self.user, 0)
            except ValueError as err:
                self.logger.error('connect %s:%s failed: %r, proxy %r', host, port, err, self._proxy)
                data = b'\x01' * random.randint(self.HEADER_SIZE // 4, self.HEADER_SIZE)
                self.send_frame(RST_STREAM, 0, stream_id, data)
                transport.close()

            timelog = time.monotonic() - timelog
            if timelog > 1:
                self.logger.warning('connect %s:%s connected, %.3fs', host, port, timelog)
            # client may reset the connection
            # TODO: maybe keep this connection for later?
            if stream_id not in self._stream_ctx:
                self.logger.warning('connect %s:%s connected, client closed', host, port)
                transport.close()
                return
            # tell client request success, header frame, first byte is \x00
            flag = OPEN
            payload = b''
            if recv_w:
                flag |= FLOW_CONTROL
                payload += struct.pack('>I', recv_w)
            payload += bytes(random.randint(self.HEADER_SIZE // 4 - len(payload),
                                            self.HEADER_SIZE - len(payload)))
            self.send_frame(HEADERS, flag, stream_id, payload)

    def send_frame(self, frame_type, flags, stream_id, payload=None):
        self.logger.debug('send frame_type: %d, stream_id: %d', frame_type, stream_id)
        if self._connection_lost:
            self.logger.debug('send_frame, connection lost')
            return
        if frame_type != PING:
            self._last_send = time.monotonic()
        if frame_type == PING and flags == 0:
            self._last_ping = time.monotonic()
        if not payload:
            payload = bytes(random.randint(self.HEADER_SIZE // 4, self.HEADER_SIZE))

        header = struct.pack('>BBH', frame_type, flags, stream_id)
        ct_ = self._cipher.encrypt(header + payload)

        self._send_frame_data(ct_)

    def send_one_data_frame(self, stream_id, data, more_padding=False, frag=False):
        payload = struct.pack('>H', len(data)) + data
        diff = self.FRAME_SPLIT_LIMIT - len(data)
        if 0 <= diff < self.FRAME_SPLIT_LIMIT * 0.05:
            padding = bytes(diff)
        elif self.bufsize - len(data) < 255:
            padding = bytes(self.bufsize - len(data))
        else:
            diff = self.MORE_PADDING_SIZE - len(data)
            if diff > 0 and more_padding:
                padding_len = random.randint(max(diff - 100, 0), diff + self.MORE_PADDING_RANGE)
            else:
                padding_len = random.randint(8, 255)
            padding = bytes(padding_len)
        payload += padding
        flag = 1 if frag else 0
        self.send_frame(DATA, flag, stream_id, payload)

    def send_pong(self, stream_id=0, size=None):
        if not size:
            size = self.PONG_SIZE
        self.send_frame(PING, PONG, stream_id, bytes(random.randint(size // 4, size)))

    def send_ping(self, size=None):
        if self._ping_time:
            return
        if not size:
            size = self.PING_SIZE
        self._ping_id = random.randint(1, 32767)
        self._ping_time = time.monotonic()
        self.send_frame(PING, 0, self._ping_id, bytes(random.randint(size // 4, size)))

    def log_access(self, stream_id):
        traffic = (self._stream_ctx[stream_id].traffic_from_client,
                   self._stream_ctx[stream_id].traffic_from_remote)
        self.user_mgr.user_access_log(self.server_addr[1],
                                      self._stream_ctx[stream_id].host,
                                      traffic,
                                      self.client_address,
                                      self.user,
                                      0)
        if len(self._stream_ctx) > 50:
            self.logger.info('active stream count: %d', len(self._stream_ctx)-1)

    async def stream_writer_drain(self, stream_id, data_len):
        if self._settings_async_drain or self._stream_ctx[stream_id].fc_enable:
            asyncio.ensure_future(self.async_drain(stream_id, data_len))
        else:
            await self._stream_ctx[stream_id].drain()
            self._stream_ctx[stream_id].data_recv(data_len)

    async def async_drain(self, stream_id, data_len):
        wbuffer_size = self._stream_ctx[stream_id].get_write_buffer_size()
        if wbuffer_size <= REMOTE_WRITE_BUFFER:
            self._stream_ctx[stream_id].data_recv(data_len)
            return
        if wbuffer_size > REMOTE_WRITE_BUFFER * 16:
            self.logger.error('wbuffer_size > REMOTE_WRITE_BUFFER * 16')

        async with self._stream_ctx[stream_id].drain_lock:
            try:
                # tell client to stop reading
                if not self._stream_ctx[stream_id].fc_enable:
                    self.send_frame(WINDOW_UPDATE, 1, stream_id)
                await self._stream_ctx[stream_id].drain()
                # tell client to resume reading
                if not self._stream_ctx[stream_id].fc_enable:
                    self.send_frame(WINDOW_UPDATE, 0, stream_id)
            except OSError:
                self.close_stream(stream_id)
        self._stream_ctx[stream_id].data_recv(data_len)

    def send_dgram2(self, client_id, udp_sid, data):
        # remote addr included in data, as shadowsocks format
        try:
            self._stream_ctx[0].acquire_nowait(len(data))
        except ValueError:
            return
        payload = client_id + udp_sid
        payload += struct.pack(b'!H', len(data))
        payload += data
        payload += bytes(random.randint(self.PING_SIZE // 4, self.PING_SIZE))
        self.send_frame(UDP_DGRAM2, 0, 0, payload)

    async def acquire(self, size):
        await self.drain()
        await self._stream_ctx[0].acquire(size)

    def _send_frame_data(self, ct_):
        raise NotImplementedError

    async def drain(self):
        raise NotImplementedError

    async def read_frame(self, timeout):
        raise NotImplementedError

    async def monitor(self):
        while not self._connection_lost:
            intv = self.PING_INTV_2
            if self._stream_ctx[0].sent_counter > self.WINDOW_SIZE[0] or \
                    self._stream_ctx[0].recv_counter > self.WINDOW_SIZE[0]:
                intv = self.PING_INTV
            delay = random.normalvariate(intv, sigma=intv / 6)
            if delay < 0:
                continue
            await asyncio.sleep(delay)
            self.send_ping()

    def close_stream(self, stream_id):
        if stream_id == 0:
            return
        loop = asyncio.get_event_loop()
        loop.call_soon(self._close_stream, stream_id)

    def _close_stream(self, stream_id):
        if stream_id in self._stream_ctx:
            ctx = self._stream_ctx[stream_id]
            del self._stream_ctx[stream_id]
            ctx.close()


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

from hxcrypto import InvalidTag, AEncryptor
from .util import open_connection


CTX = b'hxsocks2'

OPEN = 0
LOCAL_CLOSED = 1   # SENT END_STREAM
REMOTE_CLOSED = 2  # RECV END_STREAM
CLOSED = 3
END_STREAM_FLAG = 1


class hxs2_connection():
    bufsize = 8192

    def __init__(self, reader, writer, key, method, proxy, logger):
        self.__cipher = AEncryptor(key, method, CTX)
        self._client_reader = reader
        self._client_writer = writer
        self._proxy = proxy
        self._logger = logger

        self._init_time = time.time()
        self._last_recv = self._init_time
        self._last_send = self._init_time
        self._gone = False
        self._next_stream_id = 1

        self._stream_writer = {}
        self._stream_status = {}
        self._remote_status = {}
        self._stream_task = {}

        self._client_writer_lock = asyncio.Lock()

    async def wait_close(self):
        self._logger.debug('start recieving frames...')
        timeout_count = 0

        while True:
            if self._gone and len(self._stream_writer) == 0:
                break

            time_ = time.time()
            if time_ - self._last_recv > 300 and time_ - self._last_send > 300:
                break

            # read frame_len
            try:
                fut = self._client_reader.readexactly(2)
                frame_len = await asyncio.wait_for(fut, timeout=10)
                frame_len, = struct.unpack('>H', frame_len)
                timeout_count = 0
            except (asyncio.IncompleteReadError, ValueError, InvalidTag) as e:
                self._logger.debug('read frame_len error: %r' % e)
                break
            except asyncio.TimeoutError:
                timeout_count += 1
                # client should sent keep_alive chunk
                if timeout_count > 10:
                    # destroy connection
                    self._logger.debug('read frame_len timed out.')
                    break
                continue
            except OSError as e:
                self._logger.debug('read frame_len error: %r' % e)
                break

            # read chunk_data
            try:
                fut = self._client_reader.readexactly(frame_len)
                # chunk size shoule be lower than 16kB
                frame_data = await asyncio.wait_for(fut, timeout=5)
                frame_data = self.__cipher.decrypt(frame_data)
            except (OSError, InvalidTag, asyncio.TimeoutError) as e:
                # something went wrong...
                self._logger.debug('read frame error: %r' % e)
                break

            # parse chunk_data
            # +------+-------------------+----------+
            # | type | flags | stream_id | payload  |
            # +------+-------------------+----------+
            # |  1   |   1   |     2     | Variable |
            # +------+-------------------+----------+

            header, payload = frame_data[:4], frame_data[4:]
            frame_type, frame_flags, stream_id = struct.unpack('>BBH', header)
            payload = io.BytesIO(payload)

            if frame_type != 6:
                self._last_recv = time.time()

            self._logger.debug('recv frame_type: %d, stream_id: %d' % (frame_type, stream_id))
            if frame_type == 0:
                # DATA
                # first 2 bytes of payload indicates data_len
                data_len, = struct.unpack('>H', payload.read(2))
                data = payload.read(data_len)
                if len(data) != data_len:
                    # something went wrong, destory connection
                    self._logger.debug('data_len mismatch')
                    break
                # check if remote socket writable
                if self._remote_status[stream_id] & LOCAL_CLOSED:
                    continue
                # sent data to stream
                try:
                    self._stream_writer[stream_id].write(data)
                    await self._stream_writer[stream_id].drain()
                except OSError:
                    # remote closed, reset stream
                    pass
            elif frame_type == 1:
                # HEADER
                if self._next_stream_id == stream_id:
                    # open new stream
                    self._next_stream_id += 1

                    host_len = payload.read(1)[0]
                    host = payload.read(host_len).decode('ascii')
                    port, = struct.unpack('>H', payload.read(2))
                    # rest of the payload is discarded
                    asyncio.ensure_future(self.create_connection(stream_id, host, port, self._proxy))

                elif stream_id < self._next_stream_id:
                    if frame_flags & END_STREAM_FLAG:
                        if self._stream_status[stream_id] == OPEN:
                            self._stream_status[stream_id] = REMOTE_CLOSED
                            self._stream_writer[stream_id].write_eof()
                            self._remote_status[stream_id] = LOCAL_CLOSED
                        elif self._stream_status[stream_id] == LOCAL_CLOSED:
                            self._stream_status[stream_id] = CLOSED
                            self._stream_writer[stream_id].close()
                            self._remote_status[stream_id] = CLOSED
                            del self._stream_writer[stream_id]
                        else:
                            # something wrong
                            pass
            elif frame_type == 3:
                # RST_STREAM
                self._stream_status[stream_id] = CLOSED
                if stream_id in self._stream_writer:
                    self._stream_writer[stream_id].close()
                    del self._stream_writer[stream_id]
                self._remote_status[stream_id] = CLOSED
            elif frame_type == 6:
                # PING
                if frame_flags == 0:
                    await self.send_frame(6, 1, 0, b'\x00' * random.randint(64, 256))
            elif frame_type == 7:
                # GOAWAY
                # no more new stream
                # make no sense when client sending this...
                self._gone = True
            elif frame_type == 8:
                # WINDOW_UPDATE
                pass
            else:
                self._logger.debug('else')
                break
        # exit loop, close all streams...
        self._logger.info('recv from hxs2 connect ended')
        for stream_id, writer in self._stream_writer.items():
            try:
                writer.close()
            except:
                pass

    async def create_connection(self, stream_id, host, port, proxy):
        self._logger.info('connecting %s:%s via %s' % (host, port, proxy))
        t = time.time()
        try:
            reader, writer = await open_connection(host, port, self._proxy)
        except Exception as e:
            # tell client request failed.
            self._logger.info('connect %s:%s failed: %r' % (host, port, e))
            data = b'\x01' * random.randint(64, 256)
            await self.send_frame(3, 0, stream_id, data)
        else:
            # tell client request success, header frame, first byte is \x00
            t = time.time() - t
            self._logger.info('connect %s:%s connected, %.3fs' % (host, port, t))
            # client may reset the connection
            # TODO: maybe keep this connection for later?
            if stream_id in self._stream_status and self._stream_status[stream_id] == CLOSED:
                writer.close()
                return
            data = b'\x00' * random.randint(64, 256)
            await self.send_frame(1, 0, stream_id, data)
            # registor stream
            self._stream_writer[stream_id] = writer
            self._stream_status[stream_id] = OPEN
            self._remote_status[stream_id] = OPEN
            # start forward from remote_reader to client_writer
            task = asyncio.ensure_future(self.read_from_stream(stream_id, reader))
            self._stream_task[stream_id] = task

    async def send_frame(self, type_, flags, stream_id, payload):
        self._logger.debug('send frame_type: %d, stream_id: %d' % (type_, stream_id))
        if type_ != 6:
            self._last_send = time.time()

        await self._client_writer_lock.acquire()
        try:
            header = struct.pack('>BBH', type_, flags, stream_id)
            data = header + payload
            ct = self.__cipher.encrypt(data)
            self._client_writer.write(struct.pack('>H', len(ct)) + ct)
            await self._client_writer.drain()
        except OSError as e:
            # destroy connection
            self._logger.error('send_frame error %r' % e)
            raise e
        finally:
            self._client_writer_lock.release()

    async def read_from_stream(self, stream_id, reader):
        self._logger.debug('start read from stream')
        timeout_count = 0
        while not self._remote_status[stream_id] & REMOTE_CLOSED:
            fut = reader.read(self.bufsize)
            try:
                data = await asyncio.wait_for(fut, timeout=6)
                timeout_count = 0
            except asyncio.TimeoutError:
                timeout_count += 1
                if timeout_count <= 10:
                    continue
                self._remote_status[stream_id] = CLOSED
                # TODO: reset stream
                data = b''
            except OSError:
                self._remote_status[stream_id] = CLOSED
                # TODO: reset stream
                data = b''
            if not data:
                self._remote_status[stream_id] |= REMOTE_CLOSED
                await self.send_frame(1, END_STREAM_FLAG, stream_id,
                                      b'\x00' * random.randint(8, 2048))
                self._stream_status[stream_id] |= LOCAL_CLOSED
                if self._stream_status[stream_id] & REMOTE_CLOSED:
                    if stream_id in self._stream_writer:
                        self._stream_writer[stream_id].close()
                        del self._stream_writer[stream_id]
                    self._remote_status[stream_id] = CLOSED
                return
            if not self._stream_status[stream_id] & LOCAL_CLOSED:
                payload = struct.pack('>H', len(data)) + data + b'\x00' * random.randint(8, 255)
                await self.send_frame(0, 0, stream_id, payload)


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
import time

from hxcrypto import InvalidTag
from hxsocks.hxs_common_server import HxsCommon, ReadFrameError

OPEN = 0
EOF_SENT = 1   # SENT END_STREAM
EOF_RECV = 2  # RECV END_STREAM
CLOSED = 3

REMOTE_WRITE_BUFFER = 524288
READ_FRAME_TIMEOUT = 4

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


class Hxs2Connection(HxsCommon):

    def __init__(self, reader, writer, user, skey, mode, proxy, user_mgr, server_addr, logger, settings):
        super().__init__()
        self._skey = skey
        self.mode = mode
        self._client_reader = reader
        self._client_writer = writer
        self.client_address = writer.get_extra_info('peername')
        self._client_writer.transport.set_write_buffer_limits(524288)

        self._proxy = proxy
        self.server_addr = server_addr
        self.logger = logger
        self.settings = settings

        self.user = user
        self.user_mgr = user_mgr

    async def _rfile_read(self, size, timeout=None):
        if timeout:
            fut = self._client_reader.readexactly(size)
            data = await asyncio.wait_for(fut, timeout=timeout)
            return data
        return await self._client_reader.readexactly(size)

    async def read_frame(self, timeout=30):
        try:
            frame_len = await self._rfile_read(2, timeout)
            frame_len, = struct.unpack('>H', frame_len)
        except (ConnectionError, asyncio.IncompleteReadError) as err:
            # destroy connection
            raise ReadFrameError(err) from err

        # read frame_data
        try:
            frame_data = await self._rfile_read(frame_len, timeout=READ_FRAME_TIMEOUT)
            frame_data = self.decrypt_frame(frame_data)
            return frame_data
        except (ConnectionError, asyncio.TimeoutError, asyncio.IncompleteReadError, InvalidTag) as err:
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
        self._client_writer.write(struct.pack('>H', len(ct_)) + ct_)
        try:
            await self._client_writer.drain()
        except ConnectionError:
            self._connection_lost = True
            raise

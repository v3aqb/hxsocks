
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
import hashlib

from hxcrypto import InvalidTag
from hxcrypto.encrypt import EncryptorStream
from hxsocks.hxs_common_server import HxsCommon, ReadFrameError, CLIENT_WRITE_BUFFER, READ_FRAME_TIMEOUT


class Hxs2Connection(HxsCommon):

    def __init__(self, reader, writer, user, skey, mode, proxy, user_mgr, server_addr, logger, settings):
        super().__init__(mode)
        self._skey = skey
        self.encrypt_flen = self._mode & 2
        self._flen_cipher = None
        if self.encrypt_flen:
            md5 = hashlib.md5()
            md5.update(self._skey)
            md5.update(b'encrypt_flen')
            key = md5.digest()
            self._flen_cipher = EncryptorStream(key, 'rc4', check_iv=False)
            self._flen_cipher.encrypt(bytes(1024))
            self._flen_cipher.decrypt(bytes(1024))
        self._client_reader = reader
        self._client_writer = writer
        self.client_address = writer.get_extra_info('peername')
        self._client_writer.transport.set_write_buffer_limits(CLIENT_WRITE_BUFFER)

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
            if self.encrypt_flen:
                frame_len = self._flen_cipher.decrypt(frame_len)
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

    def _send_frame_data(self, ct_):
        frame_len = struct.pack('>H', len(ct_))
        if self.encrypt_flen:
            frame_len = self._flen_cipher.encrypt(frame_len)
        self._client_writer.write(frame_len + ct_)

    async def drain(self):
        try:
            await self._client_writer.drain()
        except ConnectionError as err:
            self.logger.error('send_frame fail: %r', err)
            self._connection_lost = True
            raise

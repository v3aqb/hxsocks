
# util.py - funtion used by both hxsocks and hxsocks2 protocol

# Copyright (C) 2016 - 2018, v3aqb

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

import re
import asyncio
import socket
import struct
import ipaddress


def parse_hostport(host, default_port=80):
    m = re.match(r'(.+):(\d+)$', host)
    if m:
        return m.group(1).strip('[]'), int(m.group(2))
    return host.strip('[]'), default_port


async def get_ip_address(host):
    try:
        return ipaddress.ip_address(host)
    except Exception:
        return ipaddress.ip_address('1.1.1.1')


async def request_is_loopback(addr):
    try:
        ip = await get_ip_address(addr)
        if ip.is_loopback:
            return ip
    except Exception:
        pass
    return None


async def connect_socks5(addr, port, proxy):
    fut = asyncio.open_connection(proxy[0], proxy[1], limit=65536)
    remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=2)
    remote_writer.write(b"\x05\x01\x00")
    data = await remote_reader.readexactly(2)
    assert data[1] == 0  # no auth needed or auth passed
    remote_writer.write(b''.join([b"\x05\x01\x00\x03",
                                  chr(len(addr)).encode(),
                                  addr.encode(),
                                  struct.pack(b">H", port)]))
    data = await remote_reader.readexactly(4)
    assert data[1] == 0
    if data[3] == 1:  # read ipv4 addr
        await remote_reader.readexactly(4)
    elif data[3] == 3:  # read host addr
        size = await remote_reader.readexactly(1)
        size = ord(size)
        await remote_reader.readexactly(size)
    elif data[3] == 4:  # read ipv6 addr
        await remote_reader.readexactly(16)
    await remote_reader.readexactly(2)  # read port
    return remote_reader, remote_writer


async def open_connection(addr, port, proxy, settings):
    # do security check here
    data = await request_is_loopback(addr)
    if data:
        raise ValueError('connect to localhost denied!')
    timeout = settings.tcp_conn_timeout
    nodelay = settings.tcp_nodelay
    # create connection
    if proxy:
        fut = connect_socks5(addr, port, proxy)
        remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=timeout)
    elif settings.prefer_ipv4:
        try:
            fut = asyncio.open_connection(addr, port, limit=65536, family=socket.AF_INET)
            remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=timeout)
        except socket.gaierror:
            fut = asyncio.open_connection(addr, port, limit=65536, family=socket.AF_INET6)
            remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=timeout)
    else:
        try:
            fut = asyncio.open_connection(addr, port, limit=65536, happy_eyeballs_delay=0.25)
            remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=timeout)
        except TypeError:
            fut = asyncio.open_connection(addr, port, limit=65536)
            remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=timeout)
    if nodelay:
        soc = remote_writer.transport.get_extra_info('socket')
        soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return remote_reader, remote_writer

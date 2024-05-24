
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
    # create connection
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=65535, loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    transport = await create_connection(protocol, addr, port, proxy, settings)
    # protocol is for Reader, transport is for Writer
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    return reader, writer


async def create_connection(protocol, addr, port, proxy, settings):
    # do security check here
    is_loopback = await request_is_loopback(addr)
    if is_loopback:
        raise ValueError('connect to localhost denied!')

    loop = asyncio.get_running_loop()
    timeout = settings.tcp_conn_timeout
    if proxy:
        p_addr, p_port = proxy[0], proxy[1]
        from .proxy_client import ProxyClientProtocol
        connected_cb = loop.create_future()
        p_protocol = ProxyClientProtocol(protocol, connected_cb, (addr, port),
                                         proxy='socks5',
                                         proxy_auth=None)
        transport, _ = await loop.create_connection(lambda: p_protocol, p_addr, p_port)
        await connected_cb
        return transport
    if settings.prefer_ipv4:
        try:
            fut = loop.create_connection(lambda: protocol, addr, port, family=socket.AF_INET)
            transport, _ = await asyncio.wait_for(fut, timeout=timeout)
        except socket.gaierror:
            fut = loop.create_connection(lambda: protocol, addr, port, family=socket.AF_INET6)
            transport, _ = await asyncio.wait_for(fut, timeout=timeout)
    else:
        try:
            fut = loop.create_connection(lambda: protocol, addr, port, happy_eyeballs_delay=0.25)
            transport, _ = await asyncio.wait_for(fut, timeout=timeout)
        except TypeError:
            fut = loop.create_connection(lambda: protocol, addr, port)
            transport, _ = await asyncio.wait_for(fut, timeout=timeout)
    return transport

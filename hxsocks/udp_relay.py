
import io
import ipaddress
import socket
import struct
import time
import logging
import asyncio
import asyncio_dgram

from hxcrypto import Encryptor, InvalidTag, IVError


FULL = 0
RESTRICTED = 1
PORTRESTRICTED = 2


class UDPRelay:
    def __init__(self, parent, client_addr, timeout=60, mode=PORTRESTRICTED):
        self.parent = parent
        self.client_addr = client_addr
        self.timeout = timeout
        self.mode = mode
        self.remote_stream = None
        self.remote_addr = set()
        self.lock = asyncio.Lock()
        self._last_active = time.monotonic()
        self._close = False
        self._recv_task = None

    async def send(self, data):
        async with self.lock:
            if not self.remote_stream:
                self.remote_stream = await asyncio_dgram.bind((self.parent.server_addr[0], 0))
                self._recv_task = asyncio.ensure_future(self.recv_from_remote())
        data_io = io.BytesIO(data)
        addrtype = data_io.read(1)[0]
        if addrtype == 1:
            addr = data_io.read(4)
            addr = socket.inet_ntoa(addr)
        elif addrtype == 3:
            addr = data_io.read(1)
            addr = data_io.read(addr[0])
            addr = addr.decode('ascii')
        else:
            addr = data_io.read(16)
            addr = socket.inet_ntop(socket.AF_INET6, addr)
        port = data_io.read(2)
        port, = struct.unpack('>H', port)

        dgram = data_io.read()
        remote_ip = ipaddress.ip_address(addr)
        if remote_ip.is_private:
            self.parent.logger.warning('on_server_recv, %r, %r, is_private', self.client_addr, addr)
            return
        self._last_active = time.monotonic()
        if self.mode:
            key = addr if self.mode == 1 else (addr, port)
            self.remote_addr.add(key)
        await self.remote_stream.send(dgram, (addr, port))

    async def recv_from_remote(self):
        while not self._close:
            try:
                fut = self.remote_stream.recv()
                dgram, remote_addr = await asyncio.wait_for(fut, timeout=6)
            except asyncio.TimeoutError:
                if time.monotonic() - self._last_active > self.timeout:
                    break
                continue
            except OSError:
                break

            if self.mode:
                key = remote_addr[0] if self.mode == 1 else remote_addr
                if key not in self.remote_addr:
                    self.parent.logger.info('udp drop %r', remote_addr)
                    continue

            self._last_active = time.monotonic()
            remote_ip = ipaddress.ip_address(remote_addr[0])
            buf = b'\x01' if remote_ip.version == 4 else b'\x04'
            buf += remote_ip.packed
            buf += struct.pack(b'>H', remote_addr[1])
            buf += dgram
            await self.parent.on_remote_recv(self.client_addr, buf)
        self.remote_stream.close()
        self.parent.close_relay(self.client_addr)

    def close(self):
        self._close = True

    def is_closing(self):
        return self._close

    async def drain(self):
        return

    async def wait_closed(self):
        return


class UDPRelayServer:
    '''
    provide udp relay for shadowsocks
    '''
    def __init__(self, server_addr, method, key, timeout, mode):
        self.server_addr = server_addr
        self.task = None
        self.method = method
        self.__key = key
        self.timeout = timeout
        self.mode = mode
        self.server_stream = None
        self.relay_holder = {}  # {client_addr: udp_relay}

        self.logger = logging.getLogger('ssudp_%d' % self.server_addr[1])
        self.logger.setLevel(logging.INFO)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

    async def serve_forever(self):
        self.logger.info('start udp_relay server %r', self.server_addr)
        self.server_stream = await asyncio_dgram.bind(self.server_addr)
        while True:
            data, client_addr = await self.server_stream.recv()
            asyncio.ensure_future(self.handle(client_addr, data))

    def start(self):
        self.task = asyncio.ensure_future(self.serve_forever())

    async def handle(self, client_addr, data):
        try:
            data = self.decrypt(data)
        except (InvalidTag, IVError) as err:
            self.logger.error('%s %s', repr(err), repr(client_addr))
            return

        self.logger.debug('on_server_recv, %r', client_addr)
        relay = await self.get_relay(client_addr)
        await relay.send(data)

    async def on_remote_recv(self, client_addr, data):
        '''
            create dgram, encrypt and send to client
        '''
        if client_addr not in self.relay_holder:
            return
        self.logger.debug('on_remote_recv %r', client_addr)

        cipher = Encryptor(self.__key, self.method)
        buf = cipher.encrypt_once(data)
        await self.server_stream.send(buf, client_addr)

    def close_relay(self, client_addr):
        if client_addr in self.relay_holder:
            self.relay_holder[client_addr].close()
            del self.relay_holder[client_addr]

    def decrypt(self, data):
        cipher = Encryptor(self.__key, self.method)
        data = cipher.decrypt(data)
        return data

    async def get_relay(self, client_addr):
        '''
            for each client_addr, create a ctx and udp stream
            start udp recv, store udp stream in ctx
            return udp_relay object
        '''
        if client_addr not in self.relay_holder:
            self.logger.debug('start udp_relay %r', client_addr)
            relay = UDPRelay(self, client_addr, self.timeout, self.mode)
            self.relay_holder[client_addr] = relay
        return self.relay_holder[client_addr]

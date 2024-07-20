
import ipaddress
import struct
import time
import logging

import asyncio
import asyncio_dgram

logger = logging.getLogger('udp2')


def set_logger():
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()

USER_RELAY = {}


def get_relay2(user, settings):
    logger.setLevel(settings.log_level)
    if user not in USER_RELAY:
        USER_RELAY[user] = UserRelay(user, settings)
    return USER_RELAY[user]


class UserRelay:
    def __init__(self, user, settings):
        logger.debug('UserRelay.__init__: %s', user)
        self.user = user
        self.settings = settings
        self.relay_list = []
        self.callback_store = {}
        self.addr_count = {}  # callback_info(callback, callback_addr), address_count

    async def send_dgram(self, addr, dgram, callback, callback_addr):
        logger.debug('UserRelay:%s.send_dgram', self.user)
        # check relay_sid, for session recovery(Not Implemented)
        # find / get available relay
        # send_dgram, relay return relay_sid
        remote_ip = ipaddress.ip_address(addr)

        if remote_ip.is_multicast:
            logger.warning('udp send_dgram, %s, %r, is_multicast, drop', self.user, addr)
            return

        if remote_ip.is_private:
            logger.warning('udp send_dgram, %s, %r, is_private, drop', self.user, addr)
            return

        relay_selected = self.find_relay(addr, callback, callback_addr)
        await relay_selected.send_dgram(addr, dgram, callback, callback_addr)

    def find_relay(self, addr, callback, callback_addr):
        for relay in self.relay_list:
            if relay.check_reg(addr, callback, callback_addr):
                return relay
        for relay in self.relay_list:
            if relay.check(addr, callback, callback_addr):
                self.addr_plus((callback, callback_addr))
                return relay
        relay = UDPRelay2(self, self.settings.udp_timeout)
        self.relay_list.append(relay)
        self.addr_plus((callback, callback_addr))
        return relay

    def addr_plus(self, callback_info):
        if callback_info not in self.addr_count:
            self.addr_count[callback_info] = 1
        else:
            self.addr_count[callback_info] += 1

    def addr_minus(self, callback_info):
        self.addr_count[callback_info] -= 1
        if self.addr_count[callback_info] <= 0:
            callback, client_addr = callback_info
            callback.close_relay(client_addr)

    def remove_relay(self, relay):
        self.relay_list.remove(relay)

    def user_close(self, callback):
        for relay in self.relay_list:
            relay.user_close(callback)


class UDPRelay2:
    def __init__(self, parent, timeout):
        self.parent = parent
        self.timeout = timeout
        self.logger = logger
        self.lock = asyncio.Lock()
        self.remote_stream = None
        self.remote_addr = set()
        self.last_addr = ('0.0.0.0', 0)
        self.init_time = time.monotonic()
        self.last_active = {}
        self.last_active_global = 0
        self.callback_info = {}
        self.running = False
        self._recv_task = None

    def clear(self):
        # TODO: tell UserDispatcher to close streams
        for _, callback_info in self.callback_info.items():
            self.parent.addr_minus(callback_info)
        self.remote_stream = None
        self.remote_addr = set()
        self.last_addr = ('0.0.0.0', 0)
        self.init_time = time.monotonic()
        self.last_active = {}
        self.last_active_global = 0
        self.callback_info = {}

    def check_reg(self, addr, callback, callback_addr):
        if addr not in self.callback_info:
            return False
        if self.callback_info[addr] == (callback, callback_addr):
            return True

    def check(self, addr, callback, callback_addr):
        if addr not in self.callback_info:
            return True
        if self.callback_info[addr] == (callback, callback_addr):
            return True

    def user_close(self, callback):
        addr_list = []
        for addr, callback_info in self.callback_info.items():
            if callback_info[0] == callback:
                addr_list.append(addr)
        for addr in addr_list:
            self.close_addr(addr)

    def close_addr(self, addr):
        self.parent.addr_minus(self.callback_info[addr])
        del self.callback_info[addr]
        del self.last_active[addr]

    def clean(self):
        clean_pending = []
        time_now = time.monotonic()
        for addr in self.last_active:
            timeout = self.timeout if addr[1] != 53 else 6
            if time_now - self.last_active[addr] > timeout:
                clean_pending.append(addr)
        for addr in clean_pending:
            self.close_addr(addr)
        if not self.last_active and time_now - self.init_time > 10:
            self.running = False

    async def bind(self):
        async with self.lock:
            if self.running:
                return
            stream = await asyncio_dgram.connect(('8.8.8.8', 53))
            interface = stream.sockname[0]
            stream.close()
            self.remote_stream = await asyncio_dgram.bind((interface, 0))
            self.logger.info('udp_relay start, %s', self.remote_stream.sockname)
            self._recv_task = asyncio.ensure_future(self.recv_from_remote())
            self.running = True
            return self.remote_stream.sockname

    async def send_dgram(self, remote_addr, dgram, callback, callback_addr):
        '''send dgram to addr, request come from (callback, callback_addr) with relay_sid
           if relay_sid is invalid, new relay_sid will be assigned.
        '''
        logger.debug('UDPRelay2.send_dgram')
        if not self.running:
            await self.bind()
        if remote_addr not in self.callback_info:
            self.callback_info[remote_addr] = (callback, callback_addr)
        if remote_addr not in self.remote_addr:
            self.logger.debug('udp send %s:%d, relay_port:%d',
                              remote_addr[0], remote_addr[1], self.remote_stream.sockname[1])
            self.remote_addr.add(remote_addr)
        self.last_addr = remote_addr
        try:
            await self.remote_stream.send(dgram, remote_addr)
            self.last_active[remote_addr] = time.monotonic()
            self.last_active_global = time.monotonic()
        except OSError as err:
            self.logger.info('udp send fail. %s:%d, %r', remote_addr[0], remote_addr[1], err)
            self.running = False

    async def recv_from_remote(self):
        while self.running:
            try:
                fut = self.remote_stream.recv()
                dgram, remote_addr = await asyncio.wait_for(fut, timeout=12)
                if remote_addr in self.last_active:
                    self.last_active[remote_addr] = time.monotonic()
                    self.last_active_global = time.monotonic()
            except asyncio.TimeoutError:
                self.clean()
                inactive = time.monotonic() - max(self.last_active_global, self.init_time)
                if inactive > self.timeout:
                    break
                continue
            except OSError:
                break

            addr, port = remote_addr
            self.logger.debug('udp recv %s:%d, %d', addr, port, len(dgram))

            if remote_addr not in self.remote_addr:
                self.logger.info('udp drop %r', remote_addr)
                continue
            remote_ip = ipaddress.ip_address(addr)
            buf = b'\x01' if remote_ip.version == 4 else b'\x04'
            buf += remote_ip.packed
            buf += struct.pack(b'>H', port)
            buf += dgram
            callback, callback_addr = self.callback_info[remote_addr]
            await callback.on_remote_recv(callback_addr, buf)
        self.logger.info('udp_relay end, %s, %ds', self.remote_stream.sockname, int(time.monotonic() - self.init_time))
        if len(self.remote_addr) > 1:
            self.logger.info('    remote_addr: %d, last_addr: %s', len(self.remote_addr), self.last_addr)
        self.remote_stream.close()
        self.clear()
        self.parent.remove_relay(self)

    def close(self):
        self.running = False

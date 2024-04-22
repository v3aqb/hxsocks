
import time
import struct
import hashlib
import hmac
import logging
from urllib.request import urlopen
from collections import defaultdict, deque

from hxcrypto import ECC, exchange
from hxsocks.apfilter import ap_filter


class porn_filter:
    def __init__(self, settings):
        self.logger = logging.getLogger('porn_filter')
        self.logger.setLevel(settings.log_level)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

        self.porn_filter = None
        self.last_load = 0
        self.loaded = False

    def load(self):
        self.porn_filter = ap_filter()
        hosts = urlopen('https://raw.githubusercontent.com/4skinSkywalker/Anti-Porn-HOSTS-File/master/HOSTS.txt').readlines()
        for line in hosts:
            try:
                self.porn_filter.add('||' + line.decode().strip().split()[1])
            except Exception as err:
                self.logger.error('%r', err, exc_info=True)
        self.loaded = True

    def is_blocked(self, addr):
        if not self.loaded and time.time() - self.last_load > 3600:
            self.last_load = time.time()
            try:
                self.load()
            except Exception as err:
                self.logger.error('load porn_filter failed.', exc_info=True)
        if self.loaded:
            return self.porn_filter.match(addr)


class china_filter:
    def __init__(self, settings):
        self.logger = logging.getLogger('china_filter')
        self.logger.setLevel(settings.log_level)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

        self.china_filter = None
        self.last_load = 0
        self.loaded = False

    def load(self):
        self.china_filter = ap_filter()
        hosts = urlopen('https://github.com/QiuSimons/Chnroute/raw/master/dist/chnroute/chinalist.txt').readlines()
        for line in hosts:
            try:
                self.china_filter.add('||' + line.decode().strip())
            except Exception as err:
                self.logger.error('%r', err, exc_info=True)
        hosts = urlopen('https://github.com/QiuSimons/Chnroute/raw/master/dist/chnroute/chnroute.txt').readlines()
        for line in hosts:
            if line.strip() and '#' not in line.decode():
                self.china_filter.add(line.decode().strip())
        hosts = urlopen('https://github.com/QiuSimons/Chnroute/raw/master/dist/chnroute/chnroute-v6.txt').readlines()
        for line in hosts:
            if line.strip() and '#' not in line.decode():
                self.china_filter.add(line.decode().strip())

        self.loaded = True

    def is_blocked(self, addr):
        if not self.loaded and time.time() - self.last_load > 3600:
            self.last_load = time.time()
            try:
                self.load()
            except Exception as err:
                self.logger.error('load china_filter failed.', exc_info=True)
        if self.loaded:
            return self.china_filter.match(addr)


class UserManager:
    def __init__(self, server_cert, settings):
        '''server_cert: path to server_cert'''
        self.server_cert = ECC(from_file=server_cert)
        self.settings = settings
        self.user_pass = {}
        self.user_tag = {}
        self.userpkeys = defaultdict(deque)  # user name: client key
        self.pkeyuser = {}  # user pubkey: user name
        self.porn_filter = porn_filter(settings)
        self.china_filter = china_filter(settings)
        self.quick_auth_data = {}

    def add_user(self, user, password):
        password, _, tags = password.partition(' ')
        tags = tags.split()
        self.user_pass[user] = password
        self.user_tag[user] = tags

    def remove_user(self, user):
        del self.user_pass[user]
        del self.user_tag[user]

    def quick_auth_update(self, _ts):
        ts_current = int(time.time()) // 30
        # clean
        ts_list = list(self.quick_auth_data.keys())
        for ts_stored in ts_list:
            if ts_stored < ts_current - 1:
                del self.quick_auth_data[ts_stored]
        # add
        if abs(ts_current - _ts) > 1:
            return
        if _ts in self.quick_auth_data:
            return
        self.quick_auth_data[_ts] = {}
        for username, password_ in self.user_pass.items():
            hash_ = hmac.new(password_.encode() + username.encode(),
                             struct.pack('>I', _ts),
                             hashlib.sha256).digest()
            self.quick_auth_data[_ts][hash_] = username

    def hxs2_auth(self, client_pkey, client_auth):
        ts_current = int(time.time()) // 30
        user = None
        password = None
        for _ts in [ts_current, ts_current - 1, ts_current + 1]:
            # quick auth
            if _ts not in self.quick_auth_data:
                self.quick_auth_update(_ts)
            if _ts in self.quick_auth_data and client_auth in self.quick_auth_data[_ts]:
                user = self.quick_auth_data[_ts][client_auth]
                password = self.user_pass[user]
                break
        else:
            raise ValueError('user not found')

        # return public_key, username, password
        if hashlib.md5(client_pkey).digest() in self.pkeyuser:
            raise ValueError('public key already registered. user: %s' % user)
        if len(self.userpkeys[user]) > self.settings.conn_limit:
            raise ValueError('connection limit exceeded. user: %s' % user)

        xpubkey, shared_secret = exchange(client_pkey)

        user_pkey_md5 = hashlib.md5(client_pkey).digest()
        self.userpkeys[user].append(user_pkey_md5)
        self.pkeyuser[user_pkey_md5] = user

        hash_ = hmac.new(password.encode(), client_pkey + xpubkey + user.encode(), hashlib.sha256).digest()
        scert = self.server_cert.get_pub_key()
        signature = self.server_cert.sign(hash_, 'SHA256')
        reply = b''.join([
            struct.pack(b'!BBBB', 0, len(xpubkey), len(scert), len(signature)),
            xpubkey,
            hash_,
            scert,
            signature])
        return user, reply, shared_secret

    def del_key(self, pkey):
        user = self.pkeyuser[pkey]
        del self.pkeyuser[pkey]
        self.userpkeys[user].remove(pkey)

    def user_access_ctrl(self, server_port, address, client_ip, user, cmd):
        # access control, called before each request
        # int server_port
        # tuple address: (host, port)
        # str client_ip: client ipaddress
        # int cmd: 0 for connect, 1 for udp
        # raise ValueError if denied
        if user not in self.user_tag:
            return
        if self.settings.block_china:
            if self.china_filter.is_blocked(address[0]):
                raise ValueError('china block')
        if 'noporn' in self.user_tag[user]:
            if self.porn_filter.is_blocked(address[0]):
                raise ValueError('porn block')

    def user_access_log(self, server_port, address, traffic, client_ip, user, cmd):
        # log user access, called after each request
        # traffic: (upload, download) in bytes
        pass

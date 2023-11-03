hxsocks
===============

A better encrypted socks proxy.

2022.09.26: support shadowsocks 2022-blake3 encryption method (tcp only)

2022.06.22: introduce new authentication method

2021.11.7: disable shadowsocks by default

2018.05.30: update key exchange method

new protocol
--------

hxsocks3: a websocket port of hxsocks2, works perfectly with nginx.
hxsocks4: upgraded version of hxsocks2, drop shadowsocks support.

features
--------

- compatible with shadowsocks
- multiple user on single port
- perfect forward security
- connection multiplexing
- some MITM attack protection
- udp relay (over tcp, full cone available)

install
-------

You may want to install ``python3-uvloop`` for better performance.

::

    pip3 install wheel
    pip3 install https://github.com/v3aqb/hxcrypto/archive/master.zip
    pip3 install https://github.com/v3aqb/hxsocks/archive/master.zip

update
------

using ``pip -U`` may cause problems, better uninstall and install.

::

    pip3 uninstall hxsocks
    pip3 uninstall hxcrypto
    pip3 install https://github.com/v3aqb/hxcrypto/archive/master.zip --no-cache-dir
    pip3 install https://github.com/v3aqb/hxsocks/archive/stable.zip --no-cache-dir

configure file example
----------------------

::

    servers:
        - ss://aes-128-gcm:password@127.0.0.1:8138
        - hxs2://127.0.0.1:8140/?method=aes-128-gcm&PSK=password&proxy=127.0.0.1:8120&ss=1
        - hxs3://127.0.0.1:8141/
    users:
        user: password
        user2: password2
    conn_limit: 20         # connection limit per user
    block_china: false
    prefer_ipv4: false
    tcp_nodelay: false
    tcp_timeout: 600
    tcp_conn_timeout: 12   # tcp create connection timeout
    udp_enable: false      # boolean, port_number, or list of port enabled [8138, 8139], shadowsocks only
    udp_mode: 2            # 0 for fullcone, 1 for restricted, 2 for port_restricted, 3 for symmetric
    udp_timeout: 90
    log_level: info        # str or int, error: 40, warning: 30, info: 20 debug: 10

run
-----

::

    hxsocks -c config.yaml
    or
    python3 -m hxsocks -c config.yaml

client
------

see `fwlite-cli <https://github.com/v3aqb/fwlite-cli/blob/master/fwlite_cli/hxsocks2.py>`_

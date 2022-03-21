hxsocks
===============

A better encrypted socks proxy.

2021.11.7: disable shadowsocks by default
2018.5.30: update key exchange method

new protocol
--------

hxsocks3: a websocket port of hxsocks2, works perfectly with nginx.

features
--------

- compatible with shadowsocks(with UDP relay)
- multiple user on single port
- perfect forward security
- connection multiplexing
- some MITM attack protection
- udp relay (over tcp, full cone)

install
-------

You may want to install ``python3-uvloop`` to increase performance.

::

    pip3 install https://github.com/v3aqb/hxcrypto/archive/master.zip
    pip3 install https://github.com/v3aqb/hxsocks/archive/stable.zip

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
        - ss://aes-128-gcm:password@0.0.0.0:8138
        - hxs2://0.0.0.0:8140/?method=aes-128-gcm&PSK=password&proxy=127.0.0.1:8120&ss=1
        - hxs3://0.0.0.0:8141/
    users:
        user: password
        user2: password2
    tcp_nodelay: false
    udp_timeout: 600
    udp_enable: false   # boolean, port_number, or list of port enabled [8138, 8139]
    udp_mode: 2         # 0 for fullcone, 1 for restricted, 2 for port_restricted
    udp_timeout: 600
    log_level: 20

run
-----

::

    hxsocks -c config.yaml
    or
    python3 -m hxsocks -c config.yaml

client
------

see `fwlite-cli <https://github.com/v3aqb/fwlite-cli/blob/master/fwlite_cli/hxsocks2.py>`_

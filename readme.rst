hxsocks
===============

A better encrypted socks proxy.

2018.5.30: update key exchange method

features
--------

- compatible with shadowsocks(with AEAD)
- multiple user on single port
- perfect forward security
- connection multiplexing
- some MITM attack protection

install
-------

::

    pip3 install https://github.com/v3aqb/hxcrypto/archive/master.zip
    pip3 install https://github.com/v3aqb/hxsocks/archive/master.zip

update
------

using `pip -U` may cause problems, better uninstall and install.

::

    pip3 uninstall hxsocks
    pip3 uninstall hxcrypto
    pip3 install https://github.com/v3aqb/hxcrypto/archive/master.zip
    pip3 install https://github.com/v3aqb/hxsocks/archive/master.zip

configure file example
----------------------

::

    servers:
        - ss://aes-128-gcm:password@0.0.0.0:8138
        - ss://aes-128-cfb:password@0.0.0.0:8139
    users:
        user: password
        user2: password2
    log_level: 20

run
-----

::

    hxsocks -c config.yaml
    or
    python3 -m hxsocks -c config.yaml

client
------

see `fwlite <https://github.com/v3aqb/fwlite/blob/master/fgfw-lite/hxsocks.py>`_

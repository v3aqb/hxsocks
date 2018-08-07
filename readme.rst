hxsocks
===============

A better encrypted socks proxy.

2018.5.30: update key exchange method

features
--------

- compatible with shadowsocks
- multiple user on single port
- authenticated encryption
- perfect forward security
- connection reuse
- connection multiplexing (hxsocks2 only)
- some MITM attack protection

install
-------

::

    pip install https://github.com/v3aqb/hxsocks/archive/master.zip --process-dependency-links

update
------

::

    pip install https://github.com/v3aqb/hxsocks/archive/master.zip -U --process-dependency-links

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

client
------

see `fwlite <https://github.com/v3aqb/fwlite/blob/master/fgfw-lite/hxsocks.py>`_

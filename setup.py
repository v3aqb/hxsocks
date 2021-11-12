from setuptools import setup, find_packages

setup(
    name="hxsocks",
    version="0.0.3",
    license='GNU General Public License v3 (GPLv3)',
    description="A fast tunnel proxy that help you get through firewalls",
    author='v3aqb',
    author_email='null',
    url='https://github.com/v3aqb/hxsocks',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'hxsocks = hxsocks.__main__:main'
        ]
    },
    dependency_links=['https://github.com/v3aqb/hxcrypto/archive/master.zip#egg=hxcrypto-0.0.2'],
    install_requires=["hxcrypto", "pyyaml", "asyncio-dgram"],
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Internet :: Proxy Servers',
    ],
)

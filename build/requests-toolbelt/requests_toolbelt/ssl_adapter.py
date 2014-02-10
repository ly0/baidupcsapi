# -*- coding: utf-8 -*-
"""

requests_toolbelt.ssl_adapter
=============================

This file contains an implementation of the SSLAdapter originally demonstrated
in this blog post:
https://lukasa.co.uk/2013/01/Choosing_SSL_Version_In_Requests/

"""
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager


class SSLAdapter(HTTPAdapter):
    """
    A HTTPS Adapter for Python Requests that allows the choice of the SSL/TLS
    version negotiated by Requests. This can be used either to enforce the
    choice of high-security TLS versions (where supported), or to work around
    misbehaving servers that fail to correctly negotiate the default TLS
    version being offered.

    Example usage:

        >>> import requests
        >>> import ssl
        >>> from requests_toolbelt import SSLAdapter
        >>> s = requests.Session()
        >>> s.mount('https://', SSLAdapter(ssl.PROTOCOL_TLSv1))

    You can replace the chosen protocol with any that are available in the
    default Python SSL module. All subsequent requests that match the adapter
    prefix will use the chosen SSL version instead of the default.
    """
    def __init__(self, ssl_version=None, **kwargs):
        self.ssl_version = ssl_version

        super(SSLAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=self.ssl_version)

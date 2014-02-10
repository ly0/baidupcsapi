requests toolbelt
=================

This is just a collection of utilities that some users of python-requests
might need but do not belong in requests proper.

multipart/form-data Encoder
---------------------------

The main attraction is a streaming multipart form-data object. Its API looks
like::

    from requests_toolbelt import MultipartEncoder

    import requests


    m = MultipartEncoder(
        fields={'field0': 'value', 'field1': 'value',
                'field2': ('filename', open('file.py'), 'text/plain')}
        )

    r = requests.post('http://httpbin.org/post', data=m,
                      headers={'Content-Type': m.content_type})

You can also use it to just plain use ``multipart/form-data`` encoding for
requests that do not require files::

    from requests_toolbelt import MultipartEncoder

    import requests


    m = MultipartEncoder(fields={'field0': 'value', 'field1': 'value'})

    r = requests.post('http://httpbin.org/post', data=m,
                      headers={'Content-Type': m.content_type})


You can also just use it to create the string to examine the data::

    # Assuming `m` is one of the above

    m.to_string()  # Always returns unicode


User-Agent constructor
----------------------

You can easily construct your own requests-style User-Agent string::

    from requests_toolbelt import user_agent

    headers = {
        'User-Agent': user_agent('my_package', '0.0.1')
        }

    r = requests.get('https://api.github.com/users', headers=headers)


SSLAdapter
----------

The ``SSLAdapter`` is an implementation of the adapter proposed over on
@Lukasa's blog, `here`_. This adapter allows the user to choose one of the SSL
protocols made available in Python's ``ssl`` module for outgoing HTTPS
connections::

    from requests_toolbelt import SSLAdapter

    import requests
    import ssl

    s = requests.Session()
    s.mount('https://', SSLAdapter(ssl.PROTOCOL_TLSv1))

.. _here: https://lukasa.co.uk/2013/01/Choosing_SSL_Version_In_Requests/

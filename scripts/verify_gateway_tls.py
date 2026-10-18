#!/usr/bin/env python3
"""Independent stdlib/OpenSSL TLS+HTTP client; synthetic fixture credentials only."""
import http.client
import pathlib
import ssl
import sys
import urllib.parse
root = pathlib.Path(__file__).resolve().parent.parent / 'tests/fixtures/gateway-tls'
url = urllib.parse.urlsplit(sys.argv[1])
assert url.scheme == 'https' and url.hostname == '127.0.0.1'
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_verify_locations(cafile=str(root / 'ca.pem'))
context.load_cert_chain(str(root / 'client.pem'), str(root / 'client.key'))
connection = http.client.HTTPSConnection(url.hostname, url.port, context=context, timeout=5)
connection.request('POST', url.path, b'python independent witness', {'x-kan-exchange': 'ab' * 32})
response = connection.getresponse()
assert response.status == 202
assert response.read() == b'a\x00b\xffc'
connection.close()
print('independent TLS/HTTP witness passed')

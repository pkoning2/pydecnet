#!/usr/bin/env python3

import urllib.request
import ssl
import json

# Read the list of systems
context = ssl.SSLContext (ssl.PROTOCOL_SSLv23 )
context.check_hostname = False
resp = urllib.request.urlopen ("https://127.0.0.1:8443/api", context = context)
print ("headers:")
print (" ", "\n  ".join (str (h) for h in resp.getheaders ()))
print ("list of systems returned by API:")
ret = json.loads (str (resp.read (), encoding = "latin1"))
print (" ", "\n  ".join (ret))

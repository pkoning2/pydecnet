#!/usr/bin/env python3

# Similar to apitest.py, but using the Requests package

import requests
import warnings

warnings.simplefilter ("ignore")

# Read the list of systems.  verify is False because my test certificate
# isn't completely correct, which is fine when used just for testing.
resp = requests.get ("https://127.0.0.1:8443/api", verify = False)
print ("headers:")
print (" ", "\n  ".join (str (h) for h in resp.headers.items ()))
print ("list of systems returned by API:")
ret = resp.json ()
print (" ", "\n  ".join (ret))

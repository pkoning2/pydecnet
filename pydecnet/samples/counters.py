#!/usr/bin/env python3

""" MOP counters request client test.

"""

import sys
import os
import requests
import warnings
import json

# Suppress "insecure" warnings from Requests.
warnings.simplefilter ("ignore")

pencoder = json.JSONEncoder (indent = 3, separators = (",", " : "))

def json_pp (d):
    "Pretty-print d as a JSON value"
    print (pencoder.encode (d))

if len (sys.argv) < 3:
    print ("usage: counters circuit destaddr [ sysname ]")
    sys.exit (0)
    
port = sys.argv[1]
dest = sys.argv[2]
try:
    sysname = sys.argv[3]
except IndexError:
    sysname = None

# Build the destination URL.  This is the same for all the requests we
# will send.
url = "https://127.0.0.1:8443/api/mop/circuits/{}/counters".format (port)
if sysname:
    url += "?system={}".format (sysname)
ses = requests.Session ()

# Issue the counters request
req = { "dest" : dest }
resp = ses.post (url, json = req, verify = False)
print (resp.text)
ret = resp.json ()
print (ret)
stat = ret.get ("status", "ok")
if stat != "ok":
    print ("counters request failure:", stat)
    sys.exit (1)
print ("counters response:")
json_pp (ret)

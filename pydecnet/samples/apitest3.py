#!/usr/bin/env python3

"""Test some PyDECnet API functions using the async connector

This requires Python 3.7 or later.
"""

import sys
assert sys.version_info >= (3, 7), "Python 3.7 or later required"

import json
import asyncio

pencoder = json.JSONEncoder (indent = 3, separators = (",", " : "))

def json_pp (d, hdr = None):
    "Pretty-print d as a JSON value"
    if hdr:
        print (hdr)
    print (pencoder.encode (d))

async def exch (hdr = "request", **d):
    json_pp (d, hdr)
    rc, resp = await api.exch (**d)
    json_pp (resp.__dict__, hdr.replace ("request", "reply"))
    
from decnet.async_connectors import AsyncApiConnector

async def do_tests ():
    await api.start ()
    # Issue a bunch of requests in parallel.  The first one takes at
    # least 2 seconds so if things indeed happen concurrently, the
    # later requests will complete quickly and then two seconds later
    # the loop completion will appear.
    try:
        await asyncio.gather (
            exch ("mop circuit loop request:", api = "mop", type = "loop", circuit = "eth-0", packets = 3),
            exch ("mop circuit get counters request:", api = "mop", type = "counters", circuit = "eth-0", dest = "1e-ac-90-d6-d5-63"),
            exch ("system list request:"),
            exch ("nsp get request:", api = "nsp"),
            exch ("mop get request:", api = "mop"),
            exch ("mop get sysid data request", api = "mop", type = "sysid", circuit = "eth-0")
            )
    except Exception as e:
        print ("exception", e)
    await api.close ()

api = AsyncApiConnector ()
asyncio.run (do_tests ())

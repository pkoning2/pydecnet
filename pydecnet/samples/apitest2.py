#!/usr/bin/env python3

"Test some PyDECnet API functions using the simple connector"

import json

pencoder = json.JSONEncoder (indent = 3, separators = (",", " : "))

def json_pp (d, hdr = None):
    "Pretty-print d as a JSON value"
    if hdr:
        print (hdr)
    print (pencoder.encode (d))

def exch (hdr = None, **d):
    json_pp (d, hdr)
    rc, resp = api.exch (**d)
    json_pp (resp.__dict__, "Reply")
    
from decnet.connectors import SimpleApiConnector

# Recv the list of systems
api = SimpleApiConnector ()

exch ("system list:")
exch ("nsp get:", api = "nsp")
exch ("mop get:", api = "mop")
exch ("mop get sysid data", api = "mop", type = "sysid", circuit = "eth-0")
exch ("mop circuit loop request:", api = "mop", type = "loop", circuit = "eth-0")
exch ("mop circuit get counters request:", api = "mop", type = "counters", circuit = "eth-0", dest = "52-50-38-90-e0-f7")

api.close ()

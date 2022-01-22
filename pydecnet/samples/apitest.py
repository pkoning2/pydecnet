#!/usr/bin/env python3

"Test some PyDECnet API functions using raw JSON"

import socket
import json
import time

from decnet.common import DNJsonDecoder, DNJsonEncoder

pending = b""

def readline (sock):
    "Recv a line from the socket"
    global pending
    while b"\n" not in pending:
        r = sock.recv (100)
        if not r:
            return None
        pending += r
    ret, pending = pending.split (b"\n", 1)
    return ret.decode ("latin1")

# Recv the list of systems
sock = socket.socket (socket.AF_UNIX)
sock.connect ("/tmp/decnetapi.sock")
sock.send (b"{}\n")
reply = readline (sock)
print (reply)
#sock.send (b'{"api":"node","arguments":{"op":"get"}}\n')
sock.send (b'{"api":"nsp"}\n')
reply = readline (sock)
print (reply)
sock.send (b'{"api":"mop"}\n')
reply = readline (sock)
print (reply)
sock.send (b'{"api":"mop","type":"sysid","circuit":"eth-0"}\n')
reply = readline (sock)
print (reply)
sock.send (b'{"api":"mop","type":"loop","circuit":"eth-0","tag":42}\n')
reply = readline (sock)
print (reply)
time.sleep (0.2)
sock.close ()

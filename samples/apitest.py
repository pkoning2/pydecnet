#!/usr/bin/env python3.2

import socket
import io
import sys

# We need this because socket.makefile does not support the line_buffering
# argument for text mode.
def makefile (sock, mode, buf = -1):
    f = sock.makefile (mode + "b", buffering = buf)
    f = io.TextIOWrapper (f, encoding = "ascii",
                          errors = "ignore", newline = None,
                          line_buffering = True)
    f.mode = mode
    return f
    
sock = socket.socket (socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect ("decnetsocket")
rf = makefile (sock, "r", buf = 1)
wf = makefile (sock, "w")

# "quit" argument means break the connection prematurely to test
# server error handling.
try:
    if sys.argv[1] == "quit":
        sys.exit (0)
except IndexError:
    pass

try:
    if len (sys.argv) > 1:
        s = ' '.join (sys.argv[1:]) + '\n'
    else:
        s = input ("> ") + '\n'
    wf.write (s)
    while True:
        r = rf.readline ()
        if not r:
            break
        sys.stdout.write (r)
finally:
    rf.close ()
    wf.close ()
    sock.close ()

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
args = sys.argv[1:]
if len (args) > 2 and args[0] == "-s":
    sockname = args[1]
    args = args[2:]
else:
    sockname = "decnetsocket"
sock.connect (sockname)
rf = makefile (sock, "r", buf = 1)
wf = makefile (sock, "w")

# "quit" argument means break the connection prematurely to test
# server error handling.
if args and args[0] == "quit":
    sys.exit (0)

try:
    if args:
        s = ' '.join (args) + '\n'
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

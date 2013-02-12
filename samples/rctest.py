#!/usr/bin/env python3.2

""" MOP console carrier client test.

"""


import termios
import tty
import sys
import select
from fcntl import *
import os
import io
import threading
import socket

def kb (wf, bufsiz = 100):
    """Run a keyboard raw keystroke input loop, sending all received
    characters to "chan".  The loop exits when Ctrl-] is entered.
    """
    infd = sys.stdin.fileno ()
    oldtty = termios.tcgetattr (sys.stdin)
    oldflags = fcntl (infd, F_GETFL, 0)
    p = select.poll ()
    p.register (infd, select.POLLIN)
    try:
        tty.setraw (infd)
        tty.setcbreak (infd)
        fcntl (infd, F_SETFL, oldflags | os.O_NONBLOCK)
        while True:
            p.poll ()
            while True:
                x = sys.stdin.read (bufsiz)
                if not x:
                    break
                if '\x1d' in x:
                    # Ctrl-] (as in telnet) -- just quit
                    return
                x.replace ("\r", "\n")
                wf.write (x.encode ("latin1", "ignore"))
                wf.flush ()
    except (OSError, socket.error, ValueError):
        print ("connection closed")
    finally:
        termios.tcsetattr (sys.stdin, termios.TCSADRAIN, oldtty)
        fcntl (infd, F_SETFL, oldflags)

def tt (rf):
    while True:
        x = rf.read (1)
        if not x:
            break
        sys.stdout.write (x.decode ("latin1", "ignore"))
        sys.stdout.flush ()
            
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

port = sys.argv[1]
dest = sys.argv[2]
verification = sys.argv[3]

print ("console", port, dest, verification, file = wf)
r = rf.readline ()
code = r.split()[0]
if code == "101":
    # Switch to binary unbuffered mode
    rf = rf.detach ().detach ()
    wf = wf.detach ().detach ()
    # Start the output thread
    t = threading.Thread(target = tt, args = (rf,))
    t.daemon = True
    t.start ()
    # Enter the keyboard loop
    kb (wf)
else:
    print (r)
    print (rf.read ())

rf.close ()
wf.close ()
sock.close ()

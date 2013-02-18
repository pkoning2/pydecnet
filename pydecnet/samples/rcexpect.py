#!/usr/bin/env python3.2

""" MOP console carrier client access via pexpect.

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
import fdpexpect
from pexpect import EOF, TIMEOUT

port, dest, verification, user, passwd = sys.argv[1:]

sock = socket.socket (socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect ("decnetsocket")

rc = fdpexpect.fdspawn (sock, logfile = open ("rcexpect.log", "wt"))
rc.send ("console %s %s %s\n" % (port, dest, verification))
i = rc.expect (["101 Continue binary", "300 Error"])
if i == 1:
    rc.expect (TIMEOUT, 2)
    print ("Console request error:", rc.before)
    sys.exit (1)
rc.expect ("[lL]ogin:")
rc.send ("%s\n" % user)
i = rc.expect (["[pP]assword:", "incorrect"])
if i == 1:
    print ("Login incorrect")
    sys.exit (1)
rc.send ("%s\n" % passwd)
i = rc.expect ([r"\$", "[lL]ogin incorrect"])
if i == 1:
    print ("Login incorrect")
    sys.exit (1)
rc.send ("ls\n")
rc.expect (r"\$")
rc.close ()

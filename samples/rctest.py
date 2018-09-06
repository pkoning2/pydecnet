#!/usr/bin/env python3

""" MOP console carrier client test.

"""


import termios
import tty
import sys
import select
from fcntl import *
import os
import threading
import requests
import warnings

# Suppress "insecure" warnings from Requests.
warnings.simplefilter ("ignore")

def kb (bufsiz = 100):
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
                    # Ctrl-] (as in telnet) -- disconnect
                    req = { "handle" : handle, "close" : 1 }
                    resp = ses.post (url, json = req, verify = False)
                    ret = resp.json ()
                    stat = ret["status"]
                    if stat != "ok":
                        print ("\r\nconsole close failure:", stat, "\r")
                    return
                x.replace ("\r", "\n")
                req = { "handle" : handle, "data" : x }
                resp = ses.post (url, json = req, verify = False)
                ret = resp.json ()
                stat = ret["status"]
                if stat != "ok":
                    print ("\r\nconsole send failure:", stat, "\r")
                    return
    finally:
        termios.tcsetattr (sys.stdin, termios.TCSADRAIN, oldtty)
        fcntl (infd, F_SETFL, oldflags)

def tt ():
    oses = requests.Session ()
    while True:
        req = { "handle" : handle }
        resp = ses.post (url, json = req, verify = False)
        ret = resp.json ()
        stat = ret["status"]
        if stat != "ok":
            if stat != "closed":
                print ("\r\nconsole receive failure:", stat, "\r")
            return
        x = ret["data"]
        if x:
            sys.stdout.write (x)
            sys.stdout.flush ()

if len (sys.argv) < 4:
    print ("usage: rctest circuit destaddr verification [ sysname ]")
    sys.exit (0)
    
port = sys.argv[1]
dest = sys.argv[2]
verification = sys.argv[3]
try:
    sysname = sys.argv[4]
except IndexError:
    sysname = None

# Build the destination URL.  This is the same for all the requests we
# will send.
url = "https://127.0.0.1:8443/api/mop/circuits/{}/console".format (port)
if sysname:
    url += "?system={}".format (sysname)
ses = requests.Session ()

# Issue the console client start request
req = { "dest" : dest, "verification" : verification }
resp = ses.post (url, json = req, verify = False)
ret = resp.json ()
stat = ret["status"]
if stat != "ok":
    print ("console start failure:", stat)
    sys.exit (1)
handle = ret["handle"]

print ("console client started, handle:", handle)

# Start the output thread
t = threading.Thread(target = tt)
t.daemon = True
t.start ()
# Enter the keyboard loop
kb ()

print ("\nconsole client closed")

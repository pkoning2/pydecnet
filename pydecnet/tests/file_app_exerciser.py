#!/usr/bin/env python3

""" Test application for session layer unit test

This application is referenced by test_session.py to exercise the
various session layer APIs, as an external subprocess.
"""

import sys
import json
import os
import signal

def main (argv):
    encode = json.JSONEncoder ().encode
    decode = json.JSONDecoder ().decode
    conn1 = conn2 = None
    for work in sys.stdin:
        work = decode (work)
        conn = work["handle"]
        type = work["type"]
        if type == "connecting":
            conn2 = conn
            req = { "handle" : conn1, "type" : "data",
                    "data" : "connection created" }
            msg = encode (req)
            print (msg, flush = True)
            continue
        msg = work["data"]
        assert conn == conn1 or conn == conn2 or conn1 is None
        if type == "connect":
            if msg == "reject":
                req = { "handle" : conn, "type" : "reject",
                        "data" : "rejected" }
            elif msg == "crash":
                raise Exception ("Crash at startup")
            else:
                req = { "handle" : conn, "type" : "accept",
                        "data" : "accepted" }
                conn1 = conn
            msg = encode (req)
            print (msg, flush = True)
        elif type == "data":
            if msg == "argument":
                req = { "handle" : conn, "type" : "data",
                        "data" : repr (argv[1:]) }
            elif msg == "disconnect":
                req = { "handle" : conn, "type" : "disconnect",
                        "data" : "as requested" }
                if conn == conn1:
                    conn1 = None
                else:
                    conn2 = None
            elif msg == "abort":
                req = { "handle" : conn, "type" : "abort",
                        "data" : "aborted" }
                if conn == conn1:
                    conn1 = None
                else:
                    conn2 = None
            elif msg == "crash":
                raise Exception ("Crash while running")
            elif msg == "signal":
                os.kill (os.getpid (), signal.SIGTERM)
            elif msg == "connect":
                req = { "type" : "connect", "data" : "test",
                        "dest" : 0, "remuser" : 73 }
            else:
                req = { "handle" : conn, "type" : "data",
                        "data" : "echo: " + msg }
            msg = encode (req)
            print (msg, flush = True)
            # If no connections left, exit (successfully)
            if not (conn1 or conn2):
                return 0
        elif type == "interrupt":
            req = { "handle" : conn, "type" : "interrupt",
                    "data" : "echo interrupt" }
            msg = encode (req)
            print (msg, flush = True)
        elif type == "accept":
            req = { "handle" : conn, "type" : "data",
                    "data" : "accepted" }
            msg = encode (req)
            print (msg, flush = True)
        elif type == "reject":
            conn2 = None
            req = { "handle" : conn1, "type" : "data",
                    "data" : "rejected" }
            msg = encode (req)
            print (msg, flush = True)
        elif type == "disconnect":
            # No reply, but we log it
            logreq = dict (level = 20, message = "Disconnected")
            print (encode (logreq), file = sys.stderr, flush = True)
            if conn == conn1:
                conn1 = None
            else:
                conn2 = None
            # If no connections left, exit (successfully)
            if not (conn1 or conn2):
                return 0
        else:
            assert 0, "Unexpected request type {}".format (type)
    # Unexpected EOF on stdin without a preceding disconnect
    return 1
        
if __name__ == "__main__":
    sys.exit (main (sys.argv))

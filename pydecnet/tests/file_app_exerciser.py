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
        mtype = work["type"]
        if mtype == "connecting":
            conn2 = conn
            req = { "handle" : conn1, "mtype" : "data",
                    "data" : "connection created" }
            msg = encode (req)
            print (msg, flush = True)
            continue
        msg = work["data"]
        assert conn == conn1 or conn == conn2 or conn1 is None
        if mtype == "connect":
            if msg == "reject":
                req = { "handle" : conn, "mtype" : "reject",
                        "data" : "rejected" }
            elif msg == "crash":
                raise Exception ("Crash at startup")
            else:
                req = { "handle" : conn, "mtype" : "accept",
                        "data" : "accepted" }
                conn1 = conn
            msg = encode (req)
            print (msg, flush = True)
        elif mtype == "data":
            if msg == "argument":
                req = { "handle" : conn, "mtype" : "data",
                        "data" : repr (argv[1:]) }
            elif msg == "disconnect":
                req = { "handle" : conn, "mtype" : "disconnect",
                        "data" : "as requested" }
                if conn == conn1:
                    conn1 = None
                else:
                    conn2 = None
            elif msg == "abort":
                req = { "handle" : conn, "mtype" : "abort",
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
                req = { "mtype" : "connect", "data" : "test",
                        "dest" : 0, "remuser" : 73 }
            else:
                req = { "handle" : conn, "mtype" : "data",
                        "data" : "echo: " + msg }
            msg = encode (req)
            print (msg, flush = True)
            # If no connections left, exit (successfully)
            if not (conn1 or conn2):
                return 0
        elif mtype == "interrupt":
            req = { "handle" : conn, "mtype" : "interrupt",
                    "data" : "echo interrupt" }
            msg = encode (req)
            print (msg, flush = True)
        elif mtype == "accept":
            req = { "handle" : conn, "mtype" : "data",
                    "data" : "accepted" }
            msg = encode (req)
            print (msg, flush = True)
        elif mtype == "reject":
            conn2 = None
            req = { "handle" : conn1, "mtype" : "data",
                    "data" : "rejected" }
            msg = encode (req)
            print (msg, flush = True)
        elif mtype == "disconnect":
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
            assert 0, "Unexpected request type {}".format (mtype)
    # Unexpected EOF on stdin without a preceding disconnect
    return 1
        
if __name__ == "__main__":
    sys.exit (main (sys.argv))

#!/usr/bin/env python3

""" LSN (talk server application) implementation.

Implementation of the DECnet "talk" protocol.

There doesn't seem to be any specification for this.  The code here
is reverse-engineered from the DECnet/8 and DECnet/E implementations.
"""

import sys
import os

from decnet.connectors import SimplePipeConnector, DEBUG, INFO

def main (argv):
    """The main program for LSN, the talk program responder.  It is
    started as a subprocess by pydecnet, with pipes for the three
    standard file descriptors.
    """
    connector = SimplePipeConnector ()
    #connector.log (DEBUG, "Starting LSN with arguments {}", str (argv[1:]))
    # Get the TTY device name prefix, if supplied.
    if len (sys.argv) > 1:
        ttyfmt = sys.argv[1]
    else:
        # Not sure how well this works, but it's a default.
        ttyfmt = "/dev/ttys{:d}"
    # Get the first message, which should be a "connect"
    conn, msg = connector.recv ()
    assert conn and msg.type == "connect"
    # Find the sending node name, if available, else number.
    if isinstance (msg.destination, list):
        remnode = msg.destination[1]
    else:
        remnode = str (msg.destination)
    # Process the connect data.  We handle two cases:
    # Phase 1: dest tty (2), src tty (2), dialog flag (1)
    # Phase 2: format (1), reserved (1), next 5 as above
    # DECnet/8 only actually sets dest tty, the rest is zero.  Dialog flag
    # value 0 means single line send, 1 means two-way dialog mode.
    # We only pick up dest tty and ignore the rest.
    if len (msg) == 7 and msg[0] == 0:
        # Phase II and later, connect data format 0.  The common connect
        # data starts at the 3rd byte.
        msg = msg[2:]
    elif len (msg) != 5:
        msg = msg[2:]
        #raise RuntimeError ("Unsupported connect data format", msg)
    # Now decode
    ttynum = int.from_bytes (msg[0:2], "little")
    srctty = int.from_bytes (msg[2:4], "little")
    mode = msg[4]
    pfx = bytes ("TLK>{}_TT{:d}:".format (remnode, srctty), "ascii")
    # Open the terminal the sender wants to talk to
    dev = ttyfmt.format (ttynum)
    ttyfd = os.open (dev, os.O_WRONLY)
    # Accept, no data
    conn.accept ()
    while True:
        msg = conn.recv ()
        mtype = msg.type
        if mtype == "data":
            # DECnet/8 workaround: strip the high order bit from the
            # data, since it seems to be using "Mark 'parity' ASCII"
            t = bytes (i & 0x7f for i in msg)
            os.write (ttyfd, pfx + t + b"\r\n")
            #connector.log (INFO, "LSN: {}", str (t, "ascii"))
        elif mtype == "disconnect":
            # Client connection is closed, exit
            os.close (ttyfd)
            return 0
        else:
            # Unexpected message type
            os.close (ttyfd)
            return 2
    # Unexpected EOF on stdin without a preceding disconnect
    os.close (ttyfd)
    return 1
        
if __name__ == "__main__":
    sys.exit (main (sys.argv))

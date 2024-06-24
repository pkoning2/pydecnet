#!/usr/bin/env python3

""" Mirror (loopback application) implementation.

Implementation of the DECnet network management loopback protocol.
Refer to the specification:
    DECnet Digital Network Architecture Phase IV
    Network Management Functional Specification
    Order no. AA-X437A-TK (December 1983)
The protocol is described on page 172 of that document.

This module also serves as sample code for writing standalone program
applications in Python.  For the corresponding built-in module version
of MIRROR (which is the one that is the default built-in object 25) see
modules/mirror.py.  

This version uses the raw JSON encoded API to the PyDECnet session
layer.  For versions that use the "connector" wrapper classes, see
mirror2.py and mirror3.py.
"""

import sys
import json

def main (argv):
    """The main program for this process-level object.  It is started as
    a subprocess by pydecnet, with pipes for the three standard file
    descriptors.

    stdin carries a stream of JSON objects (one per line) which deliver
    Session Control messages for this program.

    stdout carries a stream of JSON objects (one per line) which contain
    requests from the program to Session control.

    stderr may be used for logging.  (TODO: should this be a config
    option?)  Normally it carries JSON objects (one per line) that are
    used as arguments for a logging.log call in pydecnet.  If a line is
    not a valid JSON encoded object, it is instead logged as a plain
    text message.

    A simple request/response server program such as MIRROR can simply
    wait for input, parse it and generate a response, then wait some
    more.  Applications that need to be full-duplex would typically
    create a helper thread so there is a thread for each direction.

    When done (typically when the last connection is closed, or earlier
    if something goes wrong) the program should exit.  If it exits
    prematurely, pydecnet will close any currently open connections.
    """
    encode = json.JSONEncoder ().encode
    decode = json.JSONDecoder ().decode
    # Example of a request to send something to the pydecnet logging
    # service.  A JSON encoded dict is sent to stderr, with elements
    # "level", "message" and optionally "args".  Level is an integer,
    # the log level (see the Python standard "logging" module
    # documentation.  "message" is the message to log, which is run
    # through "format" to fill in any arguments at { } placeholders.
    # "args" is a list of values -- typically strings -- which will be
    # substituted.  If no args are needed, this element may be
    # omitted, it will default to an empty list.
    logreq = dict (level = 10,
                   message = "Starting MIRROR with arguments {}",
                   args = [ str (argv[1:]) ])
    # Note that all writes to stderr and stdout must include a "flush"
    # operation, otherwise they won't be seen by pydecnet since we're
    # dealing with buffered streams at this end.
    print (encode (logreq), file = sys.stderr, flush = True)
    for work in sys.stdin:
        work = decode (work)
        # We now have a dict object which contains a work item from
        # Session Control.  Each corresponds to a
        # session.ApplicationWork item, delivering network traffic
        # received from the layers below.
        #
        # Each work item contains three standard fields:
        #   handle - an integer that uniquely identifies a connection
        #   type   - the type of data, for example "interrupt"
        #   data   - the payload received (as a latin-1 encoded string,
        #            which stands for the underlying bytes 1:1)
        #
        # For types "reject" and "disconnect" there is an additional
        # data item, "reason", an integer containing the disconnect or
        # reject reason code.
        conn = work["handle"]
        mtype = work["type"]
        msg = work["data"]
        if mtype == "data":
            if msg[0] == '\x00':
                # Function code: loop command. Reply with status code:
                # success.
                msg = "\x01" + msg[1:]
            else:
                # Reply with status code: failure.
                msg = "\xff"
            # Outgoing requests are written to stdout (in a single
            # line), JSON encoded.  The required fields are in general
            # the same as the three standard fields mentioned above
            # for incoming work items.  Note that "reason" is not used
            # because applications don't get to specify a disconnect
            # or reject reason (the reason for those actions when
            # requested by the application is always zero).
            #
            # Exception: outgoing connect requests have a different
            # set of arguments, refer to the documentation in api.txt
            # for details.
            req = { "handle" : conn, "type" : "data", "data" : msg }
            msg = encode (req)
            print (msg, flush = True)
        elif mtype == "connect":
            # Some applications may need to check the connect data (in
            # "msg") for example to handle a protocol version number
            # carried there.
            #
            # Similarly, the accept (Connect Confirm) message may need
            # data, which is the (optional) argument of the confirm
            # method on the connection.  Alternatively, the
            # application may reject the connect request by calling
            # the conn.reject method.
            #
            # For MIRROR, the accept data is the max data length, a
            # two byte integer.  We have no limit so send 65535.
            i = 65535
            msg = str (i.to_bytes (2, "little"), "latin1")
            req = { "handle" : conn, "type" : "accept",
                    "data" : msg }
            msg = encode (req)
            print (msg, flush = True)
        elif mtype == "disconnect":
            # Client connection is closed, exit
            return 0
    # Unexpected EOF on stdin without a preceding disconnect
    return 1
        
if __name__ == "__main__":
    sys.exit (main (sys.argv))

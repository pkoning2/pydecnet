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

This version uses the SimplePipeConnector to wrap the low level JSON
interface.
"""

import sys

from decnet.connectors import SimplePipeConnector, DEBUG

def main (argv):
    """The main program for this process-level object.  It is started as
    a subprocess by pydecnet, with pipes for the three standard file
    descriptors.

    In the version shown here, we use the SimplePipeConnector helper
    object to wrap those pipes and expose to the application a
    friendlier interface, similar to the module-level API used in the
    module style object.  
    """
    connector = SimplePipeConnector ()
    # Example of a request to send something to the pydecnet logging
    # service.  The arguments to this method are the same as for the
    # standard Python library logging.log function.
    connector.log (DEBUG, "Starting MIRROR with arguments {}", str (argv[1:]))
    # Get the first message, which should be a "connect"
    conn, msg = connector.recv ()
    assert conn and msg.type == "connect"
    # Some applications may need to check the connect data (in
    # "msg") for example to handle a protocol version number
    # carried there.  Nothing is needed for mirror.
    #
    # After receiving the connect, the application must accept (Connect
    # Confirm) message may need data, which is the (optional) argument
    # of the confirm method on the connection.  Alternatively, the
    # application may reject the connect request by calling the
    # conn.reject method.  One or the other must be done before the
    # sender of the Connect Initiate times out.
    #
    # For MIRROR, the accept data is the max data length, a
    # two byte integer.  We have no limit so send 65535.
    i = 65535
    msg = i.to_bytes (2, "little")
    conn.accept (msg)
    while True:
        msg = conn.recv ()
        # conn is a connectors.Connection object with an API similar
        # to that of a standard DECnet connection.  In particular, it
        # has a set of methods for sending messages of various kinds.
        #
        # msg is a ConnMessage instance encapsulating a message
        # received from Session Control.  Each corresponds to a
        # session.ApplicationWork item, delivering network traffic
        # received from the layers below.  ConnMessage is a subtype of
        # "bytes", which carries the message data.
        #
        # Each message instance has a standard attribute:
        #   type   - the type of data, for example "interrupt"
        #
        # For types "reject" and "disconnect" there is an additional
        # data item, "reason", an integer containing the disconnect or
        # reject reason code.
        mtype = msg.type
        if mtype == "data":
            if msg[0] == 0:
                # Function code: loop command. Reply with status code:
                # success.
                msg = b"\x01" + msg[1:]
            else:
                # Reply with status code: failure.
                msg = b"\xff"
            # Outgoing requests are made by calls to the connection
            # object.
            conn.data (msg)
        elif mtype == "disconnect":
            # Client connection is closed, exit
            return 0
        else:
            # Unexpected message type
            return 2
    # Unexpected EOF on stdin without a preceding disconnect
    return 1
        
if __name__ == "__main__":
    sys.exit (main (sys.argv))

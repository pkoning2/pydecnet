#!

""" Mirror (loopback application) implementation.

Implementation of the DECnet network management loopback protocol.
Refer to the specification:
    DECnet Digital Network Architecture Phase IV
    Network Management Functional Specification
    Order no. AA-X437A-TK (December 1983)
The protocol is described on page 172 of that document.

This module also serves as sample code for writing Python module based
applications.  For a sample external (executable file running in a new
process) application, look in samples/mirror.py.  That implements the
same protocol but as an external process via the JSON API.
"""

from decnet.common import Element
from decnet import session

SvnFileRev = "$LastChangedRevision$"

class Application (Element):
    def __init__ (self, parent, obj):
        super ().__init__ (parent)
        # obj is not needed here.  Some applications may want to refer
        # to it, specifically obj.argument (the value in the
        # --argument switch in the object definition).

    def dispatch (self, item):
        # Process work sent up from the Session Control layer.  It
        # arrives in the form of an object subclassed from
        # session.ApplicationWork.  The individual work items can be
        # distinguished by their class (using isinstance) or by name,
        # which is how they are sent to the JSON API.  Name may be
        # useful if you don't want to import decnet.session to get the
        # class names.
        #
        # All these work items have a "data" attribute which is a
        # bytes object, the application data in that particular
        # message.  (For example, for a Connect Init it is the connect
        # data, if supplied by the sender.)  And the "connection"
        # attribute refers to the SessionConnection object, which has
        # methods such as "send_data" or "confirm" for the application
        # to send messages to the client.
        #
        # The specific items that can appear are, shown as <class> (<name>):
        #  ConnectInit (connect): an incoming connection request.
        #  Data (data): Normal data.  This is a full message, after
        #    reassembly.
        #  Interrupt (interrupt): Interrupt data.
        #  Disconnect (disconnect): A disconnect or abort.  This work
        #    item has an additional attribute "reason", an integer
        #    specifying the disconnect reason code.  When this item is
        #    delivered, the connection has been closed.
        conn = item.connection
        msg = item.message
        if isinstance (item, session.Data):
            if msg[0] == 0:
                # Function code: loop command. Reply with status code:
                # success.
                conn.send_data (b"\x01" + msg[1:])
            else:
                # Reply with status code: failure.
                conn.send_data (b"\xff")
        elif isinstance (item, session.ConnectInit):
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
            conn.accept (i.to_bytes (2, "little"))
        elif item.name == "disconnect":
            # This shows how to match a work item by its name instead
            # of by its type.  Some applications may need to do
            # cleanup for a disconnect, in a way that may depend on
            # the disconnect reason and/or disconnect data.  For
            # Mirror, we have nothing to do.
            pass
        

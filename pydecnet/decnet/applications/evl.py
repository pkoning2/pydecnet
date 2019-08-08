#!

"""Event log listener implementation.

Implementation of the DECnet network management event logging protocol.
Refer to the specification:
    DECnet Digital Network Architecture Phase IV
    Network Management Functional Specification
    Order no. AA-X437A-TK (December 1983)

This is the listener end of the protocol, i.e., it handles incoming 
event messages from another node that specified this one as its 
"sink node".

Received events are converted to Event objects which are delivered to
the Python logging machinery, which will format them and send them to
whatever destinations are specified in the logging configuration.
"""

from decnet.common import *
from decnet import session
from decnet import pktlogging
from decnet import events

SvnFileRev = "$LastChangedRevision$"

class Application (Element):
    def __init__ (self, parent, obj):
        super ().__init__ (parent)

    def dispatch (self, item):
        # Process work sent up from the Session Control layer. 
        conn = item.connection
        msg = item.message
        pktlogging.tracepkt ("Event {} message".format (item.name), msg)
        if isinstance (item, session.Data):
            try:
                # All we have to do is decode the event message into
                # an Event object, then send that to our logger.
                e = events.decode_event (msg)
                logging.log (e.loglevel, e)
            except DecodeError:
                logging.exception ("Error parsing event {}", msg)
        elif isinstance (item, session.ConnectInit):
            # Check the connect data (in "msg") which carries the
            # protocol version number.  Here we save it in case it's
            # needed but take no action on it; it doesn't seem that
            # there are any version dependent algorithms in this
            # protocol.
            self.rversion = msg
            # Set the RSTS segmentation workaround bug, because the
            # DECnet/E event sender does not manage the BOM/EOM flags
            # correctly.
            conn.setsockopt (rstssegbug = True)
            # Accept the connection; our version number is 4.0.0.
            conn.accept (bytes ([4, 0, 0]))

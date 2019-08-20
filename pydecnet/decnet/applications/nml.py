#!

"""Network management listener implementation.

Implementation of the DECnet network management (NICE) protocol.
Refer to the specification:
    DECnet Digital Network Architecture Phase IV
    Network Management Functional Specification
    Order no. AA-X437A-TK (December 1983)

This is the listener end of the protocol, i.e., it handles incoming 
event messages from another node to process requests from NCP.
"""

from decnet.common import *
from decnet import session
from decnet import pktlogging
from decnet import nicepackets

SvnFileRev = "$LastChangedRevision$"

MYVERSION = ( 4, 0, 0 )

class Application (Element):
    def __init__ (self, parent, obj):
        super ().__init__ (parent)

    def dispatch (self, item):
        # Process work sent up from the Session Control layer. 
        conn = item.connection
        msg = item.message
        pktlogging.tracepkt ("NICE {} message".format (item.name), msg, logging.DEBUG)
        if isinstance (item, session.Data):
            try:
                fun = msg[0]
                if fun != nicepackets.NiceReadInfoHdr.function:
                    logging.trace ("Unsupported NICE request")
                    resp = nicepackets.NiceReply ()
                    resp.retcode = -1   # Unrecognized function
                    conn.send_data (resp)
                    return
                ent = msg[1] & 0x07
                cls = nicepackets.NiceReadInfoHdr.findclass (ent)
                resp = 0
                detail = 0xffff
                try:
                    req = cls (msg)
                    detail = req.entity_class.e_type
                except DecodeError:
                    logging.debug ("Invalid NICE request packet: {}", msg)
                    resp = -1
                if not resp:
                    if  req.permanent:
                        logging.trace ("Read permanent data not supported")
                        resp = -1   # Unrecognized function
                    else:
                        resp = self.node.nice_read (req)
                if not resp:     # Reply is None or empty
                    resp = -8    # Unrecognized component
                if isinstance (resp, int):
                    # Error code returned
                    logging.trace ("Read data error code {}", resp)
                    resp2 = nicepackets.NiceReply ()
                    resp2.retcode = resp
                    resp2.detail = detail
                    conn.send_data (resp2)
                    return
                resp = [ v for k, v in resp.sorted (req) ]
                if len (resp) == 1 and (not isinstance (resp[0], list) or
                                        len (resp[0]) == 1):
                    resp = resp[0]
                    if isinstance (resp, list):
                        resp = resp[0]                        
                    resp.retcode = 1   # success
                    conn.send_data (resp)
                else:
                    resp0 = nicepackets.NiceReply ()
                    resp0.retcode = 2   # multiple items
                    conn.send_data (resp0)
                    for r in resp:
                        if not r:
                            continue
                        if isinstance (r, list):
                            for r2 in r[:-1]:
                                r2.retcode = 3  # more for this entity
                                conn.send_data (r2)
                            r = r[-1]
                        r.retcode = 1  # success
                        conn.send_data (r)
                    resp = nicepackets.NiceReply ()
                    resp.retcode = -128   # end of multiple items
                    conn.send_data (resp)
            except DecodeError:
                logging.exception ("Error parsing event {}", msg)
        elif isinstance (item, session.ConnectInit):
            # Check the connect data (in "msg") which carries the
            # protocol version number.  Here we save it in case it's
            # needed but take no action on it; it doesn't seem that
            # there are any version dependent algorithms in this
            # protocol.
            self.rversion = msg[:3]
            logging.trace ("Network management listener connection from {}, version {}",
                           conn.remotenode,
                           ".".join (str (i) for i in self.rversion))
            # Accept the connection; our version number is 4.0.0.
            conn.accept (MYVERSION)
        elif isinstance (item, session.Disconnect):
            logging.trace ("Network management listener disconnect from {}",
                           conn.remotenode)

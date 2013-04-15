#!

"""NSP (End Communications and Session Control layers) for DECnet/Python

"""

import random
from collections import deque

from .common import *
from .routing_packets import ShortData, LongData
from .events import *
from . import packet
from . import timers
from . import statemachine

# NSP packet layouts.  These cover the routing layer payload (or the
# datalink layer payload, in the case of Phase II)

# Common header -- just the MSGFLG field, expanded into its subfields.
class NspHdr (packet.Packet):
    _layout = (( "bm",
                 ( "mbz", 0, 2 ),
                 ( "type", 2, 2 ),
                 ( "subtype", 4, 3 ),
                 ( "int_ls", 4, 1 ),
                 ( "bom", 5, 1 ),    # if int_ls == 0 (data message)
                 ( "eom", 6, 1 ),    # if int_ls == 0 (data message)
                 ( "int", 5, 1 ),    # if int_ls == 1 (other-data message)
                 ( "mbz2", 7, 1 )), )
    mbz = 0
    mbz2 = 0
    # type codes
    DATA = 0
    ACK = 1
    CTL = 2
    # Ack subtype codes
    ACK_DATA = 0
    ACK_OTHER = 1
    ACK_CONN = 2
    # Control subtype codes
    #NOP = 0   # Phase 2 NOP (doesn't come to NSP)
    CI = 1
    CC = 2
    DI = 3
    DC = 4
    #NI = 5    # Phase 2 node init (doesn't come to NSP)
    RCI = 6    # Retransmitted CI
    
    def encode_optack (self, field, x):
        """The third argument -- usually length -- instead encodes the
        cross-subchannel bit of the QUAL field.
        """
        v = getattr (self, field, None)
        if v is None:
            return b''
        x &= 2
        m = (getattr (self, field + "_qual", 0) & 1) + x
        v = (v & 4095) + (m << 12) + 0x8000
        return v.to_bytes (2, LE)

    def decode_optack (self, field, x):
        """The third argument -- usually length -- instead encodes the
        cross-subchannel bit of the QUAL field.  We expect it to match.
        In other words, even though theoretically one could put a cross-
        subchannel ack in before a regular ack, this won't work.  You're
        allowed to omit one, either one, but if both are present the
        cross-subchannel one has to be second because that's how the packet
        layout tables specify it.
        """
        v = int.from_bytes (buf[:2])
        if v & 0x8000:
            m = ((v >> 12) & 3) - x
            v &= 4095
            # Check that cross-channel is in the expected spot
            if m in (0, 1):
                setattr (self, field, v)
                setattr (self, field + "_qual", m)
                return buf[2:]
        setattr (self, field, None)
        return buf

class AckData (NspHdr):
    _layout = (( "b", "dstaddr", 2 ),
               ( "b", "srcaddr", 2 ),
               ( "optack", "acknum", 0 ),  # This is mandatory
               ( "optack", "ackoth", 2 ))
    type = NspHdr.ACK
    subtype = NspHdr.ACK_DATA
    
class AckInt (NspHdr):
    _layout = (( "b", "dstaddr", 2 ),
               ( "b", "srcaddr", 2 ),
               ( "optack", "acknum", 0 ),
               ( "optack", "ackdat", 2 ))
    type = NspHdr.ACK
    subtype = NspHdr.ACK_OTHER

class AckConn (NspHdr):
    _layout = (( "b", "dstaddr", 2 ),)
    type = NspHdr.ACK
    subtype = NspHdr.ACK_CONN
    
# Data messages start with the same stuff as ACK messages, so subclass
# them that way.
class DataSeg (AckData):
    _layout = (( "b", "segnum", 2 ),)
    type = NspHdr.DATA
    subtype = 0
    int_ls = 0
    
class IntMsg (AckInt):
    _layout = (( "b", "segnum", 2 ),)
    type = NspHdr.DATA
    subtype = 0
    int_ls = 1
    int = 1

# Link Service message is a variation on interrupt message.
class LinkSvcMsg (IntMsg):
    _layout = (( "bm",
                 ( "fcmod", 0, 2 ),
                 ( "fcval_int", 2, 3 )),
               ( "signed", "fcval", 1 ))
    int = 0
    # fcval_int values:
    DATA_REQ = 0
    INT_REQ = 1
    # fcmod values:
    NO_CHANGE = 0
    XOFF = 1
    XON = 2

# Control messages.  0 (NOP) and 5 (Node init) are handled
# in route_ptp since they are really datalink dependent routing
# layer messages.
class ConnInit (NspHdr):
    _layout = (( "b", "dstaddr", 2 ),
               ( "b", "srcaddr", 2 ),
               ( "ex", "services", 1 ),
               ( "ex", "info", 1 ),
               ( "b", "segsize", 2 ))
    subtype = NspHdr.CI
    dstaddr = 0
    # Services:
    SVC_NONE = 0
    SVC_SEG = 1 << 2    # Segment flow control
    SVC_MSG = 2 << 2    # Message flow control
    # Info:
    VER_PH3 = 0         # Phase 3 (NSP 3.2)
    VER_PH2 = 1         # Phase 2 (NSP 3.1)
    VER_PH4 = 2         # Phase 4 (NSP 4.0)

class RetConnInit (ConnInit):
    subtype = NspHdr.RCI
    info = ConnInit.VER_PH4

# Connect Confirm is very similar to Connect Confirm (the differences are
# mainly in the session layer, which is just payload to us).
# However, the scraddr is now non-zero.
class ConnConf (ConnInit):
    _layout = (( "i", "data_ctl", 16 ),)    # CC payload is an I field
    subtype = NspHdr.CC
    srcaddr = None    # Cancel the fixed 0 in ConnInit

class DiscConf (NspHdr):
    _layout = (( "b", "dstaddr", 2 ),
               ( "b", "srcaddr", 2 ),
               ( "b", "reason", 2 ))
    subtype = NspHdr.DC

# DI is like DC but it adds session control disconnect data
class DiscInit (DiscConf):
    _layout = (( "i", "data_ctl", 16 ),)
    subtype = NspHdr.DI
    
class NSP (Element):
    """The NSP Entity.  This owns all the connections.  It implements
    the ECL (formerly NSP) layer of the DECnet Network Architecture.
    """
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        logging.debug ("Initializing NSP")
        self.connections = dict ()
        self.config = config = config.nsp
        c = self.maxconns = config.max_connections
        c += 1
        #self.freeconns = set (range (1, 65536))
        self.freeconns = deque (i + random.randrange (0, 65536, c)
                                for i in range (1, c))
        
    def start (self):
        logging.debug ("Starting NSP")
        self.routing = self.parent.routing

    def stop (self):
        logging.debug ("Stopping NSP")

    def dispatch (self, item):
        if isinstance (item, Received):
            # Arriving packet delivered up from Routing.
            logging.trace ("NSP packet received from %s: %s",
                           item.src, item.packet)

    def get_id (self):
        """Return a free connection ID, per the algorithm in the NSP spec.
        Note that the Phase 2 spec mandates this (it's not just a suggestion)
        for "intercept" node interoperability.
        """
        if not self.freeconns:
            return None
        return self.freeconns.popleft ()

    def ret_id (self, i):
        i = (i + self.maxconns + 1) & 0xffff
        self.freeconns.append (i)
        
class Connection (Element, statemachine.StateMachine):
    """An NSP connection object.
    """
    def __init__ (self, parent):
        Element.__init__ (self, parent)
        statemachine.StateMachine.__init__ (self)
        # srcaddr and dstaddr are the connection identifiers, not
        # node addresses -- this matches the spec terminology
        self.srcaddr = srcaddr = self.parent.get_id ()
        if srcaddr is None:
            raise Exception ("Connection limit")
        self.dstaddr = 0
        self.ackdat = self.ackoth = 0
        self.pending_dat = list ()
        # We use the optional "multiple other-data messages allowed at a time"
        # model, rather than the one at a time model that the NSP spec uses.
        self.pending_oth = list ()
        # These flow control variables describe the other end flow control;
        # we don't use flow control (there isn't much point given how
        # Python manages memory).
        self.flowtype = None
        self.req_dat = self.req_oth = 0
        self.dat_on = True
        
        self.destnode = None
        # All done.  Add this connection to the dictionary of connections
        # known to NSP.
        self.parent.connections[srcaddr] = self
        
    def __del__ (self):
        self.parent.ret_id (self.srcaddr)


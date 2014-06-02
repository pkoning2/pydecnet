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
from . import modulo

# NSP packet layouts.  These cover the routing layer payload (or the
# datalink layer payload, in the case of Phase II)

# Sequence numbers are modulo 4096
class Seq (modulo.Mod, mod = 4096):
    """Sequence numbers for NSP -- integers modulo 2^12.
    """
    _len = 2

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
            # The relevant ack number attribute is not defined or is
            # set to None -- skip this ack number field
            return b''
        m = (getattr (self, field + "_qual", 0) & 1) + x
        v = int (v) + (m << 12) + 0x8000
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
            v = Seq (v)
            # Check that cross-channel is in the expected spot
            if m in (0, 1):
                setattr (self, field, v)
                setattr (self, field + "_qual", m)
                return buf[2:]
        setattr (self, field, None)
        return buf

# Note on classes for packet layouts:
#
# It is tempting at times to make packet type x a subclass of packet
# type y, when x looks just like y but with some extra stuff, or with
# a change in type code only.  IntMsg vs. LinkSvcMsg are an example
# of the former, AckData vs. AckOther or DataSeg vs. IntMsg an example
# of the latter.  This is typically not a good idea, because "isinstance"
# will match an object of a subclass of the supplied class.  To keep
# the actual message classes distinct, in the hierarchy below they are
# almost always derived from a base class that is not in itself an
# actual message class.

class AckData (NspHdr):
    _layout = (( "b", "dstaddr", 2 ),
               ( "b", "srcaddr", 2 ),
               ( "optack", "acknum", 0 ),  # This is mandatory
               ( "optack", "ackoth", 2 ))
    type = NspHdr.ACK
    subtype = NspHdr.ACK_DATA
    
class AckOther (NspHdr):
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
    _addslots = { "payload" }
    _layout = (( Seq, "segnum" ),)
    type = NspHdr.DATA
    subtype = 0
    
class IntMsg (AckOther):
    _addslots = { "payload" }
    _layout = (( Seq, "segnum" ),)
    type = NspHdr.DATA
    subtype = 3

# Link Service message is a variation on interrupt message.
class LinkSvcMsg (AckOther):
    _layout = (( Seq, "segnum" ),
               ( "bm",
                 ( "fcmod", 0, 2 ),
                 ( "fcval_int", 2, 3 )),
               ( "signed", "fcval", 1 ))
    subtype = 1
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

# Common parts of CI, RCI, and CC
class ConnMsg (NspHdr):
    _layout = (( "b", "dstaddr", 2 ),
               ( "b", "srcaddr", 2 ),
               ( "bm",
                 ( "mb1", 0, 2 ),
                 ( "fcopt", 2, 2 ),
                 ( "mbz", 4, 4 )),
               ( "ex", "info", 1 ),
               ( "b", "segsize", 2 ))
    type = NspHdr.CTL
    mb1 = 1
    mbz = 0
    # Services:
    SVC_NONE = 0
    SVC_SEG = 1         # Segment flow control
    SVC_MSG = 2         # Message flow control
    # Info:
    VER_PH3 = 0         # Phase 3 (NSP 3.2)
    VER_PH2 = 1         # Phase 2 (NSP 3.1)
    VER_PH4 = 2         # Phase 4 (NSP 4.0)

# This is either Connect Initiate or Retransmitted Connect Initiate
# depending on the subtype value.
class ConnInit (ConnMsg):
    _addslots = { "payload" }
    #subtype = NspHdr.CI
    #subtype = NspHdr.RCI
    dstaddr = 0
    
# Connect Confirm is very similar to Connect Init (the differences are
# mainly in the session layer, which is just payload to us).
# However, the scraddr is now non-zero.
class ConnConf (ConnMsg):
    _layout = (( "i", "data_ctl", 16 ),)    # CC payload is an I field
    subtype = NspHdr.CC
    srcaddr = None    # Cancel the fixed 0 in ConnInit

class DiscConf (NspHdr):
    _layout = (( "b", "dstaddr", 2 ),
               ( "b", "srcaddr", 2 ),
               ( "b", "reason", 2 ))
    type = NspHdr.CTL
    subtype = NspHdr.DC

# Three reason codes are treated as specific packets in the NSP spec;
# all others are in effect synonyms for disconnect initiate for Phase II
# compatibility.  Define subclasses for the three here so we can use
# those later.
class NoRes (DiscConf):
    reason = 1

class DiscComp (DiscConf):
    reason = 42

class NoLink (DiscConf):
    reason = 43

# DI is like DC but it adds session control disconnect data
class DiscInit (DiscConf):
    _layout = (( "i", "data_ctl", 16 ),)
    subtype = NspHdr.DI

# Mapping from packet type code (msgflg field) to packet class
msgmap = { (c.type << 2) + (c.subtype << 4) : c
           for c in ( AckData, AckOther, AckConn, ConnConf,
                      DiscConf, DiscInit, IntMsg, LinkSvcMsg ) }
# Put in Connect Init with its two msgflag values
msgmap[(NspHdr.CTL << 2) + (NspHdr.CI << 4)] = ConnInit
msgmap[(NspHdr.CTL << 2) + (NspHdr.RCI << 4)] = ConnInit
# For data segments we put in all 4 combinations of bom/eom flags so
# we can just do the message map without having to check for those cases
# separately.
for st in range (4):
    msgmap[NspHdr.DATA + (st << 5)] = DataSeg

# Mapping from reason to specific Disconnect Confirm subclass
dcmap = { c.reason : c for c in ( NoRes, DiscComp, NoLink ) }

class NSPNode (object):
    """The remote node state needed by NSP.  This is a base class of
    the Nodeinfo object, which is what node.nodeinfo() returns.
    """
    def __init__ (self):
        # NSP specific node state -- see NSP 4.0.1 spec, table 6.
        self.delay = 0
        self.byt_rcv = 0
        self.byt_xmt = 0
        self.msg_rcv = 0
        self.msg_xmt = 0
        self.con_rcv = 0
        self.con_xmt = 0
        self.con_rej = 0
        self.timeout = 0

# Packet types that trigger No Link response if not mapped to a connection
nolinkset = { ConnConf, DiscInit, DataSeg, IntMsg, LinkSvcMsg }

class NSP (Element):
    """The NSP Entity.  This owns all the connections.  It implements
    the ECL (formerly NSP) layer of the DECnet Network Architecture.
    """
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        logging.debug ("Initializing NSP")
        # Dictionary of connections indexed by local connection address
        self.connections = dict ()
        # Ditto but indexed by node ID and remote connection address
        self.rconnections = dict ()
        self.config = config = config.nsp
        self.maxconns = config.max_connections
        self.init_id ()
        
    def start (self):
        logging.debug ("Starting NSP")
        self.routing = self.parent.routing

    def stop (self):
        logging.debug ("Stopping NSP")

    def dispatch (self, item):
        if isinstance (item, Received):
            # Arriving packet delivered up from Routing.  Map the packet
            # to a port (Connection object), see NSP 4.0.1 spec
            # section 6.2 (receive dispatcher)
            buf = item.packet.payload
            logging.trace ("NSP packet received from %s: %s",
                           item.src, item.packet)
            msgflg = packet.getbyte (buf)
            try:
                t = msgmap[msgflg]
            except KeyError:
                # TYPE or SUBTYPE invalid, or MSGFLG is extended (step 1)
                logging.trace ("Unrecognized msgflg value %d, ignored", msgflg)
                return
            pkt = t (buf)
            if t is DiscConf:
                # Do a further lookup on disconnect confirm reason code
                # (step 5)
                try:
                    t = dcmap[pkt.reason]
                    pkt = t (buf)
                except KeyError:
                    # Other Disconnect Confirm, that's Phase II stuff.
                    # Handle it as a Disconnect Initiate
                    t = DiscInit
                    pkt = t (buf)
            if t is ConnInit:
                # Step 4: if this is a returned CI, find the connection
                # that sent it.
                if item.rts:
                    try:
                        conn = self.connections[pkt.srcaddr]
                    except KeyError:
                        # Not there, must have been deleted.  Ignore.
                        return
                else:
                    # Step 3: see if this is a retransmit, otherwise
                    # map it onto a new Connection if available.
                    cikey = (item.src, pkt.srcaddr)
                    if cikey in self.rconnections:
                        conn = self.rconnections[cikey]
                    else:
                        try:
                            conn = Connection (self)
                        except Exception:
                            # Can't create another connection, send
                            # No Resources.
                            nr = NoRes (srcaddr = 0, dstaddr = pkt.srcaddr)
                            self.node.routing.send (nr, item.src)
                            return
                        conn.dstaddr = pkt.srcaddr
                        conn.destnode = self.node.nodeinfo (item.src)
                        self.rconnections[cikey] = conn
            else:
                # Step 6 or 7: look up via the local link address.
                try:
                    conn = self.connections[pkt.dstaddr]
                except KeyError:
                    # Not found, remember that
                    conn = None
                # If a connection is found and the state is not CI,
                # and the packet is not Connect Ack, check the remote
                # link address also
                if conn and conn.state != conn.ci and t is not ConnAck:
                    if conn.dstaddr != pkt.srcaddr:
                        conn = None
                # If any of these checks failed, send No Link if the packet
                # type is one for which we do that.
                if not conn:
                    if t in nolinkset:
                        nl = NoLink (srcaddr = pkt.dstaddr,
                                     dstaddr = pkt.srcaddr)
                        self.node.routing.send (nl, item.src)
                    return
            # Packet is mapped to a port, so process it there.
            conn.dispatch (item)
            
    def init_id (self):
        # Initialize the free connection ID list
        c = self.maxconns + 1
        self.freeconns = deque (i + random.randrange (0, 65536, c)
                                for i in range (1, c))
        
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

class txqentry (timers.Timer):
    """An entry in the retransmit queue for a subchannel.
    """
    __slots__ = ("packet", "txtime", "channel", "tries", "seqnum")
    def __init__ (self, packet, channel, seqnum):
        super ().__init__ ()
        self.packet = packet
        self.seqnum = seqnum
        self.channel = channel
        self.tries = self.txtime = 0

    def send (self):
        if type (self.packet) is ConnInit:
            if self.tries:
                self.packet.subtype = NspHdr.RCI
            else:
                self.packet.subtype = NspHdr.CI
        self.channel.node.timers.start (self, self.channel.acktimeout ())
        self.tries += 1

    def ack (self):
        """Handle acknowledgment of packet.  Also used when the packet
        is not going to be transmitted again for some other reason
        (like connection abort).

        Returns True if this is a packet for which the message flow control
        request count is adjusted.
        """
        self.channel.node.timers.stop (self)
        if self.txtime:
            self.channel.parent.update_delay (self.txtime)
        t = type (self.packet)
        return t is IntMsg or (t is DataSeg and t.eom)
        
class Subchannel (Element, timers.Timer):
    """A subchannel (data or other-data) within an NSP connection.  This
    is where we keep the per-subchannel state: queues, flow control
    parameters, sequence numbers, etc.

    The timer base class is for the ack holdoff timer.
    """
    # Classes for associated packets
    Ack = AckData
    
    def __init__ (self, parent):
        Element.__init__ (self, parent)
        timers.Timer.__init__ (self)
        self.pending_ack = deque ()   # List of pending txqentry items
        self.seqnum = Seq (1)         # Next transmitted sequence number
        self.acknum = Seq (0)         # Outbound ack number
        # The flow control parameters are remote flow control -- we don't
        # do local flow control other than to request another interrupt
        # each time we get one.  So there are no explicit local flow
        # attributes.
        self.reqnum = 0               # Count requested by remote
        self.minreq = 0               # Lowest allowed value of minreq
        self.xon = True               # Flow on/off switch
        self.flow = ConnInit.SVC_NONE # Outbound flow control selected
        self.ooo = dict ()            # Pending received out of order packets

    def dispatch (self, item):
        if isinstance (item, timers.Timeout):
            # Send an explicit ack
            ack = self.parent.makepacket (self.Ack, acknum = self.acknum,
                                          acknum_qual = 0)
            self.parent.send (ack)
        else:
            item.subchannel = self
            self.parent.dispatch (item)

    def ack (self, acknum):
        """Handle a received ack on this subchannel.
        """
        firsttxq = self.pending_ack[0]
        if acknum <= firsttqx.seqnum or acknum >= self.seqnum:
            # Duplicate or out of range ack, ignore
            return
        while True:
            acked = self.pending_ack.popleft ()
            adj = (acked.ack () and self.flow == ConnInit.SVC_MSG) or \
                  self.flow == ConnInit.SVC_SEG
            self.reqnum -= adj
            if acked.seqnum == acknum:
                break
            
class Other_Subchannel (Subchannel):
    Ack = AckOther

    def __init__ (self, parent):
        super ().__init__ (parent)
        self.reqnum = 1               # Other data req count initially 1
        # Interrupt flow control is different from data flow control, but
        # the closest analog is message flow control because the count
        # cannot be negative, and not every packet is subjected to control.
        # (In this case, interrupts are but link service messages are not.)
        self.flow = ConnInit.SVC_MSG
        
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
        self.parent.connections[srcaddr] = self
        self.dstaddr = 0
        self.data = Subchannel ()
        # We use the optional "multiple other-data messages allowed at a time"
        # model, rather than the one at a time model that the NSP spec uses.
        # That makes the two subchannels look basically the same -- same data
        # structures, same control machinery.
        self.other = Other_Subchannel ()
        
        self.destnode = None
        # All done.  Add this connection to the dictionary of connections
        # known to NSP.
        self.parent.connections[srcaddr] = self
        
    def __del__ (self):
        self.parent.ret_id (self.srcaddr)

    def update_delay (self, txtime):
        if txtime and self.destnode:
            delta = time.time () - txtime
            if self.destnode.delay:
                # TODO: weighted average
                pass
            else:
                self.destnode.delay = delta
                
    def makepacket (self, cls, **kwds):
        return cls (srcaddr = self.srcaddr, dstaddr = self.dstaddr, **kwds)

    def send (self, pkt):
        pass


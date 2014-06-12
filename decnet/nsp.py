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
    NOP = 0    # NOP (normally only in Phase II, but spec doesn't restrict it)
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
class DiscInit (NspHdr):
    _layout = (( "b", "dstaddr", 2 ),
               ( "b", "srcaddr", 2 ),
               ( "b", "reason", 2 ),
               ( "i", "data_ctl", 16 ))
    type = NspHdr.CTL
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
# Put in an "ignore me" entry for NOP packets
msgmap[(NspHdr.CTL << 2) + (NspHdr.NOP << 4)] = None

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
        # Create the "reserved port"
        self.resport = ReservedPort (self)
        self.nspver = (ConnMsg.VER_PH2, ConnMsg.VER_PH3, ConnMsg.VER_PH4)[self.node.phase - 2]
        
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
            msgflg = buf[0]
            try:
                t = msgmap[msgflg]
            except KeyError:
                # TYPE or SUBTYPE invalid, or MSGFLG is extended (step 1)
                logging.trace ("Unrecognized msgflg value %d, ignored", msgflg)
                # FIXME: this needs to log the message in the right format
                self.node.logevent (Event.inv_msg, buf, item.src)
                return
            if not t:
                # NOP message to be ignored, do so.
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
                if pkt.dstaddr != 0:
                    logging.trace ("CI with nonzero dstaddr")
                    # FIXME: this needs to log the message in the right format
                    self.node.logevent (Event.inv_msg, buf, item.srcnode)
                    return
                if item.rts:
                    try:
                        conn = self.connections[pkt.srcaddr]
                        if conn.state != conn.ci:
                            # Unexpected RTS, ignore
                            return
                    except KeyError:
                        # Not there, must have been deleted.  Ignore.
                        return
                else:
                    # Step 3: see if this is a retransmit, otherwise
                    # map it onto a new Connection if available.
                    cikey = (item.src, pkt.srcaddr)
                    if cikey in self.rconnections:
                        conn = self.rconnections[cikey]
                        if conn.state not in (conn.cr, conn.cc):
                            # Unexpected in this state, discard
                            return
                    else:
                        try:
                            conn = Connection (self)
                            self.rconnections[cikey] = conn
                        except Exception:
                            # Can't create another connection, give it
                            # to the reserved port for a No Resources reply.
                            conn = self.resport
            else:
                # Step 6 or 7: look up via the local link address.
                conn = self.connections.get (pkt.dstaddr, None)

                # Do all the port mapping checks.  The NSP spec
                # (section 6.2) lists them in a manner that doesn't
                # directly match the flow here, because here we start
                # with a lookup based only on the dstaddr (our
                # address) field.
                if conn:
                    if conn.state in (conn.ci, conn.cd):
                        # CI or CD state, check the message (rule 6 first
                        # part, rule 7 note).
                        if t not in (AckConn, NoRes, ConnConf, DiscInit,
                                     DiscConf):
                            conn = None   # Not a valid mapping
                    else:
                        # We have a remote address, do a full check
                        # (rule 6 second part, rule 7)
                        if t is AckConn:
                            # Conn Ack only maps to a connection in CI state
                            conn = None
                        # Do the source address check
                        elif pkt.srcaddr != conn.dstaddr or \
                                 pkt.src != conn.dest:
                            # Mismatch, map to reserved port or discard
                            conn = None
                # No valid connection mapping found, send message to the
                # reserved port or discard, according to message type.
                if not conn:
                    if t in (AckConn, NoRes, DiscConf, DiscComp, NoLink,
                             AckData, AckOther):
                        # discard the packet silently
                        return
                    # Something with data, map to reserved port
                    conn = self.resport
            # Packet is mapped to a port, so process it there.  Change
            # the packet attribute in the work item to match the outcome
            # of the parse done above
            item.packet = pkt
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

    def connect (self, dest, payload):
        """Session control interface.  Allocate a connection object,
        send a connection request, and return the resulting connection.
        """
        c = Connection (self)
        if c.connect (dest, payload):
            return c
        c.reset ()
        return None
    
class txqentry (timers.Timer):
    """An entry in the retransmit queue for a subchannel.
    """
    __slots__ = ("packet", "txtime", "channel", "tries")
    
    def __init__ (self, packet, channel):
        super ().__init__ ()
        self.packet = packet
        self.channel = channel
        self.tries = self.txtime = 0

    def send (self):
        if type (self.packet) is ConnInit:
            if self.tries:
                self.packet.subtype = NspHdr.RCI
            else:
                self.packet.subtype = NspHdr.CI
        self.channel.node.timers.start (self, self.channel.parent.acktimeout ())
        self.tries += 1
        if self.txtime == 0:
            self.txtime = time.time ()
        self.channel.parent.send (self.packet)

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
        self.numhigh = Seq (0)        # Sequence number of last packet queued
        # The flow control parameters are remote flow control -- we don't
        # do local flow control other than to request another interrupt
        # each time we get one.  So there are no explicit local flow
        # attributes.
        self.reqnum = 0               # Count requested by remote
        self.minreq = 0               # Lowest allowed value of minreq
        self.xon = True               # Flow on/off switch
        self.flow = ConnMsg.SVC_NONE  # Outbound flow control selected
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

    def send (self, pkt):
        """Queue a packet for transmission, and send it if we're allowed.
        """
        if isinstance (pkt, IntMsg) and not self.reqnum:
            # Interrupt sends are refused if we're not allowed to send
            # right now.  (On the other hand, regular data is queued
            # and transmitted whenever flow control permits.)
            raise CantSend
        qe = txqentry (pkt, self)
        self.pending_ack.append (qe)
        if isinstance (pkt, DataSeg):
            # For data segments, check if we can transmit now.  If not,
            # just leave it queued; it will be transmitted when flow
            # control permits.
            self.numhigh += 1
            ql = len (self.pending_ack)
            if ql > Seq.maxdelta or \
               (self.flow == ConnMsg.SVC_SEG and ql > self.reqnum) or \
               (self.flow == ConnMsg.SVC_MSG and self.mm () > self.reqnum):
                # Not allowed to send.  The firs term is there because we
                # queue without limit, but we can't ever have more than
                # half the sequence number space worth of packets in
                # flight.  So even without flow control, the limit of
                # sent but unacked packets is 2047.
                return
        # Good to go; send it and start the timeout.
        qe.send ()
        
    def ack (self, acknum):
        """Handle a received ack on this subchannel.
        """
        firsttxq = self.pending_ack[0]
        if isinstance (firsttxq.packet, (IntMsg, DataSeg)):
            if acknum <= firsttqx.seqnum or acknum >= self.seqnum:
                # Duplicate or out of range ack, ignore.
                # Note that various control packets end up in the Data
                # subchannel as well, and those don't have sequence numbers.
                return
            count = acknum - firsttqx.seqnum
        else:
            count = 1
        for i in range (count):
            acked = self.pending_ack.popleft ()
            adj = (acked.ack () and self.flow == ConnMsg.SVC_MSG) or \
                  self.flow == ConnMsg.SVC_SEG
            self.reqnum -= adj

    def close (self):
        """Handle connection close actions for this subchannel.  This is
        also used for connection abort, to discard all pending packets and
        stop timers.
        """
        self.remove ()
        for pkt in self.pending_ack:
            pkt.ack ()
        self.pending_ack.clear ()
        self.ooo = dict ()
        
class Other_Subchannel (Subchannel):
    Ack = AckOther

    def __init__ (self, parent):
        super ().__init__ (parent)
        self.reqnum = 1               # Other data req count initially 1
        # Interrupt flow control is different from data flow control, but
        # the closest analog is message flow control because the count
        # cannot be negative, and not every packet is subjected to control.
        # (In this case, interrupts are but link service messages are not.)
        self.flow = ConnMsg.SVC_MSG

# API exceptions
class NSPException (Exception): pass
class WrongState (NSPException): "Connection is in the wrong state"
class RangeError (NSPException): "Parameter is out of range"
class ConnectionLimit (NSPException): "Connection limit reached"
class CantSend (NSPException): "Can't send interrupt at this time"

# These reason codes are internal to NSP and not available to SC
reservedreasons = { NoRes.reason, DiscComp.reason, NoLink.reason }

class Connection (Element, statemachine.StateMachine, timers.Timer):
    """An NSP connection object.  This contains the connection state
    machine, the data and other-data subchannel state, and the session
    control API with the exception of the "connect" call.  Arriving
    packets that are mapped onto the connection come into the per-state
    processing function (via "dispatch" in the Statemachine base class).
    Note that packet type validation and address checks have already
    been done as part of the "mapping" of arriving packets onto connections.
    The timer of a Connection is the inactivity timer.  (Retransmit timers
    are found in the two subchannels.)
    
    A note on connection states:

    The NSP spec uses a model where the Session Control layer polls NSP
    for things it needs to know about.  Because of that model, there are
    a number of connection states to represent "waiting for SC to poll
    NSP for something it has to hear".  The implementation we have here
    uses queueing of messages to SC instead of polling.  The result is that
    none of those "waiting for SC to poll" states are needed; instead,
    whatever the NSP spec delivers to SC for a poll in such a state is
    handled instead by a message to SC and an immediate transition to
    the state after.

    Specifically, this means that the O, DN, RJ, NC, and NR states
    do not exist.

    In the same way, states that exist only to model the "waiting for
    SC to close the port" case do not exist either.  Instead, the
    connection is closed immediately.

    This means that the DRC, CN, and DIC states do not exist either.

    Note, though, that CL exists after a fashion.  When a connection is
    closed, NSP no longer knows about it (for example, it is no longer
    listed in the connection address lookup tables) but it is possible for
    some other component still to hold a reference to it.  State CN is
    represented by Connection.state = None.
    """
    def __init__ (self, parent):
        Element.__init__ (self, parent)
        statemachine.StateMachine.__init__ (self)
        timers.Timer.__init__ (self)
        # srcaddr and dstaddr are the connection identifiers, not
        # node addresses -- this matches the spec terminology
        self.srcaddr = srcaddr = self.parent.get_id ()
        if srcaddr is None:
            raise ConnectionLimit
        self.parent.connections[srcaddr] = self
        self.dstaddr = 0
        self.shutdown = False
        self.data = Subchannel (self)
        # We use the optional "multiple other-data messages allowed at a time"
        # model, rather than the one at a time model that the NSP spec uses.
        # That makes the two subchannels look basically the same -- same data
        # structures, same control machinery.
        self.other = Other_Subchannel (self)
        
        self.destnode = None
        # All done.  Add this connection to the dictionary of connections
        # known to NSP.
        self.parent.connections[srcaddr] = self

    def connect (self, dest, payload):
        """Create an outbound connection to the given destination node,
        with the supplied session control layer payload.
        """
        if self.state != self.s0:
            raise WrongState
        self.dest = dest
        self.destnode = self.parent.node.nodeinfo (dest)
        ci = self.makepacket (ConnInit, payload = payload,
                              fcopt = ConnMsg.SVC_NONE,
                              info = self.parent.nspver,
                              segsize = MSS)
        logging.trace ("Connecting to %s: %s", dest, payload)
        # Send it on the data subchannel
        self.data.send (ci)
        self.state = self.ci
        return True
    
    def close (self):
        """Get rid of this connection.  This doesn't send anything;
        if messages are needed, that is up to the caller.  
        """
        del self.parent.connections[self.srcaddr]
        if self.dstaddr:
            del self.parent.rconnections[(self.dest, self.dstaddr)]
        self.parent.ret_id (self.srcaddr)
        # Clean up the subchannels
        self.data.close ()
        self.other.close ()
        self.state = None
        logging.trace ("Deleted connection %s to %s", self.srcaddr, self.dest)
        return True

    def accept (self, payload = b""):
        """Accept an incoming connection, using the supplied payload
        as session control accept data.
        """
        if self.state != self.cr:
            raise WrongState
        cc = self.makepacket (ConnConf, data_ctl = payload,
                              fcopt = ConnMsg.SVC_NONE,
                              info = self.parent.nspver,
                              segsize = MSS)
        logging.trace ("Accepting to %s: %s", dest, payload)
        # Send it on the data subchannel
        self.data.send (cc)
        self.state = self.cc
        if self.node.phase == 2:
            # Phase 2, go directly to RUN state.
            self.state = self.run
        return True
        
    def reject (self, reason = 0, payload = b""):
        """Reject an incoming connection, using the supplied reason
        code and payload as session control reject data.
        """
        if self.state != self.cr:
            raise WrongState
        self.disc_rej (reason, payload)
        self.state = self.dr
        return True
    
    def disc_rej (self, reason, payload):
        # Common code for reject, disconnect, and abort
        if reason < 0 or reason > 255 or reason in reservedreasons:
            raise RangeError
        di = self.makepacket (DiscInit, reason = reason, data_ctl = payload)
        logging.trace ("Disconnecting (or rejecting) to %s: %s", dest, payload)
        # Send it on the data subchannel
        self.data.send (di)
        
    def disconnect (self, reason = 0, payload = b""):
        """Disconnect an active connection, using the supplied reason
        code and payload as session control disconnect data.  This is
        a "clean shutdown", the connection is closed once pending outbound
        transmits have been acknowledged.
        """
        if self.state != self.run:
            raise WrongState
        if self.data.pending_ack:
            # Data not all acked yet, don't send DI just yet
            self.shutdown = True
        else:
            self.disc_rej (reason, payload)
        self.state = self.di
        return True
    
    def abort (self, reason = 0, payload = b""):
        """Disconnect an active connection, using the supplied reason
        code and payload as session control disconnect data.  This is
        a "hard shutdown", the connection is closed immediately, any
        pending transmits are discarded.
        """
        if self.state != self.run:
            raise WrongState
        self.disc_rej (reason, payload)
        self.state = self.di
        return True

    def send (self, data):
        """Send a message.  Segmentation will be done here, i.e., we
        implement a session control message interface.  Messages are
        queued without limit, but of course are only transmitted if
        flow control rules permit.
        """
        if self.state != self.run:
            raise WrongState
        flags = 2               # BOM
        dl = len (data)
        for i in range (0, dl, self.segsize):
            if dl - i <= self.segsize:
                flags |= 4      # EOM
            pkt = self.makepacket (DataSeg, st = flags,
                                   payload = data[i:i + self.segsize],
                                   seqnum = self.data.seqnum)
            self.data.seqnum += 1
            self.data.send (pkt)
        return True
    
    def interrupt (self, data):
        """Send an interrupt.  This is accepted only if an interrupt
        message is allowed to be sent right now.  That is true when
        the connection is first opened, and whenever the remote node
        allows another interrupt to be sent.  Typically DECnet nodes
        allow only one interrupt at a time, so when this function is
        called, permission to send another is denied until the remote
        node gets around to sending another flow control message that
        issues another interrupt credit.
        """
        if self.state != self.run:
            raise WrongState
        sc = self.other
        pkt = self.makepacket (IntMsg, payload = data,
                               segnum = sc.seqnum)
        sc.send (pkt)
        # It was accepted, so increment the sequence number
        logging.trace ("sent interrupt seq %d", sc.seqnum)
        sc.seqnum += 1
        return True
    
    def to_sc (self, item):
        """Send a work item to Session Control.
        """
        item.src = self
        #self.node.addwork (item, self.node.session)
        
    def update_delay (self, txtime):
        if txtime and self.destnode:
            delta = time.time () - txtime
            if self.destnode.delay:
                # There is an estimate, do weighted average
                self.destnode.delay += (delta - self.destnode.delay) \
                                       / (self.parent.config.nsp_weight + 1)
            else:
                # No estimate yet, use this one
                self.destnode.delay = delta

    def acktimeout (self):
        if self.destnode.delay:
            return self.destnode.delay * self.parent.config.nsp_delay
        return 5
    
    def makepacket (self, cls, **kwds):
        pkt = cls (dstaddr = self.dstaddr, **kwds)
        # Connect Ack doesn't have a source address, so handle that separately
        try:
            pkt.srcaddr = self.srcaddr
        except AttributeError:
            pass
        return pkt
    
    def sendmsg (self, pkt):
        self.parent.routing.send (pkt, self.dest)

    def validate (self, item):
        logging.trace ("Processing %s in connection %s", item, self)
        return True
    
    def s0 (self, item):
        """Initial state.  We come here to handle a request for a new
        inbound connection.
        """
        pkt = item.packet
        # Inbound connection.  Save relevant state about the remote
        # node, and send the payload up to session control.
        self.dest = item.src
        self.destnode = self.parent.node.nodeinfo (self.dest)
        self.dstaddr = pkt.srcaddr
        self.nspver = pkt.info
        self.data.flow = pkt.fcopt
        self.segsize = min (pkt.segsize, MSS)
        if self.nspver != ConnMsg.VER_PH2 and self.node.phase > 2:
            # If phase 3 or later, send CA
            ca = self.makepacket (AckConn)
            self.sendmsg (ca)
        # Send the packet up to Session Control
        self.to_sc (item)
        return self.cr

    def cr (self, item):
        """Connect Received state.  Mostly we wait here for Session
        Control to decide what to do about an inbound connection.
        We also ACK any retransmitted CI messages.
        """
        pkt = item.packet
        if isinstance (pkt, ConnInit) and self.node.phase > 2:
            # Retransmitted or out of order CI.  Resend the CA.
            if self.nspver != ConnMsg.VER_PH2:
                # If phase 3 or later, send another CA
                ca = self.makepacket (AckConn)
                self.sendmsg (ca)
            return

    def ci (self, item):
        """Connect Init sent state.  This just checks for Connect Ack
        and returned Connect Init, everything else is common with the
        CD state.
        """
        pkt = item.packet
        if isinstance (pkt, AckConn) and self.node.phase > 2:
            # Connect Ack, go to CD state
            self.data.ack (0)    # Process ACK of the CI
            return self.cd
        elif isinstance (pkt, ConnInit):
            # Returned outbound CI (inbound CI can't come here).
            # Report unreachable to Session Control
            self.to_sc (item)
            self.close ()
            return
        return self.cd (item)

    def cd (self, item):
        """Connect Delivered state.  This also serves as common code for
        the Connect Init state since they are nearly identical.
        """
        pkt = item.packet
        if isinstance (pkt, ConnConf):
            # Connection was accepted.  Save relevant state about the remote
            # node, and send the payload up to session control.
            self.dstaddr = pkt.srcaddr
            self.nspver = pkt.info
            self.data.flow = pkt.fcopt
            self.segsize = min (pkt.segsize, MSS)
            self.data.ack (0)    # Treat this as ACK of the CI
            if self.nspver != ConnMsg.VER_PH2 and self.node.phase > 2:
                # If phase 3 or later, send data Ack
                ack = self.makepacket (DataAck, acknum = self.data.acknum)
                self.sendmsg (ack)
            # Send the accept up to Session Control
            self.to_sc (item)
            return self.run
        elif isinstance (pkt, DiscInit):
            # Connect Reject
            self.dstaddr = pkt.srcaddr
            # Send the reject up to Session Control
            self.to_sc (item)
            # Ack the reject message
            ack = self.makepacket (DiscComp)
            self.sendmsg (ack)
            self.close ()
        elif isinstance (pkt, (NoRes, DiscConf)):
            # No resources, or Phase 2 reject.
            # Send the reject up to Session Control
            self.to_sc (item)
            self.close ()

    def cc (self, item):
        """Connect Confirm state.  Accept on an incoming connection
        gets us to this point (except in Phase II where that goes
        straight to RUN state).
        """
        pkt = item.packet
        if isinstance (pkt, (AckData, Interrupt, LinkSvcMsg, AckOther)):
            self.data.ack (0)   # Treat as ACK of CC message
            self.state = self.run
            return self.run ()

    def run (self, item):
        if isinstance (item, Received):
            pkt = item.packet
            # On any received packet, restart the inactivity timer,
            # if phase 3 or higher
            if self.node.phase > 2 and self.rphase > 2:
                #self.node.timers.start (self, self.inact_time)
                pass
        elif isinstance (item, timers.Timeout):
            # Inactivity timeout, send a no-change Link Service message
            # (make it XON for grins, we never send XOFF so this is in
            # effect a no-change message).
            pkt = LinkSvcMsg (fcval_int = DATA_REQ, fcmod = XON)
            self.other.send (pkt)
        
class ReservedPort (Element):
    """An NSP "reserved port".  This is a descriptive trick to talk about
    error responses not tied to an active connection, things like no such
    connection, or no resources.  We implement a "reserved port" here
    because that makes things simple.
    """
    def dispatch (self, item):
        """Handle a work item for the reserved port.  Typically these
        generate an error response back to the sender; the specific
        response depends on what we're replying to.
        """
        pkt = item.packet
        if isinstance (pkt, ConnInit):
            # ConnInit could not be mapped, send No Resources
            t = NoRes
        else:
            # Some other message could not be mapped, send No Link
            t = NoLink
        reply = t (srcaddr = pkt.dstaddr, dstaddr = pkt.srcaddr)
        self.node.routing.send (reply, item.src)


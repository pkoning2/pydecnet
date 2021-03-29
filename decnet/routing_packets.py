#!/usr/bin/env python3

"""DECnet routing packet layouts.

"""

from .common import *
from . import logging
from . import events
from . import packet

# Router type codes (basically those used in the routing packets --
# NOT the encoding in NICE):
PHASE2 = 0
L2ROUTER = 1
L1ROUTER = 2
ENDNODE = 3
UNKNOWN = 4

tiver_ph2 = Version (0, 0, 0)
tiver_ph3 = Version (1, 3, 0)
tiver_ph4 = Version (2, 0, 0)
nspver_ph2 = Version (3, 1, 0)

# Exceptions related to routing packet parsing
class InvalidAddress (packet.DecodeError):
    """Invalid node address."""

class RoutingDecodeError (packet.DecodeError): pass

class FormatError (RoutingDecodeError):
    """Invalid field in routing packet."""

class ChecksumError (RoutingDecodeError):
    """Routing packet checksum error."""

# Mapping from router type code to strings:
ntypestrings = ( "Phase 2 node", "Area router", "L1 router", "Endnode" )

# Utility to turn packet into event data.
def splithdr (b, lens):
    # Split a prefix of b into pieces of length specified by the lens
    # sequence.  Return those pieces.
    st = 0
    ret = list ()
    for l in lens:
        f = b[st:st + l]
        if l <= 4:
            f = int.from_bytes (f, "little")
        ret.append (f)
        st += l
    return ret

def evtpackethdr (pkt, exc = None):
    """Build the packet header parameter from the header
    fields, according to whether it's a short or long header.
    Optional argument "exc" is an exception instance, which
    may change the choice of parameter used.
    """
    if isinstance (pkt, bytetypes):
        buf = pkt
    else:
        try:
            buf = pkt.decoded_from
        except Exception:
            return { }
    if exc is None or isinstance (exc, RoutingDecodeError):
        if isinstance (pkt, bytetypes):
            fields = splithdr (buf, (1, 2, 2, 1))
            return { "packet_header" : fields }
        elif isinstance (pkt, ShortData):
            fields = splithdr (buf, (1, 2, 2, 1))
            return { "packet_header" : fields }
        elif isinstance (pkt, LongData):
            fields = splithdr (buf, (1, 1, 1, 6, 1, 1, 6, 1, 1, 1, 1))
            return { "eth_packet_header" : fields }
        elif isinstance (pkt, CtlHdr):
            fields = splithdr (buf, (1, 2))
            return { "packet_header" : fields }
        elif isinstance (pkt, NodeInit):
            fields = splithdr (buf, (1, 1)) + [ pkt.srcnode, pkt.nodename ]
            return { "ni_packet_header" : fields }
        elif isinstance (pkt, NodeVerify):
            fields = splithdr (buf, (1, 1))
            return { "nv_packet_header" : fields }
    return { "packet_beginning" : buf[:6] }
    
class ShortData (packet.Packet):
    _layout = (( packet.BM,
                 ( "sfpd", 0, 3 ),
                 ( "rqr", 3, 1 ),
                 ( "rts", 4, 1 ),
                 ( "vers", 6, 1 ),
                 ( "pf", 7, 1 )),
               ( Nodeid, "dstnode" ),
               ( Nodeid, "srcnode" ),
               ( packet.BM,
                 ( "visit", 0, 6 )),
               packet.Payload )
    sfpd = 2
    vers = 0
    pf = 0
    ie = 0    # "intra ethernet" -- for translation to/from long

class LongData (packet.Packet):
    _layout = (( packet.BM,
                 ( "lfpd", 0, 3 ),
                 ( "rqr", 3, 1 ),
                 ( "rts", 4, 1 ),
                 ( "ie", 5, 1 ),
                 ( "vers", 6, 1 ),
                 ( "pf", 7, 1 )),
               ( packet.RES, 2 ),    # d-area, d-subarea
               ( packet.BV, "dsthi", 4 ),
               ( Nodeid, "dstnode" ),
               ( packet.RES, 2 ),    # s-area, s-subarea
               ( packet.BV, "srchi", 4 ),
               ( Nodeid, "srcnode" ),
               ( packet.RES, 1 ),
               ( packet.B, "visit", 1 ),
               ( packet.RES, 2 ),    # s-class, pt
               packet.Payload)
    lfpd = 6
    vers = 0
    pf = 0
    dsthi = HIORD
    srchi = HIORD

class CtlHdr (packet.Packet):
    _layout = (( packet.BM,
                 ( "control", 0, 1 ),
                 ( "type", 1, 3 ),
                 ( "ext_type", 4, 3 ),   # Phase IV-prime extended type
                 ( "pf", 7, 1 )),)
    control = 1
    pf = 0

class PtpInit (CtlHdr):
    _layout = (( Nodeid, "srcnode" ),
               ( packet.BM,
                 ( "ntype", 0, 2 ),
                 ( "verif", 2, 1 ),
                 ( "blo", 3, 1 )),
               ( packet.B, "blksize", 2 ),
               ( Version, "tiver" ),
               ( packet.B, "timer", 2 ),
               ( packet.I, "reserved", 64 ))
    type = 0
    blo = 0

    # This defaults tiver but allows it to be overridden.
    def __init__ (self, *args, **kwargs):
        self.tiver = tiver_ph4
        super ().__init__ (*args, **kwargs)
        
    def check (self):
        # Check that the node number is valid
        if not self.srcnode:
            logging.debug ("Invalid Phase IV node address")
            raise InvalidAddress (self.srcnode)
    
class PtpInit3 (CtlHdr):
    _layout = (( Nodeid, "srcnode" ),
               ( packet.BM,
                 ( "ntype", 0, 2 ),
                 ( "verif", 2, 1 )),
               ( packet.B, "blksize", 2 ),
               ( Version, "tiver" ),
               ( packet.I, "reserved", 64 ))
    type = 0
    blo = 0
    # Defined in phase IV hello, supply dummy value for commonality
    timer = 0

    def __init__ (self, *args, **kwargs):
        self.tiver = tiver_ph3
        super ().__init__ (*args, **kwargs)
        
    def check (self):
        # Check that the node number is valid
        if not 1 <= self.srcnode <= 255:
            logging.debug ("Invalid Phase III node address")
            raise InvalidAddress (self.srcnode)

class PtpVerify (CtlHdr):
    _layout = (( Nodeid, "srcnode" ),
               ( packet.I, "fcnval", 64 ))
    type = 1
    
class PtpHello (CtlHdr):
    _layout = (( Nodeid, "srcnode" ),
               ( packet.I, "testdata", 128 ))
    type = 2

class RouteSegEntry (packet.Packet):
    """An entry in the routing message: the cost/hops fields.
    """
    _layout = (( packet.BM,
                 ( "cost", 0, 10 ),
                 ( "hops", 10, 5 )),)

class L1Segment (packet.Packet):
    """A segment of a Level 1 routing message.  It consists of
    a header followed by some number of segment entries.
    """
    _layout = (( packet.B, "count", 2 ),
               ( packet.B, "startid", 2 ))
    _addslots = { "entries" }

    def validate (self):
        if self.count + self.startid > 1024 or self.count == 0:
            logging.debug ("Invalid L1 segment, start {}, count {}",
                           self.startid, self.count)
            raise FormatError

    @classmethod
    def decode (cls, buf):
        seg, buf = super (__class__, cls).decode (buf)
        seg.validate ()
        seg.entries, buf = packet.LIST.decode (buf, RouteSegEntry, seg.count)
        return seg, buf

    def encode (self):
        self.count = len (self.entries)
        entries = packet.LIST.checktype ("entries", self.entries)
        return super ().encode () + entries.encode (RouteSegEntry)
    
class L2Segment (L1Segment):
    """A segment of a Level 2 routing message.  Similar to the
    Level 1 segment, except that it lists areas rather than
    nodes within an area.

    For maximal code reuse, we'll call the "startarea" field by
    its L1 name ("startid") instead.
    """
    def validate (self):
        if self.count + self.startid > 64 or \
               self.startid == 0 or self.count == 0:
            logging.debug ("Invalid L2 segment, start {}, count {}",
                           self.startid, self.count)
            raise FormatError
    
class RoutingMessage (CtlHdr):
    """Routing message base class.  It consists of a header,
    followed by some number of segments, followed by a checksum.
    """
    _layout = (( packet.B, "srcnode", 2 ),
               ( packet.RES, 1 ))
    _addslots = { "segments" }
    initchecksum = 1    # Phase 4 case

    def validate (self, segs):
        segslen = len (segs)
        if not segs or (segslen & 1):
            logging.debug ("Invalid routing packet payload")
            raise FormatError
        s = self.initchecksum
        for i in range (0, segslen - 2, 2):
            s += int.from_bytes (segs[i:i + 2], packet.LE)
        # end around carry
        s = (s & 0xffff) + (s >> 16)
        s = (s & 0xffff) + (s >> 16)
        check = int.from_bytes (segs[-2:], packet.LE)
        if s != check:
            logging.debug ("Routing packet checksum error "
                           "(expected {:0>4x}, received {:0>4x})",
                           s, check)
            raise ChecksumError

    @classmethod
    def decode (cls, buf):
        ret, buf2 = super (__class__, cls).decode (buf)
        ret.validate (buf2)
        ret.segments, buf = packet.LIST.decode (buf2[:-2], ret.segtype)
        return ret, buf
    
    def encode (self):
        segs = packet.LIST.checktype ("segments", self.segments)
        segs = segs.encode (self.segtype)
        s = self.initchecksum
        for i in range (0, len (segs), 2):
            s += int.from_bytes (segs[i:i+2], packet.LE)
        # end around carry
        s = (s & 0xffff) + (s >> 16)
        s = (s & 0xffff) + (s >> 16)
        payload = segs + s.to_bytes (2, packet.LE)
        return super ().encode () + payload

    def entries (self, circ):
        """Return a generator that walks over the routing message
        entries, yielding tuples: id, (hops, cost) -- the latter from the
        point of view of the caller, i.e., with incoming circuit's
        hop/cost included.
        """
        cost = circ.cost
        for s in self.segments:
            i = s.startid
            for e in s.entries:
                yield i, (e.hops + 1, e.cost + cost)
                i += 1
    
class L1Routing (RoutingMessage):
    type = 3
    segtype = L1Segment
    lowid = 0
    
class L2Routing (RoutingMessage):
    """A level 2 routing message.  Similar to a Level 1 routing
    message, but with a different packet type code and entries
    for areas rather than nodes in the area.
    """
    type = 4
    segtype = L2Segment
    lowid = 1
    
class PhaseIIIRouting (RoutingMessage):
    """A Phase III routing message.  Similar to a Level 1 routing
    message, but contains only a single segment with no header
    (defining routing data for all the nodes starting at node 1).
    """
    initchecksum = 0
    type = 3
    # "segtype" is normally the type of a routing segment, which is
    # the outer type.  We don't have segments, so instead the inner
    # type is the one we mention.
    segtype = RouteSegEntry
    lowid = 1
    startid = 1
    
    def entries (self, circ):
        """Return a generator that walks over the routing message
        entries, yielding tuples: id, (hops, cost) -- the latter from the
        point of view of the caller, i.e., with incoming circuit's
        hop/cost included.
        """
        cost = circ.cost
        i = 1
        for e in self.segments:
            yield i, (e.hops + 1, e.cost + cost)
            i += 1

class RouterHello (CtlHdr):
    _layout = (( Version, "tiver" ),
               ( packet.BV, "hiid", 4 ),
               ( Nodeid, "id" ),
               ( packet.BM,
                 ( "ntype", 0, 2 )),
               ( packet.B, "blksize", 2 ),
               ( packet.B, "prio", 1 ),
               ( packet.RES, 1 ),    # area
               ( packet.B, "timer", 2 ),
               ( packet.RES, 1 ),    # mpd
               ( packet.I, "elist", 244 ))
    type = 5
    hiid = HIORD
    ntype_l1 = 2
    ntype_l2 = 1
    # Values for ext_type field encoding the PF flag
    ext_type_4 = 0
    ext_type_4prime = 1
    
class Elist (packet.Packet):
    _layout = (( packet.RES, 7 ),
               ( packet.I, "rslist", 236 ))

class RSent (packet.Packet):
    _layout = (( packet.BV, "hiid", 4 ),
               ( Nodeid, "router" ),
               ( packet.BM,
                 ( "prio", 0, 7 ),
                 ( "twoway", 7, 1 )))
    hiid = HIORD
    
class EndnodeHelloBase (CtlHdr):
    _layout = (( Version, "tiver" ),
               ( packet.BV, "hiid", 4 ),
               ( Nodeid, "id" ),
               ( packet.BM,
                 ( "ntype", 0, 2 )),
               ( packet.B, "blksize", 2 ),
               ( packet.RES, 9 ),    # area and seed
               ( packet.BV, "neighbor", 6 ),
               ( packet.B, "timer", 2 ),
               ( packet.RES, 1 ),
               ( packet.I, "testdata", 128 ))
    ntype = ENDNODE
    # Note that HIORD appears in the packet header even for Phase IV
    # Prime nodes; the spec says that the real upper 32 bits only
    # appear in MAC layer headers.
    hiid = HIORD
    # Only meaningful for router hellos, but defined here for commonality
    prio = 0

class EndnodeHello (EndnodeHelloBase):
    type = 6

class EndnodeHelloPrime (EndnodeHelloBase):
    type = 7
    ext_type = 1
    
class NodeInit (packet.Packet):
    _layout = (( packet.B, "msgflag", 1 ),
               ( packet.B, "starttype", 1 ),
               ( packet.EX, "srcnode", 2 ),
               ( packet.A, "nodename", 6 ),
               ( packet.BM,
                 ( "int", 0, 3 )),
               ( packet.BM,
                 ( "verif", 0, 1 ),
                 ( "rint", 1, 2 )),
               ( packet.B, "blksize", 2 ),
               ( packet.B, "nspsize", 2 ),
               ( packet.B, "maxlnks", 2 ),
               ( Version, "routver" ),
               ( Version, "commver" ),
               ( packet.A, "sysver", 32 ))
    msgflag = 0x58
    starttype = 1
    # These two are field of Phase 3/4 messages, but are implied here.
    ntype = PHASE2
    tiver = tiver_ph2

    def check (self):
        # Check that the node number is valid
        if not 1 <= self.srcnode <= 255:
            logging.debug ("Invalid Phase II node address")
            raise InvalidAddress (self.srcnode)

class NodeVerify (packet.Packet):
    _layout = (( packet.B, "msgflag", 1 ),
               # Yes, the spec says this is 2 bytes even though it's 1 in Init
               ( packet.B, "starttype", 2 ),
               ( packet.BV, "password", 8 ))
    msgflag = 0x58
    starttype = 2

class NopMsg (packet.Packet):
    _layout = (( packet.B, "msgflag", 1 ),
               packet.Payload)
    msgflag = 0x08

# Phase 2 routing header
class RouteHdr (packet.Packet):
    _layout = (( packet.B, "msgflag", 1 ),
               ( packet.A, "dstnode", 6 ),
               ( packet.A, "srcnode", 6 ),
               packet.Payload)
               
# Regexp used to validate "testdata" field.
testdata_re = re.compile (b"^\252*$")
    
# Mappings from control packet type code to packet class
ptpcontrolpackets = { c.type : c for c in
                      ( PtpInit, PtpVerify, PtpHello, L1Routing, L2Routing ) }
ph3controlpackets = { c.type : c for c in
                      ( PtpInit, PtpVerify, PtpHello, PhaseIIIRouting ) }
bccontrolpackets = { c.type : c for c in
                     ( RouterHello, EndnodeHello, L1Routing, L2Routing) }


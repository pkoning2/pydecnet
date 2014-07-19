#!/usr/bin/env python3

"""DECnet routing packet layouts.

"""

from .common import *
from . import events
from . import packet

# Router type codes (basically those used in NICE):
PHASE2 = 0
L2ROUTER = 1
L1ROUTER = 2
ENDNODE = 3

tiver_ph2 = Version (0, 0, 0)
tiver_ph3 = Version (1, 3, 0)
tiver_ph4 = Version (2, 0, 0)
nspver_ph2 = Version (3, 1, 0)

# Mapping from router type code to strings:
ntypestrings = ( "Phase 2", "Area router", "L1 router", "Endnode" )

# Utility to turn packet into event data.
def splithdr (b, lens):
    # Split a prefix of b into pieces of length specified by the lens
    # sequence.  Return those pieces.
    st = 0
    ret = list ()
    for l in lens:
        ret.append (b[st:st + l])
        st += l
    return ret

def evtpackethdr (pkt):
    # Build the packet header parameter from the header
    # fields, according to whether it's a short or long header.
    if isinstance (pkt, bytes):
        buf = pkt
    else:
        try:
            buf = pkt.decoded_from
        except Exception:
            return { }
    if isinstance (pkt, (ShortData, bytes)):
        fields = splithdr (buf, (1, 2, 2, 1))
        return { "packet_header" : fields }
    elif isinstance (pkt, LongData):
        fields = splithdr (pkt, (1, 1, 1, 6, 1, 1, 6, 1, 1, 1, 1))
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
    else:
        return { "packet_beginning" : buf[:6] }

class ShortData (packet.Packet):
    _addslots = { "payload" }
    _layout = (( "bm",
                 ( "sfpd", 0, 3 ),
                 ( "rqr", 3, 1 ),
                 ( "rts", 4, 1 ),
                 ( "vers", 6, 1 ),
                 ( "pf", 7, 1 )),
               ( Nodeid, "dstnode" ),
               ( Nodeid, "srcnode" ),
               ( "bm",
                 ( "visit", 0, 6 )))
    sfpd = 2
    vers = 0
    pf = 0
    ie = 0    # "intra ethernet" -- for translation to/from long

class LongData (packet.Packet):
    _addslots = { "payload" }
    _layout = (( "bm",
                 ( "lfpd", 0, 3 ),
                 ( "rqr", 3, 1 ),
                 ( "rts", 4, 1 ),
                 ( "ie", 5, 1 ),
                 ( "vers", 6, 1 ),
                 ( "pf", 7, 1 )),
               ( "res", 2 ),    # d-area, d-subarea
               ( "bv", "dsthi", 4 ),
               ( Nodeid, "dstnode" ),
               ( "res", 2 ),    # s-area, s-subarea
               ( "bv", "srchi", 4 ),
               ( Nodeid, "srcnode" ),
               ( "res", 1 ),
               ( "b", "visit", 1 ),
               ( "res", 2 ))    # s-class, pt
    lfpd = 6
    vers = 0
    pf = 0
    dsthi = HIORD
    srchi = HIORD

class CtlHdr (packet.Packet):
    _layout = (( "bm",
                 ( "control", 0, 1 ),
                 ( "type", 1, 3 ),
                 ( "pf", 7, 1 )),)
    control = 1
    pf = 0

class PtpInit (CtlHdr):
    _layout = (( Nodeid, "srcnode" ),
               ( "bm",
                 ( "ntype", 0, 2 ),
                 ( "verif", 2, 1 ),
                 ( "blo", 3, 1 )),
               ( "b", "blksize", 2 ),
               ( Version, "tiver" ),
               ( "b", "timer", 2 ),
               ( "i", "reserved", 64 ))
    type = 0
    blo = 0

    def check (self):
        # Check that the node number is valid
        if not self.srcnode:
            logging.debug ("Invalid Phase IV node address")
            raise events.fmt_err
    
class PtpInit3 (CtlHdr):
    _layout = (( Nodeid, "srcnode" ),
               ( "bm",
                 ( "ntype", 0, 2 ),
                 ( "verif", 2, 1 )),
               ( "b", "blksize", 2 ),
               ( Version, "tiver" ),
               ( "i", "reserved", 64 ))
    type = 0
    blo = 0
    # Defined in phase IV hello, supply dummy value for commonality
    timer = 0

    def check (self):
        # Check that the node number is valid
        if not 1 <= self.srcnode <= 255:
            logging.debug ("Invalid Phase III node address")
            raise events.fmt_err

class PtpVerify (CtlHdr):
    _layout = (( Nodeid, "srcnode" ),
               ( "i", "fcnval", 64 ))
    type = 1
    
class PtpHello (CtlHdr):
    _layout = (( Nodeid, "srcnode" ),
               ( "i", "testdata", 128 ))
    type = 2

class RouteSegEntry (packet.Packet):
    """An entry in the routing message: the cost/hops fields.
    """
    _layout = (( "bm",
                 ( "cost", 0, 10 ),
                 ( "hops", 10, 5 )),)

class L1Segment (packet.Packet):
    """A segment of a Level 1 routing message.  It consists of
    a header followed by some number of segment entries.
    """
    _layout = (( "b", "count", 2 ),
               ( "b", "startid", 2 ))
    _addslots = { "entries" }

    def validate (self):
        if self.count + self.startid > 1024 or self.count == 0:
            logging.debug ("Invalid L1 segment, start %d, count %d",
                           self.startid, self.count)
            raise events.fmt_err
        
    def decode (self, buf):
        data = super ().decode (buf)
        self.validate ()
        self.entries = [ ]
        for id in range (self.count):
            ent = RouteSegEntry ()
            data = ent.decode (data)
            self.entries.append (ent)
        return data

    def encode (self):
        payload = b''.join ([ bytes (e) for e in self.entries ])
        self.count = len (self.entries)
        return super ().encode () + payload
    
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
            logging.debug ("Invalid L2 segment, start %d, count %d",
                           self.startid, self.count)
            raise events.fmt_err
    
class L1Routing (CtlHdr):
    """A Level 1 routing message.  It consists of a header,
    followed by some number of segments, followed by a checksum.
    """
    _layout = (( "b", "srcnode", 2 ),
               ( "res", 1 ))
    _addslots = { "segments" }
    initchecksum = 1
    type = 3
    segtype = L1Segment
    lowid = 0
    
    def validate (self, segs):
        segslen = len (segs)
        if not segs or (segslen & 1):
            logging.debug ("Invalid routing packet payload")
            raise events.fmt_err
        s = self.initchecksum
        for i in range (0, segslen - 2, 2):
            s += int.from_bytes (segs[i:i + 2], packet.LE)
        # end around carry
        s = (s & 0xffff) + (s >> 16)
        s = (s & 0xffff) + (s >> 16)
        check = int.from_bytes (segs[-2:], packet.LE)
        if s != check:
            logging.debug ("Routing packet checksum error (%04x not %04x)",
                           s, check)
            raise events.adj_down (reason = "checksum_error")

    def decode_segments (self, data):
        segments = [ ]
        while data:
            seg = self.segtype ()
            data = seg.decode (data)
            segments.append (seg)
        return segments
            
    def decode (self, buf):
        segs = super ().decode (buf)
        self.validate (segs)
        self.segments = self.decode_segments (segs[:-2])

    def encode_segments (self):
        return b''.join ([ bytes (s) for s in self.segments ])
    
    def encode (self):
        segs = self.encode_segments ()
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
        cost = circ.config.cost
        for s in self.segments:
            i = s.startid
            for e in s.entries:
                yield i, (e.hops + 1, e.cost + cost)
                i += 1
    
class L2Routing (L1Routing):
    """A level 2 routing message.  Similar to a Level 1 routing
    message, but with a different packet type code and entries
    for areas rather than nodes in the area.
    """
    type = 4
    segtype = L2Segment
    lowid = 1
    
class PhaseIIIRouting (L1Routing):
    """A Phase III routing message.  Similar to a Level 1 routing
    message, but contains only a single segment with no header
    (defining routing data for all the nodes starting at node 1).
    """
    initchecksum = 0
    segtype = None
    lowid = 1
    
    def decode_segments (self, data):
        id = 1
        entries = [ ]
        while data:
            e = RouteSegEntry ()
            data = e.decode (data)
            entries.append (e)
        return entries

    def entries (self, circ):
        """Return a generator that walks over the routing message
        entries, yielding tuples: id, (hops, cost) -- the latter from the
        point of view of the caller, i.e., with incoming circuit's
        hop/cost included.
        """
        cost = circ.config.cost
        i = 1
        for e in self.segments:
            yield i, (e.hops + 1, e.cost + cost)
            i += 1

class RouterHello (CtlHdr):
    _layout = (( Version, "tiver" ),
               ( "bv", "hiid", 4 ),
               ( Nodeid, "id" ),
               ( "bm",
                 ( "ntype", 0, 2 )),
               ( "b", "blksize", 2 ),
               ( "b", "prio", 1 ),
               ( "res", 1 ),    # area
               ( "b", "timer", 2 ),
               ( "res", 1 ),    # mpd
               ( "i", "elist", 244 ))
    type = 5
    hiid = HIORD
    ntype_l1 = 2
    ntype_l2 = 1

class Elist (packet.Packet):
    _layout = (( "res", 7 ),
               ( "i", "rslist", 236 ))

class RSent (packet.Packet):
    _layout = (( "bv", "hiid", 4 ),
               ( Nodeid, "router" ),
               ( "bm",
                 ( "prio", 0, 7 ),
                 ( "twoway", 7, 1 )))
    hiid = HIORD
    
class EndnodeHello (CtlHdr):
    _layout = (( Version, "tiver" ),
               ( "bv", "hiid", 4 ),
               ( Nodeid, "id" ),
               ( "bm",
                 ( "ntype", 0, 2 )),
               ( "b", "blksize", 2 ),
               ( "res", 9 ),    # area and seed
               ( "bv", "neighbor", 6 ),
               ( "b", "timer", 2 ),
               ( "res", 1 ),
               ( "i", "testdata", 128 ))
    type = 6
    hiid = HIORD
    ntype = ENDNODE
    # Only meaningful for router hellos, but defined here for commonality
    prio = 0

class NodeInit (packet.Packet):
    _layout = (( "b", "msgflag", 1 ),
               ( "b", "starttype", 1 ),
               ( "ex", "srcnode", 2 ),
               ( "i", "nodename", 6 ),
               ( "bm",
                 ( "int", 0, 3 )),
               ( "bm",
                 ( "verif", 0, 1 ),
                 ( "rint", 1, 2 )),
               ( "b", "blksize", 2 ),
               ( "b", "nspsize", 2 ),
               ( "b", "maxlnks", 2 ),
               ( Version, "routver" ),
               ( Version, "commver" ),
               ( "i", "sysver", 32 ))
    msgflag = 0x58
    starttype = 1
    # These two are field of Phase 3/4 messages, but are implied here.
    ntype = PHASE2
    tiver = tiver_ph2

class NodeVerify (packet.Packet):
    _layout = (( "b", "msgflag", 1 ),
               # Yes, the spec says this is 2 bytes even though it's 1 in Init
               ( "b", "starttype", 2 ),
               ( "bv", "password", 8 ))
    msgflag = 0x58
    starttype = 2

class NopMsg (packet.Packet):
    _addslots = { "payload" }
    _layout = (( "b", "msgflag", 1 ),)
    msgflag = 0x08

# Phase 2 routing header
class RouteHdr (packet.Packet):
    _addslots = { "payload" }
    _layout = (( "b", "msgflag", 1 ),
               ( "i", "dstnode", 6 ),
               ( "i", "srcnode", 6 ))
               
# Regexp used to validate "testdata" field.
testdata_re = re.compile (b"^\252*$")
    
# Mappings from control packet type code to packet class
ptpcontrolpackets = { c.type : c for c in
                      ( PtpInit, PtpVerify, PtpHello, L1Routing, L2Routing ) }
bccontrolpackets = { c.type : c for c in
                     ( RouterHello, EndnodeHello, L1Routing, L2Routing) }


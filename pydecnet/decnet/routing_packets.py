#!/usr/bin/env python3

"""DECnet routing packet layouts.

"""

import array

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

tiver_ph2 = Version (3, 1, 0)
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

class RoutingPacketBase (packet.IndexedPacket):
    _layout = ()
    _allowempty = True
    classindex = nlist (128)
    classindexkey = "flags"

    def instanceindexkey (buf):
        require (buf, 1)
        return buf[0]

# Optimization note: the packet definition given here (for LongData as
# well) results in parsing steps for each of the bit fields in the
# packet flags (first byte).  It would be possible, with a bunch of
# extra complexity in the BM field class and the Packet class and
# metaclass, to decode just the byte containing all these flags and
# let the fields be accessed via descriptors.  Since in the fast path
# they are not in fact looked at, that would save a bit of overhead.
# But the difference is not large enough to make it really worth
# doing: 5.6 vs. 6.6 microseconds to decode a LongData packet in
# timing tests.  So for now leave it alone, but the idea is captured
# here in case it needs to be dusted off at some point.
class ShortData (RoutingPacketBase):
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
    flags = 0x02
    classindexmask = 0xc7
    sfpd = 2
    vers = 0
    pf = 0
    # "intra ethernet" -- for translation to/from long Allow it to be
    # set but ignore that value.  This happens when converting from
    # long to short format.
    ie = packet.ROAnyField ("ie", 0)

class LongData (RoutingPacketBase):
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
    flags = 0x06
    classindexmask = 0xc7
    lfpd = 6
    vers = 0
    pf = 0
    dsthi = HIORD
    srchi = HIORD

class CtlHdr (RoutingPacketBase):
    _layout = (( packet.BM,
                 ( "control", 0, 1 ),
                 ( "type", 1, 3 ),
                 ( "ext_type", 4, 3 ),   # Phase IV-prime extended type
                 ( "pf", 7, 1 )),)
    control = 1
    pf = 0

class PtpInit34 (CtlHdr):
    _layout = (( Nodeid, "srcnode" ),
               ( packet.BM,
                 ( "ntype", 0, 2 ),
                 ( "verif", 2, 1 ),
                 ( "blo", 3, 1 )),
               ( packet.B, "blksize", 2 ),
               ( Version, "tiver" ))
    flags = 0x01
    classindexmask = 0x8f
    type = 0
    blo = 0
    classindex = nlist(4)
    
    def instanceindexkey (buf):
        require (buf, 7)
        return buf[6]

    @classmethod
    def defaultclass (cls, idx):
        # For an unknown version we supply this base class as the
        # default.
        return __class__
    
class PtpInit3 (PtpInit34):
    _layout = (( packet.I, "reserved", 64 ),)
    classindexkeys = ( 1, )
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

class PtpInit (PtpInit34):
    _layout = (( packet.B, "timer", 2 ),
               ( packet.I, "reserved", 64 ))
    classindexkeys = ( 2, )
    
    # This defaults tiver but allows it to be overridden.
    def __init__ (self, *args, **kwargs):
        self.tiver = tiver_ph4
        super ().__init__ (*args, **kwargs)
        
    def check (self):
        # Check that the node number is valid
        if not self.srcnode:
            logging.debug ("Invalid Phase IV node address")
            raise InvalidAddress (self.srcnode)
    
class PtpVerify (CtlHdr):
    _layout = (( Nodeid, "srcnode" ),
               ( packet.I, "fcnval", 64 ))
    flags = 0x03
    classindexmask = 0x8f
    type = 1
    
class PtpHello (CtlHdr):
    _layout = (( Nodeid, "srcnode" ),
               ( packet.I, "testdata", 128 ))
    flags = 0x05
    classindexmask = 0x8f
    type = 2

def RouteSegEntry (hops, cost):
    return (hops << 10) + cost

class L1Segment (packet.Field):
    """A segment of a Level 1 routing message.  It consists of
    a header followed by some number of segment entries.
    """
    __slots__ = ( "count", "startid", "entries" )

    def __init__ (self, **kwargs):
        super ().__init__ ()
        for k, v in kwargs.items ():
            setattr (self, k, v)

    def __eq__ (self, other):
        # Helper method for test_routingpacket
        return self.count == other.count and \
               self.startid == other.startid and \
               self.entries == array.array ("H", other.entries)
               
    def validate (self):
        if self.count + self.startid > 1024 or self.count == 0:
            logging.debug ("Invalid L1 segment, start {}, count {}",
                           self.startid, self.count)
            raise FormatError

    @classmethod
    def decode (cls, a):
        # This is called with an array of uint16 values.
        seg = cls ()
        c = a[0]
        seg.count = c
        seg.startid = a[1]
        seg.validate ()
        c += 2
        seg.entries = a[2:c]
        return seg, a[c:]

    def encode (self):
        self.count = len (self.entries)
        ret = [ self.count.to_bytes (2, LE), self.startid.to_bytes (2, LE) ]
        ent = self.entries
        if not isinstance (ent, array.array):
            ent = array.array ("H", ent)
        if sys.byteorder == "big":
            # Make a copy of the entries and convert to little endian
            a = ent[:]
            a.byteswap ()
            ret.append (a.tobytes ())
        else:
            ret.append (ent.tobytes ())
        return b"".join (ret)
    
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

    @classmethod
    def decode (cls, buf):
        # Pick up the payload, after the 4 byte header (3 shown above
        # plus the type field in CtlHdr).
        segs = buf[4:]
        segslen = len (segs)
        if not segs or (segslen & 1):
            logging.debug ("Invalid routing packet payload length {}", segslen)
            raise FormatError
        a = array.array ("H")
        # Can't do this in the constructor because that treats a
        # memoryview as a vector of integers rather than a byte-like
        # type.
        a.frombytes (segs)
        if sys.byteorder == "big":
            # Convert from little endian protocol order to host order
            a.byteswap ()
        # Complement the last element, that's the checksum
        a[-1] = ~a[-1] & 0xffff
        s = sum (a)
        # Now remove the checksum word
        del a[-1]
        # end around carry
        s = (s & 0xffff) + (s >> 16)
        s = (s & 0xffff) + (s >> 16)
        # At this point should be the negative of the checksum initial
        # value, i.e., 0 or -1.  More precisely -0 or -1.  Note that
        # +0 is not a possible answer because no valid routing message
        # has an all-zero payload.
        # We will now use that residu to identify the correct packet
        # class.  This covers the case of the L1 routing message which
        # is either Phase III or Phase IV format, according to the
        # checksum value.
        try:
            cls2 = cls.rdict[s]
        except KeyError:
            logging.debug ("Routing packet checksum error, "
                           "(residue is {:0>4x})", s)
            raise ChecksumError from None
        pkt, x = super (__class__, cls2).decode (buf)
        pkt.decode2 (a)
        return pkt, b""

# This one comes first because it has the same code point as
# L1Routing, which we want to have as the chosen class for the packet
# index lookup in the routing messages base class.
class PhaseIIIRouting (RoutingMessage):
    """A Phase III routing message.  Similar to a Level 1 routing
    message, but contains only a single segment with no header
    (defining routing data for all the nodes starting at node 1).
    """
    initchecksum = 0
    flags = 0x07
    classindexmask = 0x8f
    type = 3
    
    def decode2 (self, segs):
        self.segments = segs
    
    def encode (self):
        ent = self.segments
        if not isinstance (ent, array.array):
            ent = array.array ("H", ent)
        if sys.byteorder == "big":
            # Make a copy of the entries and convert to little endian
            a = ent[:]
            a.byteswap ()
            seg = a.tobytes ()
        else:
            segs = ent.tobytes ()
        # Compute the checksum.  
        s = sum (self.segments)
        # end around carry
        s = (s & 0xffff) + (s >> 16)
        s = (s & 0xffff) + (s >> 16)
        payload = segs + s.to_bytes (2, LE)
        return super ().encode () + payload

    def entries (self, circ):
        """Return a generator that walks over the routing message
        entries, yielding tuples: id, (hops, cost) -- the latter from the
        point of view of the caller, i.e., with incoming circuit's
        hop/cost included.
        """
        cost = circ.cost
        i = 1
        for e in self.segments:
            yield i, ((e >> 10) + 1, (e & 1023) + cost)
            i += 1
PhaseIIIRouting.rdict = { 0xffff : PhaseIIIRouting }

class Ph4RoutingMessage (RoutingMessage):
    initchecksum = 1    # Phase 4 case

    def decode2 (self, segs):
        self.segments, segs = packet.LIST.decode (segs, self.segtype)
        if segs:
            logging.debug ("Unexpected data for {} after parse: {}",
                           cls.__name__, segs)
            raise ExtraData
    
    def encode (self):
        segs = packet.LIST.checktype ("segments", self.segments)
        segs = segs.encode (self.segtype)
        a = array.array ("H", segs)
        if sys.byteorder == "big":
            # Convert from little endian protocol order to host order
            a.byteswap ()
        s = sum (a) + self.initchecksum
        # end around carry
        s = (s & 0xffff) + (s >> 16)
        s = (s & 0xffff) + (s >> 16)
        payload = segs + s.to_bytes (2, LE)
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
                yield i, ((e >> 10) + 1, (e & 1023) + cost)
                i += 1
    
class L1Routing (Ph4RoutingMessage):
    flags = 0x07
    classindexmask = 0x8f
    type = 3
    segtype = L1Segment
    lowid = 0
    
L1Routing.rdict = { 0xfffe : L1Routing }

class P34Routing (RoutingMessage):
    # Define this after the other two.  It will become the entry in
    # the main packet index, allowing either type of valid routing
    # message to be recognized by its checksum.
    flags = 0x07
    classindexmask = 0x8f
    type = 3
    rdict = { 0xfffe : L1Routing, 0xffff : PhaseIIIRouting }
    
class L2Routing (Ph4RoutingMessage):
    """A level 2 routing message.  Similar to a Level 1 routing
    message, but with a different packet type code and entries
    for areas rather than nodes in the area.
    """
    flags = 0x09
    classindexmask = 0x8f
    type = 4
    segtype = L2Segment
    lowid = 1

L2Routing.rdict = { 0xfffe : L2Routing }
    
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
    flags = 0x0b
    classindexmask = 0x8f
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
    flags = 0x0d
    classindexmask = 0x8f
    type = 6

class EndnodeHelloPrime (EndnodeHelloBase):
    flags = 0x0f
    classindexmask = 0x8f
    type = 7
    ext_type = 1

class P2BareNSP (RoutingPacketBase):
    # This will match (Phase II) NSP packets not handled in the
    # routing layer, i.e., anything other than Node Init/Verify, NOP
    # messages, or Phase II routing headers.  For these we parse no
    # header at all; the whole packet ends up in _payload.  The same
    # is true for Routing Header, so either way we can give the
    # _payload field to NSP when passing up the packet.
    _layout = ( packet.Payload, )
    flags = 0x00
    classindexmask = 0x83
    
class P2StartBase (RoutingPacketBase):
    _layout = (( packet.B, "flags", 1 ),
               ( packet.B, "starttype", 1 ))
    flags = 0x58
    classindex = nlist (3)
    classindexkey = "starttype"
    
class NodeInit (P2StartBase):
    _layout = (( packet.EX, "srcnode", 2 ),
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
    starttype = 1
    # These two are field of Phase 3/4 messages, but are implied here.
    ntype = PHASE2
    tiver = tiver_ph2

    def check (self):
        # Check that the node number is valid
        if not 1 <= self.srcnode <= 255:
            logging.debug ("Invalid Phase II node address")
            raise InvalidAddress (self.srcnode)

class NodeVerify (P2StartBase):
    # The spec says that "starttype" is 2 bytes here even though it's
    # 1 byte in NodeInit.  It appears this is a typo and VMS, at
    # least, ignores that and implements it as one byte in both cases.
    # So we'll do the same.
    _layout = (( packet.BV, "password", 8 ),)
    starttype = 2

class NopMsg (RoutingPacketBase):
    _layout = (( packet.B, "flags", 1 ),
               packet.Payload)
    flags = 0x08

# Phase 2 routing header
class RouteHdr (RoutingPacketBase):
    _layout = (( packet.B, "msgflag", 1 ),
               ( packet.A, "dstnode", 6 ),
               ( packet.A, "srcnode", 6 ),
               packet.Payload)
    flags = 0x42
    classindexmask = 0xf3
    
    def __init__ (self, *args, **kwargs):
        self.msgflag = 0x46
        super ().__init__ (*args, **kwargs)

# Regexp used to validate "testdata" field.
testdata_re = re.compile (b"^\252*$")
    
# Build a (subset) index.  This returns an index (an nlist(128)) with
# entries for the keys of the specified classes.  This allows packet
# class lookup to be done with an index that lists only some of the
# packet classes, for example only those valid for point to point
# links, or only those valid when talking to a Phase II adjacency.
def pktindex (*classes):
    ret = nlist (128)
    for c in classes:
        # Find the class where the first index key is defined
        for c2 in c.__mro__:
            ci = super (c2, c2).classindex
            if ci is RoutingPacketBase.classindex:
                ci = c2.classindexkeys
                break
        for i in ci:
            # Note that if two classes have the same key, the one
            # listed later in the argument list will end up in the
            # index.
            ret[i] = c
    return ret

#!/usr/bin/env python3

"""DECnet routing packet layouts.

"""

from .common import *
from . import packet

class ShortData (packet.Packet):
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
        if self.count + self.startid > 1024:
            raise OverflowError ("Invalid L1 segment, start %d, count %d" % (self.startid, self.count))
        
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
        if self.count + self.startid > 64 or self.startid == 0:
            raise OverflowError ("Invalid L2 segment, start %d, count %d" % (self.startid, self.count))
        
    
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
    
    def validate (self):
        segs = self.payload
        segslen = len (segs)
        if not segs or (segslen & 1):
            raise ValueError ("Invalid routing packet payload")
        s = self.initchecksum
        for i in range (0, segslen - 2, 2):
            s += int.from_bytes (segs[i:i + 2], packet.LE)
        # end around carry
        s = (s & 0xffff) + (s >> 16)
        s = (s & 0xffff) + (s >> 16)
        check = int.from_bytes (segs[-2:], packet.LE)
        if s != check:
            raise ValueError ("Routing packet checksum error (%04x not %04x)" % (s, check))

    def decode_segments (self):
        data = self.payload[:-2]
        segments = [ ]
        while data:
            seg = self.segtype ()
            data = seg.decode (data)
            segments.append (seg)
        return segments
            
    def decode (self, buf):
        super ().decode (buf)
        self.validate ()
        self.segments = self.decode_segments ()

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

    def entries (self):
        """Returns the routing information entries defined
        by this routing message.  Returned value is a dictionary
        of entries, each with key = node id, and value (cost, hops)
        """
        entries = dict ()
        for s in self.segments:
            i = 0
            for e in s.entries:
                entries[i] = ( e.cost, e.hops )
                i += 1
        return entries
    
class L2Routing (L1Routing):
    """A level 2 routing message.  Similar to a Level 1 routing
    message, but with a different packet type code and entries
    for areas rather than nodes in the area.
    """
    type = 4
    segtype = L2Segment
    
class PhaseIIIRouting (L1Routing):
    """A Phase III routing message.  Similar to a Level 1 routing
    message, but contains only a single segment with no header
    (defining routing data for all the nodes starting at node 1).
    """
    initchecksum = 0

    def decode_segments (self):
        id = 1
        data = self.payload[:-2]
        entries = [ ]
        while data:
            e = RouteSegEntry ()
            data = e.decode (data)
            entries.append (e)
        return entries

    def entries (self):
        """Returns the routing information entries defined
        by this routing message.  Returned value is a dictionary
        of entries, each with key = node id, and value (cost, hops)
        """
        entries = dict ()
        i = 1
        for e in self.segments:
            entries[i] = ( e.cost, e.hops )
            i += 1
        return entries

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
    ntype = 3

tiver_ph3 = Version (1, 3, 0)
tiver_ph4 = Version (2, 0, 0)

# Regexp used to validate "testdata" field.
testdata_re = re.compile (b"^\252*$")
    
# Mappings from control packet type code to packet class
ptpcontrolpackets = { c.type : c for c in
                      ( PtpInit, PtpVerify, PtpHello, L1Routing, L2Routing ) }
bccontrolpackets = { c.type : c for c in
                     ( RouterHello, EndnodeHello, L1Routing, L2Routing) }


#!/usr/bin/env python3

"""DECnet routing decision and update modules.

"""

from .common import *
from .node import ApiRequest, ApiWork
from .config import scan_ver
from . import packet
from . import datalink
from . import timers
from . import statemachine
from . import route_ptp
#from . import route_lan

class CtlHdr (packet.Packet):
    _layout = (( "bm",
                 ( "control", 0, 1 ),
                 ( "type", 1, 3 ),
                 ( "pf", 7, 1 )),)
    control = 1
    pf = 0

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

#class RoutingAdjacency (Adjacency):
#    """The state for a adjacency to a routing node.
#    """
#    def __init__ (self, nodeid):
#        super ().__init__ (nodeid)
#        self.routes = dict ()
#        self.sendupdate = dict ()
#        self.pendingupdates = False
#        
#    def newroutes (self, pkt):
#        for id, val in pkt.entries ():
#            if self.routes[id] != val:
#                self.routes[id] = val
#                sendupdate (id, skip = self)
#            if id == self.nodeid and val != ( 0, 0 ):
#                raise ValueError ("Neighbor %s route entry for self is not zero" % nodeid (self.node))
#        

nodetypes = { "l2router" : 1,
              "l1router" : 2,
              "endnode" : 3,
              "phase3router" : 2,
              "phase3endnode" : 2,
              "phase2" : 0 }

class Routing (Element):
    """The routing layer.  Mainly this is the parent of a number of control
    components and collections of circuits and adjacencies.
    """
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        logging.debug ("Initializing routing layer")
        self.config = config
        self.circuits = dict ()
        self.adjacencies = dict ()
        self.node.routing = self
        self.nodeid = config.id
        self.typename = self.config.executor.type
        self.nodetype = nodetypes[self.typename]
        self.endnode = self.nodetype == 3
        if self.endnode:
            if len (config.circuits) > 1:
                raise ValueError ("End node must have 1 circuit, found %d" % \
                                  len (config.circuits))
        for name, c in config.circuit.items ():
            dl = dlcirc[name]
            try:
                self.circuits[name] = routing_circuit (self, name, dl, c)
                logging.debug ("Initialized routing circuit %s", name)
            except Exception:
                logging.exception ("Error initializing routing circuit %s", name)
        
    def routing_circuit (self, name, dl, c):
        if self.endnode:
            if isinstance (dl, datalink.BcDatalink):
                if self.type == "phase3endnode":
                    raise ValueError ("LAN datalink for Phase 3 node")
                return EndnodeLanCircuit (self, name, dl, c)
            return EndnodePtpCircuit (self, name, dl, c)
        else:
            if isinstance (dl, datalink.BcDatalink):
                if self.type in { "phase3router", "phase2" }:
                    raise ValueError ("LAN datalink for Phase 2 or 3 node")
                return RoutingLanCircuit (self, name, dl, c)
            return RoutingPtpCircuit (self, name, dl, c)

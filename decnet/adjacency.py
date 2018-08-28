#!/usr/bin/env python3

"""DECnet routing layer adjacencies.

This is a separate file because it needs to be imported by the
datalink dependent sublayer modules, which in turn are imported by
the routing module.  Separating this out avoids failing with a
recursive import.
"""

from .common import *
from .events import *
from .routing_packets import *
from . import logging
from . import timers

class Adjacency (Element, timers.Timer):
    """DECnet adjacency class.  Its parent (owner) is the circuit
    to which this adjacency belongs.  
    """
    def __init__ (self, circuit, info):
        """Create an adjacency based on the information in the hello
        message that announced the node (broadcast circuit) or the
        information saved away from the Init message (point to point
        circuit).
        """
        Element.__init__ (self, circuit)
        timers.Timer.__init__ (self)
        self.circuit = circuit
        self.routing = circuit.parent
        self.t4 = info.timer * circuit.T3MULT
        if not self.t4:
            # Phase 3 or before, no timer in the hello message
            self.t4 = circuit.t3 * circuit.T3MULT
        self.blksize = info.blksize
        self.nodeid = info.id
        self.ntype = info.ntype
        self.tiver = info.tiver
        self.macid = Macaddr (self.nodeid)
        self.priority = info.prio

    def __str__ (self):
        return "{0.nodeid}".format (self)

    def __format__ (self, fmt):
        # A bit of a hack: "format" gives you a longer string than "str"
        return "{0.circuit} {0.nodeid}".format (self)
    
    def adjnode (self):
        # Return a Nodeinfo object for this adjacency's adjacent node
        return self.node.nodeinfo (self.nodeid)
    
    def html (self, what, first):
        if first:
            hdr = """<tr><th>Neighbor</th><th>Type</th><th>Block size</th>
            <th>Priority</th><th>Listen time</th><th>Version</th></tr>"""
        else:
            hdr = ""
        neighbor = str (self.node.nodeinfo (self.nodeid))
        ntype = ntypestrings[self.ntype]
        s = """<tr><td>{1}</td><td>{2}</td>
        <td>{0.blksize}</td><td>{0.priority}</td><td>{0.t4}</td>
        <td>{0.tiver}</td></tr>""".format (self, neighbor, ntype)
        return hdr + s

    def get_api (self):
        ret = { "neighbor" : self.nodeid,
                "blocksize" : self.blksize,
                "type" : ntypestrings[self.ntype],
                "version" : self.tiver }
        if self.ntype != ENDNODE:
            ret["priority"] = self.priority
        return ret
    
    def __eq__ (self, other):
        if isinstance (other, self.__class__):
            return self.circuit == other.circuit and \
                   self.nodeid == other.nodeid
        else:
            return super ().__eq__ (other)

    def __hash__ (self):
        return hash ((id (self.circuit), self.nodeid))

    def dispatch (self, item):
        """Work item handler.
        """
        if isinstance (item, timers.Timeout):
            self.down ()
            self.circuit.adj_timeout (self)

    def up (self, **kwargs):
        if self.ntype != PHASE2:
            # Start the listen timer, except for Phase II neighbors
            # because those aren't required to send periodic messages
            self.node.timers.start (self, self.t4)
        self.routing.adj_up (self)
        
    def down (self, **kwargs):
        self.circuit.adj_down += 1
        self.node.timers.stop (self)
        self.routing.adj_down (self)
    
    def alive (self):
        """Mark this adjacency as alive -- restart its listen timeout.
        """
        if self.ntype != PHASE2:
            self.node.timers.start (self, self.t4)

    def send (self, pkt):
        """Send the supplied packet on this adjacency.  
        """
        logging.trace ("Sending {} byte packet to nexthop {} on {}: {}",
                       len (pkt), self.nodeid, self.circuit.name, pkt)
        self.circuit.send (pkt, self.macid)

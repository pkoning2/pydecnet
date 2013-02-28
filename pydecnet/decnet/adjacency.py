#!/usr/bin/env python3

"""DECnet common adjacency handling

"""

from .common import *
from . import packet
from . import timers
from .route_ptp import ShortData
from .route_eth import LongData

class Adjacency (Element, timers.Timer):
    """Base class for DECnet adjacencies.  Its parent class is the circuit
    to which this adjacency belongs.
    """
    def __init__ (self, circuit, nodeid, t4):
        Element.__init__ (self, circuit)
        timers.Timer.__init__ (self)
        self.circuit = circuit
        self.nodeid = nodeid
        self.t4 = t4
        self.alive ()
        self.macid = Macaddr (nodeid)
        self.priority = 0
        
    def __eq__ (self, other):
        if isinstance (other, self.__class__):
            return self.circuit == other.circuit and self.nodeid == other.nodeid
        else:
            return super ().__eq__ (other)

    def __hash__ (self):
        return hash ((id (self.circuit), self.nodeid))

    def dispatch (self, item):
        """Work item handler.
        """
        if isinstance (item, timers.Timeout):
            self.down ()
            
    def alive (self):
        """Mark this adjacency as alive -- restart its listen timeout.
        """
        self.node.timers.start (self, self.t4)
        
    def down (self):
        """Mark this adjacency down by external request.  This in turn
        calls the adjacency down handler for the parent circuit for
        further action.
        """
        self.node.timers.stop (self)
        self.circuit.adjacency_down (self)

    def up (self):
        self.circuit.adjacency_up (self)

class BcAdjacency (Adjacency):
    """Adjacency on a broadcast (LAN) circuit.
    """
    def send (self, pkt):
        """Send the supplied packet on this adjacency.  If it has a short
        header, give it a long header instead.
        """
        if isinstance (pkt, ShortData):
            pkt = LongData (copy = pkt, payload = pkt.payload)
        self.circuit.datalink.send (pkt, dest = self.macid)

    def sortkey (self):
        return self.priority, self.nodeid
    
class PtpAdjacency (Adjacency):
    """Adjacency on a point to point (non-LAN) circuit.
    """
    def send (self, pkt):
        """Send the supplied packet on this adjacency.  If it has a long
        header, give it a short header instead.
        """
        if isinstance (pkt, LongData):
            pkt = ShortData (copy = pkt, payload = pkt.payload)
        self.circuit.datalink.send (pkt)
    

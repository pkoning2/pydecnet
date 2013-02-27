#!/usr/bin/env python3

"""DECnet routing broadcast datalink dependent sublayer

"""

import re

from .common import *
from .node import ApiRequest, ApiWork
from .routing_packets import *
from . import datalink
from . import timers
from . import adjacency
from .route_ptp import ShortData

# Some well known Ethernet addresses
ALL_ROUTERS = Macaddr ("AB-00-00-03-00-00")
ALL_ENDNODES = Macaddr ("AB-00-00-04-00-00")

class LanCircuit (Element, timers.Timer):
    """A broadcast circuit, i.e., the datalink dependent
    routing sublayer instance for an Ethernet type circuit.

    Arguments are "parent" (Routing instance), "name" (user visible name)
    "datalink" (the datalink layer object for this circuit), and "config"
    (the config parameters for the circuit).
    """
    def __init__ (self, parent, name, datalink, config):
        Element.__init__ (self, parent)
        timers.Timer.__init__ (self)
        self.name = name
        self.config = config
        self.hellotime = config.t3 or 10
        self.datalink = datalink.create_port (self, ROUTINGPROTO)
        self.datalink.set_macaddr (parent.nodeid)

    def restart (self):
        self.start ()

    def start (self):
        self.sendhello ()

    def common_dispatch (self, work):
        if isinstance (work, datalink.DlReceive):
            buf = work.packet
            if not buf:
                logging.debug ("Null routing layer packet received on %s",
                               self.name)
                return
            hdr = packet.getbyte (buf)
            if hdr & 0x80:
                # Padding.  Skip over it.  Low 7 bits are the total pad
                # length, pad header included.
                buf = buf[pad & 0x7f:]
                hdr = packet.getbyte (buf)
                if hdr & 0x80:
                    logging.debug ("Double padded packet received on %s",
                                   self.name)
                    return
            if hdr & 1:
                # Routing control packet.  Figure out which one
                code = (hdr >> 1) & 7
                try:
                    work = bccontrolpackets[code] (buf, src = work.src)
                except KeyError:
                    logging.debug ("Unknown routing control packet %d from %s",
                                   code, self.name)
                    return
            else:
                code = hdr & 7
                if code == 6:
                    work = LongData (buf, src = work.src)
                elif code == 2:
                    work = ShortData (buf, src = work.src)
                else:
                    logging.debug ("Unknown routing packet %d from %s",
                                   code, self.name)
                    return
        return work
    
class NiCacheEntry (timers.Timer):
    """An entry in the on-Ethernet cache.  Or rather, in the previous hop
    cache, which is in Phase IV plus.  The difference is that it doesn't
    depend on the on-NI bit, but instead remembers the source MAC address
    of incoming traffic as the "previous hop".
    """
    __slots__ = ("id", "prevhop", "circuit")
    cachetime = 60
    
    def __init__ (self, id, prevhop, circuit):
        super ().__init__ ()
        self.circuit = circuit
        self.id = id
        self.prevhop = prevhop
        self.alive ()
        
    def dispatch (self, item):
        self.circuit.cache_expire (self.id)

    def alive (self):
        self.circuit.node.timers.start (self, self.cachetime)
        
class EndnodeLanCircuit (LanCircuit):
    """The datalink dependent sublayer for broadcast circuits on an endnode.
    """
    def __init__ (self, parent, name, datalink, config):
        super ().__init__ (parent, name, datalink, config)
        self.hello = EndnodeHello (tiver = tiver_ph4,
                                   blksize = MTU, id = parent.nodeid,
                                   timer = self.hellotime,
                                   testdata = 50 * b'\252')
        self.datalink.add_multicast (ALL_ENDNODES)
        self.dr = None
        self.prevhops = dict ()
        
    def sendhello (self):
        h = self.hello
        if self.dr:
            h.neighbor = self.dr.macid
        else:
            h.neighbor = NULLID
        self.datalink.send (h, ALL_ROUTERS)
        self.node.timers.start (self, self.hellotime)

    def dispatch (self, item):
        item = self.common_dispatch (item)
        if not item:
            # Rejected by common code
            return
        if isinstance (item, RouterHello):
            if item.id.area != self.parent.homearea:
                # Silently ignore out of area hellos
                return
            if self.dr:
                # Router hello when we already know a router.  Same?
                if self.dr.nodeid != item.id:
                    # Different.  Make the old one go away
                    self.dr.down ()
                    self.dr = adjacency.BcAdjacency (self, item.id,
                                                     item.timer * BCT3MULT)
                    self.parent.adjacency_up (self.dr)
                else:
                    self.dr.alive ()
            else:
                self.dr = adjacency.BcAdjacency (self, item.id,
                                                 item.timer * BCT3MULT)
                self.parent.adjacency_up (self.dr)
        elif isinstance (item, EndnodeHello):
            logging.debug ("Endnode hello from %s received by endnode",
                           item.src)
            return
        elif isinstance (item, timers.Timeout):
            self.sendhello ()
        else:
            if isinstance (item, (LongData, ShortData)):
                try:
                    self.prevhops[item.srcnode].alive ()
                except KeyError:
                    self.prevhops[item.srcnode] = NiCacheEntry (item.srcnode,
                                                                item.src, self)
            self.parent.dispatch (item)

    def cache_expire (self, id):
        try:
            del self.prevhops[id]
        except KeyError:
            pass
        
    def adjacency_down (self):
        self.parent.adjacency_down (self.dr)
        self.dr = None

    def send (self, pkt, dstnode, tryhard = False):
        """Send pkt to dstnode.
        """
        if isinstance (pkt, ShortData):
            pkt = LongData (copy = pkt, payload = pkt.payload)
        if tryhard:
            self.expire_cache (dstnode)
        else:
            try:
                prev = self.prevhops[dstnode]
                self.datalink.send (pkt, prev)
                return
            except KeyError:
                pass
        if self.dr:
            self.dr.send (pkt)
        else:
            self.datalink.send (pkt, Macaddr (dstnode))
            

#!/usr/bin/env python3

"""DECnet routing broadcast datalink dependent sublayer

"""

import re
import time

from .common import *
from .routing_packets import *
from .events import *
from . import datalink
from . import timers
from .route_ptp import ShortData

# Some well known Ethernet addresses
ALL_ROUTERS = Macaddr ("AB-00-00-03-00-00")
ALL_ENDNODES = Macaddr ("AB-00-00-04-00-00")

def sortkey (adj):
    return adj.priority, adj.nodeid

class LanCircuit (timers.Timer):
    """A broadcast circuit, i.e., the datalink dependent
    routing sublayer instance for an Ethernet type circuit.

    Arguments are "parent" (Routing instance), "name" (user visible name)
    "datalink" (the datalink layer object for this circuit), and "config"
    (the config parameters for the circuit).
    """
    def __init__ (self, parent, name, datalink, config):
        super ().__init__ ()
        self.hellotime = config.t3 or 10
        self.datalink = datalink.create_port (self, ROUTINGPROTO)
        self.datalink.set_macaddr (parent.nodemacaddr)
        self.lasthello = 0
        self.holdoff = False
        
    def __str__ (self):
        return "Circuit {0.name}".format (self)

    def restart (self):
        self.start ()

    def start (self):
        self.up ()
        self.sendhello ()

    def common_dispatch (self, work):
        if isinstance (work, datalink.DlReceive):
            if work.src == self.parent.nodemacaddr:
                # Ignore packets from self.
                return
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
                                   blksize = ETHMTU, id = parent.nodeid,
                                   timer = self.hellotime,
                                   testdata = 50 * b'\252')
        self.datalink.add_multicast (ALL_ENDNODES)
        self.dr = None
        self.prevhops = dict ()
        
    def sendhello (self):
        self.lasthello = time.time ()
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
        if isinstance (item, timers.Timeout):
            self.sendhello ()
        elif isinstance (item, RouterHello):
            if item.id.area != self.parent.homearea:
                # Silently ignore out of area hellos
                return
            if self.dr:
                # Router hello when we already know a router.  Same?
                if self.dr.nodeid != item.id:
                    # Different.  Make the old one go away
                    self.dr.down ()
                    self.dr = self.Adjacency (self, item)
                else:
                    self.dr.alive ()
            else:
                self.dr = self.Adjacency (self, item)
        elif isinstance (item, EndnodeHello):
            logging.debug ("Endnode hello from %s received by endnode",
                           item.src)
            return
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

# Adjacency states
INIT = 1
UP = 2

class RoutingLanCircuit (LanCircuit):
    """The datalink dependent sublayer for broadcast circuits on a router.
    """
    def __init__ (self, parent, name, datalink, config):
        super ().__init__ (parent, name, datalink, config)
        self.datalink.add_multicast (ALL_ROUTERS)
        self.adjacencies = dict ()
        self.isdr = False
        self.dr = None
        self.nr = config.nr
        self.prio = config.priority
        self.drkey = (self.prio, self.node.nodeid)
        self.hello = RouterHello (tiver = tiver_ph4, prio = self.prio,
                                  ntype = parent.ntype,
                                  blksize = ETHMTU, id = parent.nodeid,
                                  timer = self.hellotime)
        self.minrouterblk = ETHMTU
        
    def routers (self, anyarea = True):
        return ( a for a in self.adjacencies.values ()
                 if a.ntype != ENDNODE and
                 (anyarea or a.nodeid.area == self.parent.homearea))
    
    def sendhello (self):
        self.lasthello = time.time ()
        h = self.hello
        rslist = b''.join ([ bytes (RSent (router = a.nodeid, prio = a.priority,
                                           twoway = (a.state == UP)))
                             for a in self.routers () ])
        h.elist = bytes (Elist (rslist = rslist))
        self.datalink.send (h, ALL_ROUTERS)
        if self.isdr:
            self.datalink.send (h, ALL_ENDNODES)
        self.node.timers.start (self, self.hellotime)
        
    def dispatch (self, item):
        hellochange = False
        item = self.common_dispatch (item)
        if not item:
            # Rejected by common code
            return
        if isinstance (item, timers.Timeout):
            self.calcdr ()
            self.sendhello ()
        elif isinstance (item, (EndnodeHello, RouterHello)):
            id = item.id
            t4 = item.timer * BCT3MULT
            if id.area != self.parent.homearea and \
               not (self.parent.ntype == 1 and \
                    item.ntype == 1):
                # Silently ignore out of area hellos, unless we're an
                # area router and so is the sender.
                return
            # See if we have an existing adjacency
            a = self.adjacencies.get (id, None)
            if isinstance (item, EndnodeHello):
                if not testdata_re.match (item.testdata):
                    if a:
                        self.deladj (a, reason = "listener_invalid_data")
                    return
                # End node.  If it's new, add its adjacency and mark it up.
                if a is None:
                    a = self.adjacencies[id] = self.Adjacency (self, item)
                    a.state = UP
                    a.up ()
                elif a.ntype == ENDNODE:
                    a.alive ()
                else:
                    self.deladj (a, reason = "address_change")
                    return
            else:
                # Router hello.  Add its adjacency if it's new.
                if a is None:
                    a = self.adjacencies[id] = self.Adjacency (self, item)
                    a.state = INIT
                    # Check that the RSlist is not too long
                    rslist = list (self.routers ())
                    if len (rslist) > self.nr:
                        # The list is full.  Add the new node and remove
                        # the lowest priority one.
                        a2 = min (rslist, key = sortkey)
                        self.deladj (a2)
                        if a == a2:
                            # This node is the lowest priority, ignore its hello
                            return
                    self.minrouterblk = min (a.blksize for a in rslist)
                    hellochange = True
                else:
                    a.alive ()
                if a.ntype == ENDNODE or \
                       a.ntype != item.ntype or a.priority != item.prio:
                    self.deladj (a, reason = "address_change")
                    return
                # Process the received E-list and see if two-way state changed.
                rslist = Elist (item.elist).rslist
                while rslist:
                    ent = RSent ()
                    rslist = ent.decode (rslist)
                    if ent.router == self.parent.nodeid:
                        if ent.prio != self.prio:
                            logging.error ("Node %s has our prio as %d rather than %d",
                                           id, ent.prio, self,prio)
                            self.deladj (a, reason = "data_errors")
                            return
                        if ent.twoway:
                            if a.state == INIT:
                                a.state = UP
                                a.up ()
                                hellochange = True
                        else:
                            if a.state == UP:
                                # Don't kill the adjacency in our state, but
                                # do as far as the control layer is concerned.
                                self.adjacency_down (a, reason = "dropped")
                                a.state = INIT
                                hellochange = True
                # Update the DR state, if needed
                self.calcdr ()
                # If something we saw changes what we say in the hello, send
                # an updated hello now.
                if hellochange:
                    self.newhello ()
        elif isinstance (item, packet.Packet):
            # Some other packet type.  Pass it up, but only if it is for
            # an adjacency that is in the UP state
            a = self.adjacencies.get (Nodeid (item.src), None)
            if a and a.state == UP:
                item.src = a
                self.parent.dispatch (item)
            
    def calcdr (self):
        """Figure out who should be the designated router.  More precisely,
        are we DR, or someone else?
        """
        routers = list (self.routers (False))
        if routers:
            # Look for the best remote router, if there are any
            dr = max (routers, key = sortkey)
        if not routers or self.drkey > sortkey (dr):
            # Tag, we're it, but don't act on that for DRDELAY seconds.
            if not self.isdr:
                logging.debug ("Designated router is self")
                self.isdr = True
                self.holdoff = True
                self.node.timers.start (self, DRDELAY)
        else:
            self.isdr = False
            if self.dr != dr:
                self.dr = dr
                logging.debug ("Designated router is %s", dr.nodeid)
            
    def newhello (self):
        """Hello content changed.  Send a new one right now, unless
        it's been less than T2 since we sent the last one.
        If a deferred hello is already pending, take no action (the previously
        set timer will remain in effect).
        """
        deltat = time.time () - self.lasthello
        if deltat < T2:
            if not self.holdoff:
                self.holdoff = True
                self.node.timers.start (self, deltat)
        else:
            self.sendhello ()

    def deladj (self, a, **kwargs):
        self.adjacency_down (a, **kwargs)
        try:
            del self.adjacencies[a.nodeid]
        except KeyError:
            pass

    def adjacency_down (self, a, **kwargs):
        if a.state == UP:
            a.state = INIT
            a.down ()
        if a.ntype != ENDNODE:
            # Router adjacency, update DR state and send an updated hello
            self.calcdr ()
            self.newhello ()

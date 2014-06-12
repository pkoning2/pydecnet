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
    ph4 = True
    ph2 = False
    
    def __init__ (self, parent, name, datalink, config):
        super ().__init__ ()
        self.hellotime = config.t3 or 10
        self.datalink = datalink.create_port (self, ROUTINGPROTO)
        self.datalink.set_macaddr (parent.nodemacaddr)
        self.lasthello = 0
        self.holdoff = False
        
    def __str__ (self):
        return "{0.name}".format (self)

    def restart (self):
        self.start ()

    def start (self):
        self.up ()
        self.sendhello ()

    def stop (self):
        pass
    
    def common_dispatch (self, work):
        if isinstance (work, datalink.Received):
            if work.src == self.parent.nodemacaddr:
                # Ignore packets from self.
                return
            buf = work.packet
            if not buf:
                logging.debug ("Null routing layer packet received on %s",
                               self.name)
                return
            hdr = buf[0]
            if hdr & 0x80:
                # Padding.  Skip over it.  Low 7 bits are the total pad
                # length, pad header included.
                buf = buf[pad & 0x7f:]
                hdr = buf[0]
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
                    # Short data is not expected, but it is accepted
                    # just for grins (and because the spec allows it).
                    work = ShortData (buf, src = work.src)
                else:
                    logging.debug ("Unknown routing packet %d from %s",
                                   code, self.name)
                    return
        return work

    def up (self, **kwargs):
        pass

    def down (self, **kwargs):
        pass

    def html (self, what, first):
        if first:
            hdr = """<tr><th>Name</th><th>Cost</th>
            <th>Priority</th><th>Hello time</th>
            <th>Designated router</th></tr>\n"""
        else:
            hdr = ""
        dr = self.node.nodeinfo (self.dr)
        s = """<tr><td>{0.name}</td><td>{0.config.cost}</td>
        <td>{0.config.priority}</td><td>{0.hellotime}</td>
        <td>{1}</td></tr>\n""".format (self, dr)
        return hdr + s
    
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
        self.hello = EndnodeHello (tiver = parent.tiver,
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
                    self.dr.down (reason = "address_change")
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
        logging.trace ("Sending %d byte packet to %s: %s",
                       len (pkt), dstnode, pkt)
        if isinstance (pkt, ShortData):
            pkt = LongData (copy = pkt, payload = pkt.payload)
        if tryhard:
            self.cache_expire (dstnode)
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
        self.drtimer = timers.CallbackTimer (self.becomedr, None)
        self.dr = None
        self.nr = config.nr
        self.prio = config.priority
        self.drkey = (self.prio, self.node.nodeid)
        self.hello = RouterHello (tiver = parent.tiver, prio = self.prio,
                                  ntype = parent.ntype,
                                  blksize = ETHMTU, id = parent.nodeid,
                                  timer = self.hellotime)
        self.minrouterblk = ETHMTU

    def stop (self):
        self.node.timers.stop (self.drtimer)
        self.sendhello (empty = True)
        time.sleep (0.1)
        # Do it again to make sure
        self.sendhello (empty = True)
        time.sleep (0.1)

    def html (self, what, first):
        if what != "adjacencies":
            return super ().html (what, first)
        ret = list ()
        first = True
        for a in self.adjacencies.values ():
            if a.state == UP:
                s = a.html ("status", first)
                if s:
                    ret.append (s)
                    first = False
        if ret:
            ret.insert (0, "<table border=1 cellspacing=0 cellpadding=4>")
            ret.append ("</table>")
        return '\n'.join (ret)
    
    def routers (self, anyarea = True):
        return ( a for a in self.adjacencies.values ()
                 if a.ntype != ENDNODE and
                 (anyarea or a.nodeid.area == self.parent.homearea))
    
    def sendhello (self, empty = False):
        self.lasthello = time.time ()
        self.holdoff = False
        h = self.hello
        if empty:
            rslist = b''
        else:
            rslist = b''.join ([ bytes (RSent (router = a.nodeid,
                                               prio = a.priority,
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
            logging.trace ("LAN hello message received: %s", item)
            id = item.id
            t4 = item.timer * BCT3MULT
            if id.area != self.parent.homearea and \
               not (self.parent.ntype == L2ROUTER and \
                    item.ntype == L2ROUTER):
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
                    logging.trace ("New adjacency from %s", item)
                    a.state = INIT
                    # Check that the RSlist is not too long
                    rslist = list (self.routers ())
                    if len (rslist) > self.nr:
                        # The list is full.  Remove the lowest priority one
                        # (which may be the new one).
                        a2 = min (rslist, key = sortkey)
                        logging.trace ("Dropped adjacency %s", a2)
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
                # First look to see if our entry is in there.
                rslist = Elist (item.elist).rslist
                selfent = None
                while rslist:
                    ent = RSent ()
                    rslist = ent.decode (rslist)
                    if ent.router == self.parent.nodeid:
                        if ent.prio != self.prio:
                            logging.error ("Node %s has our prio as %d rather than %d",
                                           id, ent.prio, self,prio)
                            self.deladj (a, reason = "data_errors")
                            return
                        selfent = ent
                        break
                if selfent:
                    # We're listed, which means two way communication,
                    # so set the adjacency "up"
                    logging.trace ("self entry in received hello is %s",
                                   selfent)
                    if a.state == INIT:
                        a.state = UP
                        a.up ()
                        hellochange = True
                else:
                    # We're either not listed, or not two way.
                    logging.trace ("self not listed in received hello")
                    if a.state == UP:
                        a.down (reason = "dropped")
                        # Put it back into the adjacencies dict because
                        # a.down deleted it.
                        self.adjacencies[id] = a
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
            if item.src:
                a = self.adjacencies.get (Nodeid (item.src), None)
            else:
                # GRE, which is an Ethernet-style datalink but point to
                # point, doesn't pass up a source address (it doesn't have
                # any).  So pick up the first adjacency.
                a = None
                for a in self.adjacencies.values ():
                    break
            if a and a.state == UP:
                item.src = a
                logging.trace ("Routing LAN message received from %s: %s",
                               a, item)
                self.parent.dispatch (item)
            else:
                logging.trace ("%s packet dropped, no adjacency",
                               item.__class__.__name__)

    def findbestdr (self):
        """Return who should be designated router according to the current
        set of known routers.  Returns self for local node, or the router
        list entry otherwise.
        """
        routers = list (self.routers (False))
        if routers:
            # Look for the best remote router, if there are any
            dr = max (routers, key = sortkey)
        if not routers or self.drkey > sortkey (dr):
            return self
        else:
            return dr
            
    def calcdr (self):
        """Figure out who should be the designated router.  More precisely,
        are we DR, or someone else?
        """
        dr = self.findbestdr ()
        if dr is self:
            # Tag, we're it, but don't act on that for DRDELAY seconds,
            # and don't do it again if the DR timer is already running
            if not self.isdr and not self.drtimer.islinked ():
                logging.debug ("Designated router on %s will be self, %d second delay",
                               self.name, DRDELAY)
                self.node.timers.start (self.drtimer, DRDELAY)
        else:
            if self.isdr:
                self.isdr = False
                self.newhello ()
            if self.dr != dr:
                self.node.timers.stop (self.drtimer)
                self.dr = dr
                logging.debug ("Designated router on %s is %s",
                               self.name, dr.nodeid)

    def becomedr (self, arg):
        self.isdr = True
        # See if this is still the right answer.  If yes, make it effective.
        # If not, put that other conclusion into effect.
        # Note we don't just call calcdr() right away because that does
        # some more things and generates more messages for the first case.
        if self.findbestdr () is self:
            logging.debug ("Designated router on %s is self", self.name)
            self.newhello ()
        else:
            self.calcdr ()
            
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
        if a.state == UP:
            a.state = INIT
            a.down (**kwargs)
        if a.ntype != ENDNODE:
            # Router adjacency, update DR state and send an updated hello
            self.calcdr ()
            self.newhello ()
            self.minrouterblk = ETHMTU
            for r in self.routers ():
                self.minrouterblk = min (self.minrouterblk, r.blksize)
        try:
            del self.adjacencies[a.nodeid]
        except KeyError:
            pass

    def adjacency_down (self, a, **kwargs):
        """Called from the control layer to take an adjacency down.
        """
        a.state = INIT    # Avoid recursion
        self.deladj (a, **kwargs)


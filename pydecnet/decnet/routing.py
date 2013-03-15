#!/usr/bin/env python3

"""DECnet routing decision and update modules.

"""

import time
import array
import sys

from .common import *
from .routing_packets import *
from .events import *
from . import datalink
from . import timers
from . import statemachine
from . import route_ptp
from . import route_eth

def allocvecs (maxidx):
    hops = bytearray (maxidx + 1)
    cost = array.array ("H", [ 0 ]) * (maxidx + 1)
    setinf (hops, cost)
    return hops, cost

def setinf (hops, cost):
    for i in range (len (hops)):
        hops[i] = INFHOPS
        cost[i] = INFCOST

class CirAdj (object):
    """Base class for what is common between point to point circuits
    and LAN adjacencies.
    """
    def __init__ (self, circuit):
        self.circuit = circuit
        self.routing = circuit.routing
        
    def up (self, nodeid = None, ntype = None, **kwargs):
        if ntype:
            self.nodeid = nodeid
            self.ntype = ntype
        self.log_up (**kwargs)

    def down (self, **kwargs):
        self.log_down (**kwargs)
    
class L1CirAdj (CirAdj):
    """Circuit/Adjacency common behavior on L1 routers (or the L1 part
    of area routers).
    """
    def __init__ (self, circuit):
        CirAdj.__init__ (self, circuit)
        self.hops, self.cost = allocvecs (self.routing.maxnodes)
        self.routeinfo = RouteInfo (self)

    def up (self, nodeid = None, ntype = None, **kwargs):
        CirAdj.up (self, nodeid, ntype, **kwargs)
        if self.ntype == ENDNODE:
            id = self.nodeid.tid
            circ = self.circuit
            circ.hops[id] = 1
            circ.cost[id] = circ.config.cost
            self.routing.l1info[circ] = circ.routeinfo
            self.routing.route (id)
        else:
            setinf (self.hops, self.cost)
            self.routeinfo.nodeid = self.nodeid
            self.circuit.setsrm (0, self.routing.maxnodes)
            self.routing.l1info[self] = self.routeinfo
        
    def down (self, **kwargs):
        CirAdj.down (self, **kwargs)
        if self.ntype == ENDNODE:
            id = self.nodeid.tid
            circ = self.circuit
            circ.hops[id] = INFHOPS
            circ.cost[id] = INFCOST
            self.routing.route (id)
        else:
            del self.routing.l1info[self]
            self.routing.route (0, self.routing.maxnodes)

class L2CirAdj (L1CirAdj):
    """The additional adjacency/cicuit common behavior for an area router.
    """
    def __init__ (self, circuit):
        L1CirAdj.__init__ (self, circuit)
        self.ahops, self.acost = allocvecs (self.routing.maxarea)
        self.arouteinfo = RouteInfo (self, l2 = True)
    
    def up (self, nodeid = None, ntype = None, **kwargs):
        L1CirAdj.up (self, nodeid, ntype, **kwargs)
        setinf (self.ahops, self.acost)
        if self.ntype == L2ROUTER:
            self.circuit.setasrm (0, self.routing.maxarea)
            self.routing.l2info[self] = self.arouteinfo

    def down (self, **kwargs):
        L1CirAdj.down (self, **kwargs)
        if self.ntype == L2ROUTER:
            del self.routing.l2info[self]
            self.routing.aroute (0, self.routing.maxarea)

class _Adjacency (Element, timers.Timer):
    """DECnet broadcast adjacency base class.  Its parent (owner) is
    the circuit to which this adjacency belongs.  We only use these
    for LANs; for point to point, the circuit does double duty to
    carry the adjacency related data.  This base class is used along with
    one of the CirAdj classes to derive the adjacency classes actually
    used by Routing.
    """
    def __init__ (self, circuit, hellomsg):
        """Create an adjacency based on the information in the hello
        message that announced the node.
        """
        Element.__init__ (self, circuit)
        timers.Timer.__init__ (self)
        self.circuit = circuit
        self.t4 = hellomsg.timer * BCT3MULT
        self.blksize = hellomsg.blksize
        self.nodeid = hellomsg.id
        self.ntype = hellomsg.ntype
        self.tiver = hellomsg.tiver
        self.macid = Macaddr (self.nodeid)
        self.priority = 0
        
    def __str__ (self):
        return "{0.nodeid}".format (self)

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
            self.down (reason = "listener_timeout")
            
    def alive (self):
        """Mark this adjacency as alive -- restart its listen timeout.
        """
        self.node.timers.start (self, self.t4)

    def send (self, pkt):
        """Send the supplied packet on this adjacency.  If it has a short
        header, give it a long header instead.
        """
        if isinstance (pkt, ShortData):
            pkt = LongData (copy = pkt, payload = pkt.payload)
        self.circuit.datalink.send (pkt, dest = self.macid)

    def log_up (self, **kwargs):
        self.node.logevent (Event.adj_up, self.circuit,
                            adjacent_node = self.node.eventnode (self.nodeid),
                            **kwargs)

    def log_down (self, **kwargs):
        self.node.logevent (Event.adj_down, self.circuit,
                            adjacent_node = self.node.eventnode (self.nodeid),
                            **kwargs)
    
class EndnodeAdjacency (CirAdj, _Adjacency):
    """Adjacency class as used on endnodes.
    """
    def __init__ (self, circuit, hellomsg):
        """Create an adjacency on an endnode, and mark it as "up"
        """
        CirAdj.__init__ (self, circuit)
        _Adjacency.__init__ (self, circuit, hellomsg)
        self.up ()

class L1Adjacency (L1CirAdj, _Adjacency):
    """Adjacency class as used on level 1 routers.
    """
    def __init__ (self, circuit, hellomsg):
        L1CirAdj.__init__ (self, circuit)
        _Adjacency.__init__ (self, circuit, hellomsg)
        if self.ntype != ENDNODE:
            self.priority = hellomsg.prio

    def up (self, **kwargs):
        L1CirAdj.up (self, **kwargs)
        if self.ntype == ENDNODE:
            # Add this adjacency to the BEA list
            self.circuit.bea[self.nodeid.tid] = self
            
    def down (self, **kwargs):
        L1CirAdj.down (self, **kwargs)
        self.circuit.adjacency_down (self, **kwargs)
            
class L2Adjacency (L2CirAdj, L1Adjacency):
    """Adjacency class as used on area routers.
    """
    def __init__ (self, circuit, hellomsg):
        L2CirAdj.__init__ (self, circuit)
        L1Adjacency.__init__ (self, circuit, hellomsg)
    
class Circuit (Element):
    """Base class for all routing layer circuits.
    """
    def __init__ (self, parent, name, datalink, config):
        super ().__init__ (parent)
        self.routing = parent
        self.name = name
        self.config = config

    def log_up (self, **kwargs):
        self.node.logevent (Event.circ_up, self, **kwargs)

    def log_down (self, **kwargs):
        self.node.logevent (Event.circ_down, self, **kwargs)
    
class L1Circuit (Circuit):
    """The routing layer circuit behavior for a circuit in a level 1
    router (or the level 1 functionality of an area router).
    """
    def setsrm (self, tid, endtid = None):
        self.update.setsrm (tid, endtid)
        
    def setasrm (self, area, endarea = None):
        pass
    
class L2Circuit (L1Circuit):
    """The additional cicuit behavior for an area router.
    """
    def setasrm (self, area, endarea = None):
        self.aupdate.setsrm (area, endarea)

# With all the building blocks in place, define the classes to use
# for the routing circuits for various routing layer configs

class PtpEndnodeCircuit (route_ptp.PtpCircuit, CirAdj, Circuit):
    """Point to point circuit on an endnode.
    """
    def __init__ (self, parent, name, datalink, config):
        route_ptp.PtpCircuit.__init__ (self, parent, name, datalink, config)
        Circuit.__init__ (self, parent, name, datalink, config)
        CirAdj.__init__ (self, self)
        
class PtpL1Circuit (route_ptp.PtpCircuit, L1CirAdj, L1Circuit):
    """Point to point circuit on a level 1 router.
    """
    def __init__ (self, parent, name, datalink, config):
        route_ptp.PtpCircuit.__init__ (self, parent, name, datalink, config)
        L1Circuit.__init__ (self, parent, name, datalink, config)
        L1CirAdj.__init__ (self, self)
        self.update = Update (self, self.routing.config.t1,
                              self.routing.minhops, self.routing.mincost,
                              L1Routing)
        
class PtpL2Circuit (PtpL1Circuit, L2CirAdj, L2Circuit):
    """Point to point circuit on an area router.  
    """
    def __init__ (self, parent, name, datalink, config):
        PtpL1Circuit.__init__ (self, parent, name, datalink, config)
        L2Circuit.__init__ (self, parent, name, datalink, config)
        L2CirAdj.__init__ (self, self)
        self.aupdate = Update (self, self.routing.config.t1,
                               self.routing.aminhops, self.routing.amincost,
                               L2Routing)

# The LAN circuits have the analogous base classes.  Note that the routing
# versions still have a CirAdj base class -- that is used to store the
# routing information derived from endnode adjacencies.
# For LAN circuits, the node type (ntype) is taken to be that of the
# local node.  When we need to know the specific type of a neighbor,
# that information is found in the adjacency for that neighbor.

class LanEndnodeCircuit (route_eth.EndnodeLanCircuit, Circuit):
    """LAN circuit on an endnode.
    """
    Adjacency = EndnodeAdjacency
    ntype = ENDNODE
    
    def __init__ (self, parent, name, datalink, config):
        Circuit.__init__ (self, parent, name, datalink, config)
        route_eth.EndnodeLanCircuit.__init__ (self, parent, name,
                                              datalink, config)
        
class LanL1Circuit (route_eth.RoutingLanCircuit, L1CirAdj, L1Circuit):
    """LAN circuit on a level 1 router.
    """
    Adjacency = L1Adjacency
    ntype = L1ROUTER
    
    def __init__ (self, parent, name, datalink, config):
        self.nodeid = 0
        L1Circuit.__init__ (self, parent, name, datalink, config)
        L1CirAdj.__init__ (self, self)
        route_eth.RoutingLanCircuit.__init__ (self, parent, name,
                                              datalink, config)
        # Vector of broadcast endnode adjacencies, indexed by Tid
        self.bea = [ None ] * (self.routing.maxnodes + 1)
        self.update = Update (self, self.routing.config.bct1,
                              self.routing.minhops, self.routing.mincost,
                              L1Routing)

class LanL2Circuit (LanL1Circuit, L2CirAdj, L2Circuit):
    """LAN circuit on an area router.
    """
    Adjacency = L2Adjacency
    ntype = L2ROUTER
    
    def __init__ (self, parent, name, datalink, config):
        LanL1Circuit.__init__ (self, parent, name, datalink, config)
        L2Circuit.__init__ (self, parent, name, datalink, config)
        L2CirAdj.__init__ (self, self)
        self.aupdate = Update (self, self.routing.config.bct1,
                               self.routing.aminhops, self.routing.amincost,
                               L2Routing)
        
class _Router (Element):
    """The routing layer.  Mainly this is the parent of a number of control
    components and collections of circuits and adjacencies.
    """
    tiver = tiver_ph4
    
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        logging.debug ("Initializing routing layer")
        self.config = config.routing
        self.routing = self
        self.circuits = dict ()
        self.nodeid = config.routing.id
        self.nodemacaddr = Macaddr (self.nodeid)
        self.homearea, self.tid = self.nodeid.split ()
        self.typename = config.routing.type
        self.name = parent.nodeinfo (self.nodeid).nodename
        dlcirc = self.node.datalink.circuits
        for name, c in config.circuit.items ():
            dl = dlcirc[name]
            try:
                self.circuits[name] = self.routing_circuit (name, dl, c)
                logging.debug ("Initialized routing circuit %s", name)
            except Exception:
                logging.exception ("Error initializing routing circuit %s", name)

    def routing_circuit (self, name, dl, c):
        """Factory function for circuit objects.  Depending on the datalink
        type (LAN vs. not) and node type (endnode vs.router) we use different
        classes.
        """
        if isinstance (dl, datalink.BcDatalink):
            ctype = self.LanCircuit
        else:
            ctype = self.PtpCircuit
        if not ctype:
            raise TypeError ("Unsupported circuit type")
        return ctype (self, name, dl, c)
            
    def start (self):
        logging.debug ("Starting Routing layer")
        for name, c in self.circuits.items ():
            try:
                c.start ()
                logging.debug ("Started Routing circuit %s", name)
            except Exception:
                logging.exception ("Error starting Routing circuit %s", name)
        self.node.logevent (Event.node_state, reason = "operator_command",
                            old_state = "off", new_state = "on")
    
    def stop (self):
        logging.debug ("Stopping Routing layer")
        for name, c in self.circuits.items ():
            try:
                c.stop ()
                logging.debug ("Stopped Routing circuit %s", name)
            except Exception:
                logging.exception ("Error stopping Routing circuit %s", name)
        self.node.logevent (Event.node_state, reason = "operator_command",
                            old_state = "on", new_state = "off")
    
    def dispatch (self, item):
        pass

class EndnodeRouting (_Router):
    """Routing entity for endnodes.
    """
    LanCircuit = LanEndnodeCircuit
    PtpCircuit = PtpEndnodeCircuit
    ntype = ENDNODE
    
    def __init_ (self, parent, config):
        super ().__init__ (parent, config)
        if len (parent.circuits) != 1:
            raise ValueError ("End node must have 1 circuit, found %d" % \
                              len (parent.circuits))
        # Remember that one circuit for easier access
        for c in parent.circuits.values ():
            self.circuit = c

    def send (self, data, dest, rqr = False, tryhard = False):
        """Send NSP data to the given destination.  rqr is True to
        request return to sender (done for CI messages).  tryhard is
        True to request ignoring endnode cache entries; this is done
        for retransmits.  For routers it has no effect and is ignored.
        """
        pkt = LongData (rqr = rqr, ie = 1, dstnode = dest,
                        srcnode = self.nodeid, visit = 0,
                        payload = data)
        self.c.send (pkt, dest, tryhard)

    def dispatch (self, item):
        if isinstance (item, (ShortData, LongData)):
            if item.dstnode == self.nodeid:
                work = Received (self.node.nsp, packet = item,
                                 src = item.srcnode)
                self.node.addwork (work, self.node.nsp)

class RouteInfo (object):
    """The routing info, as found in the circuit or adjacency but
    separated out for easier access.
    """
    def __init__ (self, adjacency, l2 = False):
        self.adjacency = adjacency
        circ = adjacency.circuit
        if l2:
            self.hops = adjacency.ahops
            self.cost = adjacency.acost
            self.setsrm = circ.setsrm
        else:
            self.hops = adjacency.hops
            self.cost = adjacency.cost
            self.setsrm = circ.setasrm
        self.nodeid = None
            
class L1Router (_Router, L1CirAdj):
    """Routing entity for level 1 routers.  The L1CirAdj base class
    provides column 0 of the routing data -- the entries for "self".
    """
    LanCircuit = LanL1Circuit
    PtpCircuit = PtpL1Circuit
    ntype = L1ROUTER
    attached = False    # Set on L2 router, needed by check

    def __init__ (self, parent, config):
        # These are needed by various constructors so grab them first
        rconfig = config.routing
        self.maxnodes = rconfig.maxnodes
        self.maxhops = rconfig.maxhops
        self.maxcost = rconfig.maxcost
        self.maxvisits = rconfig.maxvisits
        self.minhops, self.mincost = allocvecs (rconfig.maxnodes)
        self.oadj = [ None ] * (self.maxnodes + 1)
        _Router.__init__ (self, parent, config)
        L1CirAdj.__init__ (self, self)
        self.l1info = dict ()
        self.adjacencies = dict ()

    # CirAdj.up calls this:
    def log_up (self):
        pass

    def up (self):
        # The routing object includes adjacency data which describes
        # "self" (the routing architecture spec shows this as column 0
        # of the routing matrix).
        L1CirAdj.up (self)
        # The CirAdj "up" call sets the whole column to infinite, so set our
        # own entries correctly.
        tid = self.parent.nodeid.tid
        self.hops[tid] = self.cost[tid] = 0
        self.oadj[tid] = self
        
    def start (self):
        super ().start ()
        self.up ()
        self.route (0, self.maxnodes)
        
    def routemsg (self, item, info, route, maxid):
        adj = item.src
        maxreach = 0
        for k, v in item.entries (adj.circuit):
            if k > maxid:
                if v != (INFHOPS, INFCOST):
                    maxreach = max (maxreach, k)
                continue
            oldv = info.hops[k], info.cost[k]
            if oldv != v:
                info.hops[k], info.cost[k] = v
                route (k)
        if maxreach:
            self.node.logevent (Event.rout_upd_loss, adj.circuit,
                                highest_address = maxreach,
                                adjacent_node = self.node.eventnode (adj.nodeid))
        
    def dispatch (self, item):
        if isinstance (item, L1Routing):
            adj = item.src
            if adj.nodeid.area == self.homearea:
                self.routemsg (item, adj.routeinfo, self.route, self.maxnodes)
        elif isinstance (item, (ShortData, LongData)):
            self.forward (item)
            
    def setsrm (self, tid, endtid = None):
        for c in self.circuits.values ():
            c.setsrm (tid, endtid)
            
    def setasrm (self, area, endarea = None):
        pass

    def doroute (self, start, end, l2):
        end = end or start
        if l2:
            routeinfodict = self.l2info
            minhops = self.aminhops
            mincost = self.amincost
            oadj = self.aoadj
            setsrm = self.setasrm
        else:
            routeinfodict = self.l1info
            minhops = self.minhops
            mincost = self.mincost
            oadj = self.oadj
            setsrm = self.setsrm
        self.check ()
        for i in range (start, end + 1):
            besth, bestc, besta = INFHOPS, INFCOST, None
            for r in routeinfodict.values ():
                if r.cost[i] < bestc or \
                   (r.cost[i] == bestc and \
                    (besta is None or
                     (r.nodeid and r.nodeid > besta.nodeid))):
                    bestc = r.cost[i]
                    besth = r.hops[i]
                    # routeinfo.adjacency is the adjacency for this
                    # next hop, unless we're dealing with an endnode
                    # in which case that is the circuit where the
                    # endnode lives, and we have to look in its
                    # broadcast adjacency table to find the actual
                    # adjacency.  That case is flagged by the routeinfo
                    # nodeid attribute being zero.
                    besta = r.adjacency
                    if r.nodeid == 0:
                        besta = besta.bea[i]
            if bestc > self.maxcost or besth > self.maxhops:
                besth, bestc, besta = INFHOPS, INFCOST, None
            if minhops[i] != besth or mincost[i] != bestc:
                minhops[i] = besth
                mincost[i] = bestc
                setsrm (i)
                logging.trace ("Node %d, cost %d, hops %d via %s %s",
                               i, bestc, besth,
                               besta and besta.circuit.name,
                               besta and besta.nodeid)
            if besta != oadj[i]:
                oadj[i] = besta
                if l2:
                    if besta:
                        self.node.logevent (Event.area_chg, i,
                                            status = "reachable")
                    else:
                        self.node.logevent (Event.area_chg, i,
                                            status = "unreachable")
                elif i:
                    # That check for 0 is there so reachability changes
                    # of "nearest L2 router" aren't logged.
                    nod = self.node.eventnode (Nodeid (self.homearea, i))
                    if besta:
                        self.node.logevent (Event.reach_chg, nod,
                                            status = "reachable")
                    else:
                        self.node.logevent (Event.reach_chg, nod,
                                            status = "unreachable")

    def route (self, start, end = None):
        self.doroute (start, end, l2 = False)

    def aroute (self, start, end = None):
        pass
    
    def check (self):
        try:
            tid = self.nodeid.tid
            for i in range (self.maxnodes + 1):
                if i == tid or (self.attached and i == 0):
                    assert self.hops[i] == self.cost[i] == 0
                else:
                    assert self.hops[i] == INFHOPS and self.cost[i] == INFCOST
        except AssertionError:
            logging.critical ("Check failure on L1 entry %d: %d %d",
                              i, self.hops[i], self.cost[i])
            sys.exit (1)

    def findoadj (self, dest):
        """Find the output adjacency for this destination address.
        """
        area, tid = dest.split ()
        if area != self.homearea:
            tid = 0
        return self.oadj[tid]

    def send (self, data, dest, rqr = False, tryhard = False):
        """Send NSP data to the given destination.  rqr is True to
        request return to sender (done for CI messages).  tryhard is
        True to request ignoring endnode cache entries; this is done
        for retransmits.  For routers it has no effect and is ignored.
        """
        pkt = LongData (rqr = rqr, ie = 1, dstnode = dest,
                        srcnode = self.nodeid, visit = 0,
                        payload = data)
        self.forward (pkt)
        
    def forward (self, pkt):
        dest = pkt.dstnode
        if dest == self.nodeid:
            # Terminating packet - hand it to NSP
            work = Received (self.node.nsp, packet = pkt, src = pkt.srcnode)
            self.node.addwork (work, self.node.nsp)
            return
        else:
            a = self.findoadj (dest)
            if a:
                # Destination is reachable.  Send it, unless
                # we're at the visit limit
                srcadj = pkt.src
                if srcadj:
                    # Forwarding (as opposed to originating)
                    pkt.visit += 1
                    if srcadj.circuit != a.circuit:
                        # Mark "not intra-Ethernet"
                        pkt.ie = 0
                    limit = self.maxvisits
                    if pkt.rts:
                        limit *= 2
                    if pkt.visit <= limit:
                        # Visit limit still ok, send it and exit
                        a.send (pkt)
                        return
            # If we get to this point, we could not forward the packet,
            # for one of two reasons: not reachable, or too many visits.
            # Return to sender if requested and not already underway,
            # else drop the packet.
            if pkt.rqr and not pkt.rts:
                pkt.dstnode, pkt.srcnode = pkt.srcnode, pkt.dstnode
                pkt.rts = 1
                pkt.rqr = 0
                self.forward (pkt)
                return
            # FIXME: Build correct packet header argument
            if isinstance (pkt, ShortData):
                kwargs = { packet_header : 1234 }
            else:
                kwargs = { eth_packet_header : 1234 }
            if a:
                # Reachable, so the problem was max visits
                self.node.logevent (aged_drop, **kwargs)
            else:
                self.node.logevent (unreach_drop, adjacency = srcadj, **kwargs)
            
class L2Router (L1Router, L2CirAdj):
    """Routing entity for level 2 (area) routers
    """
    LanCircuit = LanL2Circuit
    PtpCircuit = PtpL2Circuit
    ntype = L2ROUTER
    
    def __init__ (self, parent, config):
        rconfig = config.routing
        self.maxarea = rconfig.maxarea
        self.amaxhops = rconfig.amaxhops
        self.amaxcost = rconfig.amaxcost
        self.aminhops, self.amincost = allocvecs (rconfig.maxarea)
        self.aoadj = [ None ] * (self.maxarea + 1)
        L1Router.__init__ (self, parent, config)
        L2CirAdj.__init__ (self, self)
        self.attached = False
        self.l2info = dict ()
        
    def up (self):
        # The routing object includes adjacency data which describes
        # "self" (the routing architecture spec shows this as column 0
        # of the routing matrix).
        L2CirAdj.up (self)
        # The CirAdj "up" call sets the whole column to infinite, so set our
        # own entries correctly.
        tid = self.parent.nodeid.tid
        self.hops[tid] = self.cost[tid] = 0
        self.oadj[tid] = self
        area = self.nodeid.area
        self.ahops[area] = self.acost[area] = 0
        self.aoadj[area] = self
        
    def start (self):
        super ().start ()
        self.aroute (1, self.maxarea)

    def dispatch (self, item):
        if isinstance (item, L2Routing):
            adj = item.src
            self.routemsg (item, adj.arouteinfo, self.aroute, self.maxarea)
        else:
            super ().dispatch (item)
            
    def setasrm (self, area, endarea = None):
        for c in self.circuits.values ():
            c.setasrm (area, endarea)

    def aroute (self, start, end = None):
        self.doroute (start, end, l2 = True)
        attached = False
        for i, a in enumerate (self.aoadj):
            if a and i != self.homearea:
                attached = True
                break
        if attached != self.attached:
            logging.debug ("L2 attached state changed to %s", attached)
            self.attached = attached
            if attached:
                self.hops[0] = self.cost[0] = 0
            else:
                self.hops[0] = INFHOPS
                self.cost[0] = INFCOST
            self.route (0)

    def findoadj (self, dest):
        """Find the output adjacency for this destination address.
        """
        area = dest.area
        if self.attached and area != self.homearea:
            return self.aoadj[area]
        return super ().findoadj (dest)

    def check (self):
        super ().check ()
        try:
            area = self.nodeid.area
            for i in range (1, self.maxarea + 1):
                if i == area:
                    assert self.ahops[i] == self.acost[i] == 0
                else:
                    assert self.ahops[i] == INFHOPS and \
                           self.acost[i] == INFCOST
        except AssertionError:
            logging.critical ("Check failure on L2 entry %d: %d %d",
                              i, self.ahops[i], self.acost[i])
            sys.exit (1)
        
class Update (Element, timers.Timer):
    """Update process for a circuit
    """
    def __init__ (self, circ, t1, minhops, mincost, pkttype):
        Element.__init__ (self, circ)
        timers.Timer.__init__ (self)
        self.routing = circ.parent
        self.t1 = t1
        self.minhops = minhops
        self.mincost = mincost
        self.pkttype = pkttype
        self.lastupdate = self.lastfull = 0
        self.holdoff = False
        self.anysrm = False
        self.srm = bytearray (len (minhops))
        self.startpos = 0
        self.node.timers.start (self, self.t1)
            
    def setsrm (self, tid, endtid = None):
        if self.parent.ntype != ENDNODE:
            endtid = endtid or tid
            logging.trace ("Setsrm (%s): %d to %d", self.pkttype.__name__,
                           tid, endtid)
            for i in range (tid, endtid + 1):
                self.srm[i] = 1
            self.anysrm = True
            self.update_soon ()

    def update_soon (self):
        if not self.holdoff:
            delta = max (T2 - (time.time () - self.lastupdate), 0)
            logging.trace ("Scheduling update (%s) in %.1f",
                           self.pkttype.__name__, delta)
            self.holdoff = True
            self.node.timers.start (self, delta)

    def dispatch (self, item):
        if isinstance (item, timers.Timeout):
            # If anysrm is set, that means setsrm was called to
            # request sending of specific updates.  If not, then this
            # is a periodic (all destinations) update
            pkts = self.buildupdates (not self.anysrm)
            self.startpos += 1
            startpos = self.startpos % len (pkts)
            pkts = pkts[startpos:] + pkts[:startpos]
            logging.trace ("Sending %d update (%s) packets",
                           len (pkts), self.pkttype.__name__)
            for p in pkts:
                self.parent.datalink.send (p, dest = route_eth.ALL_ROUTERS)
            self.lastupdate = time.time ()
            self.holdoff = False
            if self.anysrm:
                # Not periodic update; find the delta from the last
                # periodic update as the new timeout.
                delta = min (self.lastupdate - self.lastfull, self.t1)
            else:
                delta = self.t1
                self.lastfull = self.lastupdate
            self.node.timers.start (self, delta)
            self.anysrm = False
            
    def buildupdates (self, complete):
        """Build routing messages according to the SRM flags.  The highest
        entry is obtained from the length of the minhops vector; the starting
        entry number is given by pkttype.lowid.  If "complete" is False, send
        only entries whose srm flag is set; otherwise send everything.
        
        The return value is a list of packets.
        """
        srm = self.srm
        minhops = self.minhops
        mincost = self.mincost
        pkt = self.pkttype
        seg = pkt.segtype
        if seg:
            # Phase 4 (segmented) format
            ret = list ()
            p = None
            previd = -999
            curlen = 0    # dummy value so it is defined
            mtu = self.parent.minrouterblk - 16
            for i in range (pkt.lowid, len (minhops)):
                if complete or srm[i]:
                    if curlen > mtu:
                        # If the packet is at the size limit, finish it up
                        # and append it to the returned packet list.
                        if seg:
                            p.segments.append (seg)
                        ret.append (p)
                        p = None
                    srm[i] = 0
                    if not p:
                        p = pkt (srcnode = self.node.nodeid)
                        p.segments = list ()
                        seg = None
                        curlen = 6   # Packet header plus checksum
                    # Find out how many unflagged entries there are, and
                    # send those also, if there are few enough.  If it's
                    # more efficient to start a new segment, do that
                    # instead.
                    gap = i - previd
                    if seg:
                        if gap > 2:
                            p.segments.append (seg)
                            seg = None
                        else:
                            for j in range (previd + 1, i):
                                ent = RouteSegEntry (cost = mincost[j],
                                                     hops = minhops[j])
                                seg.entries.append (ent)
                                curlen += 2
                    if not seg:
                        seg = pkt.segtype (startid = i)
                        seg.entries = list ()
                        curlen += 4    # Segment header
                    ent = RouteSegEntry (cost = mincost[i], hops = minhops[i])
                    seg.entries.append (ent)
                    previd = i
                    curlen += 2
            if seg:
                p.segments.append (seg)
            if p and p.segments:
                ret.append (p)
        else:
            # Phase 3 (not segmented) format
            p = pkt (srcnode = self.node.nodeid)
            p.entries = list ()
            for i in range (1, len (minhops)):
                srm[i] = 0
                p.append (RouteSegEntry (cost = mincost[i], hops = minhops[i]))
            ret = [ p ]
        return ret

nodetypes = { "l1router" : L1Router,
              "l2router" : L2Router,
              "endnode" : EndnodeRouting }
              #"phase3router" : P3Router,
              #"phase3endnode" : P3EndnodeRouting,
              #"phase2" : P2Routing }

def Router (parent, config):
    """Factory function for routing layer instance.  Returns an instance
    of the appropriate _Router subclass, depending on the supplied config.
    """
    rtype = config.routing.type
    try:
        return nodetypes[rtype] (parent, config)
    except KeyError:
        logging.critical ("Unsupported routing type %s", rtype)
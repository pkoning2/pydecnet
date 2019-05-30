#!/usr/bin/env python3

"""DECnet routing decision and update modules.

"""

import time
import array
import sys

from .common import *
from .routing_packets import *
from .nsp import NspCounters
from . import logging
from . import events
from . import adjacency
from . import datalink
from . import timers
from . import statemachine
from . import route_ptp
from . import route_eth
from . import html

SvnFileRev = "$LastChangedRevision$"

internals = """
Notes on circuits and adjacencies.

The DECnet Routing architecture spec makes a bit of a muddle about
circuits and adjacencies and the way route data is kept.  It seems
to come from an attempt to model what's likely to be implemented
in a tight memory environment, rather than to give a description
that's maximally simple.

In this implementation, we have circuit objects that store only
circuit things, and adjacency objects to record information about
a given neighbor.  This means, for example, that for a point to point
circuit there is an adjacency (one), describing that neighbor, instead
of keeping that data as part of the circuit.

Similarly, we try to keep the distinction between endnode adjacencies
and router adjacencies as small as possible.

Basically, adjacencies all have some common behavior: they appear and
disappear, they have an associated timeout that makes the adjacency
go away on expiration, you can send things to the adjacency.

*** adjacency created in sublayer, when node heard from.  routing.adj_up
called when ready for routing upper layer.
"""

# Circuit counter descriptions and field (attribute) names
fieldlist = (("Terminating packets received", "term_recv"),
             ("Originating packets sent", "orig_sent"),
             ("Transit packets received", "trans_recv"),
             ("Transit packets sent", "trans_sent"),
             ("Circuit down", "cir_down"),
             ("Adjacency down", "adj_down"),
             ("Initialization failure", "init_fail"))
    
def allocvecs (maxidx):
    hops = bytearray (maxidx + 1)
    cost = array.array ("H", [ 0 ]) * (maxidx + 1)
    setinf (hops, cost)
    return hops, cost

def setinf (hops, cost):
    for i in range (len (hops)):
        hops[i] = INFHOPS
        cost[i] = INFCOST

class SelfAdj (adjacency.Adjacency):
    """A pseudo-adjacency used to describe the local node.
    """
    class SelfCirc (object):
        hops = 1
        cost = 1
        name = "to NSP"
        def setsrm (self, *args): pass
        def setasrm (self, *args): pass
        
    def __init__ (self, routing):
        Element.__init__ (self, routing)
        timers.Timer.__init__ (self)
        # Note that we don't call the Adjacency constructor
        # Instead, some of the things it does are done here in
        # a slightly different way, and a lot of things are omitted
        self.hops = self.cost = 1
        self.circuit = self.SelfCirc ()
        self.routing = routing
        self.nodeid = routing.nodeid
        self.ntype = routing.ntype
        self.tiver = routing.tiver
        self.t4 = 100    # dummy value just in case someone calls alive()

    def dispatch (self, item):
        """Work item handler.
        """
        pass    # self adjacency doesn't time out

    def send (self, pkt):
        """Forwarding to self, which means pass up to NSP.
        """
        # Note that local packets (originating here and terminating
        # here as well) are not counted since there isn't any circuit
        # on which to count them.
        if pkt.src and pkt.src.circuit:
            pkt.src.circuit.datalink.counters.term_recv += 1
        work = Received (self.node.nsp, packet = pkt.payload,
                         src = pkt.srcnode, rts = pkt.rts)
        self.node.addwork (work, self.node.nsp)
        
    def __str__ (self):
        return "Self"
    
class Circuit (Element):
    """Base class for all routing layer circuits.
    """
    def __init__ (self, parent, name, datalink, config):
        super ().__init__ (parent)
        self.routing = parent
        self.name = name
        self.config = config
        self.cost = config.cost
        self.t1 = config.t1

    def init_counters (self):
        # A subset of the counters defined by the architecture
        # Add these to the base datalink (port actually) counters, which
        # were initialized before we get here.
        self.datalink.counters.term_recv = 0
        self.datalink.counters.orig_sent = 0
        self.datalink.counters.trans_recv = 0
        self.datalink.counters.trans_sent = 0
        #self.datalink.counters.term_cong = 0
        #self.datalink.counters.trans_cong = 0    # congestion loss, needed?
        self.datalink.counters.cir_down = 0
        self.datalink.counters.adj_down = 0
        self.datalink.counters.init_fail = 0

    def getentity (self, name):
        if name == "counters":
            return self.datalink.counters
        return super ().getentity (name)
    
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

class PtpEndnodeCircuit (route_ptp.PtpCircuit, Circuit):
    """Point to point circuit on an endnode.
    """
    def __init__ (self, parent, name, datalink, config):
        route_ptp.PtpCircuit.__init__ (self, parent, name, datalink, config)
        Circuit.__init__ (self, parent, name, datalink, config)
        
class PtpL1Circuit (route_ptp.PtpCircuit, L1Circuit):
    """Point to point circuit on a level 1 router.
    """
    def __init__ (self, parent, name, datalink, config):
        route_ptp.PtpCircuit.__init__ (self, parent, name, datalink, config)
        L1Circuit.__init__ (self, parent, name, datalink, config)
        # Use the circuit override of t1 if specified, else the
        # exec setting of t1
        t1 = config.t1 or self.routing.config.t1
        self.update = Update (self, t1, self.routing.minhops,
                              self.routing.mincost, L1Routing)
        
class PtpL2Circuit (PtpL1Circuit, L2Circuit):
    """Point to point circuit on an area router.  
    """
    def __init__ (self, parent, name, datalink, config):
        L2Circuit.__init__ (self, parent, name, datalink, config)
        PtpL1Circuit.__init__ (self, parent, name, datalink, config)
        # Use the circuit override of t1 if specified, else the
        # exec setting of t1
        t1 = config.t1 or self.routing.config.t1
        self.aupdate = Update (self, t1, self.routing.aminhops,
                               self.routing.amincost, L2Routing)

# The LAN circuits have the analogous base classes. 

class LanEndnodeCircuit (route_eth.EndnodeLanCircuit, Circuit):
    """LAN circuit on an endnode.
    """
    ntype = ENDNODE
    
    def __init__ (self, parent, name, datalink, config):
        Circuit.__init__ (self, parent, name, datalink, config)
        route_eth.EndnodeLanCircuit.__init__ (self, parent, name,
                                              datalink, config)
        
class LanL1Circuit (route_eth.RoutingLanCircuit, L1Circuit):
    """LAN circuit on a level 1 router.
    """
    ntype = L1ROUTER
    
    def __init__ (self, parent, name, datalink, config):
        self.nodeid = 0
        L1Circuit.__init__ (self, parent, name, datalink, config)
        route_eth.RoutingLanCircuit.__init__ (self, parent, name,
                                              datalink, config)
        # Use the circuit override of t1 if specified, else the
        # exec setting of bct1
        t1 = config.t1 or self.routing.config.bct1
        self.update = Update (self, t1, self.routing.minhops,
                              self.routing.mincost, L1Routing)

class LanL2Circuit (LanL1Circuit, L2Circuit):
    """LAN circuit on an area router.
    """
    ntype = L2ROUTER
    
    def __init__ (self, parent, name, datalink, config):
        LanL1Circuit.__init__ (self, parent, name, datalink, config)
        L2Circuit.__init__ (self, parent, name, datalink, config)
        t1 = config.t1 or self.routing.config.bct1
        self.aupdate = Update (self, t1, self.routing.aminhops,
                               self.routing.amincost, L2Routing)

class ExecCounters (NspCounters):
    """Counters for the executor (this node, as opposed to a remote
    node).  These are the standard node counters augmented with some
    additional counters maintained by the routing layer.
    """
    nodecounters = NspCounters.nodecounters + [
        ( "peak_conns", "Peak logical links" ),
        ( "aged_loss", "Aged packet loss" ),
        ( "unreach_loss", "Node unreachable packet loss" ),
        ( "node_oor_loss", "Node address out of range loss" ),
        ( "oversized_loss", "Oversized packet loss" ),
        ( "fmt_errors", "Packet format error" ),
        ( "partial_update_loss", "Partial routing update loss" ),
        ( "ver_rejects", "Verification reject" )
    ]
    
    def __init__ (self, parent):
        super ().__init__ (parent)
        # zero out the additional counters
        self.peak_conns = 0
        self.aged_loss = 0
        self.unreach_loss = 0
        self.node_oor_loss = 0
        self.oversized_loss = 0
        self.fmt_errors = 0
        self.partial_update_loss = 0
        self.ver_rejects = 0

class BaseRouter (Element):
    """The routing layer.  Mainly this is the parent of a number of control
    components and collections of circuits and adjacencies.
    """
    tiver = tiver_ph4
    
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        logging.debug ("Initializing routing layer")
        self.config = config.routing
        self.routing = self
        self.nodeid = config.routing.id
        self.nodemacaddr = Macaddr (self.nodeid)
        self.homearea, self.tid = self.nodeid.split ()
        self.typename = config.routing.type
        self.nodeinfo = parent.nodeinfo (self.nodeid)
        self.nodeinfo.counterclass = ExecCounters
        self.nodeinfo.counters = ExecCounters (self.nodeinfo)
        self.name = self.nodeinfo.nodename
        self.circuits = EntityDict ()
        self.adjacencies = dict ()
        self.selfadj = self.adjacencies[self.nodeid] = SelfAdj (self)
        dlcirc = self.node.datalink.circuits
        for name, c in config.circuit.items ():
            dl = dlcirc[name]
            try:
                self.circuits[name] = self.routing_circuit (name, dl, c)
                logging.debug ("Initialized routing circuit {}", name)
            except Exception:
                logging.exception ("Error initializing routing circuit {}", name)

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
                logging.debug ("Started Routing circuit {}", name)
            except Exception:
                logging.exception ("Error starting Routing circuit {}", name)
        self.node.logevent (events.node_state, reason = "operator_command",
                            old_state = "off", new_state = "on")
    
    def stop (self):
        logging.debug ("Stopping Routing layer")
        for name, c in self.circuits.items ():
            try:
                c.stop ()
                logging.debug ("Stopped Routing circuit {}", name)
            except Exception:
                logging.exception ("Error stopping Routing circuit {}", name)
        self.node.logevent (events.node_state, reason = "operator_command",
                            old_state = "on", new_state = "off")
    
    def dispatch (self, item):
        pass

    def adj_up (self, adj):
        self.adjacencies[adj.nodeid] = adj
    
    def adj_down (self, adj):
        try:
            del self.adjacencies[adj.nodeid]
        except KeyError:
            pass

    def http_get (self, parts, qs):
        if self.ntype == ENDNODE or self.ntype == PHASE2:
            infos = ( "summary", "counters" )
        else:
            infos = ( "summary", "status", "counters", "internals" )
        if not parts or parts == ['']:
            what = "summary"
        elif parts[0] in infos:
            what = parts[0]
        else:
            return None, None
        active = infos.index (what) + 1
        if self.ntype == ENDNODE or self.ntype == PHASE2:
            sb = html.sbelement (html.sblabel ("Information"),
                                 html.sbbutton ("routing", "Summary", qs),
                                 html.sbbutton ("routing/counters", "Counters", qs))
        else:
            sb = html.sbelement (html.sblabel ("Information"),
                                 html.sbbutton ("routing", "Summary", qs),
                                 html.sbbutton ("routing/status", "Status", qs),
                                 html.sbbutton ("routing/counters", "Counters", qs),
                                 html.sbbutton ("routing/internals", "Internals", qs))
        sb.contents[active].__class__ = html.sbbutton_active
        ntype = ntypestrings[self.ntype]
        hdr = "Routing {1} for node {0.nodeid} ({0.name})".format (self, what)
        body = [ "Node type: {}".format (ntype),
                 "Routing version: {0.tiver}".format (self) ]
        ret = [ html.firsttextsection (hdr, body) ]
        ret.extend (self.html (what))
        return sb, html.main (*ret)

    def description (self):
        ntype = ntypestrings[self.ntype]
        return html.makelink ("routing",
                              "{1} node {0.nodeid} ({0.name})".format (self, ntype),
                              "?system={0.name}".format (self))

    def json_description (self):
        return { self.name : [ ntypestrings[self.ntype], self.nodeid ] }

    def get_api (self):
        return { "circuits" : self.circuits.get_api (),
                 "address" : self.nodeid,
                 "name" : self.name,
                 "type" : ntypestrings[self.ntype],
                 "version" : self.tiver }
        
class EndnodeRouting (BaseRouter):
    """Routing entity for endnodes.
    """
    LanCircuit = LanEndnodeCircuit
    PtpCircuit = PtpEndnodeCircuit
    ntype = ENDNODE
    
    def __init__ (self, parent, config):
        super ().__init__ (parent, config)
        if len (self.circuits) != 1:
            raise ValueError ("End node must have 1 circuit, found {}".format (len (self.circuits)))
        # Remember that one circuit for easier access
        for c in self.circuits.values ():
            self.circuit = c

    def send (self, data, dest, rqr = False, tryhard = False):
        """Send NSP data to the given destination.  rqr is True to
        request return to sender (done for CI messages).  tryhard is
        True to request ignoring endnode cache entries; this is done
        for retransmits.  For routers it has no effect and is ignored.

        Returns False if the destination is known to be unreachable,
        True otherwise.  If False was returned, the packet is not sent,
        i.e., if rqr was True, you won't get the returned message.  If
        True is returned, then if the packet ends up unreachable after
        all,  you should get the return packet if one was requested.
        """
        pkt = LongData (rqr = rqr, rts = 0, ie = 1, dstnode = dest,
                        srcnode = self.nodeid, visit = 0,
                        payload = data, src = None)
        if logging.tracing:
            logging.trace ("Sending {} byte packet: {}", len (pkt), pkt)
        self.circuit.datalink.counters.orig_sent += 1
        if dest != self.nodeid:
            return self.circuit.send (pkt, None, tryhard)
        else:
            # Addressed to self, send it back up to NSP.
            self.dispatch (pkt)

    def dispatch (self, item):
        """A received packet is sent up to NSP if it is for this node,
        and ignored otherwise.
        """
        if logging.tracing:
            logging.trace ("{}: processessing work item {}", self.name, item)
        if isinstance (item, (ShortData, LongData)):
            if item.dstnode == self.nodeid:
                self.selfadj.send (item)

    def html (self, what):
        header = self.circuit.html_header ()
        h = self.circuit.html_row ()
        if what == "counters":
            ctr = [ ( "{} =".format (fl),
                      getattr (self.circuit.datalink.counters, f))
                    for fl, f in fieldlist ]
            h.append (ctr)
        if what == "counters":
            return [ html.detail_section ("Circuit", header, [ h ]) ]
        else:
            return [ html.tbsection ("Circuit", header, [ h ]) ]

class Phase3EndnodeRouting (EndnodeRouting):
    """Routing entity for Phase III endnodes.
    """
    LanCircuit = None    # not supported

class Phase2Routing (BaseRouter):
    """Routing entity for Phase II node.
    """
    LanCircuit = None    # not supported
    PtpCircuit = PtpEndnodeCircuit
    ntype = PHASE2
    
    def send (self, pkt, dest, rqr = False, tryhard = False):
        """Send NSP packet to the given destination. rqr and
        tryhard are ignored in Phase II.
        TODO: Intercept support.

        Returns False if the destination is known to be unreachable,
        True otherwise.  If False was returned, the packet is not sent,
        i.e., if rqr was True, you won't get the returned message.  If
        True is returned, then if the packet ends up unreachable after
        all,  you should get the return packet if one was requested.
        """
        try:
            a = self.adjacencies[dest]
            # Destination matches this adjacency, send
            if logging.tracing:
                logging.trace ("Sending {} byte packet to {}: {}",
                               len (pkt), a, pkt)
            pkt = ShortData (payload = pkt, srcnode = self.nodeid,
                             dstnode = dest, src = None)
            a.circuit.datalink.counters.orig_sent += 1
            # For now, destination is also nexthop.  If we do intercept,
            # that will no longer be true.
            return a.circuit.send (pkt, dest)
        except KeyError:
            logging.trace ("{} unreachable: {}", dest, pkt)
            return False

    def dispatch (self, item):
        """A received packet is sent up to NSP if it is for this node,
        and ignored otherwise.
        TODO: Intercept support.
        """
        if isinstance (item, (ShortData, LongData)):
            if item.dstnode == self.nodeid:
                item.rts = False
                self.selfadj.send (item)

    def html (self, what):
        header = self.PtpCircuit.html_header ()
        rows = list ()
        for k, c in sorted (self.circuits.items ()):
            h = c.html_row ()
            if h:
                if what == "counters":
                    ctr = [ ( "{} =".format (fl),
                              getattr (c.datalink.counters, f))
                            for fl, f in fieldlist ]
                    h.append (ctr)
                rows.append (h)
        if rows:
            if what == "counters":
                return [ html.detail_section ("Circuits", header, rows) ]
            else:
                return [ html.tbsection ("Circuits", header, rows) ]
    
class RouteInfo (object):
    """The routing info, as found in the circuit or adjacency but
    separated out for easier access.
    """
    def __init__ (self, adjacency, maxidx, l2 = False):
        self._adjacency = adjacency
        self.hops, self.cost = allocvecs (maxidx)
        if adjacency:
            circ = adjacency.circuit
        self.nodeid = None

    def adjacency (self, id):
        return self._adjacency

class EndnodesRouteInfo (RouteInfo):
    def __init__ (self, maxidx):
        super ().__init__ (None, maxidx, False)
        self.adjacencies = [ None ] * (maxidx + 1)

    def adjacency (self, id):
        return self.adjacencies[id]
    
class L1Router (BaseRouter):
    """Routing entity for level 1 routers.
    """
    LanCircuit = LanL1Circuit
    PtpCircuit = PtpL1Circuit
    ntype = L1ROUTER
    attached = False    # Defined for L2 routers, needed by check
    firstnode = 0       # For routing table display
    
    def __init__ (self, parent, config):
        # These are needed by various constructors so grab them first
        rconfig = config.routing
        self.maxnodes = rconfig.maxnodes
        self.maxhops = rconfig.maxhops
        self.maxcost = rconfig.maxcost
        self.maxvisits = rconfig.maxvisits
        self.minhops, self.mincost = allocvecs (rconfig.maxnodes)
        self.oadj = [ None ] * (self.maxnodes + 1)
        BaseRouter.__init__ (self, parent, config)
        self.l1info = dict ()
        # Create the special routeinfo column that is used
        # to record information for all the endnode adjacencies
        # Note that this one also keeps a per-ID adjacency pointer.
        self.l1info[ENDNODE] = EndnodesRouteInfo (self.maxnodes)
        
    def adj_up (self, adj):
        """Take the appropriate actions for an adjacency that has
        just come up.  If it is an adjacency to a router, allocate
        the routing control data we will need later.
        """
        super ().adj_up (adj)
        logging.trace ("adj up, {}, type {}", adj, adj.ntype)
        if adj.ntype in { L1ROUTER, L2ROUTER }:
            adj.routeinfo = RouteInfo (adj, self.maxnodes, l2 = False)
            self.l1info[adj] = adj.routeinfo
            if adj is self.selfadj:
                # The initial RouteInfo is all infinite, so set our
                # own entries correctly.
                tid = self.nodeid.tid
                self.selfadj.routeinfo.hops[tid] = 0
                self.selfadj.routeinfo.cost[tid] = 0
            self.setsrm (0, self.maxnodes)
            self.route (0, self.maxnodes)
        else:
            # End node and Phase II node
            adj.routeinfo = None
            ri = self.l1info[ENDNODE]
            tid = adj.nodeid.tid
            if ri.hops[tid] != INFHOPS and ri.oadj[tid] != adj:
                # We already have an endnode here.  Curious.
                logging.debug ("Possible duplicate endnode {} on {} and {}",
                               adj.nodeid, adj.circuit,
                               ri.oadj[tid].circuit)
            ri.hops[tid] = 1
            ri.cost[tid] = adj.circuit.cost
            ri.adjacencies[tid] = adj
            self.route (tid, tid)

    def adj_down (self, adj):
        """Take the appropriate actions for an adjacency that has
        just gone down. 
        """
        super ().adj_down (adj)
        if adj.ntype in { L1ROUTER, L2ROUTER }:
            try:
                del self.l1info[adj]
            except KeyError:
                pass
            self.route (0, self.maxnodes)
        else:
            # End node and Phase II node
            ri = self.l1info[ENDNODE]
            tid = adj.nodeid.tid
            ri.hops[tid] = INFHOPS
            ri.cost[tid] = INFCOST
            ri.adjacencies[tid] = None
            self.route (tid, tid)
        
    def up (self):
        # The routing object includes adjacency data which describes
        # "self" (the routing architecture spec shows this as column 0
        # of the routing matrix).
        self.adj_up (self.selfadj)
        
    def start (self):
        super ().start ()
        self.up ()
        
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
                route (k, k)
        if maxreach:
            self.node.logevent (events.rout_upd_loss, adj.circuit,
                                highest_address = maxreach,
                                adjacent_node = self.node.nodeinfo (adj.nodeid),
                                **evtpackethdr (item))
        
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
                    besta = r.adjacency (i)
            if bestc > self.maxcost or besth > self.maxhops:
                besth, bestc, besta = INFHOPS, INFCOST, None
            if minhops[i] != besth or mincost[i] != bestc:
                minhops[i] = besth
                mincost[i] = bestc
                setsrm (i)
                logging.trace ("Node {}, cost {}, hops {} via {} {}",
                               i, bestc, besth,
                               besta and besta.circuit.name,
                               besta and besta.nodeid)
            if besta != oadj[i]:
                # It's a reachability change only if either the
                # previous or the current output is None; otherwise
                # it's just a change from one route to another.
                rchange = besta is None or oadj[i] is None
                oadj[i] = besta
                if rchange and besta is not self.selfadj:
                    # Note that reachable events are not logged if the
                    # output adjacency is SelfAdj.  Those happen at
                    # startup.
                    if l2:
                        if not besta:
                            self.node.logevent (events.area_chg, i,
                                                status = "unreachable")
                        else:
                            self.node.logevent (events.area_chg, i,
                                                status = "reachable")
                    elif i:
                        # That check for 0 is there so reachability changes
                        # of "nearest L2 router" aren't logged.
                        nod = self.node.nodeinfo (Nodeid (self.homearea, i))
                        if not besta:
                            self.node.logevent (events.reach_chg, nod,
                                                status = "unreachable")
                        else:
                            self.node.logevent (events.reach_chg, nod,
                                                status = "reachable")

    def usecol (self, adj, l2):
        return l2 or adj.nodeid.area == self.homearea

    @staticmethod
    def adjkey (adj):
        return adj.nodeid, adj.circuit.name
    
    def html_matrix (self, l2):
        if l2:
            start = 1
            end = self.maxarea
            routeinfodict = self.l2info
            what = "Area"
            selfcol = [ self.selfadj ]
        else:
            start = 0
            end = self.maxnodes
            routeinfodict = self.l1info
            what = "Level 1"
            selfcol = [ self.selfadj, ENDNODE ]
        ret = list ()
        INF = ( INFHOPS, INFCOST )
        rkeys = sorted ((k for k in routeinfodict.keys ()
                       if k is not self.selfadj and
                         isinstance (k, adjacency.Adjacency) and
                         self.usecol (k, l2)),
                        key = self.adjkey)
        rkeys = selfcol + rkeys
        data = list ()
        for i in range (start, end + 1):
            inf = True
            row = [ i ]
            for rk in rkeys:
                r = routeinfodict[rk]
                e = ( r.hops[i], r.cost[i] )
                if e >= INF:
                    e = ( "&infin;", "&infin;" )
                else:
                    inf = False
                h, c = e
                row.extend ([ h, html.cell (c, 'class="double_right"') ])
            if not inf:
                row[-1].markup = ""
                data.append (row)
        hdr = [ html.hcell ("Dest", valign = "bottom") ]
        prev = None
        for rk in rkeys:
            if rk is ENDNODE:
                s = "Endnodes"
            elif rk is self.selfadj:
                s = "Self"
            else:
                if prev and prev.nodeid == rk.nodeid:
                    s = "{}<br>{}".format (prev.nodeid, prev.circuit.name)
                    hdr[-1] = html.hcell (s, 'class="double_right" colspan=2',
                                          "bottom")
                    s = "{}<br>{}".format (rk.nodeid, rk.circuit.name)
                else:
                    s = "{}".format (rk.nodeid)
                prev = rk
            hdr.append (html.hcell (s, 'class="double_right" colspan=2',
                                    "bottom"))
        hdr[-1].markup = "colspan=2"
        return html.tbsection ("{} routing matrix".format (what), hdr, data)
    
    def route (self, start, end):
        self.doroute (start, end, l2 = False)

    def aroute (self, start, end):
        pass
    
    def check (self):
        tid = self.nodeid.tid
        ri = self.selfadj.routeinfo
        try:
            for i in range (self.maxnodes + 1):
                if i == tid or (self.attached and i == 0):
                    assert ri.hops[i] == ri.cost[i] == 0
                else:
                    assert ri.hops[i] == INFHOPS and ri.cost[i] == INFCOST
        except AssertionError:
            logging.critical ("Check failure on L1 entry {}: {} {} {}",
                              i, ri.hops[i], ri.cost[i], self.oadj[i])
            sys.exit (1)

    def findoadj (self, dest):
        """Find the output adjacency for this destination address.

        Returns None for unreachable, or False for out of range.
        """
        area, tid = dest.split ()
        if area != self.homearea:
            if self.tiver != tiver_ph4:
                # Not Phase IV, so out of area is unreachable
                return None
            tid = 0
        try:
            return self.oadj[tid]
        except IndexError:
            return False

    def send (self, data, dest, rqr = False, tryhard = False):
        """Send NSP data to the given destination.  rqr is True to
        request return to sender (done for CI messages).  tryhard is
        True to request ignoring endnode cache entries; this is done
        for retransmits.  For routers it has no effect and is ignored.

        Returns False if the destination is known to be unreachable,
        True otherwise.  If False was returned, the packet is not sent,
        i.e., if rqr was True, you won't get the returned message.  If
        True is returned, then if the packet ends up unreachable after
        all,  you should get the return packet if one was requested.
        """
        pkt = LongData (rqr = rqr, rts = 0, ie = 1, dstnode = dest,
                        srcnode = self.nodeid, visit = 0,
                        payload = data, src = None)
        return self.forward (pkt, orig = True)
        
    def forward (self, pkt, orig = False):
        """Send a data packet to where it should go next.  "pkt" is the
        packet object to send.  For received packets, "pkt.src" is the
        adjacency on which it was received; for originating packets,
        if orig is True, and the destination is known to be unreachable,
        return False and don't try to send the packet.
        """
        dest = pkt.dstnode
        srcadj = pkt.src
        a = self.findoadj (dest)
        if a:
            # Destination is reachable.  Send it, unless
            # we're at the visit limit
            limit = self.maxvisits
            if a is not self.selfadj:
                # Forwarding or originating (as opposed to terminating)
                if not orig:
                    # Forwarding (as opposed to originating)
                    if srcadj.circuit != a.circuit:
                        # Mark "not intra-Ethernet"
                        pkt.ie = 0
                    if pkt.rts:
                        limit *= 2
                if pkt.visit < limit:
                    # Visit limit still ok, send it and exit
                    if orig:
                        a.circuit.datalink.counters.orig_sent += 1
                    else:
                        srcadj.circuit.datalink.counters.trans_recv += 1
                        a.circuit.datalink.counters.trans_sent += 1
                        pkt.visit += 1
                    if logging.tracing:
                        logging.trace ("Sending {} byte packet to {}: {}",
                                       len (pkt), a, pkt)
                    a.send (pkt)
                    return True
            else:
                # Terminating, don't count anything here.
                a.send (pkt)
                return True
        # If we get to this point, we could not forward the packet,
        # for one of three reasons: not reachable, too many visits,
        # or address out of range.
        # Return to sender if requested and not already underway,
        # else drop the packet.
        if orig:
            return False
        if pkt.rqr and not pkt.rts:
            pkt.dstnode, pkt.srcnode = pkt.srcnode, pkt.dstnode
            pkt.rts = 1
            pkt.rqr = 0
            # On Ethernet does not apply to this case
            pkt.ie = 0
            self.forward (pkt)
            return True    # Note that we did "send" it
        kwargs = evtpackethdr (pkt)
        if a:
            # Reachable, so the problem was max visits
            self.nodeinfo.counters.aged_loss += 1
            # The architecture spec doesn't mention the source adjacency
            # argument, but that seems like a mistake so put it in.
            self.node.logevent (events.aged_drop, srcadj.circuit,
                                adjacent_node = srcadj.nodeid,
                                **kwargs)
        else:
            if a is False:
                c = events.oor_drop
                self.nodeinfo.counters.node_oor_loss += 1
            else:
                c = events.unreach_drop
                self.nodeinfo.counters.unreach_loss += 1
            self.node.logevent (c, srcadj.circuit,
                                adjacent_node = srcadj.nodeid,
                                **kwargs)
        return True
    
    def html (self, what):
        ret = [ ]
        for t in (self.LanCircuit, self.PtpCircuit):
            if t == self.LanCircuit:
                title = "LAN circuits"
            else:
                title = "Point to point circuits"
            header = t.html_header ()
            rows = list ()
            for k, c in sorted (self.circuits.items ()):
                if isinstance (c, t):
                    h = c.html_row ()
                    if h:
                        if what == "counters":
                            ctr = [ ( "{} =".format (fl),
                                      getattr (c.datalink.counters, f))
                                    for fl, f in fieldlist ]
                            h.append (ctr)
                        rows.append (h)
            if rows:
                if what == "counters":
                    ret.append (html.detail_section (title, header, rows))
                else:
                    ret.append (html.tbsection (title, header, rows))
        if what in ("status", "internals"):
            for k, c in sorted (self.circuits.items ()):
                if isinstance (c, self.LanCircuit):
                    h, d = c.adj_tabledata ()
                    if d:
                        ret.append (html.tbsection ("Adjacencies on {}".format (c.name), h, d))
            hdr = ( "Node", "Hops", "Cost", "Nexthop" )
            data = list ()
            for i in range (self.firstnode, self.maxnodes + 1):
                if self.oadj[i]:
                    if i:
                        name = str (self.node.nodeinfo (Nodeid (self.homearea, i)))
                    else:
                        name = "Nearest L2"
                    adj = self.oadj[i]
                    if adj == self.selfadj:
                        adj = "Self"
                    data.append ([ name, self.minhops[i],
                                   self.mincost[i], adj ])
            ret.append (html.tbsection ("Level 1 routing table", hdr, data))
        if what == "internals":
            ret.append (self.html_matrix (False))
        return ret

class Phase3Router (L1Router):
    """Routing entity for Phase III routers.
    """
    LanCircuit = None
    firstnode = 1       # For routing table display
    
class L2Router (L1Router):
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
        self.attached = False
        self.l2info = dict ()
        
    def adj_up (self, adj):
        """Take the appropriate actions for an adjacency that has
        just come up.  If it is an adjacency to a router, allocate
        the routing control data we will need later.
        """
        if adj.ntype == L2ROUTER:
            adj.arouteinfo = RouteInfo (adj, self.maxarea, l2 = True)
            self.l2info[adj] = adj.arouteinfo
            if adj is self.selfadj:
                # The initial RouteInfo is all infinite, so set our
                # own entries correctly.
                area = self.nodeid.area
                self.selfadj.arouteinfo.hops[area] = 0
                self.selfadj.arouteinfo.cost[area] = 0
                self.aoadj[area] = self.selfadj
        else:
            adj.arouteinfo = None
        super ().adj_up (adj)
        if adj.ntype == L2ROUTER:
            self.setasrm (1, self.maxarea)
            self.aroute (1, self.maxarea)

    def adj_down (self, adj):
        """Take the appropriate actions for an adjacency that has
        just gone down. 
        """
        super ().adj_down (adj)
        if adj.ntype == L2ROUTER:
            try:
                del self.l2info[adj]
            except KeyError:
                pass
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

    def aroute (self, start, end):
        self.doroute (start, end, l2 = True)
        #
        # Calculate the value of the Attached flag.
        #
        # The algorithm used here is what the DNA Routing 2.0.0 spec
        # describes.  It is actually not the best algorithm; instead
        # a better definition of "attached" is "this node has adjacencies
        # up to L2 routers out of area".  The difference is that the
        # specification definition makes all L2 routers in an area
        # "attached" as soon as the area is attached to other areas.
        # If only one router has an out of area connection, it is the
        # right place to forward packets going out of area, but with the
        # spec algorithm, other L2 routers may be "nearest L2 router" for
        # a portion of the area, which causes packets to travel farther
        # than they should.  If only routers with out of area connections
        # appear attached, then out of area traffic will go directly to
        # those exits.
        #
        # For now, leave things per spec.
        attached = False
        for i, a in enumerate (self.aoadj):
            if a and i != self.homearea:
                attached = True
                break
        if attached != self.attached:
            logging.debug ("L2 attached state changed to {}", attached)
            self.attached = attached
            ri = self.selfadj.routeinfo
            if attached:
                ri.hops[0] = ri.cost[0] = 0
            else:
                ri.hops[0] = INFHOPS
                ri.cost[0] = INFCOST
            self.setsrm (0)
            self.route (0, 0)

    def findoadj (self, dest):
        """Find the output adjacency for this destination address.
        """
        area = dest.area
        if self.attached and area != self.homearea:
            try:
                return self.aoadj[area]
            except IndexError:
                return False
        return super ().findoadj (dest)

    def check (self):
        super ().check ()
        try:
            area = self.nodeid.area
            for i in range (1, self.maxarea + 1):
                ari = self.selfadj.arouteinfo
                if i == area:
                    assert ari.hops[i] == ari.cost[i] == 0
                else:
                    assert ari.hops[i] == INFHOPS and \
                           ari.cost[i] == INFCOST
        except AssertionError:
            logging.critical ("Check failure on L2 entry {}: {} {}",
                              i, self.ari.ahops[i], self.ari.acost[i])
            sys.exit (1)
        
    def html (self, what):
        ret = super ().html (what)
        if what in ("status", "internals"):
            hdr = ( "Area", "Hops", "Cost", "Nexthop" )
            data = list ()
            for i in range (1, self.maxarea + 1):
                if self.aoadj[i]:
                    data.append ([ i, self.aminhops[i],
                                   self.amincost[i], self.aoadj[i] ])
            ret.append (html.tbsection ("Level 2 routing table", hdr, data))
        if what == "internals":
            ret.append (self.html_matrix (True))
        return ret

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
        if self.parent.ntype != ENDNODE and self.parent.ntype != PHASE2:
            endtid = endtid or tid
            logging.trace ("Setsrm ({}): {} to {}", self.pkttype.__name__,
                           tid, endtid)
            for i in range (tid, endtid + 1):
                self.srm[i] = 1
            self.anysrm = True
            self.update_soon ()

    def update_soon (self):
        if not self.holdoff:
            delta = max (T2 - (time.time () - self.lastupdate), 0)
            logging.trace ("Scheduling update ({}) in {:.1f}",
                           self.pkttype.__name__, delta)
            self.holdoff = True
            self.node.timers.start (self, delta)

    def dispatch (self, item):
        if isinstance (item, timers.Timeout) and self.parent.ntype != ENDNODE \
          and self.parent.ntype != PHASE2:
            # If anysrm is set, that means setsrm was called to
            # request sending of specific updates.  If not, then this
            # is a periodic (all destinations) update
            pkts = self.buildupdates (not self.anysrm)
            self.startpos += 1
            startpos = self.startpos % len (pkts)
            pkts = pkts[startpos:] + pkts[:startpos]
            logging.trace ("Sending {} update ({}) packets",
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
        if pkt == L1Routing and self.node.phase == 3:
            pkt = PhaseIIIRouting
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
            p.segments = list ()
            for i in range (1, len (minhops)):
                srm[i] = 0
                p.segments.append (RouteSegEntry (cost = mincost[i],
                                                  hops = minhops[i]))
            ret = [ p ]
        return ret

nodetypes = { "l1router" : L1Router,
              "l2router" : L2Router,
              "endnode" : EndnodeRouting,
              "phase3router" : Phase3Router,
              "phase3endnode" : Phase3EndnodeRouting,
              "phase2" : Phase2Routing }

def Router (parent, config):
    """Factory function for routing layer instance.  Returns an instance
    of the appropriate BaseRouter subclass, depending on the supplied config.
    """
    rtype = config.routing.type
    try:
        c = nodetypes[rtype]
    except KeyError:
        logging.critical ("Unsupported routing type {}", rtype)
    return c (parent, config)

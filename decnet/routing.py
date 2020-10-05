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
from . import nicepackets

SvnFileRev = "$LastChangedRevision$"

UNREACHABLE = Failure ("Unreachable")
OUT_OF_RANGE = Failure ("Address out of range")
AGED = Failure ("Visit count exceeded")

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

# Circuit counter descriptions and field (attribute) names.  Note that
# we don't do congestion so the congestion loss counter is omitted.
fieldlist = (("Time since counters zeroed", "time_since_zeroed"),
             ("Terminating packets received", "term_recv"),
             ("Originating packets sent", "orig_sent"),
             ("Transit packets received", "trans_recv"),
             ("Transit packets sent", "trans_sent"),
             ("Circuit down", "cir_down"),
             ("Adjacency down", "adj_down"),
             ("Initialization failure", "init_fail"),
             ("Time since circuit up", "last_up"))
rtr_only_fields = { "trans_recv", "trans_sent" }

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
        ( "peak_conns", "Maximum logical links active" ),
        ( "aged_loss", "Aged packet loss" ),
        ( "unreach_loss", "Node unreachable packet loss" ),
        ( "node_oor_loss", "Node out-of-range loss" ),
        ( "oversized_loss", "Oversized packet loss" ),
        ( "fmt_errors", "Packet format error" ),
        ( "partial_update_loss", "Partial routing update loss" ),
        ( "ver_rejects", "Verification reject" )
    ]
    rtr_only_nc = { "aged_loss",
                    "unreach_loss",
                    "node_oor_loss",
                    "partial_update_loss" }

    def __init__ (self, parent, node):
        super ().__init__ (parent)
        # zero out the additional counters
        self.peak_conns = 0
        self.oversized_loss = 0
        self.fmt_errors = 0
        self.ver_rejects = 0
        if node.ntype == ENDNODE or node.ntype == PHASE2:
            self.exclude = self.rtr_only_nc
        else:
            self.exclude = ()
            self.partial_update_loss = 0
            self.aged_loss = 0
            self.unreach_loss = 0
            self.node_oor_loss = 0

class BaseRouter (Element):
    """The routing layer.  Mainly this is the parent of a number of control
    components and collections of circuits and adjacencies.
    """
    tiver = tiver_ph4
    defmaxnode = 1023
    
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
        self.nodeinfo.counters = ExecCounters (self.nodeinfo, self)
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

    def http_get (self, mobile, parts, qs):
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
                                 html.sbbutton (mobile, "routing",
                                                "Summary", qs),
                                 html.sbbutton (mobile, "routing/counters",
                                                "Counters", qs))
        else:
            sb = html.sbelement (html.sblabel ("Information"),
                                 html.sbbutton (mobile, "routing",
                                                "Summary", qs),
                                 html.sbbutton (mobile, "routing/status",
                                                "Status", qs),
                                 html.sbbutton (mobile, "routing/counters",
                                                "Counters", qs),
                                 html.sbbutton (mobile, "routing/internals",
                                                "Internals", qs))
        sb.contents[active].__class__ = html.sbbutton_active
        hdr = "Routing {1} for node {0.nodeid} ({0.name})".format (self, what)
        body = [ "Node type: {}".format (self.ntypestring),
                 "Routing version: {0.tiver}".format (self) ]
        if self.ntype in { L1ROUTER, L2ROUTER }:
            body.append ("Max nodes: {0.maxnodes}".format (self))
            body.append ("Max hops: {0.maxhops}".format (self))
            body.append ("Max cost: {0.maxcost}".format (self))
            body.append ("Max visits: {0.maxvisits}".format (self))
        if self.ntype == L2ROUTER:
            body.append ("Max area: {0.maxarea}".format (self))
            body.append ("Area max hops: {0.amaxhops}".format (self))
            body.append ("Area max cost: {0.amaxcost}".format (self))
        ret = [ html.firsttextsection (hdr, body) ]
        ret.extend (self.html (what))
        return sb, html.main (*ret)

    def description (self, mobile):
        return html.makelink (mobile, "routing",
                              "{0.ntypestring} {0.nodeid} ({0.name})".format (self),
                              "?system={0.name}".format (self))

    def json_description (self):
        return { self.name : [ self.ntypestring, self.nodeid ] }

    def get_api (self):
        return { "circuits" : self.circuits.get_api (),
                 "address" : self.nodeid,
                 "name" : self.name,
                 "type" : self.ntypestring,
                 "version" : self.tiver }

    def read_node (self, req, nodeid, resp):
        r = resp[nodeid]
        # Supply the requested information for the indicated node.
        if req.info == 2:
            # Characteristics.  This applies only to executor, which
            # the caller has already checked.
            r.routing_version = self.tiver
            # Generate NICE style node type
            if self.tiver == tiver_ph4:
                r.type = self.ntype + 2
            elif self.tiver == tiver_ph3:
                r.type = 1 if self.ntype == ENDNODE else 0
            else:
                r.type = 2
            r.segment_buffer_size = MTU
            # Have the subclass supply anything else it wants to
            self.node_char (r)

    def node_char (self, r):
        pass
    
    def nice_read (self, req, resp):
        if isinstance (req, nicepackets.NiceReadNode):
            # Read node
            if req.info == 3:
                # counters, nothing to do since NSP took care of that.
                return
            if req.info == 2:
                # characteristics -- only executor has those
                if (req.one () and req.entity.value == self.nodeid) \
                   or req.mult () and not req.adj ():
                    # Supply executor characteristics.  Note that
                    # "adjacent" does not do this since the executor
                    # isn't an adjacent node.
                    self.read_node (req, self.nodeid, resp)
            else:
                # status or summary.
                if req.one ():
                    self.read_node (req, req.entity.value, resp)
                else:
                    # multiple nodes.  start with adjacencies.
                    for c in self.circuits.values ():
                        c.nice_read (req, resp)
                    if not req.adj ():
                        # known or significant or active, thrown in
                        # reachability information
                        self.reach (req, resp)
                # Make sure nexthop is set if known.
                self.nexthop (req, resp)
        elif isinstance (req, nicepackets.NiceReadCircuit):
            if req.entity.code > 0:
                # read one circuit
                cn = req.entity.value.upper ()
                try:
                    c = self.circuits[cn]
                except KeyError:
                    return
                c.nice_read (req, resp)
            else:
                # Read active or known circuits.  We handle those the
                # same because all our circuits are always on.
                for c in self.circuits.values ():
                    c.nice_read (req, resp)
            return resp
        
    def reach (self, req, resp):
        pass

    def nexthop (self, req, resp):
        pass

class EndnodeRouting (BaseRouter):
    """Routing entity for endnodes.
    """
    LanCircuit = LanEndnodeCircuit
    PtpCircuit = PtpEndnodeCircuit
    ntype = ENDNODE
    ntypestring = "Phase 4 endnode"
    
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
        """
        pkt = LongData (rqr = rqr, rts = 0, ie = 1, dstnode = dest,
                        srcnode = self.nodeid, visit = 0,
                        payload = data, src = None)
        if logging.tracing:
            logging.trace ("Sending {} byte packet: {}", len (pkt), pkt)
        self.circuit.datalink.counters.orig_sent += 1
        if dest != self.nodeid:
            self.circuit.send (pkt, None, tryhard)
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
            ctr = list ()
            for fl, f in fieldlist:
                c = getattr (self.circuit.datalink.counters, f, None)
                if c is not None and f not in rtr_only_fields:
                    ctr.append (( "{} =".format (fl), c))
            h.append (ctr)
        if what == "counters":
            return [ html.detail_section ("Circuit", header, [ h ]) ]
        else:
            return [ html.tbsection ("Circuit", header, [ h ]) ]

class Phase3EndnodeRouting (EndnodeRouting):
    """Routing entity for Phase III endnodes.
    """
    tiver = tiver_ph3
    LanCircuit = None    # not supported
    ntypestring = "Phase 3 endnode"

class Phase2Routing (BaseRouter):
    """Routing entity for Phase II node.
    """
    LanCircuit = None    # not supported
    PtpCircuit = PtpEndnodeCircuit
    ntype = PHASE2
    ntypestring = "Phase 2 node"
    
    def send (self, pkt, dest, rqr = False, tryhard = False):
        """Send NSP packet to the given destination. rqr and
        tryhard are ignored in Phase II.
        TODO: Intercept support.
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
            a.circuit.send (pkt, dest)
        except KeyError:
            logging.trace ("{} unreachable: {}", dest, pkt)

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
        self.oadj = [ UNREACHABLE ] * (maxidx + 1)

    def adjacency (self, id):
        return self.adjacencies[id]
    
class L1Router (BaseRouter):
    """Routing entity for level 1 routers.
    """
    LanCircuit = LanL1Circuit
    PtpCircuit = PtpL1Circuit
    ntype = L1ROUTER
    ntypestring = "L1 router"
    attached = False    # Defined for L2 routers, needed by check
    firstnode = 0       # For routing table display
    
    def __init__ (self, parent, config):
        # These are needed by various constructors so grab them first
        rconfig = config.routing
        self.maxnodes = min (rconfig.maxnodes, self.defmaxnode)
        self.maxhops = rconfig.maxhops
        self.maxcost = rconfig.maxcost
        self.maxvisits = rconfig.maxvisits
        self.minhops, self.mincost = allocvecs (rconfig.maxnodes)
        self.oadj = [ UNREACHABLE ] * (self.maxnodes + 1)
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
            if adj.nodeid.area != self.nodeid.area:
                # Adjacency to out of area router, which means it's an
                # L2 router and we're called from the L2 adj_up.  For
                # that case, L2 related data is kept but no L1 related
                # data, since we're not doing L1 routing to out of
                # area nodes.
                adj.routeinfo = None
            else:
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
            if ri.hops[tid] != INFHOPS and ri.oadj[tid] != adj \
              and not ri.oadj[tid]:
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
        ntype = adj.ntype
        super ().adj_down (adj)
        if ntype in { L1ROUTER, L2ROUTER }:
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
            self.node.logevent (events.rout_upd_loss,
                                events.CircuitAdj (adj.circuit),
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
            besth, bestc, besta = INFHOPS, INFCOST, UNREACHABLE
            for r in routeinfodict.values ():
                if r.cost[i] < bestc or \
                   (r.cost[i] == bestc and \
                    (not besta or
                     (r.nodeid and r.nodeid > besta.nodeid))):
                    bestc = r.cost[i]
                    besth = r.hops[i]
                    besta = r.adjacency (i)
            if bestc > self.maxcost or besth > self.maxhops:
                besth, bestc, besta = INFHOPS, INFCOST, UNREACHABLE
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
                # previous or the current output is UNREACHABLE;
                # otherwise it's just a change from one route to
                # another.
                rchange = not besta or not oadj[i]
                oadj[i] = besta
                if rchange and besta is not self.selfadj:
                    # Note that reachable events are not logged if the
                    # output adjacency is SelfAdj.  Those happen at
                    # startup.
                    if l2:
                        if not besta:
                            self.node.logevent (events.area_chg,
                                                events.AreaEventEntity (i),
                                                status = "unreachable")
                        else:
                            self.node.logevent (events.area_chg, 
                                                events.AreaEventEntity (i),
                                                status = "reachable")
                    elif i:
                        # That check for 0 is there so reachability changes
                        # of "nearest L2 router" aren't logged.
                        nod = self.node.nodeinfo (Nodeid (self.homearea, i))
                        if not besta:
                            self.node.logevent (events.reach_chg,
                                                events.NodeEventEntity (nod),
                                                status = "unreachable")
                        else:
                            self.node.logevent (events.reach_chg, 
                                                events.NodeEventEntity (nod),
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

        Returns UNREACHABLE for unreachable, or OUT_OF_RANGE for out of
        range.
        """
        area, tid = dest.split ()
        if area != self.homearea:
            if self.tiver != tiver_ph4:
                # Not Phase IV, so out of area is unreachable
                return UNREACHABLE
            tid = 0
        try:
            return self.oadj[tid]
        except IndexError:
            return OUT_OF_RANGE

    def send (self, data, dest, rqr = False, tryhard = False):
        """Send NSP data to the given destination.  rqr is True to
        request return to sender (done for CI messages).  tryhard is
        True to request ignoring endnode cache entries; this is done
        for retransmits.  For routers it has no effect and is ignored.
        """
        pkt = LongData (rqr = rqr, rts = 0, ie = 1, dstnode = dest,
                        srcnode = self.nodeid, visit = 0,
                        payload = data, src = None)
        self.forward (pkt, orig = True)
        
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
                        # Double the limit with a max of 63 since
                        # we're dealing with a 6 bit field.
                        limit = min (limit * 2, 63)
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
                else:
                    a = AGED
            # Send the packet on the chosen adjacency if all is well
            if a:
                a.send (pkt)
                return
        # If we get to this point, we could not forward the packet,
        # for one of three reasons: not reachable, too many visits,
        # or address out of range.
        #
        # Return to sender if requested and not already underway, else
        # drop the packet.  We do this even for originating packets,
        # so that CI message unreachable destination handling in NSP
        # is common whether the issue is detected at the sending node
        # or later.  But for originating packets to unreachable
        # destinations we do not log any event.
        if pkt.rqr and not pkt.rts:
            pkt.dstnode, pkt.srcnode = pkt.srcnode, pkt.dstnode
            pkt.rts = 1
            pkt.rqr = 0
            # On Ethernet does not apply to this case
            pkt.ie = 0
            self.forward (pkt)
            return
        if orig:
            return
        kwargs = evtpackethdr (pkt)
        if a is AGED:
            # The problem was max visits
            self.nodeinfo.counters.aged_loss += 1
            # The architecture spec doesn't mention the source adjacency
            # argument, but that seems like a mistake so put it in.
            self.node.logevent (events.aged_drop,
                                events.CircuitEventEntity (srcadj.circuit),
                                adjacent_node = srcadj.nodeid,
                                **kwargs)
        else:
            if a is OUT_OF_RANGE:
                c = events.oor_drop
                self.nodeinfo.counters.node_oor_loss += 1
            else:
                c = events.unreach_drop
                self.nodeinfo.counters.unreach_loss += 1
            self.node.logevent (c, events.CircuitEventEntity (srcadj.circuit),
                                adjacent_node = srcadj.nodeid,
                                **kwargs)
    
    def html (self, what):
        ret = [ ]
        for t in (self.LanCircuit, self.PtpCircuit):
            if not t:
                continue
            elif t == self.LanCircuit:
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
                            ctr = list ()
                            for fl, f in fieldlist:
                                i = getattr (c.datalink.counters, f, None)
                                if i is not None:
                                    ctr.append (( "{} =".format (fl), i))
                            h.append (ctr)
                        rows.append (h)
            if rows:
                if what == "counters":
                    ret.append (html.detail_section (title, header, rows))
                else:
                    ret.append (html.tbsection (title, header, rows))
        if what in ("status", "internals"):
            for k, c in sorted (self.circuits.items ()):
                if self.LanCircuit and isinstance (c, self.LanCircuit):
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

    def reach (self, req, resp):
        for i in range (1, self.maxnodes + 1):
            a = self.oadj[i]
            if a is self.selfadj:
                continue
            ni = Nodeid (self.homearea, i)
            if a:
                r = resp[ni]
                r.state = 4    # reachable
                r.adj_circuit = a.circuit
                nxt = self.node.nodeinfo (a.nodeid)
                r.next_node = nxt
                if req.info == 1:
                    r.hops = self.minhops[i]
                    r.cost = self.mincost[i]
            elif req.info == -1 or ni in resp:
                r = resp[ni]
                r.state = 5    # unreachable

    def nexthop (self, req, resp):
        for k, v in resp.items ():
            oa = self.findoadj (k)
            if oa and oa is not self.selfadj:
                v.adj_circuit = oa.circuit
                if oa.nodeid != k:
                    v.next_node = self.node.nodeinfo (oa.nodeid)
                        
    def node_char (self, rec):
        # Add router characteristics to "rec"
        rec.maximum_address = self.maxnodes
        rec.maximum_cost = self.maxcost
        rec.maximum_hops = self.maxhops
        rec.maximum_visits = self.maxvisits
        rec.routing_timer = self.config.t1
        rec.broadcast_routing_timer = self.config.bct1
    
class Phase3Router (L1Router):
    """Routing entity for Phase III routers.
    """
    LanCircuit = None
    tiver = tiver_ph3
    defmaxnode = 255
    firstnode = 1       # For routing table display
    ntypestring = "Phase 3 router"

class L2Router (L1Router):
    """Routing entity for level 2 (area) routers
    """
    LanCircuit = LanL2Circuit
    PtpCircuit = PtpL2Circuit
    ntype = L2ROUTER
    ntypestring = "Area router"
    
    def __init__ (self, parent, config):
        rconfig = config.routing
        self.maxarea = rconfig.maxarea
        self.amaxhops = rconfig.amaxhops
        self.amaxcost = rconfig.amaxcost
        self.aminhops, self.amincost = allocvecs (rconfig.maxarea)
        self.aoadj = [ UNREACHABLE ] * (self.maxarea + 1)
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
        # Call the base class method to do any L1 adjacency up actions
        # that are appropriate.  If this is an out of area router, it
        # will handle that (by not doing L1 routing work).
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
                    adj = self.aoadj[i]
                    if adj == self.selfadj:
                        adj = "Self"
                    data.append ([ i, self.aminhops[i],
                                   self.amincost[i], adj ])
            ret.append (html.tbsection ("Level 2 routing table", hdr, data))
        if what == "internals":
            ret.append (self.html_matrix (True))
        return ret

    def node_char (self, rec):
        # Add router characteristics to "rec"
        rec.maximum_area = self.maxarea
        rec.area_maximum_cost = self.amaxcost
        rec.area_maximum_hops = self.amaxhops

    def nice_read (self, req, resp):
        if isinstance (req, nicepackets.NiceReadArea):
            # Read area
            if req.info > 1:
                # characteristics or counters, no such thing
                return
            if req.mult ():
                # active or known entities, return the reachable ones.
                for i in range (1, self.maxarea):
                    a = self.aoadj[i]
                    if a:
                        r = resp[i]
                        r.state = 4    # Reachable
                        if a is self.selfadj:
                            r.next_node = self.nodeinfo
                        else:
                            r.circuit = a.circuit
                            r.next_node = self.node.nodeinfo (a.nodeid)
                        if req.info == 1:
                            # status
                            r.hops = self.aminhops[i]
                            r.cost = self.amincost[i]
            else:
                i = req.entity.value
                if not 0 < i <= self.maxarea:
                    return
                r = resp[i]
                a = self.aoadj[i]
                if a:
                    r.state = 4    # Reachable
                    if a is self.selfadj:
                        r.next_node = self.nodeinfo
                    else:
                        r.circuit = a.circuit
                        r.next_node = self.node.nodeinfo (a.nodeid)
                    if req.info == 1:
                        # statuss
                        r.hops = self.aminhops[i]
                        r.cost = self.amincost[i]
                else:
                    r.state = 5    # Unreachable
        else:
            super ().nice_read (req, resp)
                        
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
        # Set the requested SRM flags, and schedule transmission of a
        # routing update momentarily, subject to holdoff by T2 (one
        # second).  This will also restart the periodic (T1) routing
        # message transmission after the current batch of updates has
        # been sent.
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
        if isinstance (item, timers.Timeout):
            # No holdoff in effect
            self.holdoff = False
            # Time to send some updates.  See if the neighbor wants
            # them.  We skip Phase 2, end nodes, and unknown (meaning
            # a point to point circuit where we haven't heard from the
            # other end yet).
            if self.parent.ntype in (UNKNOWN, ENDNODE, PHASE2):
                return
            pkttype = self.pkttype
            if isinstance (self.parent, route_ptp.PtpCircuit):
                # Point to point, see if neighbor wants this update
                if pkttype == L2Routing:
                    if self.parent.ntype != L2ROUTER:
                        return
                else:
                    if self.parent.ntype == L2ROUTER \
                      and self.parent.id.area != self.routing.homearea:
                        # Do not send L1 routing data out of area.
                        return
                    if self.node.phase == 3 or self.parent.rphase == 3:
                        # Either we are phase 3 or neighbor is, use that format.
                        pkttype = PhaseIIIRouting
            # If anysrm is set, that means setsrm was called to
            # request sending of specific updates.  If not, then this
            # is a periodic (all destinations) update
            pkts = self.buildupdates (pkttype, not self.anysrm)
            self.startpos += 1
            startpos = self.startpos % len (pkts)
            pkts = pkts[startpos:] + pkts[:startpos]
            logging.trace ("Sending {} update ({}) packets",
                           len (pkts), self.pkttype.__name__)
            for p in pkts:
                self.parent.datalink.send (p, dest = route_eth.ALL_ROUTERS)
            self.lastupdate = time.time ()
            if self.anysrm:
                # Not periodic update; find the delta from the last
                # periodic update as the new timeout.
                delta = min (self.lastupdate - self.lastfull, self.t1)
            else:
                delta = self.t1
                self.lastfull = self.lastupdate
            self.node.timers.start (self, delta)
            self.anysrm = False
            
    def buildupdates (self, pkttype, complete):
        """Build routing messages according to the SRM flags.  The highest
        entry is obtained from the length of the minhops vector; the starting
        entry number is given by pkttype.lowid.  If "complete" is False, send
        only entries whose srm flag is set; otherwise send everything.
        
        The return value is a list of packets.
        """
        srm = self.srm
        minhops = self.minhops
        mincost = self.mincost
        seg = pkttype.segtype
        if pkttype is not PhaseIIIRouting:
            # Phase 4 (segmented) format
            ret = list ()
            p = None
            previd = -999
            curlen = 0    # dummy value so it is defined
            mtu = self.parent.minrouterblk - 16
            for i in range (pkttype.lowid, len (minhops)):
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
                        p = pkttype (srcnode = self.node.nodeid)
                        p.segments = packet.LIST ()
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
                        seg = pkttype.segtype (startid = i)
                        seg.entries = packet.LIST ()
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
            p = pkttype (srcnode = self.routing.tid)
            p.segments = packet.LIST ()
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

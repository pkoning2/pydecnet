#!/usr/bin/env python3

"""DECnet routing decision and update modules.

"""

from .common import *
from .routing_packets import *
from .events import *
from . import datalink
from . import timers
from . import statemachine
from . import route_ptp
from . import route_eth
from . import adjacency

nodetypes = { "l1router" : L1ROUTER,
              "l2router" : L2ROUTER,
              "endnode" : ENDNODE,
              "phase3router" : L1ROUTER,
              "phase3endnode" : ENDNODE,
              "phase2" : PHASE2 }

def Routing (parent, config):
    """Factory class for routing layer instance.  Returns an instance
    of RouterRouting :-) or EndnodeRouting depending on the supplied config.
    """
    if nodetypes[config.routing.type] == ENDNODE:
        return EndnodeRouting (parent, config)
    else:
        return RouterRouting (parent, config)
    
class _Routing (Element):
    """The routing layer.  Mainly this is the parent of a number of control
    components and collections of circuits and adjacencies.
    """
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        logging.debug ("Initializing routing layer")
        self.config = config.routing
        self.circuits = dict ()
        self.nodeid = config.routing.id
        self.nodemacaddr = Macaddr (self.nodeid)
        self.homearea = self.nodeid.area
        self.tid = self.nodeid.tid
        self.typename = config.routing.type
        self.nodetype = nodetypes[self.typename]
        self.endnode = self.nodetype == ENDNODE
        if self.endnode:
            if len (config.circuit) > 1:
                raise ValueError ("End node must have 1 circuit, found %d" % \
                                  len (config.circuits))
        dlcirc = self.node.datalink.circuits
        for name, c in config.circuit.items ():
            dl = dlcirc[name]
            try:
                self.circuits[name] = self.routing_circuit (name, dl, c)
                logging.debug ("Initialized routing circuit %s", name)
            except Exception:
                logging.exception ("Error initializing routing circuit %s", name)
        
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
    
    def dispatch (self, item):
        pass

    def circuit_up (self, circ):
        pass

    def circuit_down (self, circ):
        pass
    
    def adjacency_up (self, adj):
        pass
    
    def adjacency_down (self, adj):
        pass
    
class EndnodeRouting (_Routing):
    """Routing entity for endnodes.
    """
    def routing_circuit (self, name, dl, c):
        """Factory function for circuit objects.  Depending on the datalink
        type (LAN vs. not) and node type (endnode vs.router) we use different
        classes.  More precisely, LAN does, point to point doesn't since
        the differences aren't significant there.
        """
        if isinstance (dl, datalink.BcDatalink):
            if self.typename == "phase3endnode":
                raise ValueError ("LAN datalink for Phase 3 node")
            return route_eth.EndnodeLanCircuit (self, name, dl, c)
        return route_ptp.PtpCircuit (self, name, dl, c)

class RouterRouting (_Routing):
    """Routing entity for routers -- either L1 or L2 routers.
    """
    def __init__ (self, parent, config):
        rconfig = config.routing
        self.maxnodes = rconfig.maxnodes
        self.maxhops = rconfig.maxhops
        self.maxcost = rconfig.maxcost
        self.maxvisits = rconfig.maxvisits
        self.l2 = rconfig.type == "l2router"
        if self.l2:
            self.maxarea = rconfig.maxarea
            self.amaxhops = rconfig.amaxhops
            self.amaxcost = rconfig.amaxcost
        super ().__init__ (parent, config)
        # There's a dummy adjacency for "self" and associated routing state
        self.adjacencies = dict ()
        self.selfadj = adjacency.BcAdjacency (self, self.nodeid, 0,
                                              self.nodetype)
        self.adjacency_up (self.selfadj)
        self.mincost, self.minhops = self.infvec (self.maxnodes + 1)
        self.oadj = [ None for i in range (self.maxnodes + 2) ]
        tid = self.nodeid.tid
        self.selfadj.hops[tid] = self.selfadj.cost[tid] = 0
        self.oadj[tid] = self.selfadj
        if self.l2:
            self.amincost, self.aminhops = self.infvec (self.maxarea)
            self.aoadj = [ None for i in range (self.maxarea + 1) ]
            area = self.nodeid.area
            self.selfadj.ahops[area] = self.selfadj.acost[area] = 0
            self.aoadj[area] = self.selfadj

    def infvec (self, vecmax):
        """Return a pair of routing vectors, containing new instances of
        InfHops and InfCost respectively.  The vector max index is given by
        the argument.
        """
        return [ INFHOPS for i in range (vecmax + 1) ], \
               [ INFCOST for i in range (vecmax + 1) ]

    def routing_circuit (self, name, dl, c):
        """Factory function for circuit objects.  Depending on the datalink
        type (LAN vs. not) and node type (endnode vs.router) we use different
        classes.  More precisely, LAN does, point to point doesn't since
        the differences aren't significant there.
        """
        if isinstance (dl, datalink.BcDatalink):
            if self.typename in { "phase3router", "phase2" }:
                raise ValueError ("LAN datalink for Phase 2 or 3 node")
            circ = route_eth.RoutingLanCircuit (self, name, dl, c)
        else:
            circ = route_ptp.PtpCircuit (self, name, dl, c)
            if self.l2:
                circ.ahops, circ.acost = self.infvec (self.maxarea)
        circ.hops, circ.cost = self.infvec (self.maxnodes + 1)
        return circ

    def circuit_up (self, circ):
        circ.hops, circ.cost = self.infvec (self.maxnodes + 1)

    def adjacency_up (self, adj):
        self.adjacencies[adj.nodeid] = adj
        adj.hops, adj.cost = self.infvec (self.maxnodes + 1)
        adj.srm = bytearray (self.maxnodes + 1)
        if self.l2:
            adj.ahops, adj.acost = self.infvec (self.maxarea)
            adj.asrm = bytearray (self.maxarea)
        if adj.ntype == ENDNODE:
            # Mark this endnode as reachable via this adjacency
            tid = adj.nodeid.tid
            adj.hops[tid] = 1
            adj.cost[tid] = adj.circuit.config.cost
            self.route (tid)
            self.setsrm (tid, None)

    def adjacency_down (self, adj):
        try:
            id = adj.nodeid
            del self.adjacencies[id]
            if adj.ntype != ENDNODE:
                self.route (id.tid)
                if adj.ntype == L2ROUTER:
                    self.aroute (id.area)
        except KeyError:
            pass
        
    def dispatch (self, item):
        adj = item.src
        maxreach = 0
        if isinstance (item, L2Routing):
            if not self.l2:
                # Silently ignore L2 Routing packets if we're not L2
                return
            for k, v in item.entries (adj.circuit):
                if k > self.maxarea:
                    if v != (INFCOST, INFHOPS):
                        maxreach = max (maxreach, k)
                    continue
                oldv = adj.acost[k], adj.ahops[k]
                if oldv != v:
                    adj.acost[k], adj.ahops[k] = v
                    self.aroute (k)
                    self.setasrm (k, adj)
        elif isinstance (item, L1Routing):
            for k, v in item.entries (adj.circuit):
                if k > self.maxnodes:
                    if v != (INFCOST, INFHOPS):
                        maxreach = max (maxreach, k)
                    continue
                oldv = adj.cost[k], adj.hops[k]
                if oldv != v:
                    adj.cost[k], adj.hops[k] = v
                    self.route (k)
                    self.setsrm (k, adj)
        if maxreach:
            self.node.logevent (Event.rout_upd_loss, adj.circuit,
                                highest_address = maxreach,
                                adjacent_node = self.node.eventnode (adj.nodeid))
            
    def setsrm (self, tid, srcadj):
        for a in self.adjacencies.values ():
            if a != srcadj and a.ntype != ENDNODE:
                a.srm[tid] = 1

    def route (self, start, end = None):
        end = end or start
        self.check ()
        for i in range (start, end + 1):
            bestc, besta = INFCOST, None
            for a in self.adjacencies.values ():
                if a.cost[i] < bestc or \
                   (a.cost[i] == bestc and \
                    (besta is None or a.nodeid > besta.nodeid)):
                    bestc = a.cost[i]
                    besta = a
            besth = besta.hops[i]
            if bestc > self.maxcost or besth > self.maxhops:
                bestc, besth, besta = INFCOST, INFHOPS, None
            if self.minhops[i] != besth or self.mincost[i] != bestc:
                self.minhops[i] = besth
                self.mincost[i] = bestc
                self.setsrm (i, None)
            if besta != self.oadj[i]:
                self.oadj[i] = besta
                #logging.debug ("Node %d, cost %d, hops %d via %s %s",
                #               i, bestc, besth,
                #               besta.circuit.name, besta.nodeid)
                nod = self.node.eventnode (Nodeid (self.homearea, i))
                if besta:
                    self.node.logevent (Event.reach_chg, nod,
                                        status = "reachable")
                else:
                    self.node.logevent (Event.reach_chg, nod,
                                        status = "unreachable")

    def setasrm (self, area, srcadj):
        for a in self.adjacencies.values ():
            if a != srcadj and a.ntype == L2ROUTER:
                a.asrm[tid] = 1

    def aroute (self, area):
        pass    

    def check (self):
        tid = self.nodeid.tid
        a = self.selfadj
        for i in range (self.maxnodes + 2):
            if i == tid:
                assert a.hops[i] == a.cost[i] == 0
            else:
                assert a.hops[i] == INFHOPS and a.cost[i] == INFCOST
        if self.l2:
            area = self.nodeid.area
            for i in range (1, self.maxarea + 1):
                if i == area:
                    assert a.ahops[i] == a.acost[i] == 0
                else:
                    assert a.ahops[i] == INFHOPS and a.acost[i] == INFCOST
            # Todo: attached flag

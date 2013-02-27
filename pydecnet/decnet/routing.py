#!/usr/bin/env python3

"""DECnet routing decision and update modules.

"""

from .common import *
from .node import ApiRequest, ApiWork
from .routing_packets import *
from . import datalink
from . import timers
from . import statemachine
from . import route_ptp
from . import route_eth
from . import adjacency

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
        self.config = config.routing
        self.circuits = dict ()
        self.adjacencies = dict ()
        self.node.routing = self
        # Save node id in the parent Node object for easy reference
        self.node.nodeid = self.nodeid = config.routing.id
        self.homearea = self.nodeid.area
        self.tid = self.nodeid.tid
        self.typename = config.routing.type
        self.nodetype = nodetypes[self.typename]
        self.endnode = self.nodetype == 3
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
    
    def routing_circuit (self, name, dl, c):
        """Factory function for circuit objects.  Depending on the datalink
        type (LAN vs. not) and node type (endnode vs.router) we use different
        classes.  More precisely, LAN does, point to point doesn't since
        the differences aren't significant there.
        """
        if self.endnode:
            if isinstance (dl, datalink.BcDatalink):
                if self.typename == "phase3endnode":
                    raise ValueError ("LAN datalink for Phase 3 node")
                return route_eth.EndnodeLanCircuit (self, name, dl, c)
            return route_ptp.PtpCircuit (self, name, dl, c)
        else:
            if isinstance (dl, datalink.BcDatalink):
                if self.typename in { "phase3router", "phase2" }:
                    raise ValueError ("LAN datalink for Phase 2 or 3 node")
                return route_eth.RoutingLanCircuit (self, name, dl, c)
            return route_ptp.PtpCircuit (self, name, dl, c)

    def dispatch (self, item):
        pass

    def adjacency_up (self, adj):
        logging.debug ("Adjacency up: %s %s", adj.circuit.name, adj.nodeid)

    def adjacency_down (self, adj):
        logging.debug ("Adjacency down: %s %s", adj.circuit.name, adj.nodeid)        

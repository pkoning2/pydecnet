#!

"""DECnet/Python Node object -- the container for all the parts of DECNET

"""

import os
import queue
import threading
import logging

from .common import *
from .events import *
from . import timers
from . import datalink
from . import datalinks    # All the datalinks we know
from . import mop
from . import routing
from . import apiserver
from . import nsp
from . import monitor

class Nodeinfo (nsp.NSPNode):
    """A container for node database entries.  This contains the attributes
    needed by the various layers for remote node items -- for example, the
    state and counters needed by NSP.  The argument is the node config entry.
    """
    def __init__ (self, c, id = None):
        super ().__init__ ()
        if c:
            self.nodeid = c.id
            self.nodename = c.name
            self.overif = c.outbound_verification
            self.iverif = c.inbound_verification
        else:
            self.nodeid = id
            self.nodename = None
            self.overif = None
            self.iverif = None
            
    def __str__ (self):
        if self.nodename:
            return "{0.nodeid} ({0.nodename})".format (self)
        return "{0.nodeid}".format (self)

# A mapping from router node type to DECnet Phase number.  We need this
# in a number of layers so we'll keep the answer in the Node object.
phases = { "l2router" : 4, "l1router" : 4, "endnode" : 4,
           "phase3router" : 3, "phase3endnode" : 3,
           "phase2" : 2 }

class Node (object):
    """A Node object is the outermost container for all the other objects
    that make up a DECnet node.  Typically there is one Node object, but
    it's certainly possible to create multiple ones (to emulate an
    entire network within a single process).
    """
    startlist = ( "datalink", "mop", "routing", "nsp",
                  "api", "monitor" )
    
    def __init__ (self, config):
        self.node = self
        self.config = config
        self.phase = phases[config.routing.type]
        if self.phase == 4:
            self.nodeid = config.routing.id
        else:
            # Not phase IV, so make sure node ID is an old style (8 bit) value
            self.nodeid = NodeId (0, config.routing.id.tid)
        # Build node lookup dictionaries
        self.nodeinfo_byname = dict()
        self.nodeinfo_byid = dict()
        for n in config.node.values ():
            n = Nodeinfo (n)
            self.nodeinfo_byname[n.nodename] = n
            self.nodeinfo_byid[n.nodeid] = n
        self.nodename = self.nodeinfo (self.nodeid).nodename
        threading.current_thread ().name = self.nodename
        logging.debug ("Initializing node %s", self.nodename)
        self.timers = timers.TimerWheel (self, 0.1, 3600)
        sock = config.system.api_socket
        self.api = apiserver.ApiServer (self, sock)
        self.monitor = monitor.Monitor (self, config)
        self.workqueue = queue.Queue ()

        # We now have a node.
        # Create its child entities in the appropriate order.
        self.datalink = datalink.DatalinkLayer (self, config)
        self.mop = mop.Mop (self, config)
        self.routing = routing.Router (self, config)
        self.nsp = nsp.NSP (self, config)
        
    def nodeinfo (self, n):
        """Look up a node in the node database.  The argument can be either
        a name (a string) or an id (a number or Nodeid).

        If the entry is not found and the lookup is by number, add a Nodeinfo
        object to the dictionary for that number, with no name.  This implements
        what we need for the NSP node database.
        """
        if isinstance (n, str):
            return self.nodeinfo_byname[n.upper ()]
        try:
            return self.nodeinfo_byid[n]
        except KeyError:
            # No entry for this node ID; add one with no name
            n = Nodeinfo (None, id)
            self.nodeinfo_byid[n.nodeid] = n
            return n
    
    def addwork (self, work, handler = None):
        """Add a work item (instance of a Work subclass) to the node's
        work queue.  This can be called from any thread.  If "handler"
        is specified, set the owner of the work item to that value,
        overriding the handler specified when the Work object was created.
        """
        if handler is not None:
            work.owner = handler
        self.workqueue.put (work)
        
    def start (self, mainthread = False):
        """Start the node, i.e., its child entities in the right order
        and then the node main loop.
        """
        threading.current_thread ().name = self.nodename
        logging.debug ("Starting node %s", self.nodename)
        for m in self.startlist:
            c = getattr (self, m)
            if c:
                c.start ()
        if mainthread:
            self.mainloop ()
        else:
            t = threading.Thread (target = self.mainloop, name = self.nodename)
            # Exit the server thread when the main thread terminates
            t.daemon = True
            t.start ()
            
    def mainloop (self):
        """Node main loop.  This is intended to be the main loop of
        the whole DECnet process, so it loops here and does not return
        until told to shut down.
        """
        q = self.workqueue
        try:
            while True:
                try:
                    work = q.get ()
                except KeyboardInterrupt:
                    break
                if isinstance (work, Shutdown):
                    break
                try:
                    work.dispatch ()
                except Event as e:
                    # If processing of the work item raises an Event
                    # exception, log that event and keep going.
                    # Any other exception terminates things.
                    self.logevent (e)
        finally:
            self.stop ()

    def stop (self):
        threading.current_thread ().name = self.nodename
        logging.debug ("Stopping node")
        # Stop things in the reverse order they are started
        for m in reversed (self.startlist):
            c = getattr (self, m)
            if c:
                c.stop ()
        self.timers.shutdown ()
        
    def register_api (self, command, handler, help = None):
        """Register a command under the DECnet/Python API.  Arguments
        are the command name, the handler element (where requests for this
        command will be dispatched to) and optional help text.  The
        function returns an argparse subparser object, which the caller
        should populate with any command arguments desired.

        When requests matching this command are subsequently dispatched,
        they will come to the owner in the form of ApiRequest work items.
        """
        return self.api.register_api (command, handler, help)

    def logevent (self, event, entity = None, **kwds):
        if not isinstance (event, Event):
            event = Event (event, entity, **kwds)
        event._local_node = self
        logging.info (event)

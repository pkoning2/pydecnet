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
from . import mop
from . import routing
from . import apiserver
from . import nsp
from . import monitor

class Nodeinfo (object):
    """A container for node database entries.
    """
    def __init__ (self, id, name):
        self.nodeid = id
        self.nodename = name

    def __str__ (self):
        if self.nodename:
            return "{0.nodeid} ({0.nodename})".format (self)
        return "{0.nodeid}".format (self)
        
class Node (object):
    """A Node object is the outermost container for all the other objects
    that make up a DECnet node.  Typically there is one Node object, but
    it's certainly possible to create multiple ones (to emulate an
    entire network within a single process).
    """
    def __init__ (self, config):
        self.node = self
        self.config = config
        self.nodeid = config.routing.id
        # Build node lookup dictionaries
        self.nodeinfo_byname = dict()
        self.nodeinfo_byid = dict()
        for n in config.node.values ():
            n = Nodeinfo (n.id, n.name)
            self.nodeinfo_byname[n.nodename] = n
            self.nodeinfo_byid[n.nodeid] = n
        self.nodename = self.nodeinfo (self.nodeid).nodename
        threading.current_thread ().name = self.nodename
        logging.debug ("Initializing node %s", self.nodename)
        self.timers = timers.TimerWheel (self, 0.1, 3600)
        try:
            sock = config.system.api_socket
        except AttributeError:
            sock = DEFAPISOCKET
        self.api = apiserver.ApiServer (self, sock)
        self.monitor = monitor.Monitor (self, config)
        self.workqueue = queue.Queue ()

        # We now have a node.  Create its child entities in the appropriate order
        self.datalink = datalink.DatalinkLayer (self, config)
        self.mop = mop.Mop (self, config)
        self.routing = routing.Router (self, config)
        self.nsp = nsp.NSP (self, config)
        
    def nodeinfo (self, n):
        """Look up a node in the node database.  The argument can be either
        a name (a string) or an id (a number or Nodeid).
        """
        if isinstance (n, str):
            return self.nodeinfo_byname[n.upper ()]
        try:
            return self.nodeinfo_byid[n]
        except KeyError:
            return Nodeinfo (n, "")
    
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
        self.datalink.start ()
        self.mop.start ()
        self.routing.start ()
        self.nsp.start ()
        self.api.start ()
        self.monitor.start ()
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
        self.api.stop ()
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

    def eventnode (self, id):
        """Convert a node ID to a node argument for event logging.
        """
        try:
            n = self.nodeinfo (id)
            return NodeEntity (n.nodeid, n.nodename)
        except KeyError:
            return NodeEntity (id, None)

    def logevent (self, event, entity = None, **kwds):
        if not isinstance (event, Event):
            event = Event (event, entity, **kwds)
        event._local_node = self
        logging.info (event)

class NodeEntity (object):
    def __init__ (self, nodeid, nodename):
        self.nodeid = nodeid
        self.nodename = nodename

    def __str__ (self):
        if self.nodename:
            return "{0.nodeid} ({0.nodename})".format (self)
        return "{0.nodeid}".format (self)

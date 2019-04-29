#!

"""DECnet/Python Node object -- the container for all the parts of DECNET

"""

import os
import queue
import threading

from .common import *
from . import nice
from . import events
from . import timers
from . import logging
from . import datalink
from . import datalinks    # All the datalinks we know
from . import mop
from . import routing
from . import nsp
from . import http
from . import html
from . import event_logger
from . import bridge
from . import session

class Nodeinfo (nsp.NSPNode, nice.NiceNode):
    """A container for node database entries.  This contains the attributes
    needed by the various layers for remote node items -- for example, the
    state and counters needed by NSP.  The argument is the node config entry.
    """
    def __new__ (cls, c, nodeid = None):
        if c:
            return nice.NiceNode.__new__ (cls, c.id, c.name)
        assert (nodeid is not None)
        return nice.NiceNode.__new__ (cls, nodeid)

    def __init__ (self, c, nodeid = None):
        nsp.NSPNode.__init__ (self)
        if c:
            self.overif = c.outbound_verification
            self.iverif = c.inbound_verification
        else:
            self.overif = None
            self.iverif = None

    def get_api (self):
        ret = nice.NiceNode.get_api (self)
        ret.update (nsp.NSPNode.get_api (self))
        if self.overif:
            ret["outbound_verification"] = self.overif
        if self.iverif:
            ret["inbound_verification"] = self.iverif
        return ret
    
# A mapping from router node type to DECnet Phase number.  We need this
# in a number of layers so we'll keep the answer in the Node object.
phases = { "l2router" : 4, "l1router" : 4, "endnode" : 4,
           "phase3router" : 3, "phase3endnode" : 3,
           "phase2" : 2 }

class Node (Entity):
    """A Node object is the outermost container for all the other objects
    that make up a DECnet node.  Typically there is one Node object, but
    it's certainly possible to create multiple ones (to emulate an
    entire network within a single process).
    """
    startlist = ( "event_logger", "datalink", "mop", "routing", "nsp",
                  "session", "bridge" )

    def __init__ (self, config):
        self.node = self
        self.config = config
        self.nodeinfo_byname = dict()
        self.nodeinfo_byid = dict()
        self.decnet = hasattr (config, "routing")
        if self.decnet:
            # This is a DECnet node.
            self.bridge = None
            self.phase = phases[config.routing.type]
            if self.phase == 4:
                self.nodeid = config.routing.id
            else:
                # Not phase IV, so make sure node ID is an old style
                # (8 bit) value
                self.nodeid = NodeId (0, config.routing.id.tid)
            # Build node lookup dictionaries
            for n in config.node.values ():
                n = Nodeinfo (n)
                self.addnodeinfo (n)
            self.nodename = self.nodeinfo (self.nodeid).nodename
        else:
            # bridge, dummy up some attributes
            self.mop = self.routing = self.nsp = self.session = None
            self.phase = 0
            self.nodeid = None
            self.nodename = config.bridge.name
        threading.current_thread ().name = self.nodename
        logging.debug ("Initializing node {}", self.nodename)
        self.timers = timers.TimerWheel (self, 0.1, 3600)
        self.workqueue = queue.Queue ()
        # We now have a node.
        # Create its child entities in the appropriate order.
        self.event_logger = event_logger.EventLogger (self, config)
        self.datalink = datalink.DatalinkLayer (self, config)
        if self.decnet:
            self.mop = mop.Mop (self, config)
            self.routing = routing.Router (self, config)
            self.nsp = nsp.NSP (self, config)
            self.session = session.Session (self, config)
        else:
            self.bridge = bridge.Bridge (self, config)

    def get_api (self):
        ##### TEMP
        return [ n.get_api () for n in self.nodeinfo_byid.values () ]
            
    def addnodeinfo (self, n):
        self.nodeinfo_byname[n.nodename] = n
        self.nodeinfo_byid[n] = n
        
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
            n = Nodeinfo (None, n)
            self.nodeinfo_byid[n] = n
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
        logging.debug ("Starting node {}", self.nodename)
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
                except events.Event as e:
                    # If processing of the work item raises an Event
                    # exception, log that event and keep going.
                    # Any other exception terminates things.
                    self.logevent (e)
        except Exception:
            logging.exception ("Exception caught in mainloop")
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
        
    def logevent (self, event, entity = None, **kwds):
        if isinstance (event, events.Event):
            event.setsource (self.nodeid)
            event.setparams (**kwds)
        else:
            event = event (entity, source = self.nodeid, **kwds)
        self.event_logger.logevent (event)
        
    def description (self):
        try:
            return self.routing.description ()
        except AttributeError:
            return self.bridge.description ()

    def json_description (self):
        try:
            return self.routing.json_description ()
        except AttributeError:
            return self.bridge.json_description ()

    def http_get (self, parts):
        qs = "?system={}".format (self.nodename)
        br = self.bridge
        if br:
            title = "DECnet/Python monitoring on bridge {0.nodename}".format (self)
            sb = html.sbelement (html.sblabel ("Entities"),
                                 html.sbbutton ("", "Overall summary", qs),
                                 html.sbbutton ("bridge", "Bridge layer", qs))
            if parts == ['']:
                active = 1
                sb2, body = br.http_get (parts, qs)
            elif parts[0] == "bridge":
                active = 2
                sb2, body = br.http_get (parts[1:], qs)
            else:
                return None
        else:
            title = "DECnet/Python monitoring on node {0.nodeid} ({0.nodename})".format (self)
            sb = html.sbelement (html.sblabel ("Entities"),
                                 html.sbbutton ("", "Overall summary", qs),
                                 html.sbbutton ("routing", "Routing layer", qs),
                                 html.sbbutton ("mop", "MOP", qs))
            if parts == ['']:
                active = 1
                sb2, body = self.routing.http_get (parts, qs)
            elif parts[0] == "routing":
                active = 2
                sb2, body = self.routing.http_get (parts[1:], qs)
            elif parts[0] == "mop":
                active = 3
                sb2, body = self.mop.http_get (parts[1:], qs)
            else:
                return None
        if not body:
            return None
        sb.contents[active].__class__ = html.sbbutton_active
        return title, [ sb, sb2 ], body

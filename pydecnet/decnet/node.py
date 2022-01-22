#!

"""DECnet/Python Node object -- the container for all the parts of DECNET

"""

import os
import queue
import threading
import collections

from .common import *
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
from . import nicepackets
from . import intercept

SvnFileRev = "$LastChangedRevision$"

class WorkStats:
    "A collection of time histograms for work items"
    header = ( "Owner", "Work" ) + Histogram.header

    def __init__ (self):
        self.hdict = collections.defaultdict (Histogram)
        
    def add (self, w, dt):
        "Record a delta-time for work item w"
        owner = w.owner.__class__.__name__
        what = w.__class__.__name__
        self.hdict[(owner, what)].count (dt)

    def stats (self):
        "Return a sequence of stats rows"
        ret = list ()
        for k, v in sorted (self.hdict.items ()):
            v.calc_stats ()
            ret.append (k + v.stats ())
        return ret

    def encode_json (self):
        ret = dict ()
        for k, v in self.hdict.items ():
            owner, what = k
            try:
                r = ret[owner]
            except KeyError:
                ret[owner] = r = dict ()
            r[what] = v
        return ret
    
class Nodeinfo (nsp.NSPNode, NiceNode):
    """A container for node database entries.  This contains the attributes
    needed by the various layers for remote node items -- for example, the
    state and counters needed by NSP.  The argument is the node config entry.
    """
    loopnode = False
    def __new__ (cls, c, nodeid = None):
        if c:
            return NiceNode.__new__ (cls, c.id, c.name)
        assert (nodeid is not None)
        return NiceNode.__new__ (cls, nodeid)

    def __init__ (self, c, nodeid = None):
        nsp.NSPNode.__init__ (self)
        self.overif = None
        self.iverif = None
        if c:
            if c.outbound_verification:
                self.overif = bytes (c.outbound_verification,
                                     encoding = "latin1")
            if c.inbound_verification:
                self.iverif = bytes (c.inbound_verification,
                                     encoding = "latin1")

    def get_api (self):
        ret = NiceNode.get_api (self)
        ret.update (nsp.NSPNode.get_api (self))
        if self.overif:
            ret["outbound_verification"] = str (self.overif,
                                                encoding = "latin1")
        if self.iverif:
            ret["inbound_verification"] = str (self.iverif,
                                               encoding = "latin1")
        return ret

    def get_dest (self):
        return Nodeid (self)

    def __eq__ (self, other):
        if isinstance (other, str):
            return self.nodename == other
        return super ().__eq__ (other)

    def __hash__ (self):
        return super ().__hash__ ()
    
class LoopNode (Nodeinfo):
    loopnode = True
    def __new__ (cls, name, circuit):
        n = NiceNode.__new__ (cls, 0, name)
        n.circuit = circuit
        return n

    def __init__ (self, name, circuit):
        super ().__init__ (None, 0)
        
    def get_api (self):
        ret = super ().get_api ()
        ret["cicuit"] = circuit
        return ret

    def get_dest (self):
        "Get the destination information for this node"
        return self.circuit
    
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
    # These are the elements to start, in this order.
    startlist = ( "datalink", "mop", "routing", "nsp",
                  "session", "bridge", "event_logger",
                  "intercept" )

    def __init__ (self, config):
        self.node = self
        self.config = config
        self.nodeinfo_byname = dict ()
        self.nodeinfo_byid = dict ()
        self.decnet = hasattr (config, "routing")
        self.ident = self.swident = "{}-{}".format (http.DNVERSION, http.DNREV)
        if config.system.identification:
            self.ident = config.system.identification
        if self.decnet:
            # This is a DECnet node.
            self.bridge = self.intercept = None
            self.phase = phases[config.routing.type]
            if self.phase == 4:
                self.nodeid = config.routing.id
            else:
                # Not phase IV, so make sure node ID is an old style
                # (8 bit) value
                self.nodeid = Nodeid (0, config.routing.id.tid)
            # Build node lookup dictionaries
            for n in config.node.values ():
                n = Nodeinfo (n)
                self.addnodeinfo (n)
            self.nodename = self.nodeinfo (self.nodeid).nodename
            self.nicenode = NiceNode (self.nodeid, self.nodename)
        else:
            # bridge, dummy up some attributes
            self.mop = self.routing = self.nsp = None
            self.intercept = self.session = None
            self.phase = 0
            self.nodeid = None
            self.nodename = config.bridge.name
        threading.current_thread ().name = self.nodename
        logging.debug ("Initializing node {}", self.nodename)
        self.timers = timers.TimerWheel (self, JIFFY, 3600)
        self.workqueue = queue.Queue ()
        self.stats = WorkStats ()
        self.apis = dict ()
        # We now have a node.
        # Create its child entities in the appropriate order.
        self.event_logger = event_logger.EventLogger (self, config)
        self.datalink = datalink.DatalinkLayer (self, config)
        if self.decnet:
            self.mop = mop.Mop (self, config)
            # This will be one of several flavors of intercept
            # support, possibly "no support".
            self.intercept = intercept.Intercept (self, config)
            # Routing depends on intercept to be created first
            self.routing = routing.Router (self, config)
            self.nsp = nsp.NSP (self, config)
            self.session = session.Session (self, config)
        else:
            self.bridge = bridge.Bridge (self, config)

    def register_api (self, name, sfun, efun = None):
        # Register a server function for the named API, and optionally
        # a clean up "exit" function called if the API client
        # disconnects.
        assert name not in self.apis and name != "node"
        self.apis[name] = (sfun, efun)
        
    def register_monitor (self, mon, evt):
        # Register the caller as an event monitor sink
        if self.decnet:
            self.event_logger.register_monitor (mon, evt)
            
    def api (self, client, apiname, reqtype, tag, args):
        if apiname == "node":
            if reqtype == "get":
                # Requesting node database information
                return { "nodenames" : [ n.get_api () for n in self.nodeinfo_byid.values () ] }
            return dict (error = "Unsupported node operation", type = reqtype)
        else:
            try:
                s, e = self.apis[apiname]
            except KeyError:
                return dict (error = "Unsupported api", api = apiname)
            try:
                return s (client, reqtype, tag, args)
            except Exception as e:
                logging.exception ("API request {} to {} failed",
                                   reqtype, apiname)
                return dict (error = "API exception", exception = e)

    def end_api (self, client):
        "Called when an API connection is closed"
        for s, e in self.apis.values ():
            if e:
                e (client)
                
    def addnodeinfo (self, n):
        # Note that duplicate entries (name as well as address) are
        # caught at config read-in.
        self.nodeinfo_byname[n.nodename] = n
        self.nodeinfo_byid[n] = n

    def addloopnodeinfo (self, name, circ):
        n = LoopNode (name, circ)
        self.nodeinfo_byname[name] = n
        self.nodeinfo_byid[circ] = n
        return n
    
    def nodeinfo (self, n):
        """Look up a node in the node database.  The argument can be
        either a name (a string) or an id (a number or Nodeid).

        If the entry is not found and the lookup is by number, add a
        Nodeinfo object to the dictionary for that number, with no name.
        This implements what we need for the NSP node database.
        """
        if isinstance (n, str):
            try:
                # See if the supplied string is a valid node ID
                # (num.num2 or simply num).  If yes, we'll look it up
                # that way.  If we get an error, it's not a valid ID
                # so assume it is a name.
                n = Nodeid (n)
            except ValueError:
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
        #logging.trace ("Add work {} of {}", work, work.owner)
        self.workqueue.put (work)
        
    def start (self):
        """Start the node, i.e., its child entities in the right order
        and then the node main loop.
        """
        threading.current_thread ().name = self.nodename
        logging.debug ("Starting node {}", self.nodename)
        # First start the timer service in this node
        self.timers.startup ()
        # Now start all the elements
        for m in self.startlist:
            c = getattr (self, m)
            if c:
                c.start ()
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
        s = self.stats
        try:
            while True:
                try:
                    work = q.get ()
                except KeyboardInterrupt:
                    break
                if isinstance (work, Shutdown):
                    break
                started = time.time ()
                logging.trace ("Dispatching {} of {}",
                               work, work.owner)
                work.dispatch ()
                dt = time.time () - started
                self.stats.add (work, dt)
                logging.trace ("Finished with {} of {}", work, work.owner)
                if dt > 0.5:
                    logging.trace ("Excessive run time {} for work item", dt)
                    # This is an "interesting event", capture what led
                    # up to it.
                    logging.flush ()
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
        #logging.trace ("Logevent called", stack_info = True)
        if isinstance (event, events.Event):
            event.source = self.nicenode
            event.setparams (**kwds)
        else:
            event = event (entity, source = self.nicenode, **kwds)
        self.event_logger.logevent (event)
        
    def logremoteevent (self, event):
        self.event_logger.logremoteevent (event)
        
    def description (self, mobile):
        try:
            return self.routing.description (mobile)
        except AttributeError:
            return self.bridge.description (mobile)

    def json_description (self):
        return { self.nodename : list (self.apis) }

    def http_get (self, mobile, parts):
        qs = "?system={}".format (self.nodename)
        br = self.bridge
        if br:
            title = "DECnet/Python monitoring on bridge {0.nodename}".format (self)
            sb = html.sbelement (html.sblabel ("Entities"),
                                 html.sbbutton (mobile, "",
                                                "Overall summary", qs),
                                 html.sbbutton (mobile, "bridge",
                                                "Bridge layer", qs))
            if parts == ['']:
                active = 1
                sb2, body = br.http_get (mobile, parts, qs)
            elif parts[0] == "bridge":
                active = 2
                sb2, body = br.http_get (mobile, parts[1:], qs)
            else:
                return None
        else:
            title = "DECnet/Python monitoring on node {0.nodeid} ({0.nodename})".format (self)
            sb = html.sbelement (html.sblabel ("Entities"),
                                 html.sbbutton (mobile, "",
                                                "Overall summary", qs),
                                 html.sbbutton (mobile, "routing",
                                                "Routing layer", qs),
                                 html.sbbutton (mobile, "nsp",
                                                "NSP and above", qs),
                                 html.sbbutton (mobile, "mop", "MOP", qs),
                                 html.sbbutton (mobile, "stats",
                                                "Statistics", qs))
            if parts == ['']:
                active = 1
                # TODO: at some point this should become an actual
                # "overall summary" as the description claims, rather
                # than simply a synonym for routing layer summary.
                sb2, body = self.routing.http_get (mobile, parts, qs)
            elif parts[0] == "routing":
                active = 2
                sb2, body = self.routing.http_get (mobile, parts[1:], qs)
            elif parts[0] == "nsp":
                active = 3
                sb2, body = self.nsp.http_get (mobile, parts[1:], qs)
            elif parts[0] == "mop":
                active = 4
                sb2, body = self.mop.http_get (mobile, parts[1:], qs)
            elif parts[0] == "stats":
                active = 5
                sb2, body = self.http_stats (mobile, parts[1:], qs)
            else:
                return None
        if not body:
            return None
        sb.contents[active].__class__ = html.sbbutton_active
        return title, [ sb, sb2 ], body

    def http_stats (self, mobile, parts, qs):
        infos = ( "statistics", "raw" )
        if not parts or parts == ['']:
            what = infos[0]
        elif parts[0] in infos:
            what = parts[0]
        else:
            return None, None
        active = infos.index (what) + 1
        sb = html.sbelement (html.sblabel ("Information"),
                             html.sbbutton (mobile, "stats", "Statistics", qs),
                             html.sbbutton (mobile, "stats/raw",
                                            "Raw data", qs))
        sb.contents[active].__class__ = html.sbbutton_active
        ret = [ "<h3>System timing statistics, rounded to nearest 0.1 s</h3>" ]
        if what == "raw":
            statsEncoder = DNJsonEncoder (indent = 2,
                                          separators = (',', ' : '))
            retd = { "timers" : self.timers.stats,
                     "work" : self.stats }
            ret.append (html.pre (statsEncoder.encode (retd)))
        else:
            ret.append (self.timers.html ())
            ret.append (html.tbsection ("Work queue statistics",
                                        self.stats.header, self.stats.stats ()))
        return sb, html.main (*ret)

    def nice_read (self, req):
        if isinstance (req, (nicepackets.NiceReadNode,
                             nicepackets.NiceZeroNode)) and \
           req.entity.value == 0:
            # Read of Executor is coded as node address zero, change
            # that to the explicit node address of this node.
            req.entity.value = self.routing.nodeid
        if isinstance (req, (nicepackets.NiceReadNode,
                             nicepackets.NiceZeroNode)) and \
           req.entity.code > 0:
            # Read node by name.  Look it up and substitute the
            # address so the layer functions don't need to look for
            # names.
            try:
                inf = self.nodeinfo_byname[req.entity.value]
                req.entity.code = 0
                req.entity.value = inf
            except KeyError:
                return -8    # Unknown entity
        resp = req.makereplydict (self)
        if isinstance (req, nicepackets.NiceReadLogging):
            self.event_logger.nice_read (req, resp)
            return resp
        if req.events ():
            # Asking for events
            return -1    # Unknown function or option
        # Hand the request to various layers.  NSP first because it
        # knows best what all the nodes are.
        self.nsp.nice_read (req, resp)
        self.session.nice_read (req, resp)
        self.routing.nice_read (req, resp)
        self.datalink.nice_read (req, resp)
        self.mop.nice_read (req, resp)
        if isinstance (req, nicepackets.P2NiceReadExecStatus):
            # Phase II read executor status
            exe = resp[0]
            exe.system = self.ident
            exe.state = 0    # On
        if isinstance (req, (nicepackets.NiceReadNode,
                             nicepackets.NiceZeroNode)) and \
           self.routing.nodeid in resp:
            exe = resp[self.routing.nodeid]
            # Set the "this is the executor" flag in the entity
            exe.entity.executor = True
            if req.sum () or req.char ():
                # summary or characteristics (!)
                exe.identification = self.ident
            if req.char ():
                # This is always the software identification string,
                # unlike "ident" which is configurable.
                exe.software_identification = self.swident
            elif req.stat ():
                exe.physical_address = Macaddr (self.nodeid)
            if req.sumstat ():   # summary or status
                exe.state = 0  # on
            if req.char ():  # characteristics
                # Set the network management version
                exe.management_version = [ 4, 0, 0 ]
        return resp

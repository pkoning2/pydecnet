#!

"""DECnet event logging -- filtering and sinks including remote sinks.

"""

import time
import re
import collections

from .common import *
from . import logging
from . import pktlogging
from .events import *
#from . import main
from . import nsp
from . import session
from . import timers

SvnFileRev = "$LastChangedRevision$"

EvlUser = session.EndUser1 (name = "EVENTLOGGER")
MYVERSION = ( 4, 0, 0 )
# "Known events" means all events this implementation can generate.  It
# is the maximum set for a filter.  Note that filtering applies only to
# locally generated events, so implementation specific events from other
# platforms are not part of Known Events and cannot (need not) appear in
# any filter.  Here we derive that set from the event layout
# definitions, omitting any that are base classes for a whole event
# class (event type field is None rather than a number) as well as those
# that are definitions of implementation specific events for other
# implementations (class codes 31 through 479).  We'll use class 480 and
# above ("Customer specific") for PyDECnet if it needs any product
# specific events at some point.
KNOWN_EVENTS = frozenset ((cl, e)
                          for (cl, e) in Event.classindex
                          if e is not None and not (31 < cl < 480))
CONNRETRY = 30
QLIMIT = 50        # Max items in remote sink send queue

# Bounded queue with overflow reporting
class EventQueue (collections.deque):
    def __init__ (self, node, limit):
        self.node = node
        self.limit = limit

    def append (self, item):
        if len (self) >= self.limit:
            # Queue is full.
            if isinstance (self[-1], events_lost):
                return
            # We didn't record a lost event condition yet, so add it
            item = events_lost ()
            item.entity_type = NoEntity ()
            item.source = self.node.nicenode
        super ().append (item)

evt_re = re.compile (r"(?:(\d+)\.)?(?:(?:(\d+)(?:-(\d+))?)|([*]))$")

def parse_events (s):
    """Parse an event-list string and return the corresponding
    events set.  This accepts a superset of the event-list specified
    in the DNA Network Management specification.  The additional
    capability is that multiple event classes may be specified,
    indicated by a number followed by period in the list.  For
    example:

    3.1,4.1-12,5.2,4,7
    """
    cl = None
    if s == "*.*":
        return KNOWN_EVENTS
    ret = set ()
    for item in s.split (","):
        m = evt_re.match (item)
        if not m:
            raise ValueError ("Bad event list entry {}".format (item))
        c, e1, e2, star = m.groups ()
        if c:
            cl = int (c)
            if not 0 <= cl < 512:
                raise RangeError ("Bad class in entry {}".format (item))
        elif cl is None:
            raise ValueError ("Missing event class in entry {}".format (item))
        else:
            c = cl
        if star:
            e1 = 0
            e2 = 31
        else:
            e1 = int (e1)
            if e2:
                e2 = int (e2)
                if e2 <= e1:
                    raise ValueError ("Bad range in entry {}".format (item))
            else:
                e2 = e1
            if e1 < 0 or e2 > 31:
                raise RangeError ("Bad event numbers in entry {}".format (item))
        for e in range (e1, e2 + 1):
            ret.add ((cl, e))
    return ret


# Filter class
class EventFilter (set):
    """A filter according to the DNA archictural model.

    The filter model has a filter per sink, local or remote.  And each
    entry in a filter may be qualified by the event entity; if
    qualified, it matches only events with that entity whose event ID
    is that entry; if not qualified, the event ID is the only
    consideration and the entity is not examined.

    The representation of a filter is a set, with elements that are:
    1. an event -- a pair of integers, the class and type numbers
    2. a qualified event: pair of event and entity
    """
    def __init__ (self, entity = None, events = None):
        if events:
            self.setfilter (events, entity)

    def setfilter (self, events, entity = None, enable = True):
        """Add (default) or remove (if "enable" is False) the specified
        events in the filter.  "events" is an iterable of either event
        code numbers, event objects, or event subclasses.  "entity" is
        the entity object to match, or omitted (None) for an unqualified
        match.  Events are added only if they are a member of the set
        "known events" (all the events implemented).
        """
        events &= KNOWN_EVENTS
        if enable:
            op = self.add
        else:
            op = self.discard
        for e in events:
            if entity:
                op ((entity, e))
            else:
                op (e)

    @staticmethod
    def fkey (f):
        ent, e = f
        if isinstance (ent, int):
            return (None, f)
        return (ent.key (ent), e)
    
    def format (self, prefix = "", width = 60):
        """Format the filter as standard NCP output."""
        if not self:
            return ""
        width -= len (prefix)
        ret = list ()
        le = False
        lc = fi = -1
        s = ls = ""
        for ent, e in sorted (self, key = self.fkey):
            if isinstance (ent, int):
                # Just a bare event
                c, i = ent, e
                ent = None
            else:
                c, i = e
            if ent == le  and c == lc and i == li + 1:
                li = i
            else:
                if fi != -1:
                    if fi == li:
                        ls += "{}".format (fi)
                    else:
                        ls += "{}-{}".format (fi, li)
                    s += ls
                    ls = ","
                if width and (ent != le or len (s) > width):
                    if s:
                        ret.append (prefix + s)
                    if ent:
                        s = str (ent)
                    else:
                        s = ""
                    lc = -1
                if c != lc:
                    if s:
                        s += ", "
                    s += "{}.".format (c)
                    ls = ""
                fi = li = i
                lc = c
                le = ent
        if fi == li:
            ls += "{}".format (fi)
        else:
            ls += "{}-{}".format (fi, li)
        s = "{}{}".format (s, ls)
        ret.append (prefix + s)
        return "\n".join (ret)

    def __contains__ (self, e):
        if isinstance (e, Event):
            ent = getattr (e, "entity_type", None)
            if ent is None:
                # Supply a placeholder entity if the caller didn't.
                e.entity_type = NoEntity ()
            code = e.classindexkey ()
            return code in self or (ent, code) in self
        return super ().__contains__ (e)
    
class EventSink (Element):
    def __init__ (self, parent):
        super ().__init__ (parent)
        self._filter = EventFilter ()

    @property
    def filter (self):
        return self._filter
    
    def logevent (self, evt):
        m = self.sinkmask (evt)
        if m:
            self.writeevent (evt, m)

    def sinkmask (self, evt):
        return evt in self.filter

    def start (self):
        pass
    
    def stop (self):
        pass
    
class LocalConsole (EventSink):
    def __init__ (self, parent, config = None):
        super ().__init__ (parent)
        
    def writeevent (self, evt, m):
        logging.log (evt.loglevel, evt)

class LocalFile (EventSink):
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        self.fn = config.sink_file
        self.f = open (self.fn, "ab")

    def writeevent (self, evt, m):
        # This writes the event in its encoded form (as carried in the
        # logging protocol) with a 2 byte little endian length before
        # each record.  This is the RMS variable length record format,
        # so it should be readable in most DEC operating systems.
        if not isinstance (evt, bytetypes):
            evt = evt.encode ()
        self.f.write (len (evt).to_bytes (2, "little") + evt)

    def stop (self):
        self.f.close ()
        self.f = None
        
class LocalMonitor (EventSink):
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        self.monitor = None

    def register_monitor (self, mon, evt):
        self.monitor = mon
        self.filter.setfilter (evt)
        evt = self.filter.format (width = 0).replace (" ", "")
        logging.debug ("Logging monitor initialized, events {}".format (evt))
        
    def writeevent (self, evt, m):
        if self.monitor:
            self.monitor.handleEvent (evt)
            
type2id = { "console" : 0, "file" : 1, "monitor" : 2 }
localsinktypes = [ LocalConsole, LocalFile, LocalMonitor ]
localsinks = [ None, None, None ]

class RemoteSink (EventSink, timers.Timer):
    def __init__ (self, parent, config):
        EventSink.__init__ (self, parent)
        timers.Timer.__init__ (self)
        self.filters = [ EventFilter (), EventFilter (), EventFilter () ]
        self.sinknode = config.sink_node
        self.sinkuser = config.sink_username
        self.sinkpw = config.sink_password
        self.sinkacc = config.sink_account
        self.scport = None
        self.sinkconn = None
        self.sinkqueue = EventQueue (self.node, QLIMIT)

    def start (self):
        self.scport = session.InternalConnector (self.node.session,
                                                 self, "EVENTLOGGER")
        
    def stop (self):
        if self.sinkconn and self.sinkconn is not True:
            self.sinkconn.abort ()
        self.sinkconn = None
        self.scport = None
        
    def sinkmask (self, evt):
        m = 0
        for i in range (3):
            if evt in self.filters[i]:
                m |= 1 << i
        return m

    def writeevent (self, evt, m):
        evt._sinks = m
        self.sinkqueue.append (evt)
        self.send_events ()

    def send_events (self):
        if self.sinkconn:
            # Send any pending events
            if self.sinkconn is True:
                # Still connecting, come back later
                return
            logging.trace ("send_events, {} entries", len (self.sinkqueue))
            while True:
                try:
                    evt = self.sinkqueue.popleft ()
                except IndexError:
                    break
                b = evt.encode ()
                try:
                    self.sinkconn.send_data (b)
                except Exception:
                    # Send failed, try to close the connection
                    try:
                        self.sinkconn.close ()
                    except Exception:
                        pass
                    self.sinkconn = None
                    # Restart it soon, if the timer isn't already active
                    if not self.islinked ():
                        self.node.timers.start (self, CONNRETRY)
                    # Put the event we could not send back onto the
                    # queue.
                    self.sinkqueue.appendleft (evt)
                    return
        elif self.sinknode:
            # try to open a connection
            if not self.scport:
                return
            logging.trace ("send_events connecting, {} entries",
                           len (self.sinkqueue))
            try:
                conn = self.scport.connect (self.sinknode, 26,
                                            srcname = EvlUser,
                                            data = MYVERSION,
                                            username = self.sinkuser,
                                            password = self.sinkpw,
                                            account = self.sinkacc,
                                            proxy = True)
                # Flag value for "connection pending"
                self.sinkconn = True
            except nsp.UnknownNode:
                logging.error ("Error opening logging connection to {}",
                               self.sinknode)
                self.sinknode = None
        
    def filter (self, sinktype):
        if not isinstance (sinktype, int):
            sinktype = type2id[sinktype]
        return self.filters[sinktype]

    def dispatch (self, item):
        if isinstance (item, timers.Timeout):
            # Connection retry timeout
            self.send_events ()
        else:
            conn = item.connection
            msg = item.message
            pktlogging.tracepkt ("Event sender received {} message".format (item.name), msg)
            if isinstance (item, session.Disconnect):
                logging.trace ("Event sender disconnect from {}",
                               conn.remotenode)
                self.sinkconn = None
                self.node.timers.start (self, CONNRETRY)
            elif isinstance (item, session.Reject):
                logging.trace ("Event sender connect reject from {}",
                               conn.remotenode)
                self.sinkconn = None
                self.node.timers.start (self, CONNRETRY)
            elif isinstance (item, session.Accept):
                logging.trace ("Event sender connected to {}",
                               conn.remotenode)
                self.sinkconn = conn
                self.send_events ()
            
class EventLogger (Element):
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        if not config or not config.logging:
            self.sinks = { (None, "console") :  LocalConsole (self) }
        else:
            self.sinks = dict ()
            for dest, c in config.logging.items ():
                sn, st = dest
                if sn:
                    # Remote sink.  This is only legal on DECnet nodes
                    # (not bridges).
                    if not self.node.decnet:
                        raise TypeError ("Remote sink not allowed on bridge")
                    try:
                        s = self.sinks[sn]
                    except KeyError:
                        s = self.sinks[sn] = RemoteSink (self, c)
                    f = s.filter (st)
                else:
                    stn = type2id[st]
                    sc = localsinktypes[stn]
                    try:
                        s = self.sinks[dest]
                    except KeyError:
                        s = self.sinks[dest] = localsinks[stn] = sc (self, c)
                        f = s.filter
                if c.events:
                    # parse events string and set filters.
                    evt = parse_events (c.events)
                    f.setfilter (evt)
                elif st == "console" and not sn:
                    # Local console and no events, default to all
                    f.setfilter (KNOWN_EVENTS)
                # Log what we ended up with
                if sn:
                    sname = "sink node {} {}".format (sn.upper (), st)
                else:
                    sname = "local sink {}".format (st)
                evt = f.format (width = 0).replace (" ", "")
                logging.debug ("Initialized {}, events {}".format (sname, evt))
            
    def start (self):
        for s in self.sinks.values ():
            s.start ()

    def stop (self):
        for s in self.sinks.values ():
            s.stop ()

    def logevent (self, evt):
        for s in self.sinks.values ():
            s.logevent (evt)

    def logremoteevent (self, evt):
        for name, code in type2id.items ():
            sink = localsinks[code]
            if sink and getattr (evt, name):
                sink.writeevent (evt, 1 << code)
                
    def nice_read (self, req, resp):
        return   # TODO

    def register_monitor (self, mon, evt):
        try:
            sink = self.sinks[(None, "monitor")]
        except KeyError:
            return
        sink.register_monitor (mon, evt)

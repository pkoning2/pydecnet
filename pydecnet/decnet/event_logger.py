import time

from .common import *
from . import logging
from .events import *

SvnFileRev = "$LastChangedRevision$"

# Filter classes

class EventFilter (set):
    """A filter according to the DNA archictural model.

    The filter model has a filter per sink, local or remote.  And each
    entry in a filter may be qualified by the event entity; if
    qualified, it matches only events with that entity whose event ID
    is that entry; if not qualified, the event ID is the only
    consideration and the entity is not examined.
    """
    def __init__ (self, entity = None, events = None):
        if events:
            self.setfilter (events, entity)

    def setfilter (self, events, entity = NoEntity, enable = True):
        """Add (default) or remove (if "enable" is False) the specified
        events in the filter.  "events" is an iterable of either event
        code numbers, event objects, or event subclasses.  "entity"
        is the entity object to match, or omitted (NoEntity) for an
        unqualified match.
        """
        for e in events:
            if not isinstance (e, int):
                e = Event.eventcode (e)
            if enable:
                self.add ((entity, e))
            else:
                self.discard ((entity, e))

    @staticmethod
    def fkey (f):
        ent, e = f
        return (ent.key (ent), e)
    
    def format (self, prefix = "", width = 60):
        """Format the filter as standard NCP output."""
        if not self:
            return ""
        width -= len (prefix)
        ret = list ()
        le = None
        lc = fi = -1
        s = ls = ""
        for ent, e in sorted (self, key = self.fkey):
            c, i = Event.codesplit (e)
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
                if ent != le or len (s) > width:
                    if s:
                        ret.append (prefix + s)
                    s = ent.nameformat ()
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
            ent = e._entity
            code = e.eventcode ()
            return (ent, code) in self or (NoEntity, code) in self
        return super ().__contains__ (e)
    
class EventSink (object):
    def __init__ (self):
        self.filter = EventFilter ()

    def logevent (self, evt):
        m = self.sinkmask (evt)
        if m:
            self.writeevent (evt, m)

    def sinkmask (self, evt):
        return evt in self.filter
    
class LocalConsole (EventSink):
    def __init__ (self):
        super ().__init__ ()
        self.filter.setfilter (Event.known_events ())
        
    def writeevent (self, evt, m):
        logging.info (evt)

class LocalFile (EventSink):
    def __init__ (self, config):
        self.fn = config.sink_file
        self.f = open (fn, "ab")

    def writeevent (self, evt, m):
        if not isinstance (evt, bytetypes):
            evt = evt.encode ()
        self.f.write (len (evt).to_bytes (2, "little") + evt)

type2id = { "console" : 0, "file" : 1, "monitor" : 2 }
localsinks = [ LocalConsole, LocalFile, None ]

class RemoteSink (EventSink):
    def __init__ (self, config):
        self.filters = [ EventFilter (), EventFilter (), EventFilter () ]
        self.sinknode = config.sink_node

    def sinkmask (self, evt):
        m = 0
        for i in range (3):
            if evt in self.filters[i]:
                m |= 1 << i
        return m

    def writeevent (self, evt, m):
        evt._sinks = m
        b = evt.encode ()
        # send b to destination

    def filter (self, sinktype):
        if not isinstance (sinktype, int):
            sinktype = type2id[sinktype]
        return self.filters[sinktype]
    
class EventLogger (Element):
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        if not config or not not config.logging:
            self.sinks = { (None, "console") :  LocalConsole () }
        else:
            self.sinks = dict ()
            for dest, c in config.logging.items ():
                print (c)
                sn, st = dest
                if sn:
                    # Remote sink
                    try:
                        s = self.sinks[sn]
                    except KeyError:
                        s = self.sinks[sn] = RemoteSink (c)
                    f = s.filter (st)
                else:
                    st = type2id[st]
                    sc = localsinks[st]
                    if not sc:
                        raise ValueError ("Local monitor sink not supported")
                    try:
                        s = self.sinks[dest]
                    except KeyError:
                        s = self.sinks[dest] = sc (c)
                        f = s.filter
                if c.events:
                    # TODO: parse events string and set filters
                    pass
            
    def start (self):
        pass

    def stop (self):
        pass

    def logevent (self, evt):
        for s in self.sinks.values ():
            s.logevent (evt)
            

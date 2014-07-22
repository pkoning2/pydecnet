#!

"""Event logging support for DECnet/Python

This is layered on top of the standard "logging" module, by passing along
an additional chunk of data in an Event object.  This can then be formatted
as a text log message, or sent by a new custom logging handler to a DECnet
event listener.

The Event class can also be used as an exception, and the Exception instance
can be caught and then logged, resulting in the same output as for a simple
"logevent" call.
"""

import time
import struct

from .common import Nodeid
from . import logging
from .nice import *

# Base time for time code in event message
jbase = time.mktime (time.strptime ("1977-01-01", "%Y-%m-%d"))

class Event (Exception, NiceMsg):
    """A DECnet event.  It is derived from Exception so it can be raised.
    """
    _entity_type = _label = None
    _local_node = NiceNode ()    # Should normally be set by log_event call
    _ms_valid = True
    pdict = { }
    evtids = { }
    
    def __init__ (self, entity = None, source = None, params = None, **kwds):
        """Construct an Event object.  Arguments are:
        entity: event source entity, if required.  For an event that takes
          multiple entity types, this needs to be an EventEntity object.
        source: source node for the event.  Usually omitted, will be
          set by node.logevent.
        params: a sequence of event parameters, as objects of some Param
          subclass.
        other keywords are handled as references to a Param subclass of that
          name, and the value is converted to an object of that class.
        """
        Exception.__init__ (self)
        NiceMsg.__init__ (self)
        if isinstance (entity, EventEntity):
            # entity is already an EventEntity instance
            pass
        elif self._entity_type:
            entity = self._entity_type (entity)
        elif entity is None:
            entity = NoEntity
        self._entity = entity
        if source is not None:
            self.setsource (source)
        self._timestamp = time.time ()
        self.setparams (params = params, **kwds)

    def setparams (self, params = None, **kwds):
        if params:
            for p in params:
                try:
                    name = self.pdict[p.code].__name__
                except KeyError:
                    name = "param_%d" % p.code
                setattr (self, name, p)
        for k, v in kwds.items ():
            if v is None:
                continue
            c = getattr (self.__class__, k, None)
            if c and isinstance (c, param_meta):
                try:
                    v = v.nice_val ()
                except AttributeError:
                    pass
                v = c (v)
                setattr (self, k, v)

    def setsource (self, source):
        self._local_node = source
        
    def params (self):
        # Return the parameters from the event, in ascending order of
        # parameter code
        plist = [ p for p in self.__dict__.values ()
                  if isinstance (p, Param) ]
        return sorted (plist, key = Param.key)
            
    def __str__ (self):
        n = self._local_node
        ts = self._timestamp
        ts, ms = divmod (int (ts * 1000), 1000)
        ts = time.strftime("%d-%b-%Y %H:%M:%S", time.localtime (ts))
        if self._ms_valid:
            ts = "{}.{:03d}".format (ts, ms)
        if self._label:
            l1 = "Event type {}.{}, {}".format (self._class,
                                                self._code,
                                                self._label)
        else:
            l1 = "Event type {}.{}".format (self._class, self._code)
        ret = [ l1, "  From node {}, occurred {}".format (n, ts) ]
        e = repr (self._entity)
        if e:
            ret.append ("  {}".format (e))
        for p in self.params ():
            ret.append ("  {!r}".format (p))
        return '\n'.join (ret)

    evthdr = struct.Struct ("<BBHHHHHB")

    def eventcode (self, i = None):
        """Return the event code for this event.  Call either with
        an event class or instance, or with two arguments which
        are the integer event class and event ID.
        """
        if i is None:
            return (self._class << 6) + self._code
        return (self << 6) + i

    @staticmethod
    def codesplit (evt):
        """Split event code.  Note that bits 15 and 5 are reserved
        so they are ignored.
        """
        return divmod (evt & 0x7fdf, 64)
        
    @classmethod
    def decode (cls, b):
        """Decode an event message.  Returns the resulting Event
        subclass object.
        """
        fun, sinks, evt, jhd, sec, ms, srcid, srcnlen = \
             cls.evthdr.unpack_from (b)
        if fun != 1:
            raise TypeError ("Not event message, function = %d" % fun)
        srcnam = str (b[cls.evthdr.size:cls.evthdr.size + srcnlen],
                      encoding = "latin-1", errors = "ignore")
        b = b[cls.evthdr.size + srcnlen:]
        ts = jhd * 12 * 60 * 60 + sec + jbase
        if ms & 0x8000:
            ms_valid = False
        else:
            ms_valid = True
            ts += ms / 1000.
        srcnode = NiceNode (srcid, srcnam)
        # Parse the entity field
        eid = b[0]
        ec = cls.entclass (eid)
        entity, b = ec.decode (b[1:])
        # In case it was an unknown entity
        entity._code = eid
        # Find the correct class
        c = cls.evtclass (evt)
        # Decode the event parameters data
        plist = c.decode_params (b)
        # Now create the event object
        evtclass, evtid = cls.codesplit (evt)
        e = c (entity, srcnode, params = plist)
        # Set the event identifiers in case it was an unknown class or type
        e._class = evtclass
        e._code = evtid
        e._ms_valid = ms_valid
        e._timestamp = ts
        e._sinks = sinks
        return e

    @classmethod
    def evtclass (cls, evt):
        evtclass, evtid = cls.codesplit (evt)
        c = cls.evtclasses.get (evtclass, cls)
        if c is not cls:
            c = c.evtids.get (evtid, c)
        return c

    @classmethod
    def entclass (cls, ent):
        if ent & 0x80:
            ent = 0x80
        c = cls.entclasses.get (ent, EventEntity)
        return c
    
# Event entity classes
class EventEntity (object):
    label = None
    
    def __init__ (self, val):
        assert (val)
        if not isinstance (val, str):
            val = val.name
        self.val = val

    def __str__ (self):
        return str (self.val)

    def __repr__ (self):
        label = self.label
        if not label:
            label = "Entity # {}".format (self._code)
        return "{} = {}".format (label, self)

    @classmethod
    def decode (cls, b):
        """Decode the entity encoding in b, and return a pair of
        resulting entity object and remaining data.

        The code here is the default case, for an entity encoded
        as a string.
        """
        elen = b[0]
        if elen > len (b):
            raise ValueError ("Entity image field extends beyond packet end")
        e = str (b[1:1 + elen], encoding = "latin-1", errors = "ignore")
        return cls (e), b[1 + elen:]
    
class NodeEntity (EventEntity):
    _code = 0
    label = "Node"

    def __init__ (self, val):
        self.val = val
        
    @classmethod
    def decode (cls, b):
        """Decode the entity encoding in b, and return a pair of
        resulting entity object and remaining data.
        """
        if len (b) < 3:
            raise ValueError ("Node entity extends beyond packet end")
        eid = int.from_bytes (b[:2], "little")
        elen = b[2]
        if elen > len (b) - 2:
            raise ValueError ("Entity image field extends beyond packet end")
        ename = str (b[3:3 + elen], encoding = "latin-1", errors = "ignore")
        b = b[3 + elen:]
        entity = NiceNode (eid, ename)
        e = cls (entity)
        return e, b[1 + elen:]
    
class LineEntity (EventEntity):
    _code = 1
    label = "Line"

# Code 2 is Logging, but that's not an event entity only a NICE entity.

class CircuitEntity (EventEntity):
    _code = 3
    label = "Circuit"
    
class ModuleEntity (EventEntity):
    _code = 4
    label = "Module"

class AreaEntity (EventEntity):
    _code = 5
    label = "Area"

    def __init__ (self, val):
        self.val = str (val)
        
class _NoEntity (EventEntity):
    _code = 0x80
    label = ""
    def __init__ (self, val = None): pass
    def __bool__ (self): return False
    def __str__ (self): return ""
    def __repr__ (self): return ""

    @classmethod
    def decode (cls, b):
        """Decode the entity encoding in b, and return a pair of
        resulting entity object and remaining data.
        """
        return cls (), b

# This is a singleton used for when no entity is supplied
NoEntity = _NoEntity ()

# Special formatters
def format_nodeid (self, val = None, fmt = None):
    """Special formatting for node id.  Applies only if fmt = DU-2.

    This will be set as the "format" attribute for any Param subclasses
    which have node ids in their parameter value, either as the one
    value, or as a field in a coded multiple.  Note that for the latter
    case this will only work if all fields with DU-2 format are node ids.
    """
    if fmt == DU (2):
        return str (Nodeid (val))
    return Param.format (self, val, fmt)

# Subclasses for the different layers.  Each defines the class attributes
# common (or mostly common) to that layer's events.
class NetmanEvent (Event):
    _class = 0
    
class AppEvent (Event):
    _class = 1
    
class SessionEvent (Event):
    _class = 2
    class reason (Param):
        code = 0
        fmt = C (1)
        values = { "operator_command" : 0,
                   "normal_operation" : 1}

    class old_state (Param):
        code = 1
        fmt = C (1)
        values = { "on" : 0,
                   "off" : 1,
                   "shut" : 2,
                   "restricted" : 3, }

    class new_state (old_state):
        code = 2
        
    class source_node (Param):
        code = 3
        fmt = (DU (2), AI (6))
        format = format_nodeid
        
    class source_process (Param):
        code = 4
        fmt = (DU (1), DU (2), DU (2), AI (6))
    class destination_process (source_process):
        code = 5
    class user (Param):
        code = 6
        fmt = AI (39)
    class password (Param):
        code = 7
        fmt = C (1)
        values = { "set" : 0 }
    class account (user):
        code = 8
        fmt = AI (39)

class EclEvent (Event):
    _class = 3
    class message (Param):
        code = 0
        fmt = (H (1), DU (2), DU (2), HI (6))
    class request_count (Param):
        code = 1
        fmt = DS (1)
    class source_node (Param):
        code = 2
        fmt = (DU (2), AI (6))
        format = format_nodeid
    
class RoutingEvent (Event):
    _class = 4
    _entity_type = CircuitEntity
    class packet_header (Param):
        code = 0
        fmt = (H (1), DU (2), DU (2), DU (1))
        format = format_nodeid
    class eth_packet_header (Param):
        _name = "Packet header"
        code =  0
        skip_eventdict = True
        fmt = (H (1), DU (1), DU (1), HI (6), DU (1), DU (1), HI (6),
               DU (1), DU (1), H (1), DU (1))
        send_only = True
    # Not in the spec, the next two are made up for Phase 2 headers
    class ni_packet_header (eth_packet_header):
        fmt = (H (1), H (1), DU (2), AI (6))
        format = format_nodeid
    class nv_packet_header (eth_packet_header):
        fmt = (H (1), H (1))
    class packet_beginning (Param):
        code = 1
        fmt = HI (6)
    class highest_address (Param):
        code = 2
        fmt = DU (2)
        format = format_nodeid        
    class node (Param):
        code = 3
        fmt = (DU (2), AI (6))
        format = format_nodeid
    class expected_node (node):
        code = 4
    class reason (Param):
        code = 5
        fmt = C (1)
        values = { "sync_lost" : 0,
                   "data_errors" : 1,
                   "unexpected_packet_type" : 2,
                   "checksum_error" : 3,
                   "address_change" : 4,
                   "verification_timeout" : 5,
                   "version_skew" : 6,
                   "address_out_of_range" : 7,
                   "block_size_too_small" : 8,
                   "invalid_verification" : 9,
                   "listener_timeout" : 10,
                   "listener_invalid_data" : 11,
                   "call_failed" : 12,
                   "verification_required" : 13,
                   "dropped" : 14 }
        # Override some of the default value labels
        vnames = { 0 : "Circuit synchronization lost",
                   3 : "Routing update checksum error",
                   4 : "Adjacency address change",
                   5 : "Verification receive timeout",
                   7 : "Adjacency address out of range",
                   8 : "Adjacency block size too small",
                   9 : "Invalid verification seed value",
                   10: "Adjacency listener receive timeout",
                   11: "Adjacency listener received invalid data",
                   13: "Verification password require for Phase III node",
                   14: "Dropped by adjacent node" }
        
    class received_version (Param):
        code = 6
        fmt = (DU (1), DU (1), DU (1))
    class status (Param):
        code = 7
        fmt = C (1)
        values = { "reachable" : 0,
                   "unreachable" : 1 }

    class adjacent_node (node):
        code = 8
    
class DlEvent (Event):
    _class = 5
    _entity_type = CircuitEntity

    class old_state (Param):
        code = 0
        fmt = C (1)
        values = { "halted" : 0,
                   "istrt" : 1,
                   "astrt" : 2,
                   "running" : 3,
                   "maintenance" : 4 }

    class new_state (old_state):
        code = 1

class PhyEvent (Event):
    _class = 6
    _entity_type = LineEntity
    
class PyEvent (Event):
    # DECnet/Python specific events
    _class = 320

# The actual event classes
class events_lost (NetmanEvent):
    _label = "Event records lost"
    _code = 0
    _entity_type = None
    
class node_ctrs (NetmanEvent):
    _label = "Automatic node counters"
    _code = 1
    _entity_type = NodeEntity
    
class line_ctrs (NetmanEvent):
    _label = "Automatic line counters"
    _code = 2
    _entity_type = LineEntity

class circ_svc (NetmanEvent):
    _label = "Automatic service"
    _code = 3
    _entity_type = CircuitEntity

class line_zero (NetmanEvent):
    _label = "Line counters zeroed"
    _code = 4
    _entity_type = LineEntity

class node_zero (NetmanEvent):
    _label = "Node counters zeroed",    
    _code = 5
    _entity_type = NodeEntity

class circ_loop (NetmanEvent):
    _label = "Passive loopback"
    _code = 6
    _entity_type = CircuitEntity

class circ_svcabt (NetmanEvent):
    _label = "Aborted service request"
    _code = 7
    _entity_type = CircuitEntity

class auto_ctrs (NetmanEvent):
    _label = "Automatic counters"
    _code = 8

class ctrs_zero (NetmanEvent):
    _label = "Counters zeroed"
    _code = 9

class node_state (SessionEvent):
    _label = "Local node state change"
    _code = 0
    # Reason, old state, new state

class acc_rej (SessionEvent):
    _label = "Access control reject"
    _code = 1
    # Source node, proc, dest proc, user/pw/acc

class inv_msg (EclEvent):
    _label = "Invalid message"
    _code = 0
    # Message, source node

class inv_flow (EclEvent):
    _label = "Invalid flow control"
    _code = 1
    # Message, source node

class db_reuse (EclEvent):
    _label = "Data base reused"
    _code = 2
    _entity_type = NodeEntity
    # NSP node counters

class aged_drop (RoutingEvent):
    _label = "Aged packet loss"
    _code = 0
    _entity_type = NodeEntity
    # Packet header

class unreach_drop (RoutingEvent):
    _label = "Node unreachable packet loss"
    _code = 1
    # Packet header, adjacency

class oor_drop (RoutingEvent):
    _label = "Node out-of-range packet loss"
    _code = 2
    # Packet header, adjacency

class size_drop (RoutingEvent):
    _label = "Oversized packet loss"
    _code = 3
    # Packet header, adjacency

class fmt_err (RoutingEvent):
    _label = "Packet format error"
    _code = 4
    # Packet beginning, adjacency

class rout_upd_loss (RoutingEvent):
    _label = "Partial routing update loss"
    _code = 5
    # Packet header, adjacency, highest addr

class ver_rej (RoutingEvent):
    _label = "Verification reject"
    _code = 6
    # Node

class circ_fault (RoutingEvent):
    _label = "Circuit down, circuit fault"
    _code = 7
    # Reason, adjacency

class circ_down (RoutingEvent):
    _label = "Circuit down"
    _code = 8
    # Reason, Packet header, adjacency

class circ_off (RoutingEvent):
    _label = "Circuit down, operator initiated"
    _code = 9
    # Reason, Packet header, adjacency

class circ_up (RoutingEvent):
    _label = "Circuit up"
    _code = 10
    # Adjacency

class init_fault (RoutingEvent):
    _label = "Initialization failure, line fault"
    _code = 11
    # Reason

class init_swerr (RoutingEvent):
    _label = "Initialization failure, software fault"
    _code = 12
    # Reason, Packet header

class init_oper (RoutingEvent):
    _label = "Initialization failure, operator fault"
    _code = 13
    # Reason, Packet header, received version

class reach_chg (RoutingEvent):
    _label = "Node reachability change"
    _code = 14
    _entity_type = NodeEntity
    # Status

class adj_up (RoutingEvent):
    _label = "Adjacency up"
    _code = 15
    # Adjacency

class adj_rej (RoutingEvent):
    _label = "Adjacency rejected"
    _code = 16
    # Reason, adjacency

class area_chg (RoutingEvent):
    _label = "Area reachability change"
    _code = 17
    # Status

class adj_down (RoutingEvent):
    _label = "Adjacency down"
    _code = 18
    # Reason, packet header, adjacency

class adj_oper (RoutingEvent):
    _label = "Adjacency down, operator initiated"
    _code = 19
    # Reason, packet header, adjacency

class circ_lcl (DlEvent):
    _label = "Locally initiated state change"
    _code = 0
    _entity_type = CircuitEntity

class circ_rem (DlEvent):
    _label = "Remotely initiated state change"
    _code = 1

class circ_maint (DlEvent):
    _label = "Protocol restart received in maintenance mode"
    _code = 2

class circ_xerr (DlEvent):
    _label = "Send error threshold"
    _code = 3

class circ_rerr (DlEvent):
    _label = "Receive error threshold"
    _code = 4

class circ_sel (DlEvent):
    _label = "Select error threshold"
    _code = 5

class circ_bherr (DlEvent):
    _label = "Block header format error"
    _code = 6

class circ_addr (DlEvent):
    _label = "Selection address error"
    _code = 7

class circ_trib (DlEvent):
    _label = "Streaming tributary"
    _code = 8

class circ_bufsz (DlEvent):
    _label = "Local buffer too small"
    _code = 9

class mod_restart (DlEvent):
    _label = "Restart"
    _code = 10
    _entity_type = ModuleEntity

class mod_state (DlEvent):
    _label = "State change"
    _code = 11
    _entity_type = ModuleEntity

class mod_stmax (DlEvent):
    _label = "Retransmit maximum exceeded"
    _code = 12
    _entity_type = ModuleEntity

class line_initfail (DlEvent):
    _label = "Initialization failure"
    _entity_type = LineEntity
    _code = 13

class line_xfail (DlEvent):
    _label = "Send failed"
    _code = 14
    _entity_type = LineEntity

class line_rfail (DlEvent):
    _label = "Receive failed"
    _code = 15

class line_coll (DlEvent):
    _label = "Collision detect check failed"
    _code = 16
    _entity_type = LineEntity

class mod_dteup (DlEvent):
    _label = "DTE up"
    _code = 17
    _entity_type = ModuleEntity

class mod_dtedown (DlEvent):
    _label = "DTE down"
    _code = 18
    _entity_type = ModuleEntity

class line_dsr (PhyEvent):
    _label = "Data set ready transition"
    _code = 0

class line_ring (PhyEvent):
    _label = "Ring indicator transition"
    _code = 1

class line_carr (PhyEvent):
    _label = "Unexpected carrier transition"
    _code = 2

class line_mem (PhyEvent):
    _label = "Memory access error"
    _code = 3

class line_comm (PhyEvent):
    _label = "Communications interface error"
    _code = 4

class line_perf (PhyEvent):
    _label = "Performance error"
    _code = 5

# ******************* the code below must be at the end of file

def _seteventdicts ():
    # Set the entclasses, evtclasses and evtids dictionaries.
    # Note: this has to be a function so that its working variables
    # are local.  Otherwise, iterating through globals() will fail.
    entclasses = dict ()
    evtclasses = dict ()
    evtids = dict ()
    for k, c in globals ().items ():
        if isinstance (c, nicemsg_meta):
            # It's a subclass of Event.  See what kind.
            if hasattr (c, "_code"):
                code = c._code
                # It has a code, so it's a class for a specific event
                if hasattr (c, "skip_eventdict"):
                    # If we don't want it in the dictionary, skip it
                    continue
                base = c.__base__
                try:
                    iddict = evtids[base]
                except KeyError:
                    iddict = evtids[base] = dict ()
                iddict[code] = c
            else:
                # Not a leaf class, see if it's a layer (event class) class
                try:
                    eclass = c._class
                    evtclasses[eclass] = c
                except AttributeError:
                    pass
        elif isinstance (c, type) and issubclass (c, EventEntity) \
             and c is not EventEntity:
            entclasses[c._code] = c
    Event.entclasses = entclasses
    Event.evtclasses = evtclasses
    for bc, ids in evtids.items ():
        bc.evtids = ids

# Now do it
_seteventdicts ()

# ******************* the code just above must be at the end of file

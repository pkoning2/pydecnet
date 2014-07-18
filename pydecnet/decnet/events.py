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
    _entity_type = None
    _local_node = NiceNode ()    # Should normally be set by log_event call
    _ms_valid = True

    def __init__ (self, entity = None, source = None, params = None, **kwds):
        Exception.__init__ (self)
        NiceMsg.__init__ (self)
        if self._entity_type and entity:
            self._entity = self._entity_type (entity)
        else:
            self._entity = None
        if source is not None:
            self.setsource (source)
        self._timestamp = time.time ()
        if params:
            for p in params:
                try:
                    name = self.pdict[p.code].__name__
                except KeyError:
                    name = "param_%d" % p.code
                setattr (self, name, p)
        for k, v in kwds.items ():
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
        if self.__doc__:
            l1 = "Event type {}.{}, {}".format (self._class,
                                                self._code,
                                                self.__doc__)
        else:
            l1 = "Event type {}.{}".format (self._class, self._code)
        ret = [ l1, "  From node {}, occurred {}".format (n, ts) ]
        if self._entity:
            ret.append ("  {} {}".format (self._entity_type.label,
                                          self._entity))
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
        evtclass, evtid = self.codesplit (evt)
        ts = jhd * 12 * 60 * 60 + sec + jbase
        if ms & 0x8000:
            ms_valid = False
        else:
            ms_valid = True
            ts += ms / 1000.
        srcnode = NiceNode (srcid, srcnam)
        # Parse the entity field
        eid = b[0]
        if eid & 0x80:
            # sign bit is set, so no entity
            entity = None
            b = b[1:]
        else:
            if eid == 5:
                entity = b[1]
                b = b[2:]
            elif eid:
                elen = b[1]
                entity = str (b[2:2 + elen], encoding = "latin-1",
                              errors = "ignore")
                b = b[2 + elen:]
            else:
                # entity 0 is Node
                eid = int.from_bytes (b[:2], "little")
                elen = b[2]
                ename = str (b[3:3 + elen], encoding = "latin-1",
                             errors = "ignore")
                b = b[3 + elen:]
                entity = NiceNode (eid, ename)
        # Find the correct class
        c = cls.evtclasses.get (evtclass, cls)
        if c is not cls:
            c = c.evtids.get (evtid, c)
        # Decode the event parameters data
        plist = c.decode_params (b)
        e = c (entity, srcnode, params = plist)
        e._ms_valid = ms_valid
        e._timestamp = ts
        e._sinks = sinks
        return e
    
# Event entity classes
class EventEntity (object):
    def __init__ (self, val):
        assert (val)
        self.val = val

    def __str__ (self):
        return str (self.val)

class NodeEntity (EventEntity): label = "Node"
class AreaEntity (EventEntity): label = "Area"
class CircuitEntity (EventEntity): label = "Circuit"
class LineEntity (EventEntity): label = "Line"
class ModuleEntity (EventEntity): label = "Module"

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
        code =  0
        fmt = (H (1), DU (1), DU (1), HI (6), DU (1), DU (1), HI (6),
               DU (1), DU (1), H (1), DU (1))
        send_only = True
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
    "Event records lost"
    _code = 0
    _entity_type = None
    
class node_ctrs (NetmanEvent):
    "Automatic node counters"
    _code = 1
    _entity_type = NodeEntity
    
class line_ctrs (NetmanEvent):
    "Automatic line counters"
    _code = 2
    _entity_type = LineEntity

class circ_svc (NetmanEvent):
    "Automatic service"
    _code = 3
    _entity_type = CircuitEntity

class line_zero (NetmanEvent):
    "Line counters zeroed"
    _code = 4
    _entity_type = LineEntity

class node_zero (NetmanEvent):
    "Node counters zeroed",    
    _code = 5
    _entity_type = NodeEntity

class circ_loop (NetmanEvent):
    "Passive loopback"
    _code = 6
    _entity_type = CircuitEntity

class circ_svcabt (NetmanEvent):
    "Aborted service request"
    _code = 7
    _entity_type = CircuitEntity

class auto_ctrs (NetmanEvent):
    "Automatic counters"
    _code = 8

class ctrs_zero (NetmanEvent):
    "Counters zeroed"
    _code = 9

class node_state (SessionEvent):
    "Local node state change"
    _code = 0
    # Reason, old state, new state

class acc_rej (SessionEvent):
    "Access control reject"
    _code = 1
    # Source node, proc, dest proc, user/pw/acc

class inv_msg (EclEvent):
    "Invalid message"
    _code = 0
    # Message, source node

class inv_flow (EclEvent):
    "Invalid flow control"
    _code = 1
    # Message, source node

class db_reuse (EclEvent):
    "Data base reused"
    _code = 2
    _entity_type = NodeEntity
    # NSP node counters

class aged_drop (RoutingEvent):
    "Aged packet loss"
    _code = 0
    _entity_type = NodeEntity
    # Packet header

class unreach_drop (RoutingEvent):
    "Node unreachable packet loss"
    _code = 1
    # Packet header, adjacency

class oor_drop (RoutingEvent):
    "Node out-of-range packet loss"
    _code = 2
    # Packet header, adjacency

class size_drop (RoutingEvent):
    "Oversized packet loss"
    _code = 3
    # Packet header, adjacency

class fmt_err (RoutingEvent):
    "Packet format error"
    _code = 4
    # Packet beginning, adjacency

class rout_upd_loss (RoutingEvent):
    "Partial routing update loss"
    _code = 5
    # Packet header, adjacency, highest addr

class ver_rej (RoutingEvent):
    "Verification reject"
    _code = 6
    # Node

class circ_fault (RoutingEvent):
    "Circuit down, circuit fault"
    _code = 7
    # Reason, adjacency

class circ_down (RoutingEvent):
    "Circuit down"
    _code = 8
    # Reason, Packet header, adjacency

class circ_off (RoutingEvent):
    "Circuit down, operator initiated"
    _code = 9
    # Reason, Packet header, adjacency

class circ_up (RoutingEvent):
    "Circuit up"
    _code = 10
    # Adjacency

class init_fault (RoutingEvent):
    "Initialization failure, line fault"
    _code = 11
    # Reason

class init_swerr (RoutingEvent):
    "Initialization failure, software fault"
    _code = 12
    # Reason, Packet header

class init_oper (RoutingEvent):
    "Initialization failure, operator fault"
    _code = 13
    # Reason, Packet header, received version

class reach_chg (RoutingEvent):
    "Node reachability change"
    _code = 14
    _entity_type = NodeEntity
    # Status

class adj_up (RoutingEvent):
    "Adjacency up"
    _code = 15
    # Adjacency

class adj_rej (RoutingEvent):
    "Adjacency rejected"
    _code = 16
    # Reason, adjacency

class area_chg (RoutingEvent):
    "Area reachability change"
    _code = 17
    # Status

class adj_down (RoutingEvent):
    "Adjacency down"
    _code = 18
    # Reason, packet header, adjacency

class adj_oper (RoutingEvent):
    "Adjacency down, operator initiated"
    _code = 19
    # Reason, packet header, adjacency

class circ_lcl (DlEvent):
    "Locally initiated state change"
    _code = 0
    _entity_type = CircuitEntity

class circ_rem (DlEvent):
    "Remotely initiated state change"
    _code = 1

class circ_maint (DlEvent):
    "Protocol restart received in maintenance mode"
    _code = 2

class circ_xerr (DlEvent):
    "Send error threshold"
    _code = 3

class circ_rerr (DlEvent):
    "Receive error threshold"
    _code = 4

class circ_sel (DlEvent):
    "Select error threshold"
    _code = 5

class circ_bherr (DlEvent):
    "Block header format error"
    _code = 6

class circ_addr (DlEvent):
    "Selection address error"
    _code = 7

class circ_trib (DlEvent):
    "Streaming tributary"
    _code = 8

class circ_bufsz (DlEvent):
    "Local buffer too small"
    _code = 9

class mod_restart (DlEvent):
    "Restart"
    _code = 10
    _entity_type = ModuleEntity

class mod_state (DlEvent):
    "State change"
    _code = 11
    _entity_type = ModuleEntity

class mod_stmax (DlEvent):
    "Retransmit maximum exceeded"
    _code = 12
    _entity_type = ModuleEntity

class line_initfail (DlEvent):
    "Initialization failure"
    _entity_type = LineEntity
    _code = 13

class line_xfail (DlEvent):
    "Send failed"
    _code = 14
    _entity_type = LineEntity

class line_rfail (DlEvent):
    "Receive failed"
    _code = 15

class line_coll (DlEvent):
    "Collision detect check failed"
    _code = 16
    _entity_type = LineEntity

class mod_dteup (DlEvent):
    "DTE up"
    _code = 17
    _entity_type = ModuleEntity

class mod_dtedown (DlEvent):
    "DTE down"
    _code = 18
    _entity_type = ModuleEntity

class line_dsr (PhyEvent):
    "Data set ready transition"
    _code = 0

class line_ring (PhyEvent):
    "Ring indicator transition"
    _code = 1

class line_carr (PhyEvent):
    "Unexpected carrier transition"
    _code = 2

class line_mem (PhyEvent):
    "Memory access error"
    _code = 3

class line_comm (PhyEvent):
    "Communications interface error"
    _code = 4

class line_perf (PhyEvent):
    "Performance error"
    _code = 5

# ******************* the code below must be at the end of file

def _seteventdicts ():
    # Set the eventclasses and eventids dictionaries.
    # Note: this has to be a function so that its working variables
    # are local.  Otherwise, iterating through globals() will fail.
    evtclasses = dict ()
    evtids = dict ()
    for k, c in globals ().items ():
        if isinstance (c, nicemsg_meta):
            # It's a subclass of Event.  See what kind.
            try:
                code = c._code
                # It has a code, so it's a class for a specific event
                base = c.__base__
                try:
                    iddict = evtids[base]
                except KeyError:
                    iddict = evtids[base] = dict ()
                iddict[code] = c
            except AttributeError:
                # Not a leaf class, see if it's a layer (event class) class
                try:
                    eclass = c._class
                    evtclasses[eclass] = c
                except AttributeError:
                    pass
    Event.evtclasses = evtclasses
    for bc, ids in evtids.items ():
        bc.evtids = ids

# Now do it
_seteventdicts ()

# ******************* the code just above must be at the end of file

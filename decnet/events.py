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

from . import logging

class _dummy_node (object):
    nodeid = "0.0"
    nodename = "NEMO"
    
class Event (Exception):
    """A DECnet event.  It is derived from Exception so it can be raised.
    """
    _entity_type = None
    _local_node = _dummy_node ()    # Should normally be set by log_event call
    
    def __init__ (self, entity = None, **kwds):
        Exception.__init__ (self)
        if self._entity_type and entity:
            self._entity = self._entity_type (entity)
        else:
            self._entity = None
        self._timestamp = time.time ()
        self.__dict__.update (kwds)

    def params (self):
        # Yield pairs of param name and param label text,
        # in ascending order of parameter code
        citems = [ getattr (self.__class__, cn) for cn in dir (self.__class__) ]
        plist = [ c for c in citems
                  if isinstance (c, type) and issubclass (c, EventParam) ]
        for c in sorted (plist, key = EventParam.key):
            name = c.__name__
            text = name.replace ("_", " ").capitalize ()
            yield name, text
            
    def __str__ (self):
        n = self._local_node
        ts = self._timestamp
        ts, ms = divmod (int (ts * 1000), 1000)
        ts = time.strftime("%d-%b-%Y %H:%M:%S", time.localtime (ts))
        ts = "{}.{:03d}".format (ts, ms)
        ret = [ "Event type {}.{}, {}".format (self._class,
                                               self._code,
                                               self.__doc__),
                "  From node {0.nodeid} ({0.nodename}), "
                "occurred {1}".format (n, ts) ]
        if self._entity:
            ret.append ("  {} {}".format (self._entity_type.__doc__,
                                          self._entity))
        for name, text in self.params ():
            try:
                v = self.__dict__[name]
                if isinstance (v, str):
                    v = v.replace ("_", " ")
                elif isinstance (v, tuple):
                    v = ' '.join (str (i) for i in v)
                ret.append ("  {}: {}".format (text, v))
            except KeyError:
                pass
        return '\n'.join (ret)

# Event entity classes
class EventEntity (object):
    def __init__ (self, val):
        assert (val)
        self.val = val

    def __str__ (self):
        return str (self.val)

# Event Parameter classes
class EventParam (object):
    code = None
    fmt = None
    values = None

    def __init__ (self, val):
        assert (val)
        self.val = val

    def __str__ (self):
        return str (self.val)

    @staticmethod
    def key (cls):
        return cls.code
    
class NodeEntity (EventEntity): "Node"
class AreaEntity (EventEntity): "Area"
class CircuitEntity (EventEntity): "Circuit"
class LineEntity (EventEntity): "Line"
class ModuleEntity (EventEntity): "Module"

# Subclasses for the different layers.  Each defines the class attributes
# common (or mostly common) to that layer's events.
class NetmanEvent (Event):
    _class = 0
    
class AppEvent (Event):
    _class = 1
    
class SessionEvent (Event):
    _class = 2
    class reason (EventParam):
        code = 0
        fmt = ("c-1")
        values = { "operator_command" : 0,
                   "normal_operation" : 1}

    class old_state (EventParam):
        code = 1
        fmt = ("c-1")
        values = { "on" : 0,
                   "off" : 1,
                   "shut" : 2,
                   "restricted" : 3, }

    class new_state (EventParam):
        code = 2
        fmt = ("c-1")
        #values = old_state.values
        
    class source_node (EventParam):
        code = 3
        fmt = ("cm-1/2", "du-2", "ai-6")
    class source_process (EventParam):
        code = 4
        fmt = ("cm-1/2/3/4", "du-1", "du-2", "du-2", "ai-6")
    class destination_process (EventParam):
        code = 5
        fmt = ("cm-1/2/3/4", "du-1", "du-2", "du-2", "ai-6")
    class user (EventParam):
        code = 6
        fmt = ("ai-39")
    class password (EventParam):
        code = 7
        fmt = ("c-1")
        values = { "set" : 0 }
        
    class account (EventParam):
        code = 8
        fmt = ("ai-39")

SessionEvent.new_state.values = SessionEvent.old_state.values

class EclEvent (Event):
    _class = 3
    class message (EventParam):
        code = 0
        fmt = ("cm-4", "h-1", "du-2", "du-2", "hi-6")
    class request_count (EventParam):
        code = 1
        fmt = ("ds-1")
    class source_node (EventParam):
        code = 2
        fmt = ("cm-1/2", "du-2", "ai-6")
    
class RoutingEvent (Event):
    _class = 4
    _entity_type = CircuitEntity
    class packet_header (EventParam):
        code = 0
        fmt = ("cm-2/4", "h-1", "du-2", "du-2", "du-1")
    class eth_packet_header (EventParam):
        code =  0
        fmt = ("cm-11", "h-1", "du-1", "du-1", "hi-6",
               "du-1", "du-1", "hi-6", "du-1", "du-1",
               "h-1", "du-1")
    class packet_beginning (EventParam):
        code = 1
        fmt = ("hi-6")
    class highest_address (EventParam):
        code = 2
        fmt = ("du-2")
    class node (EventParam):
        code = 3
        fmt = ("cm-1/2", "du-2", "ai-6")
    class expected_node (EventParam):
        code = 4
        fmt = ("cm-1/2", "du-2", "ai-6")
    class reason (EventParam):
        code = 5
        fmt = ("c-1")
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
        
    class received_version (EventParam):
        code = 6
        fmt = ("cm-3", "du-1", "du-1", "du-1")
    class status (EventParam):
        code = 7
        fmt = ("c-1")
        values = { "reachable" : 0,
                   "unreachable" : 1 }

    class adjacent_node (EventParam):
        code = 8
        fmt = ("cm-1/2", "du-2", "ai-6")
    
class DlEvent (Event):
    _class = 5
    _entity_type = CircuitEntity
    
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
    "Restart "
    _code = 10
    _entity_type = ModuleEntity

class mod_state (DlEvent):
    "State change "
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

#!

"""Event logging support for DECnet/Python

This is layered on top of the standard "logging" module, by passing along
an additional chunk of data in an Event object.  This can then be formatted
as a text log message, or sent by a new custom logging handler to a DECnet
event listener.
"""

import logging

class Event (object):
    """A DECnet event.
    """
    # Event class codes
    netman = 0
    application = 1
    session = 2
    ecl = 3
    routing = 4
    datalink = 5
    physical = 6
    pydecnet = 320    # DECnet/Python specific events

    # Event code for all the standard events, as a tuple of class, type
    # Comment lists arguments (for events we use -- many are listed in the
    # spec but not applicable to DECnet/Python)
    events_lost = (netman, 0)
    node_ctrs = (netman, 1)
    line_ctrs = (netman, 2)
    circ_svc = (netman, 3)
    line_zero = (netman, 4)
    node_zero = (netman, 5)
    circ_loop = (netman, 6)
    circ_svcabt = (netman, 7)
    auto_ctrs = (netman, 8)
    ctrs_zero = (netman, 9)
    node_state = (session, 0)      # Reason, old state, new state
    acc_rej = (session, 1)         # Source node, proc, dest proc, user/pw/acc
    inv_msg = (ecl, 0)             # Message, source node
    inv_flow = (ecl, 1)            # Message, source node
    db_reuse = (ecl, 2)            # NSP node counters
    aged_drop = (routing, 0)       # Packet header
    unreach_drop = (routing, 1)    # Packet header, adjacency
    oor_drop = (routing, 2)        # Packet header, adjacency
    size_drop = (routing, 3)       # Packet header, adjacency
    fmt_err = (routing, 4)         # Packet beginning, adjacency
    rout_upd_loss = (routing, 5)   # Packet header, adjacency, highest addr
    ver_rej = (routing, 6)         # Node
    circ_fault = (routing, 7)      # Reason, adjacency
    circ_down = (routing, 8)       # Reason, Packet header, adjacency
    circ_off = (routing, 9)        # Reason, Packet header, adjacency
    circ_up = (routing, 10)        # Adjacency
    init_fault = (routing, 11)     # Reason
    init_swerr = (routing, 12)     # Reason, Packet header
    init_oper = (routing, 13)      # Reason, Packet header, received version
    reach_chg = (routing, 14)      # Status
    adj_up = (routing, 15)         # Adjacency
    adj_rej = (routing, 16)        # Reason, adjacency
    area_chg = (routing, 17)       # Status
    adj_down = (routing, 18)       # Reason, packet header, adjacency
    adj_oper = (routing, 19)       # Reason, packet header, adjacency
    circ_lcl = (datalink, 0)
    circ_rem = (datalink, 1)
    circ_maint = (datalink, 2)
    circ_xerr = (datalink, 3)
    circ_rerr = (datalink, 4)
    circ_sel = (datalink, 5)
    circ_bherr = (datalink, 6)
    circ_addr = (datalink, 7)
    circ_trib = (datalink, 8)
    circ_bufsz = (datalink, 9)
    mod_restart = (datalink, 10)
    mod_state = (datalink, 11)
    mod_stmax = (datalink, 12)
    line_initfail = (datalink, 13)
    line_xfail = (datalink, 14)
    line_rfail = (datalink, 15)
    line_coll = (datalink, 16)
    mod_dteup = (datalink, 17)
    mod_dtedown = (datalink, 18)
    line_dsr = (physical, 0)
    line_ring = (physical, 1)
    line_carr = (physical, 2)
    line_mem = (physical, 3)
    line_comm = (physical, 4)
    line_perf = (physical, 5)

    # This dictionary maps event codes to the corresponding string.
    # The strings are taken from the Netman spec.
    eventnames = {
        (netman, 0) : "Event records lost",
        (netman, 1) : "Automatic node counters",
        (netman, 2) : "Automatic line counters",
        (netman, 3) : "Automatic service",
        (netman, 4) : "Line counters zeroed",
        (netman, 5) : "Node counters zeroed",
        (netman, 6) : "Passive loopback",
        (netman, 7) : "Aborted service request",
        (netman, 8) : "Automatic counters",
        (netman, 9) : "Counters zeroed",
        (session, 0) : "Local node state change",
        (session, 1) : "Access control reject",
        (ecl, 0) : "Invalid message",
        (ecl, 1) : "Invalid flow control",
        (ecl, 2) : "Data base reused",
        (routing, 0) : "Aged packet loss",
        (routing, 1) : "Node unreachable packet loss",
        (routing, 2) : "Node out-of-range packet loss",
        (routing, 3) : "Oversized packet loss",
        (routing, 4) : "Packet format error",
        (routing, 5) : "Partial routing update loss",
        (routing, 6) : "Verification reject",
        (routing, 7) : "Circuit down, circuit fault",
        (routing, 8) : "Circuit down",
        (routing, 9) : "Circuit down, operator initiated",
        (routing, 10) : "Circuit up",
        (routing, 11) : "Initialization failure, line fault",
        (routing, 12) : "Initialization failure, software fault",
        (routing, 13) : "Initialization failure, operator fault",
        (routing, 14) : "Node reachability change",
        (routing, 15) : "Adjacency up",
        (routing, 16) : "Adjacency rejected",
        (routing, 17) : "Area reachability change",
        (routing, 18) : "Adjacency down",
        (routing, 19) : "Adjacency down, operator initiated",
        (datalink, 0) : "Locally initiated state change",
        (datalink, 1) : "Remotely initiated state change",
        (datalink, 2) : "Protocol restart received in maintenance mode",
        (datalink, 3) : "Send error threshold",
        (datalink, 4) : "Receive error threshold",
        (datalink, 5) : "Select error threshold",
        (datalink, 6) : "Block header format error",
        (datalink, 7) : "Selection address error",
        (datalink, 8) : "Streaming tributary",
        (datalink, 9) : "Local buffer too small",
        (datalink, 10) : "Restart ",
        (datalink, 11) : "State change ",
        (datalink, 12) : "Retransmit maximum exceeded",
        (datalink, 13) : "Initialization failure",
        (datalink, 14) : "Send failed",
        (datalink, 15) : "Receive failed",
        (datalink, 16) : "Collision detect check failed",
        (datalink, 17) : "DTE up",
        (datalink, 18) : "DTE down",
        (physical, 0) : "Data set ready transition",
        (physical, 1) : "Ring indicator transition",
        (physical, 2) : "Unexpected carrier transition",
        (physical, 3) : "Memory access error",
        (physical, 4) : "Communications interface error",
        (physical, 5) : "Performance error",
        }
    # This dictionary defines event parameters and parameter value codes
    # for each event class.  The top level dictionary is indexed by class code.
    # Each value is the dictionary for that class.
    # The dictionary for the class lists two things: (a) the mapping from
    # attribute names to event parameter codes, and (b) the mapping from
    # attribute values to parameter value codes.  The names are all as
    # given in the Netman spec, except that they are in lower case, and spaces
    # are replaced by _ characters.  Also, really long names are trimmed.
    # For attribute names (parameters), the value is a tuple consisting
    # of the parameter type code (an integer) followed by the encoding
    # rules (strings).  For attribute values, the value is an integer.
    params = {
        session : {
            "reason" : (0, "c-1"),
            "old_state" : (1, "c-1"),
            "new_state" : (2, "c-1"),
            "source_node" : (3, "cm-1/2", "du-2", "ai-6"),
            "source_process" : (4, "cm-1/2/3/4", "du-1", "du-2", "du-2", "ai-6"),
            "destination_process" : (5, "cm-1/2/3/4", "du-1", "du-2", "du-2", "ai-6"),
            "user" : (6, "ai-39"),
            "password" : (7, "c-1"),
            "account" : (8, "ai-39"),
            "operator_command" : 0,    # Reason
            "normal_operation" : 1,
            "on" : 0,                  # Old/new state
            "off" : 1,
            "shut" : 2,
            "restricted" : 3,
            "set" : 0                  # Password
            },
        ecl : {
            "message" : (0, "cm-4", "h-1", "du-2", "du-2", "hi-6"),
            "request_count" : (1, "ds-1"),
            "source_node" : (2, "cm-1/2", "du-2", "ai-6")
            },
        routing : {
            "packet_header" : (0, "cm-2/4", "h-1", "du-2", "du-2", "du-1"),
            "eth_packet_header" : (0, "cm-11", "h-1", "du-1", "du-1", "hi-6",
                                   "du-1", "du-1", "hi-6", "du-1", "du-1",
                                   "h-1", "du-1"),
            "packet_beginning" : (1, "hi-6"),
            "highest_address" : (2, "du-2"),
            "node" : (3, "cm-1/2", "du-2", "ai-6"),
            "expected_node" : (4, "cm-1/2", "du-2", "ai-6"),
            "reason" : (5, "c-1"),
            "received_version" : (6, "cm-3", "du-1", "du-1", "du-1"),
            "status" : (7, "c-1"),
            "adjacent_node" : (8, "cm-1/2", "du-2", "ai-6"),
            "sync_lost" : 0,          # Reason
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
            "dropped" : 14,
            "reachable" : 0,          # Status
            "unreachable" : 1
            },
        }

    def __init__ (self, event, **kwds):
        self.event = event
        self.__dict__.update (kwds)

    def __str__ (self):
        ret = [ "Event type {0[0]}.{0[1]}, {1}".format (self.event,
                                                        self.eventnames[self.event]) ,
                "  On {0.id} ({0.name})".format (self.local_node) ]
        for k, v in self.__dict__.items ():
            if k != "event" and k != "local_node":
                k = k.replace ("_", " ").capitalize ()
                if isinstance (v, str):
                    v = v.replace ("_", " ")
                elif isinstance (v, tuple):
                    v = ' '.join (str (i) for i in v)
                ret.append ("  {}: {}".format (k, v))
        return '\n'.join (ret)


#!/usr/bin/env python3

"""DECnet routing point to point datalink dependent sublayer

"""

import re

from .common import *
from . import packet
from .routing_packets import *
from . import logging
from . import events
from . import adjacency
from . import datalink
from . import timers
from . import statemachine
from . import html
from . import nicepackets
from . import intercept

SvnFileRev = "$LastChangedRevision$"

class Start (Work):
    """A work item that says "start the circuit".
    """

class Stop (Work):
    """A work item that says "stop the circuit".
    """

class CircuitDown (Work):
    """A work item that says "restart the circuit because of invalid packet".
    """

# Decorator to attach a lookup table of packet class index values to a
# state machine state method.  The arguments are the packet classes to
# be accepted by this state.
#
# Note that does not result in an exact filter, because the packet
# lookup is by the packet type code (first byte).  So when several
# packet types share a first byte, any of them will be accepted, in
# general.  For example, the different PtpInit packet, because they have
# the same type code and differ in the routing version number.  Or Phase
# II init and verify.  The one exception is Routing packets (Phase III
# vs. Phase IV level 1) because these are matched by checksum, not by
# subsequent indexes in the indexed packet machinery.
def setpackets (*classes):
    index = pktindex (*classes)
    def sc (f):
        f.packetindex = index
        return f
    return sc

class PtpCircuit (statemachine.StateMachine):
    """A point to point circuit, i.e., the datalink dependent

    routing sublayer instance for a non-Ethernet type circuit.

    Arguments are "parent" (Routing instance), "name" (user visible name)
    and "datalink" (the datalink layer object for this circuit).

    The state machine implemented here matches the one in the
    Phase IV Routing layer spec (route20.txt) with minor exceptions:

    1. Circuit up/down notification to the control sublayer is
    synchronous, so the states corresponding to delivery of
    notifications are omitted.

    2. Datalinks don't fail separately, so there is no timeout on the DS
    state.  The datalink will report when it's ready to do so, and we'll
    wait however long that takes.

    3. Workarounds were added for Multinet, which isn't a real datalink
    and in the UDP case has no way to comply with the "report remote
    restart" requirement.

    Note also that this code implements not just Phase III compatibility,
    as usual, but also Phase II compatibility.  This isn't specified in
    the architecture spec, but it's obvious how to do it, it just amounts
    to applying the Phase II backward compatibility rules given in the
    Phase III routing spec.
    """
    prio = 0    # For commonality with BC circuit hello processing
    T3MULT = PTP_T3MULT
    RETRY_MAXDELAY = 128
    
    def __init__ (self, parent, name, datalink, config):
        super ().__init__ ()
        self.node = parent.node
        self.name = name
        self.maxconn = self.node.config.nsp.max_connections
        self.t3 = config.t3 or 60
        self.r_neigh ()
        self.retry_delay = 1
        self.verif = config.verify
        self.datalink = datalink.create_port (self)
        self.init_counters ()
        self.intfun, self.intreq = intercept.intflags (self.node.config)
        if self.node.phase == 2:
            self.initmsg = NodeInit (srcnode = parent.tid,
                                     nodename = parent.name,
                                     verif = self.verif,
                                     routver = tiver_ph2,
                                     commver = nspver_ph2,
                                     blksize = MTU,
                                     nspsize = MTU,
                                     maxlnks = self.maxconn,
                                     int = self.intfun,
                                     rint = self.intreq,
                                     sysver = "DECnet/Python")
        else:
            if self.node.phase == 3:
                self.initmsg = PtpInit3 (srcnode = parent.tid,
                                        ntype = parent.ntype,
                                        verif = self.verif,
                                        blksize = MTU,
                                        reserved = b'')
            else:
                self.initmsg = PtpInit (srcnode = parent.nodeid,
                                        ntype = parent.ntype,
                                        timer = self.t3,
                                        verif = self.verif,
                                        blksize = MTU,
                                        reserved = b'')

    def __str__ (self):
        return "{0.name}".format (self)

    def optnode (self, nodeid = None):
        # Return a Nodeinfo object for this node number, or for self.id
        # if not specified.  If the node number is zero, return None
        # to indicate no node parameter.
        if nodeid is None:
            nodeid = self.id
        if nodeid:
            return self.node.nodeinfo (nodeid)
        return None

    def isrustate (self):
        return self.state.nice_code is None
    
    def restart (self, event = None, msg = "(none given)",
                 entity = None, **kwargs):
        if self.isrustate ():
            # One of the RU states
            self.datalink.counters.cir_down += 1
            if self.adj:
                self.adj.down ()
        logging.trace ("{} restart due to {}", self.name, msg)
        if event:
            self.node.logevent (event, entity = entity, **kwargs)
        if self.datalink.start_works:
            # Tell the datalink to restart.  It will send a DlStatus
            # (UP) when it is running again.
            self.datalink.restart ()
        else:
            self.node.addwork (datalink.DlStatus (self, status = datalink.DlStatus.UP))
        return self.ds

    def start (self):
        self.node.addwork (Start (self))

    def stop (self):
        self.node.addwork (Stop (self))

    def dlsend (self, pkt):
        "Send a packet to the data link"
        self.lastsend = pkt
        self.datalink.send (pkt)
        
    def send (self, pkt, nexthop = None, tryhard = False):
        """Send packet. "nexthop" is not used here. Returns True
        if it worked.  "Worked" means the circuit is up and the
        neighbor is a router or the destination address matches
        the neighbor address.
        """
        # Note that the function signature must match that of
        # LanCircuit.send.
        if self.isrustate ():
            # Note: this check has to be made before dstnode is changed
            # to the older form (if needed) because internally we store
            # the neighbor ID according to our phase, not its phase.
            dstnode = pkt.dstnode
            if self.ntype == ENDNODE and dstnode != self.id:
                logging.debug ("Sending packet {} to wrong address {} "
                               "(expected {})", pkt, dstnode, self.id)
                return False
            if self.rphase == 3:
                # Neighbor is Phase 3, so we have its address as an
                # 8-bit value.  Force destination address to the old
                # form.
                dstnode = Nodeid (dstnode.tid)
                pkt.dstnode = dstnode
                # Ditto for source address, if in area
                if pkt.srcnode.area == self.routing.homearea:
                    pkt.srcnode = Nodeid (pkt.srcnode.tid)
            if self.ntype == PHASE2:
                srcnode = pkt.srcnode
                ok, pkt = self.intercept.send (pkt, self)
                if not pkt:
                    # Nothing to send
                    return True
                if ok:
                    # Packet is good to go, send it
                    if logging.tracing:
                        logging.trace ("Forwarding from {} to Phase II: {}",
                                       srcnode, pkt)
                else:
                    logging.trace ("Undeliverable Phase II packet {} from "
                                   "source {}", pkt, srcnode)
                    return False
            elif isinstance (pkt, LongData):
                pkt = ShortData (copy = pkt, payload = pkt.payload)
            self.dlsend (pkt)
            return True
        return False

    def validate (self, work):
        """Common processing.  If we're handling a packet, do the
        initial parse and construct the correct specific packet class.

        If the packet is not valid, either turn the work item into a
        datalink down notification to force a circuit down as a result,
        or return False which will simply ignore the offending packet.
        """
        if logging.tracing:
            logging.trace ("{}, work item {!r}", self.statename (), work)
        if isinstance (work, datalink.Received):
            buf = work.packet
            if not buf:
                logging.debug ("Null routing layer packet received on {}",
                               self.name)
                return False
            if isinstance (buf, packet.Packet):
                # If we already parsed this, don't do it again
                return True
            hdr = buf[0]
            if hdr & 0x80:
                # Padding.  Skip over it.  Low 7 bits are the total pad
                # length, pad header included.
                if self.rphase < 4:
                    # Padding is only valid with Phase IV, and then only
                    # for packets other than Init.
                    logging.debug ("Padding but not Phase IV on {}",
                                   self.name)
                    self.node.logevent (events.fmt_err,
                                        entity = events.CircuitEventEntity (self),
                                        adjacent_node = self.optnode (),
                                        packet_beginning = buf[:6])
                    return False
                pad = hdr & 0x7f
                if not 0 < pad < len (buf):
                    logging.debug ("Padding length 0 or > packet length on {}",
                                   self.name)
                    self.node.logevent (events.fmt_err,
                                        entity = events.CircuitEventEntity (self),
                                        adjacent_node = self.optnode (),
                                        packet_beginning = buf[:6])
                    return False
                buf = buf[pad:]
                hdr = buf[0]
                if hdr & 0x80:
                    logging.debug ("Double padded packet received on {}",
                                   self.name)
                    self.node.logevent (events.fmt_err,
                                        entity = events.CircuitEventEntity (self),
                                        adjacent_node = self.optnode (),
                                        packet_beginning = buf[:6])
                    return False
            pcls = self.state.packetindex[hdr]
            if pcls:
                try:
                    work.packet = pcls (buf)
                    return True
                except ChecksumError as e:
                    # Route packet with bad checksum, take circuit down
                    self.node.logevent (events.circ_down,
                                        entity = events.CircuitEventEntity (self),
                                        reason = "checksum_error",
                                        adjacent_node = self.optnode (),
                                        **evtpackethdr (buf, e))
                    return CircuitDown (self)
                except Exception:
                    # Anything else, keep going for further analysis
                    pass
            # Something is wrong with this packet.  Try to parse it
            # again through the routing packet base class, so if it's
            # anything valid as a routing packet we will see that.
            # We're going to reject it in any case, but the answer we
            # get here will change the details of the error reporting.
            try:
                pkt, rest = RoutingPacketBase.decode (buf)
                # It worked, see what we have
                if not self.datalink.start_works and \
                       isinstance (pkt, (NodeInit, PtpInit3, PtpInit)):
                    # Unexpected init message from the other end, on a
                    # datalink that doesn't implement remote start
                    # detection.  That most likely means the other end
                    # restarted for some reason.  If we do the normal
                    # restart sequence, we'd be expecting (another) init
                    # message, and we won't be getting one.  That
                    # eventually gets sorted out but it takes quite a
                    # while.  So for this case, as a workaround, we ask
                    # for a restart, which will set the circuit state to
                    # DS but also queue a datalink UP item because of
                    # the workaround for the missing restart mechanism.
                    # After that, we queue another work item to
                    # reprocess the message we just received.
                    #
                    # However, if the most recent message we sent was
                    # an init message, and we haven't received
                    # anything else yet, just ignore this, otherwise
                    # we may get into a cycle sending inits at each
                    # other.  Forget what we last sent, though.  If
                    # the other end retries the init, then we will
                    # reply.
                    if isinstance (self.lastsend,
                                   (NodeInit, PtpInit3, PtpInit)) and \
                       self.nrec == 0:
                        self.lastsend = None
                        # Ignore the packet, don't change the state 
                        return False
                    else:
                        self.restart (msg = "init message, using init workaround")
                        # Force the state as if datalink restart
                        # completed, and requeue the packet.
                        self.node.addwork (Received (self, packet = pkt))
                        self.state = self.ds
                        return False
                # Not an init message with Multinet workaround, so it's
                # an unexpected packet.  Take the circuit down.
                if not self.isrustate ():
                    # Not an RU state, count as init fail
                    self.datalink.counters.init_fail += 1
                self.node.logevent (events.init_swerr,
                                    entity = events.CircuitEventEntity (self),
                                    reason = "unexpected_packet_type",
                                    adjacent_node = self.optnode (),
                                    **evtpackethdr (pkt))
                return CircuitDown (self)
            except ChecksumError as e:
                # Route packet with bad checksum, take circuit down
                self.node.logevent (events.circ_down,
                                    entity = events.CircuitEventEntity (self),
                                    reason = "checksum_error",
                                    adjacent_node = self.optnode (),
                                    **evtpackethdr (buf, e))
                return CircuitDown (self)
            except packet.DecodeError:
                # If parsing the packet raises a DecodeError
                # exception, log a format error and ignore the
                # packet.
                self.node.logevent (events.fmt_err,
                                    entity = events.CircuitEventEntity (self),
                                    adjacent_node = self.optnode (),
                                    packet_beginning = buf[:6])
                return CircuitDown (self)
            logging.debug ("Unexpected {} packet from {}",
                                       pkt.__class__.__name__, self.name)
            return CircuitDown (self)
        return True

    @setcode (10)  # Synchronizing
    @setlabel ("Halted")
    @setpackets ()
    def ha (self, item):
        """Initial state: "Halted".

        We look for a Start work item, that is a request from above to
        start this circuit.  The same applies for a Timeout.
        """
        if isinstance (item, (Start, timers.Timeout)):
            logging.trace ("Starting {}", self)
            self.datalink.open ()
            self.r_neigh ()
            return self.ds

    s0 = ha    # "halted" is the initial state

    def r_neigh (self):
        # Clear neighbor state
        self.tiver = self.adj = self.loopadj = None
        self.timer = 0     # No remote hello timer value received
        self.rphase = 0    # Don't know the neighbor's phase yet
        self.ntype = UNKNOWN # Nor his type
        self.id = 0        # Nor his node address
        # Use MTU as the blocksize until we learn otherwise
        self.blksize = self.minrouterblk = MTU
        
    @setcode (10)  # Synchronizing
    @setlabel ("Datalink started")
    @setpackets ()
    def ds (self, item):
        """Datalink start state.  Wait for a point to point datalink
        startup complete notification.
        """
        self.r_neigh ()
        if isinstance (item, datalink.DlStatus):
            # Process datalink status.  The status attribute is UP or
            # DOWN.  We ignore DOWN, since we know that already, but
            # sometimes the data link will send one due to common
            # machinery.
            if item.status == item.UP:
                self.dlsend (self.initmsg)
                self.node.timers.start (self, self.t3)
                return self.ri
            return self.restart (events.init_fault,
                                 entity = events.CircuitEventEntity (self),
                                 msg = "datalink down",
                                 reason = "sync_lost")
        elif isinstance (item, CircuitDown):
            return self.restart ()
        elif isinstance (item, Stop):
            # operator "stop" command
            self.node.logevent (events.circ_off,
                                entity = events.CircuitEventEntity (self),
                                adjacent_node = self.optnode ())
            self.datalink.close ()
            return self.ha

    def setsrc (self, pkt):
        """Set our own node id as source node in the supplied packet,
        in the correct form depending on the neighbor's version.
        """
        if self.rphase == 4:
            pkt.srcnode = self.parent.nodeid
        else:
            pkt.srcnode = self.parent.tid

    def checksrc (self, src):
        """Verify the SRCNODE value in a received packet.  It must match
        the value received in the Init message.

        Returns True if ok, False if not.
        """
        if self.rphase == 4:
            expected = self.id
        else:
            expected = self.id.tid
        return src == expected
    
    @setcode (0)  # Starting
    @setlabel ("Routing init")
    # "setpackets" works by packet type code (first byte), so what we
    # have here will accept any Phase 3 or above PtpInit message, and it
    # will accept both Phase II Node Init and Node Verify.
    @setpackets (PtpInit34, NodeInit)
    def ri (self, item):
        """Routing layer initialize state.  Wait for a point to point
        init message.
        """
        if isinstance (item, timers.Timeout):
            # Process timeout
            self.datalink.counters.init_fail += 1
            return self.restart (msg = "timeout")
        elif isinstance (item, Received):
            # Process received packet
            pkt = item.packet
            if isinstance (pkt, NodeInit):
                # Phase 2 neighbor
                if pkt.srcnode == 0 or \
                       (self.parent.ntype in { L1ROUTER, L2ROUTER } and
                        pkt.srcnode > self.parent.maxnodes ):
                    logging.debug ("{} Phase II node id out of range: {}",
                                   self.name, pkt.srcnode)
                    self.datalink.counters.init_fail += 1
                    n = self.optnode (pkt.srcnode)
                    return self.restart (events.init_oper,
                                         "node id out of range",
                                         entity = events.CircuitEventEntity (self),
                                         adjacent_node = n,
                                         reason = "address_out_of_range",
                                         **evtpackethdr (pkt))
                if self.node.phase > 2:
                    # We're phase 3 or up, send a Phase II init
                    initmsg = NodeInit (srcnode = self.parent.tid,
                                        nodename = self.parent.name,
                                        verif = self.initmsg.verif,
                                        routver = tiver_ph2,
                                        commver = nspver_ph2,
                                        blksize = MTU,
                                        nspsize = MTU,
                                        maxlnks = self.maxconn,
                                        int = self.intfun,
                                        rint = self.intreq,
                                        sysver = "DECnet/Python")
                    self.dlsend (initmsg)
                self.rphase = 2
                self.hellomsg = NopMsg (payload = b'\252' * 10)
                self.ntype = PHASE2
                # Technically we only need to obey the received blocksize,
                # but since some implementations send silly values,
                # instead use its size or ours, whichever is less.
                self.blksize = self.minrouterblk = min (pkt.blksize, MTU)
                self.tiver = pkt.tiver
                # Remember if intercept was offered or requested by
                # the neighbor.
                self.int = pkt.int
                self.rint = pkt.rint
                # Routing in Phase II is by name, but in later
                # versions by number.  Since we use our local node
                # database for the mapping, things won't work if the
                # node has an unknown name.
                self.rnodename = pkt.nodename
                try:
                    self.rnode = self.node.nodeinfo (self.rnodename)
                    self.rnodeid = self.rnode.get_dest ()
                except KeyError:
                    logging.error ("Phase II node name {} is unknown",
                                   self.rnodename)
                    return self.restart (events.init_oper,
                                         "node name unknown",
                                         entity = events.CircuitEventEntity (self),
                                         adjacent_node = self.rnodename,
                                         # Not accurate but the best we have:
                                         reason = "address_out_of_range",
                                         **evtpackethdr (pkt))
                self.id = self.rnode.get_dest ()
                if self.id.tid != pkt.srcnode:
                    logging.warning ("Remote node number {} for {} does not match ours: {}",
                                   self.id.tid, self.rnodename, pkt.srcnode)
                # Create the adjacency.  Note that it is not set to "up"
                # yet, that happens on transition to RU state.
                self.adj = adjacency.Adjacency (self, self)
                # Create the appropriate intercept
                self.intercept = intercept.Intercept (self, self.node.phase,
                                                      self.intfun, self.intreq,
                                                      pkt)
                if pkt.verif:
                    # Verification requested
                    verif = self.rnode.overif
                    if not verif:
                        logging.trace ("{} verification requested but not set,"
                                       " attempting null string", self.name)
                        verif = b""
                    vpkt = NodeVerify (password = verif)
                    self.dlsend (vpkt)
                # If we requested verification, wait for that.
                if self.initmsg.verif:
                    self.verif = self.rnode.iverif
                    self.node.timers.start (self, self.t3)
                    return self.rv2
                self.up ()
                return self.ru2
            elif isinstance (pkt, (PtpInit, PtpInit3)):
                if isinstance (pkt, PtpInit):
                    # Phase 4 neighbor
                    if self.node.phase < 4:
                        # If we're phase 3 or below, ignore phase 4 init
                        logging.trace ("Ignoring phase 4 init")
                        return
                    if pkt.ntype not in { ENDNODE, L1ROUTER, L2ROUTER } \
                           or pkt.blo:
                        # Log invalid packet (bad node type or blocking)
                        self.datalink.counters.init_fail += 1
                        return self.restart (events.init_swerr,
                                             "bad ntype",
                                             entity = events.CircuitEventEntity (self),
                                             adjacent_node = self.optnode (),
                                             reason = "unexpected_packet_type",
                                             **evtpackethdr (pkt))
                    area, tid = pkt.srcnode.split ()
                    if tid == 0 or \
                           (self.parent.ntype in { L1ROUTER, L2ROUTER } and
                            tid > self.parent.maxnodes ) or \
                       (pkt.ntype == L2ROUTER and self.parent.ntype == L2ROUTER
                        and not 1 <= area <= self.parent.maxarea) or \
                        ((pkt.ntype != L2ROUTER or
                          self.parent.ntype != L2ROUTER)
                         and area != self.parent.homearea):
                        logging.debug ("{} Node address out of range: {}",
                                       self.name, pkt.srcnode)
                        self.datalink.counters.init_fail += 1
                        n = self.optnode (pkt.srcnode)
                        return self.restart (events.init_oper,
                                             "node id out of range",
                                             entity = events.CircuitEventEntity (self),
                                             adjacent_node = n,
                                             reason = "address_out_of_range")
                    self.rphase = 4
                    self.timer = pkt.timer
                    self.hellomsg = PtpHello (srcnode = self.parent.nodeid,
                                              testdata = b'\252' * 10)
                    self.id = pkt.srcnode
                else:
                    # Phase 3
                    if self.node.phase < 3:
                        # If we're phase 2, ignore phase 3 init
                        logging.trace ("Ignoring phase3 init")
                        return
                    if pkt.ntype not in { ENDNODE, L1ROUTER }:
                        # Log invalid packet (bad node type)
                        self.datalink.counters.init_fail += 1
                        return self.restart (events.init_swerr,
                                             "bad ntype for phase 3",
                                             entity = events.CircuitEventEntity (self),
                                             adjacent_node = self.optnode (),
                                             reason = "unexpected_packet_type",
                                             **evtpackethdr (pkt))
                    if pkt.srcnode == 0 or \
                           (self.parent.ntype in { L1ROUTER, L2ROUTER } and
                            pkt.srcnode > self.parent.maxnodes ):
                        logging.debug ("{} Phase III node id out of range: {}",
                                       self.name, pkt.srcnode)
                        self.datalink.counters.init_fail += 1
                        n = self.optnode (pkt.srcnode)
                        return self.restart (events.init_oper,
                                             "node id out of range",
                                             entity = events.CircuitEventEntity (self),
                                             adjacent_node = n,
                                             reason = "address_out_of_range")
                    if pkt.ntype == L1ROUTER and \
                       self.parent.ntype in { L1ROUTER, L2ROUTER } and \
                       pkt.blksize < self.parent.maxnodes * 2 + 6:
                        self.datalink.counters.init_fail += 1
                        logging.debug ("{} Phase III node block size {} too small for --maxnodes {}", self.name, pkt.blksize, self.parent.maxnodes)
                        logging.debug ("   block size allows max nodes up to {}", (self.blksize - 6) // 2)
                        n = self.optnode (pkt.srcnode)
                        return self.restart (events.init_oper,
                                             "node id out of range",
                                             entity = events.CircuitEventEntity (self),
                                             adjacent_node = n,
                                             reason = "address_out_of_range")
                    self.rphase = 3
                    self.hellomsg = PtpHello (srcnode = self.parent.tid,
                                              testdata = b'\252' * 10)
                    if self.node.phase > 3:
                        # We're phase 4 and neighbor is Phase 3,
                        # send it a Phase 3 init.  (If we're phase 3, we
                        # already sent that init.)
                        ntype = self.parent.ntype
                        if ntype == L2ROUTER:
                            ntype = L1ROUTER
                        initmsg = PtpInit3 (srcnode = self.parent.tid,
                                            ntype = ntype,
                                            verif = self.initmsg.verif,
                                            blksize = MTU)
                        self.dlsend (initmsg)
                    if self.node.phase == 4:
                        self.id = Nodeid (self.parent.homearea,
                                              pkt.srcnode.tid)
                    else:
                        self.id = Nodeid (pkt.srcnode.tid)
                self.ntype = pkt.ntype
                # Technically we only need to obey the received blocksize,
                # but since some implementations send silly values,
                # instead use its size or ours, whichever is less.
                self.blksize = self.minrouterblk = min (pkt.blksize, MTU)
                self.tiver = pkt.tiver
                if pkt.verif:
                    # Verification requested
                    verif = self.node.nodeinfo (self.id).overif
                    if not verif:
                        logging.trace ("{} verification requested but not set,"
                                       " attempting null string", self.name)
                        verif = b""
                    vpkt = PtpVerify (fcnval = verif)
                    self.setsrc (vpkt)
                    self.dlsend (vpkt)
                # Create the adjacency.  Note that it is not set to "up"
                # yet, that happens on transition to RU state.
                self.adj = adjacency.Adjacency (self, self)
                # If we requested verification, wait for that.
                if self.initmsg.verif:
                    self.verif = self.node.nodeinfo (self.id).iverif
                    self.node.timers.start (self, self.t3)
                    return self.rv
                self.up ()
                return self.rustate ()
            elif isinstance (pkt, NodeVerify):
                # Unexpected packet
                self.datalink.counters.init_fail += 1
                return self.restart (events.init_swerr,
                                     entity = events.CircuitEventEntity (self),
                                     reason = "unexpected_packet_type",
                                     adjacent_node = self.optnode (),
                                    **evtpackethdr (pkt))
        elif isinstance (item, datalink.DlStatus) and item.status == item.DOWN:
            # Process datalink status Down.  Restart the datalink.
            self.datalink.counters.init_fail += 1
            return self.restart (events.init_fault,
                                 "datalink status",
                                 entity = events.CircuitEventEntity (self),
                                 adjacent_node = self.optnode (),
                                 reason = "sync_lost")
        elif isinstance (item, CircuitDown):
            return self.restart ()
        elif isinstance (item, Stop):
            # operator "stop" command
            self.node.logevent (events.circ_off,
                                entity = events.CircuitEventEntity (self),
                                adjacent_node = self.optnode ())
            self.datalink.close ()
            return self.ha
    
    @setcode (0)  # Starting
    @setlabel ("Routing verify")
    @setpackets (PtpVerify)
    def rv (self, item):
        """Waiting for Verification message.
        """
        if isinstance (item, Received):
            # Process received packet
            pkt = item.packet
            if not self.checksrc (pkt.srcnode):
                logging.debug ("{} packet from wrong node {}",
                               self.name, pkt.srcnode)
                self.datalink.counters.init_fail += 1
                return self.restart (events.adj_down, 
                                     "adjacency down",
                                     entity = events.CircuitEventEntity (self),
                                     adjacent_node = self.optnode (),
                                     reason = "address_out_of_range")
            if pkt.fcnval != self.verif:
                logging.debug ("{} verification value mismatch",
                               self.name)
                self.datalink.counters.init_fail += 1
                self.routing.nodeinfo.counters.ver_rejects += 1
                return self.restart (events.ver_rej, 
                                     "verification reject",
                                     entity = events.CircuitEventEntity (self),
                                     adjacent_node = self.optnode (),
                                     reason = "invalid_verification")
            self.up ()
            return self.rustate ()
        else:
            return self.rvcommon (item)

    @setcode (0)  # Starting
    @setlabel ("Routing verify")
    @setpackets (NodeVerify)
    def rv2 (self, item):
        # Routing verification, Phase II case
        if isinstance (item, Received):
            verif = (self.verif + bytes (7))[:8]
            pkt = item.packet
            if pkt.password != verif:
                logging.debug ("{} verification value mismatch",
                               self.name)
                self.datalink.counters.init_fail += 1
                self.routing.nodeinfo.counters.ver_rejects += 1
                return self.restart (events.ver_rej,
                                     "verification reject",
                                     entity = events.CircuitEventEntity (self),
                                     adjacent_node = self.optnode (),
                                     reason = "invalid_verification")
            self.up ()
            return self.ru2
        else:
            return self.rvcommon (item)
        
    def rvcommon (self, item):
        if isinstance (item, timers.Timeout):
            # Process timeout
            self.datalink.counters.init_fail += 1
            return self.restart (events.init_fault, 
                                 "verification timeout",
                                 entity = events.CircuitEventEntity (self),
                                 adjacent_node = self.optnode (),
                                 reason = "verification_timeout")
        elif isinstance (item, datalink.DlStatus) and item.status == item.DOWN:
            # Process datalink status Down.  Restart the datalink.
            self.datalink.counters.init_fail += 1
            return self.restart (events.init_fault,
                                 "datalink status",
                                 entity = events.CircuitEventEntity (self),
                                 adjacent_node = self.optnode (),
                                 reason = "sync_lost")
        elif isinstance (item, CircuitDown):
            return self.restart ()
        elif isinstance (item, Stop):
            # operator "stop" command
            self.node.logevent (events.circ_off,
                                entity = events.CircuitEventEntity (self),
                                adjacent_node = self.optnode ())
            self.datalink.close ()
            return self.ha

    @setcode (None)    # Running (no substate)
    @setlabel ("Running")
    @setpackets (ShortData, LongData, PtpHello, L1Routing, L2Routing)
    def ru4l2 (self, item):
        return self.ru (item)
    
    @setcode (None)    # Running (no substate)
    @setlabel ("Running")
    @setpackets (ShortData, LongData, PtpHello)
    def ru4e (self, item):
        # Phase 4 endnode
        return self.ru (item)
    
    @setcode (None)    # Running (no substate)
    @setlabel ("Running")
    @setpackets (ShortData, PtpHello)
    def ru3e (self, item):
        # Phase 3 endnode
        return self.ru (item)
    
    @setcode (None)    # Running (no substate)
    @setlabel ("Running")
    @setpackets (ShortData, PtpHello, PhaseIIIRouting)
    def ru3r (self, item):
        # Phase 3 router
        return self.ru (item)
    
    @setcode (None)    # Running (no substate)
    @setlabel ("Running")
    @setpackets (ShortData, LongData, PtpHello, L1Routing)
    def ru4l1 (self, item):
        # Phase 4 level 1 router
        return self.ru (item)
    
    @setcode (None)    # Running (no substate)
    @setlabel ("Running")
    @setpackets (ShortData, LongData, PtpHello, L1Routing, L2Routing)
    def ru4l2 (self, item):
        # Phase 4 area router
        return self.ru (item)

    def rustate (self):
        # Return the correct ruxxx state given the adjacency we just
        # brought up.
        if self.rphase == 4:
            if self.parent.ntype == L2ROUTER:
                if self.ntype == L2ROUTER:
                    return self.ru4l2
                if self.ntype == L1ROUTER:
                    return self.ru4l1
                return self.ru4e
            if self.parent.ntype == L1ROUTER and \
               self.ntype in (L1ROUTER, L2ROUTER):
                return self.ru4l1
            return self.ru4e
        else:    # Phase 3
            if self.parent.ntype in (L1ROUTER, L2ROUTER) \
               and self.ntype == L1ROUTER:
                return self.ru3r
        return self.ru3e
        
    def ru (self, item):
        """Running state.  The circuit is up at the routing control layer.
        """
        if isinstance (item, Received):
            self.nrec += 1
            # Process received packet.  Restart the listen timer.
            self.adj.alive ()
            pkt = item.packet
            # Check source address if it's a control packet.
            if isinstance (pkt, CtlHdr):
                if not self.checksrc (pkt.srcnode):
                    logging.debug ("{} packet from wrong node {}",
                                   self.name, pkt.srcnode)
                    return self.restart (events.adj_down, 
                                         "adjacency down",
                                         entity = events.CircuitEventEntity (self),
                                         adjacent_node = self.optnode (),
                                         reason = "address_out_of_range")
                if isinstance (pkt, PtpHello):
                    if testdata_re.match (pkt.testdata):
                        # Good hello, nothing else to do
                        return
                    return self.restart (events.circ_down,
                                         "invalid test data",
                                         entity = events.CircuitEventEntity (self),
                                         adjacent_node = self.optnode (),
                                         reason = "listener_invalid_data",
                                         **evtpackethdr (pkt))
            if logging.tracing:
                logging.trace ("{} data packet to routing: {}",
                               self.name, pkt)
            # Note that just the packet is dispatched, not the work
            # item we received that wraps it.
            if self.rphase < 4 and self.node.phase == 4:
                # Running phase 4 but neighbor is older, supply
                # our area number into source and destination addresses,
                # but only if they are not already set (see DNA Routing
                # spec for why).
                if isinstance (pkt, (ShortData, LongData)):
                    if pkt.srcnode.area == 0:
                        pkt.srcnode = Nodeid (self.parent.homearea,
                                              pkt.srcnode.tid)
                    if pkt.dstnode.area == 0:
                        pkt.dstnode = Nodeid (self.parent.homearea,
                                              pkt.dstnode.tid)
            pkt.src = self.adj
            self.parent.dispatch (pkt)
        else:
            return self.rucommon (item)

    @setcode (None)    # Running (no substate)
    @setlabel ("Running")
    @setpackets (P2BareNSP, RouteHdr, NopMsg)
    def ru2 (self, item):
        """Running state, for Phase II adjacency.  The circuit is up at
        the routing control layer.
        """
        if isinstance (item, Received):
            self.nrec += 1
            # Process received packet from Phase II node.  Let
            # intercept check it.
            pkt = item.packet
            if isinstance (pkt, NopMsg):
                # NOP message, ignore 
                return
            logging.trace ("Packet from Phase 2 node: {}", pkt)
            ok, pkt = self.intercept.recv (pkt, self)
            logging.trace ("Packet after intercept: {} {}", ok, pkt)
            if not ok:
                if pkt:
                    self.dlsend (pkt)
                return
            pkt.src = self.adj
            if logging.tracing:
                logging.trace ("Phase II data packet to routing: {}",
                               pkt)
            self.parent.dispatch (pkt)
        else:
            return self.rucommon (item)

    def rucommon (self, item):
        # Common code for ru and ru2 states
        if isinstance (item, timers.Timeout):
            # Process hello timer expiration
            self.sendhello ()
            return
        elif isinstance (item, datalink.DlStatus) and item.status == item.DOWN:
            # Process datalink status Down.  Restart the datalink.
            return self.restart (events.circ_fault,
                                 "datalink status",
                                 entity = events.CircuitEventEntity (self),
                                 adjacent_node = self.optnode (),
                                 reason = "sync_lost")
        elif isinstance (item, CircuitDown):
            return self.restart ()
        elif isinstance (item, Stop):
            # operator "stop" command
            self.node.logevent (events.circ_off,
                                entity = events.CircuitEventEntity (self),
                                adjacent_node = self.optnode ())
            self.down ()
            self.datalink.close ()
            return self.ha

    def sendhello (self):
        """Handler to send periodic hello messages.
        """
        if self.isrustate ():
            self.dlsend (self.hellomsg)
            self.node.timers.start (self, self.t3)

    def up (self):
        """We're done initializing with the neighbor.  Set the adjacency
        to "up", and start the hello timer.
        """
        self.adj.up ()
        if self.id == self.node.nodeid or \
           self.ntype in { L1ROUTER, L2ROUTER }:
            self.loopadj = self.adj
        self.nrec = 0
        self.datalink.counters.last_up = Timestamp ()
        self.node.logevent (events.circ_up, events.CircuitEventEntity (self),
                            adjacent_node = self.optnode ())
        self.node.timers.start (self, self.t3)

    def down (self):
        """Take the adjacency down. 
        """
        if self.adj:
            self.adj.down ()
        self.adj = self.loopadj = None

    def adj_timeout (self, adj):
        """Take the adjacency down and restart the circuit.  This is
        called by adjacency listen timeout.
        """
        self.adj = self.loopadj = None
        self.restart (events.circ_down,
                      "timeout",
                      entity = events.CircuitEventEntity (self),
                      adjacent_node = self.optnode (),
                      reason = "listener_timeout")
        self.set_state (self.ds)
        
    @staticmethod
    def html_header ():
        return ( "Name", "Cost", "Neighbor", "Type",
                 "Hello time", "Block size", "Listen time",
                 "Version", "State" )

    def html_row (self):
        if self.isrustate ():
            neighbor = str (self.optnode ())
            ntype = ntypestrings[self.ntype]
            if self.rphase == 3:
                if self.ntype == ENDNODE:
                    ntype = "Phase 3 endnode"
                else:
                    ntype = "Phase 3 router"
        else:
            neighbor = ntype = "-"
        if self.adj:
            t4 = self.adj.t4
        else:
            t4 = "-"
        return [ self.name, self.cost, neighbor, ntype,
                 self.t3, self.blksize, t4, self.tiver,
                 self.state.label ]

    def nice_read (self, req, resp, qual = None):
        if isinstance (req, nicepackets.NiceReadNode) and \
           req.sumstat () and not req.loop ():
            if self.isrustate ():
                neighbor = self.optnode ()
                if req.one () and neighbor != req.entity.value:
                    # Specific node that's not on this circuit
                    # FIXME: this check is not working right
                    return
                r = resp[neighbor]
                r.adj_circuit = str (self)
                if req.stat ():
                    # status
                    if self.rphase == 4:
                        r.adj_type = self.ntype + 2
                    elif self.rphase == 3:
                        r.adj_type = 1 if self.ntype == ENDNODE else 0
                    else:
                        r.adj_type = 2
                else:
                    r.next_node = neighbor
        elif isinstance (req, (nicepackets.NiceReadCircuit,
                               nicepackets.P2NiceReadLineStatus)):
            if qual:
                if r.substate is not None or \
                   self.optnode () != qual:
                    return
            r = resp[str (self)]
            if req.sumstat ():
                # summary or status
                r.state = 0   # on
                r.substate = self.state.nice_code
                if r.substate is None:
                    # Running, we have more info
                    if isinstance (req, nicepackets.P2NiceReadLineStatus):
                        r.adjacent_node = self.optnode ().nodename
                    else:
                        r.adjacent_node = self.optnode ()
                    if req.stat ():
                        # status
                        r.block_size = self.blksize
                if self.loop_node is not None:
                    r.loopback_name = self.loop_node.nodename
                if isinstance (req, nicepackets.P2NiceReadLineStatus):
                    r.entity = self.p2id
            elif req.char ():
                r.cost = self.cost
                r.hello_timer = self.t3
                if self.isrustate ():
                    # Running, fill in listen timer.  Yes, that's a
                    # characteristic even though it's state learned
                    # from the neighbor.  In Phase 3 it was a local
                    # setting, that's probably why.
                    r.listen_timer = self.adj.t4
            self.datalink.nice_read_port (req, r)
            
    def get_api (self):
        ret = { "name" : self.name,
                "state" : self.state.__name__,
                "hello_timer" : self.t3,
                "cost" : self.cost }
        if self.isrustate ():
            ntype = ntypestrings[self.ntype]
            if self.rphase == 3:
                if self.ntype == ENDNODE:
                    ntype = "Phase 3 endnode"
                else:
                    ntype = "Phase 3 router"
            ret.update ({ "neighbor" : self.id,
                          "type" : ntype,
                          "blocksize" : self.blksize,
                          "version" : self.tiver })
        if self.adj:
            ret["listen_timer"] = self.adj.t4
        return ret

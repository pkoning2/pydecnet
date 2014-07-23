#!/usr/bin/env python3

"""DECnet routing point to point datalink dependent sublayer

"""

import re

from .common import *
from . import packet
from .routing_packets import *
from . import events
from . import adjacency
from . import datalink
from . import timers
from . import statemachine

class Start (Work):
    """A work item that says "start the circuit".
    """

class CircuitDown (Work):
    """A work item that says "restart the circuit because of invalid packet".
    """
    
class PtpCircuit (statemachine.StateMachine):
    """A point to point circuit, i.e., the datalink dependent
    routing sublayer instance for a non-Ethernet type circuit.

    Arguments are "parent" (Routing instance), "name" (user visible name)
    and "datalink" (the datalink layer object for this circuit).

    The state machine implemented here matches the one in the
    Phase IV Routing layer spec (route20.txt), except that circuit
    up/down notification to the control sublayer is synchronous, so
    the states corresponding to delivery of notifications are omitted.

    Note also that this code implements not just Phase III compatibility,
    as usual, but also Phase II compatibility.  This isn't specified in
    the architecture spec, but it's obvious how to do it, it just amounts
    to applying the Phase II backward compatibility rules given in the
    Phase III routing spec.
    """
    prio = 0    # For commonality with BC circuit hello processing
    T3MULT = PTP_T3MULT
    pkttype = ShortData
    
    def __init__ (self, parent, name, datalink, config):
        super ().__init__ ()
        self.node = parent.node
        self.name = name
        self.t3 = config.t3 or 60
        self.timer = 0
        self.tiver = self.adj = None
        self.blksize = self.id = 0
        self.verif = config.verify
        self.datalink = datalink.create_port (self)
        if self.node.phase == 2:
            self.initmsg = NodeInit (srcnode = parent.tid,
                                     nodename = parent.name,
                                     verif = self.verif,
                                     routver = tiver_ph2,
                                     commver = nspver_ph2,
                                     blksize = MTU, nspsize = MTU,
                                     sysver = "DECnet/Python")
        else:
            if self.node.phase == 3:
                self.initmsg = PtpInit3 (srcnode = parent.tid,
                                        ntype = parent.ntype,
                                        tiver = parent.tiver,
                                        verif = self.verif,
                                        blksize = MTU,
                                        reserved = b'')
            else:
                self.initmsg = PtpInit (srcnode = parent.nodeid,
                                        ntype = parent.ntype,
                                        timer = self.t3,
                                        tiver = parent.tiver,
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
        
    def restart (self, event = None, msg = None, **kwargs):
        if self.state == self.ru:
            self.cir_down += 1
            if self.adj:
                self.adj.down ()
        if msg:
            logging.trace ("%s restart due to %s", self.name, msg)
        if event:
            self.node.logevent (event, entity = self, **kwargs)
        self.datalink.close ()
        self.state = self.ha
        self.start ()
        return self.ha

    def start (self):
        # Put in some dummy values until we hear from the neighbor
        self.ntype = ENDNODE
        self.id = 0
        self.node.addwork (Start (self))

    def stop (self):
        self.node.addwork (Shutdown (self))

    def send (self, pkt, dstnode, tryhard = False):
        """Send packet to the specified destination.  Returns True
        if it worked.  "Worked" means the circuit is up and the
        neighbor is a router or the destination address matches
        the neighbor address.
        """
        # Note that the function signature must match that of
        # LanCircuit.send.
        if self.state == self.ru:
            # Note: this check has to be made before dstnode is changed
            # to the older form (if needed) because internally we store
            # the neighbor ID according to our phase, not its phase.
            if self.ntype in (ENDNODE, PHASE2) and dstnode != self.id:
                logging.debug ("Sending packet %s to wrong address %s "
                               "(expected %s)", pkt, dstnode, self.id)
                return False
            if self.rphase < 4:
                # Neighbor is Phase 3 or older, so we have its address
                # as an 8-bit value.  Force destination address to
                # the old form.
                dstnode = Nodeid (dstnode.tid)
                pkt.dstnode = dstnode
                # Ditto for source address, if in area
                if pkt.srcnode.area == self.routing.homearea:
                    pkt.srcnode = Nodeid (pkt.srcnode.tid)
            if self.ntype == PHASE2:
                pkt = pkt.payload
            elif isinstance (pkt, LongData):
                pkt = ShortData (copy = pkt, payload = pkt.payload)
            self.datalink.send (pkt)
            return True
        return False

    def validate (self, work):
        """Common processing.  If we're handling a packet, do the
        initial parse and construct the correct specific packet class.
        If the packet is not valid, turn the work item into a datalink
        down notification, which will produce the right outcome.
        """
        logging.trace ("Ptp circuit %s, work item %r", self.name, work)
        if isinstance (work, datalink.Received):
            buf = work.packet
            if not buf:
                logging.debug ("Null routing layer packet received on %s",
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
                    logging.debug ("Padding but not Phase IV on %s",
                                   self.name)
                    self.node.logevent (events.fmt_err, entity = self,
                                        packet_beginning = buf[:6])
                    return False
                pad = hdr & 0x7f
                if pad >= len (buf):
                    logging.debug ("Padding exceeds packet length on %s",
                                   self.name)
                    self.node.logevent (events.fmt_err, entity = self,
                                        packet_beginning = buf[:6])
                    return False
                buf = buf[hdr & 0x7f:]
                hdr = buf[0]
                if hdr & 0x80:
                    logging.debug ("Double padded packet received on %s",
                                   self.name)
                    self.node.logevent (events.fmt_err, entity = self,
                                        packet_beginning = buf[:6])
                    return False
            p2route = None
            if (hdr & 0xf3) == 0x42:
                # Phase 2 routing header
                try:
                    p2route = RouteHdr (buf)
                except packet.DecodeError:
                    # If parsing the packet raises a DecodeError
                    # exception, log a format error
                    self.node.logevent (events.fmt_err, entity = self,
                                        packet_beginning = buf[:6])
                    return False
                buf = p2route.payload
                hdr = buf[0]
                if hdr & 0x83:
                    # Invalid bits set, complain
                    logging.debug ("Invalid msgflgs after Ph2 route hdr: %x",
                                   hdr)
                    self.node.logevent (events.fmt_err, entity = self,
                                        packet_beginning = buf[:6])
                    return False
                logging.trace ("Phase II packet with route header: %s", p2route)
            if (hdr & 1) != 0 and self.node.phase > 2:
                # Routing (phase 3 or 4) control packet.  Figure out which one
                code = (hdr >> 1) & 7
                if code:
                    # Not init
                    try:
                        work.packet = ptpcontrolpackets[code] (buf, src = None)
                    except KeyError:
                        logging.debug ("Unknown routing control packet %d from %s",
                                       code, self.name)
                        return CircuitDown (self)
                    except ChecksumError as e:
                        # Route packet with bad checksum, take circuit down
                        self.node.logevent (events.circ_down, entity = self,
                                            reason = "checksum_error",
                                            **evtpackethdr (buf, e))
                        return CircuitDown (self)
                    except packet.DecodeError as e:
                        # If parsing the packet raises a DecodeError
                        # exception, log a format error event
                        self.node.logevent (events.fmt_err, entity = self,
                                            packet_beginning = buf[:6])
                        return False
                else:
                    # Init message type depends on major version number.
                    if len (buf) < 7:
                        logging.debug ("Init message is too short: %d",
                                       len (buf))
                        self.node.logevent (events.fmt_err, entity = self,
                                            packet_beginning = buf[:6])
                        return False
                    mver = buf[6]
                    if mver == tiver_ph3[0]:
                        # Phase 3
                        phase = 3
                        try:
                            work.packet = PtpInit3 (buf)
                        except InvalidAddress as e:
                            nodeargs = (e.args[0],)
                            self.node.logevent (events.init_oper,
                                                entity = self,
                                                adjacent_node = nodeargs,
                                                reason = "address_out_of_range",
                                                **evtpackethdr (buf))
                            return CircuitDown (self)
                        except packet.DecodeError:
                            self.node.logevent (events.fmt_err, entity = self,
                                                packet_beginning = buf[:6])
                            return False
                    elif mver == tiver_ph4[0]:
                        phase = 4
                        try:
                            work.packet = PtpInit (buf)
                        except packet.DecodeError:
                            self.node.logevent (events.fmt_err, entity = self,
                                                packet_beginning = buf[:6])
                            return False
                    elif mver < tiver_ph3[0]:
                        logging.debug ("Unknown routing version %d", mver)
                        self.node.logevent (events.init_oper, entity = self,
                                            reason = "version_skew",
                                            **evtpackethdr (buf))
                        return CircuitDown (self)
                    else:
                        logging.trace ("Ignoring high version init %d", mver)
                        return False    # Too high, ignore it
                    if phase > self.node.phase:
                        logging.trace ("Ignoring init higher than our phase")
                        return False
            else:
                code = hdr & 7
                if self.node.phase > 3 and code == 6:
                    # Long data is not expected, but it is accepted
                    # just for grins (and because the phase 4 spec allows it).
                    try:
                        work.packet = LongData (buf, src = None)
                    except packet.DecodeError:
                        self.node.logevent (events.fmt_err, entity = self,
                                            packet_beginning = buf[:6])
                        return False
                elif self.node.phase > 2 and code == 2:
                    try:
                        work.packet = ShortData (buf, src = None)
                    except packet.DecodeError:
                        self.node.logevent (events.fmt_err, entity = self,
                                            packet_beginning = buf[:6])
                        return False
                elif (code & 3) == 0:
                    # Phase 2 packet.  Figure out what exactly.
                    if (hdr & 0x0f) == 8:
                        # Control packet
                        if hdr == 0x58:
                            # Node init or node verification
                            if len (buf) > 2:
                                code = buf[1]
                            else:
                                code = 0
                            if code == 1:
                                try:
                                    work.packet = NodeInit (buf)
                                except InvalidAddress as e:
                                    nargs = (e.args[0],)
                                    self.node.logevent (events.init_oper,
                                                        entity = self,
                                                        adjacent_node = nargs,
                                                        reason = "address_out"
                                                        "_of_range",
                                                        packet_beginning =
                                                        buf[:6])
                                    return CircuitDown (self)
                                except packet.DecodeError:
                                    self.node.logevent (events.fmt_err,
                                                        entity = self,
                                                        packet_beginning =
                                                        buf[:6])
                                    return False
                            elif code == 2:
                                try:
                                    work.packet = NodeVerify (buf)
                                except packet.DecodeError:
                                    self.node.logevent (events.fmt_err,
                                                        entity = self,
                                                        packet_beginning =
                                                        buf[:6])
                                    return False
                            else:
                                self.node.logevent (events.init_swerr,
                                                    entity = self,
                                                    packet_beginning =
                                                    buf[:6])
                                logging.debug ("Unknown Phase 2 control packet"
                                               " %x from %s",
                                               code, self.name)
                                return CircuitDown (self)
                    else:
                        # Phase 2 data packet, don't set a specific packet
                        # type, it will be handled in NSP
                        return True
                else:
                    logging.debug ("Unknown routing packet %d from %s",
                                   code, self.name)
                    if code == 1:
                        # Phase 3/4 init message on phase 2 node, ignore
                        return False
                    self.node.logevent (events.init_swerr, entity = self,
                                        reason = "unexpected_packet_type",
                                        **evtpackethdr (buf))
                    return CircuitDown (self)
        return True
                
    def ha (self, item):
        """Initial state: "Halted".
        """
        if isinstance (item, Start):
            self.datalink.open ()
            self.tiver = self.adj = None
            self.timer = 0     # No remote hello timer value received
            self.rphase = 0    # Don't know the neighbor's phase yet
            self.node.timers.start (self, self.t3)
            return self.ds

    s0 = ha    # "halted" is the initial state
    
    def ds (self, item):
        """Datalink start state.  Wait for a point to point datalink
        startup complete notification.
        """
        if isinstance (item, timers.Timeout):
            # Process timeout -- restart the datalink (no event)
            return self.restart (msg = "timeout")
        elif isinstance (item, datalink.DlStatus):
            # Process datalink status.  The status attribute is True
            # for up, False for down.
            if item.status:
                self.datalink.send (self.initmsg)
                self.node.timers.start (self, self.t3)
                return self.ri
            return self.restart (events.init_fault, msg = "datalink down",
                                 reason = "sync_lost")
        elif isinstance (item, CircuitDown):
            return self.restart ()
        elif isinstance (item, Shutdown):
            # operator "stop" command
            self.node.logevent (events.circ_off, self,
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

    def ri (self, item):
        """Routing layer initialize state.  Wait for a point to point
        init message.
        """
        if isinstance (item, timers.Timeout):
            # Process timeout
            self.init_fail += 1
            return self.restart (msg = "timeout")
        elif isinstance (item, Received):
            # Process received packet
            pkt = item.packet
            if isinstance (pkt, NodeInit):
                # Phase 2 neighbor
                if pkt.srcnode == 0 or \
                       (self.parent.ntype in { L1ROUTER, L2ROUTER } and
                        pkt.srcnode > self.parent.maxnodes ):
                    logging.debug ("%s Phase II node id out of range: %d",
                                   self.name, pkt.srcnode)
                    self.init_fail += 1
                    nodeargs = (pkt.srcnode,)
                    return self.restart (events.init_oper,
                                         "node id out of range",
                                         adjacent_node = nodeargs,
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
                                        sysver = "DECnet/Python")
                    self.initmsg = initmsg
                    self.datalink.send (initmsg)
                self.rphase = 2
                self.hellomsg = NopMsg (payload = b'\252' * 10)
                self.ntype = PHASE2
                self.blksize = self.minrouterblk = pkt.blksize
                if self.node.phase == 4:
                    self.id = Nodeid (self.parent.homearea, pkt.srcnode)
                else:
                    self.id = Nodeid (pkt.srcnode)
                self.tiver = pkt.tiver
                # Create the adjacency.  Note that it is not set to "up"
                # yet, that happens on transition to RU state.
                self.adj = adjacency.Adjacency (self, self)
                if pkt.verif:
                    # Verification requested
                    verif = self.node.nodeinfo (self.id).overif
                    if not verif:
                        logging.trace ("%s verification requested but not set,"
                                       " attempting null string", self.name)
                        verif = b""
                    vpkt = NodeVerify (password = verif)
                    self.datalink.send (vpkt)
                # If we requested verification, wait for that.
                if self.initmsg.verif:
                    self.node.timers.start (self, self.t3)
                    return self.rv
                self.up ()
                return self.ru
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
                        self.init_fail += 1
                        return self.restart (events.init_swerr,
                                             "bad ntype",
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
                        logging.debug ("%s Node address out of range: %s",
                                       self.name, pkt.srcnode)
                        self.init_fail += 1
                        nodeargs = (pkt.srcnode,)
                        return self.restart (events.init_oper,
                                             "node id out of range",
                                             adjacent_node = nodeargs,
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
                        self.init_fail += 1
                        return self.restart (events.init_swerr,
                                             "bad ntype for phase 3",
                                             adjacent_node = self.optnode (),
                                             reason = "unexpected_packet_type",
                                             **evtpackethdr (pkt))
                    if pkt.srcnode == 0 or \
                           (self.parent.ntype in { L1ROUTER, L2ROUTER } and
                            pkt.srcnode > self.parent.maxnodes ):
                        logging.debug ("%s Phase III node id out of range: %d",
                                       self.name, pkt.srcnode)
                        self.init_fail += 1
                        nodeargs = (pkt.srcnode,)
                        return self.restart (events.init_oper,
                                             "node id out of range",
                                             adjacent_node = nodeargs,
                                             reason = "address_out_of_range")
                    if pkt.ntype == L1ROUTER and \
                       self.parent.ntype in { L1ROUTER, L2ROUTER } and \
                       pkt.blksize < self.parent.maxnodes * 2 + 6:
                        self.init_fail += 1
                        nodeargs = (pkt.srcnode,)
                        return self.restart (events.init_oper,
                                             "node id out of range",
                                             adjacent_node = nodeargs,
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
                                            tiver = tiver_ph3,
                                            verif = self.initmsg.verif,
                                            blksize = MTU)
                        self.datalink.send (initmsg)
                    if self.node.phase == 4:
                        self.id = Nodeid (self.parent.homearea,
                                              pkt.srcnode.tid)
                    else:
                        self.id = Nodeid (pkt.srcnode.tid)
                self.ntype = pkt.ntype
                self.blksize = self.minrouterblk = pkt.blksize
                self.tiver = pkt.tiver
                if pkt.verif:
                    # Verification requested
                    verif = self.node.nodeinfo (self.id).overif
                    if not verif:
                        logging.trace ("%s verification requested but not set,"
                                       " attempting null string", self.name)
                        verif = b""
                    vpkt = PtpVerify (fcnval = verif)
                    self.setsrc (vpkt)
                    self.datalink.send (vpkt)
                # Create the adjacency.  Note that it is not set to "up"
                # yet, that happens on transition to RU state.
                self.adj = adjacency.Adjacency (self, self)
                # If we requested verification, wait for that.
                if self.initmsg.verif:
                    self.node.timers.start (self, self.t3)
                    return self.rv
                self.up ()
                return self.ru
            else:
                # Some unexpected message
                self.init_fail += 1
                return self.restart (events.init_swerr,
                                     "unexpected message",
                                     adjacent_node = self.optnode (),
                                     reason = "unexpected_packet_type",
                                     **evtpackethdr (pkt))
        elif isinstance (item, datalink.DlStatus):
            # Process datalink status.  Restart the datalink.
            self.init_fail += 1
            return self.restart (events.init_fault,
                                 "datalink status",
                                 adjacent_node = self.optnode (),
                                 reason = "sync_lost")
        elif isinstance (item, CircuitDown):
            return self.restart ()
        elif isinstance (item, Shutdown):
            # operator "stop" command
            self.node.logevent (events.circ_off, self,
                                adjacent_node = self.optnode ())
            self.datalink.close ()
            return self.ha
    
    def rv (self, item):
        """Waiting for Verification message.
        """
        if isinstance (item, timers.Timeout):
            # Process timeout
            self.init_fail += 1
            return self.restart (events.init_fault, 
                                 "verification timeout",
                                 adjacent_node = self.optnode (),
                                 reason = "verification_timeout")
        elif isinstance (item, Received):
            # Process received packet
            pkt = item.packet
            verif = self.node.nodeinfo (self.id).iverif
            if not verif:
                logging.debug ("%s verification required but not set",
                               self.name)
                self.init_fail += 1
                self.routing.ver_rejects += 1
                return self.restart (events.ver_rej,
                                     "verification reject",
                                     adjacent_node = self.optnode (),
                                     reason = "verification_required")
            if isinstance (pkt, PtpVerify) and self.rphase > 2:
                if pkt.fcnval != verif:
                    logging.debug ("%s verification value mismatch",
                                   self.name)
                    self.init_fail += 1
                    self.routing.ver_rejects += 1
                    return self.restart (events.ver_rej, 
                                         "verification reject",
                                         adjacent_node = self.optnode (),
                                         reason = "invalid_verification")
                self.up ()
                return self.ru
            elif isinstance (pkt, NodeVerify) and self.rphase == 2:
                verif = (verif + bytes (7))[:8]
                if pkt.password != verif:
                    logging.debug ("%s verification value mismatch",
                                   self.name)
                    self.init_fail += 1
                    self.routing.ver_rejects += 1
                    return self.restart (events.ver_rej,
                                         "verification reject",
                                         adjacent_node = self.optnode (),
                                         reason = "invalid_verification")
                self.up ()
                return self.ru                
            else:
                self.init_fail += 1
                return self.restart (events.init_swerr,
                                     "unexpected message",
                                     adjacent_node = self.optnode (),
                                     reason = "unexpected_packet_type",
                                     **evtpackethdr (pkt))
        elif isinstance (item, datalink.DlStatus):
            # Process datalink status.  Restart the datalink.
            self.init_fail += 1
            return self.restart (events.init_fault,
                                 "datalink status",
                                 adjacent_node = self.optnode (),
                                 reason = "sync_lost")
        elif isinstance (item, CircuitDown):
            return self.restart ()
        elif isinstance (item, Shutdown):
            # operator "stop" command
            self.node.logevent (events.circ_off, self,
                                adjacent_node = self.optnode ())
            self.datalink.close ()
            return self.ha

    def ru (self, item):
        """Running state.  The circuit is up at the routing control layer.
        """
        if isinstance (item, timers.Timeout):
            # Process hello timer expiration
            self.sendhello ()
            return
        elif isinstance (item, Received):
            if self.rphase == 2:
                # Process received packet from Phase II node.
                if not isinstance (item.packet, packet.Packet):
                    # Data packet (not something we matched as a packet
                    # type we know).  Give it to NSP.  Wrap it in a
                    # ShortData object for consistency, but note that
                    # there is no routing header so the attributes that
                    # normally relate to routing header fields are
                    # made up here instead.
                    # TODO: handle intercept mode operation.
                    pkt = ShortData (dstnode = self.parent.nodeid,
                                     srcnode = self.id, rts = 0, visit = 1,
                                     payload = item.packet, src = self)
                    logging.trace ("Phase II data packet to routing: %s", pkt)
                    self.parent.dispatch (pkt)
                    return
            # Process received packet.  Restart the listen timer if not phase 2.
            self.adj.alive ()
            pkt = item.packet
            if isinstance (pkt, (ShortData, LongData, L1Routing, L2Routing)) \
               and self.rphase > 2:
                logging.trace ("%s data packet to routing: %s", self.name, pkt)
                # Note that just the packet is dispatched, not the work
                # item we received that wraps it.
                if self.rphase < 4 and self.node.phase == 4:
                    # Running phase 4 but neighbor is older, supply
                    # our area number into source and destination addresses,
                    # but only if they are not already set (see DNA Routing
                    # spec for why).
                    if pkt.srcnode.area == 0:
                        pkt.srcnode = Nodeid (self.parent.homearea,
                                              pkt.srcnode.tid)
                    if isinstance (pkt, (ShortData, LongData)) and \
                           pkt.dstnode.area == 0:
                        pkt.dstnode = Nodeid (self.parent.homearea,
                                              pkt.dstnode.tid)
                pkt.src = self
                self.parent.dispatch (pkt)
            elif isinstance (pkt, PtpHello) and self.node.phase > 2:
                if not testdata_re.match (pkt.testdata):
                    return self.restart (events.circ_down,
                                         "invalid test data",
                                         adjacent_node = self.optnode (),
                                         reason = "listener_invalid_data",
                                         **evtpackethdr (pkt))
            else:
                if not self.datalink.start_works and \
                       isinstance (pkt, (NodeInit, PtpInit3, PtpInit)):
                    # Unexpected init message from the other end, on a
                    # datalink that doesn't implement remote start
                    # detection.  That most likely means the other end
                    # restarted for some reason.  If we do the
                    # normal restart sequence, we'd be expecting (another)
                    # init message, and we won't be getting one.  That
                    # eventually gets sorted out but it takes quite a while.
                    # So for this case, as a workaround, we declare the
                    # circuit down, set the next state to DI, and
                    # reprocess the message we just received.
                    self.down ()
                    logging.trace ("%s restart due to init message, using init workaround", self.name)
                    # Next 3 lines lifted from "HA" state handler
                    self.tiver = None
                    # Fake a datalink up notification to generate init packet
                    self.node.addwork (datalink.DlStatus (self, status = True))
                    self.node.addwork (Received (self, packet = pkt))
                    return self.ds
                return self.restart (events.init_swerr,
                                     "unexpected packet",
                                     adjacent_node = self.optnode (),
                                     reason = "unexpected_packet_type",
                                     **evtpackethdr (pkt))
        elif isinstance (item, datalink.DlStatus):
            # Process datalink status.  Restart the datalink.
            return self.restart (events.circ_fault,
                                 "datalink status",
                                 adjacent_node = self.optnode (),
                                 reason = "sync_lost")
        elif isinstance (item, CircuitDown):
            return self.restart ()
        elif isinstance (item, Shutdown):
            # operator "stop" command
            self.node.logevent (events.circ_off, self,
                                adjacent_node = self.optnode ())
            self.down ()
            self.datalink.close ()
            return self.ha

    def sendhello (self):
        """Handler to send periodic hello messages.
        """
        if self.state == self.ru:
            self.datalink.send (self.hellomsg)
            self.node.timers.start (self, self.t3)

    def up (self):
        """We're done initializing with the neighbor.  Set the adjacency
        to "up", and start the hello timer.
        """
        self.adj.up ()
        self.node.logevent (events.circ_up, self,
                            adjacent_node = self.optnode ())
        self.node.timers.start (self, self.t3)

    def down (self):
        """Take the adjacency down. 
        """
        self.adj.down ()
        self.adj = None

    def adj_timeout (self, adj):
        """Take the adjacency down and restart the circuit.  This is
        called by adjacency listen timeout.
        """
        self.adj = None
        self.restart (events.circ_down,
                      "timeout",
                      adjacent_node = self.optnode (),
                      reason = "listener_timeout")
        
    def html (self, what, first):
        if first:
            hdr = """<tr><th>Name</th><th>Cost</th>
            <th>Neighbor</th><th>Type</th>
            <th>Hello time</th><th>Block size</th>
            <th>Listen time</th><th>Version</th>
            <th>State</th></tr>"""
        else:
            hdr = ""
        if self.state == self.ru:
            neighbor = str (self.optnode ())
        else:
            neighbor = ""
        ntype = ntypestrings[self.ntype]
        s = """<tr><td>{0.name}</td><td>{0.config.cost}</td>
        <td>{1}</td><td>{2}</td><td>{0.t3}</td><td>{0.blksize}</td>
        <td>{0.adj.t4}</td><td>{0.tiver}</td>
        <td>{0.state.__name__}</dt></tr>""".format (self, neighbor, ntype)
        return hdr + s
    

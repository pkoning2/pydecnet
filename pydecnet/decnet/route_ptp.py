#!/usr/bin/env python3

"""DECnet routing point to point datalink dependent sublayer

"""

import re

from .common import *
from . import packet
from .routing_packets import *
from .events import *
from . import datalink
from . import timers
from . import statemachine

class Start (Work):
    """A work item that says "start the circuit".
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
    def __init__ (self, parent, name, datalink, config):
        super ().__init__ ()
        self.node = parent.node
        self.name = name
        self.hellotime = config.t3 or 60
        self.t4 = self.hellotime * 3
        self.tiver = None
        self.blksize = self.nodeid = 0
        self.hellotimer = timers.CallbackTimer (self.sendhello, None)
        self.datalink = datalink.create_port (self)
        if self.node.phase == 2:
            self.initmsg = NodeInit (srcnode = parent.tid,
                                     nodename = parent.name,
                                     verif = 0,
                                     routver = tiver_ph2,
                                     commver = nspver_ph2,
                                     blksize = MTU, nspsize = MTU,
                                     sysver = "DECnet/Python")
            self.hellomsg = NopMsg (payload = b'\252' * 10)
        else:
            if self.node.phase == 3:
                self.initmsg = PtpInit3 (srcnode = parent.tid,
                                        ntype = parent.ntype,
                                        tiver = parent.tiver,
                                        verif = 0,
                                        blksize = MTU,
                                        reserved = b'')
            else:
                self.initmsg = PtpInit (srcnode = parent.nodeid,
                                        ntype = parent.ntype,
                                        timer = self.hellotime,
                                        tiver = parent.tiver,
                                        verif = 0,
                                        blksize = MTU,
                                        reserved = b'')
            self.hellomsg = PtpHello (srcnode = parent.nodeid,
                                      testdata = b'\252' * 10)

    def __str__ (self):
        return "{0.name}".format (self)

    def restart (self, msg = None):
        if self.state == self.ru:
            self.down ()            
        if msg:
            logging.trace ("%s restart due to %s", self.name, msg)
        self.datalink.close ()
        self.state = self.ha
        self.start ()
        return self.ha

    def fmterr (self, pkt):
        # Get the packet beginning, 16 bytes even though spec says max of 6
        hdrb = bytes (pkt)[:16]
        hdrs = ':'.join ([ "{:02X}".format (i) for i in hdrb ])
        self.node.logevent (Event.fmt_err, self,
                            adjacent_node = self.node.nodeinfo (self.nodeid),
                            packet_beginning = hdrs)
        
    def start (self):
        # Put in some dummy values until we hear from the neighbor
        self.ntype = ENDNODE
        self.nodeid = 0
        self.node.addwork (Start (self))

    def stop (self):
        self.node.addwork (Shutdown (self))

    def send (self, pkt, dstnode, tryhard = False):
        # Note that the function signature must match that of
        # EndnodeLanCircuit.send.
        if self.state == self.ru:
            if self.rphase < 4:
                # Neighbor is Phase 3 or older, so we have its address
                # as an 8-bit value.  Force destination address to
                # the old size.
                dstnode = NodeId (0, dstnode.tid)
                pkt.dstnode = dstnode
            if self.ntype in (ENDNODE, PHASE2) and dstnode != self.nodeid:
                logging.debug ("Sending packet %s to wrong address %s (expected %s)", pkt, dstnode, self.nodeid)
                return
            if self.ntype == PHASE2:
                pkt = pkt.payload
            elif isinstance (pkt, LongData):
                pkt = ShortData (copy = pkt, payload = pkt.payload)
            self.datalink.send (pkt)
            
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
                return datalink.DlStatus (status = False)
            if isinstance (buf, packet.Packet):
                # If we already parsed this, don't do it again
                return True
            hdr = buf[0]
            if (hdr & 0x80) != 0 and self.node.phase > 3:
                # Padding.  Skip over it.  Low 7 bits are the total pad
                # length, pad header included.
                buf = buf[pad & 0x7f:]
                hdr = buf[0]
                if hdr & 0x80:
                    logging.debug ("Double padded packet received on %s",
                                   self.name)
                    return datalink.DlStatus (status = False)
            p2route = None
            if (hdr & 0xf3) == 0x42:
                # Phase 2 routing header
                p2route = RouteHdr (buf)
                buf = p2route.payload
                hdr = buf[0]
                if hdr & 0x83:
                    # Invalid bits set, complain
                    logging.debug ("Invalid msgflgs after Ph2 route hdr: %x",
                                   hdr)
                    return datalink.DlStatus (status = False)
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
                        return datalink.DlStatus (status = False)
                else:
                    # Init message type depends on major version number.
                    mver = buf[6]
                    if mver == tiver_ph3[0]:
                        # Phase 3
                        phase = 3
                        work.packet = PtpInit3 (buf)
                    elif mver == tiver_ph4[0]:
                        phase = 4
                        work.packet = PtpInit (buf)
                    elif mver < tiver_ph3[0]:
                        logging.debug ("Unknown routing version %d", mver)
                        return datalink.DlStatus (status = False)
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
                    work.packet = LongData (buf, src = None)
                elif self.node.phase > 2 and code == 2:
                    work.packet = ShortData (buf, src = None)
                elif (code & 3) == 0:
                    # Phase 2 packet.  Figure out what exactly.
                    if (hdr & 0x0f) == 8:
                        # Control packet
                        if hdr == 0x58:
                            # Node init or node verification
                            code = buf[1]
                            if code == 1:
                                work.packet = NodeInit (buf)
                            elif code == 2:
                                work.packet = NodeVerify (buf)
                            else:
                                logging.debug ("Unknown Phase 2 control packet %x from %s",
                                               code, self.name)
                                return datalink.DlStatus (status = False)
                    else:
                        # Phase 2 data packet, don't set a specific packet
                        # type, it will be handled in NSP
                        return True
                else:
                    logging.debug ("Unknown routing packet %d from %s",
                                   code, self.name)
                    return datalink.DlStatus (status = False)
        return True
                
    def ha (self, item):
        """Initial state: "Halted".
        """
        if isinstance (item, Start):
            self.datalink.open ()
            self.t4 = self.hellotime * 3
            self.tiver = None
            self.node.timers.start (self, self.t4)
            return self.ds

    s0 = ha    # "halted" is the initial state
    
    def ds (self, item):
        """Datalink start state.  Wait for a point to point datalink
        startup complete notification.
        """
        if isinstance (item, timers.Timeout):
            # Process timeout -- restart the datalink
            return self.restart ("timeout")
        elif isinstance (item, datalink.DlStatus):
            # Process datalink status.  The status attribute is True
            # for up, False for down.
            if item.status:
                self.datalink.send (self.initmsg)
                return self.ri
            return self.restart ("datalink down")
        elif isinstance (item, Shutdown):
            # operator "stop" command
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
            return self.restart ("timeout")
        elif isinstance (item, Received):
            # Process received packet
            pkt = item.packet
            if isinstance (pkt, NodeInit):
                # Phase 2 neighbor
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
                self.ntype = PHASE2
                self.blksize = self.minrouterblk = pkt.blksize
                self.nodeid = pkt.srcnode
                self.tiver = pkt.tiver
                if pkt.verif:
                    # Verification requested
                    verif = self.node.nodeinfo (self.nodeid).verif
                    if not verif:
                        logging.trace ("%s verification requested but not set, attempting null string", self.name)
                        verif = ""
                    vpkt = NodeVerify (password = verif)
                    self.setsrc (vpkt)
                    self.datalink.send (vpkt)
                # If we requested verification, wait for that.
                if self.initmsg.verif:
                    return self.rv
                self.node.timers.start (self.hellotimer, self.hellotime)
                self.up ()
                return self.ru
            elif isinstance (pkt, (PtpInit, PtpInit3)):
                if isinstance (pkt, PtpInit):
                    # Phase 4 neighbor
                    if self.node.phase < 4:
                        # If we're phase 3 or below, ignore phase 4 init
                        logging.trace ("Ignoring phase 4 init")
                        return
                    self.t4 = pkt.timer * T3MULT
                    self.rphase = 4
                    if pkt.ntype not in { ENDNODE, L1ROUTER, L2ROUTER } \
                           or pkt.blo:
                        # Log invalid packet (bad node type or blocking)
                        self.init_fail += 1
                        return self.restart ("bad ntype")
                    self.nodeid = pkt.srcnode
                else:
                    # Phase 3
                    if self.node.phase < 3:
                        # If we're phase 2, ignore phase 3 init
                        logging.trace ("Ignoring phase3 init")
                        return
                    self.t4 = self.t3 * T3MULT
                    self.rphase = 3
                    if pkt.ntype not in { ENDNODE, L1ROUTER }:
                        # Log invalid packet (bad node type)
                        self.fmterr (pkt)
                        self.init_fail += 1
                        return self.restart ("bad ntype for phase 3")
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
                    self.nodeid = NodeId (self.parent.homearea, pkt.srcnode.tid)
                self.ntype = pkt.ntype
                self.blksize = self.minrouterblk = pkt.blksize
                self.tiver = pkt.tiver
                if pkt.verif:
                    # Verification requested
                    verif = self.node.nodeinfo (self.nodeid).verif
                    if not verif:
                        logging.trace ("%s verification requested but not set, attempting null string", self.name)
                        verif = ""
                    vpkt = PtpVerify (fcnval = verif)
                    self.setsrc (vpkt)
                    self.datalink.send (vpkt)
                # If we requested verification, wait for that.
                if self.initmsg.verif:
                    return self.rv
                self.node.timers.start (self, self.t4)
                self.node.timers.start (self.hellotimer, self.hellotime)
                self.up ()
                return self.ru
            else:
                # Some unexpected message
                self.fmterr (pkt)
                self.init_fail += 1
                return self.restart ("unexpected message")
        elif isinstance (item, datalink.DlStatus):
            # Process datalink status.  Restart the datalink.
            self.init_fail += 1
            return self.restart ("datalink status")
        elif isinstance (item, Shutdown):
            # operator "stop" command
            self.datalink.close ()
            return self.ha
    
    def rv (self, item):
        """Waiting for Verification message.
        """
        if isinstance (item, timers.Timeout):
            # Process timeout
            self.init_fail += 1
            return self.restart ("timeout")
        elif isinstance (item, Received):
            # Process received packet
            pkt = item.packet
            if isinstance (pkt, PtpVerify) and self.rphase > 2:
                # todo: check verification value
                self.node.timers.start (self, self.t4)
                self.node.timers.start (self.hellotimer, self.hellotime)
                self.up ()
                return self.ru
            elif isinstance (pkt, NodeVerify) and self.rphase == 2:
                # todo: check verification value
                self.node.timers.start (self.hellotimer, self.hellotime)
                self.up ()
                return self.ru                
            else:
                self.fmterr (pkt)
                self.init_fail += 1
                return self.restart ("unexpected packet")
        elif isinstance (item, datalink.DlStatus):
            # Process datalink status.  Restart the datalink.
            self.init_fail += 1
            return self.restart ("datalink status")
        elif isinstance (item, Shutdown):
            # operator "stop" command
            self.datalink.close ()
            return self.ha

    def ru (self, item):
        """Running state.  The circuit is up at the routing control layer.
        """
        if isinstance (item, timers.Timeout):
            # Process listen timeout
            return self.restart ("timeout")
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
                                     srcnode = self.nodeid, rts = 0, visit = 1,
                                     payload = item.packet, src = self)
                    logging.trace ("Phase II data packet to routing: %s", pkt)
                    self.parent.dispatch (pkt)
                    return
            # Process received packet.  Restart the listen timer if not phase 2.
            if self.rphase > 2:
                self.node.timers.start (self, self.t4)
            pkt = item.packet
            if isinstance (pkt, (ShortData, LongData, L1Routing, L2Routing)) \
               and self.rphase > 2:
                logging.trace ("%s data packet to routing: %s", self.name, pkt)
                # Note that just the packet is dispatched, not the work
                # item we received that wraps it.
                if self.rphase < 4 and self.node.phase == 4:
                    # Running phase 4 but neighbor is older, supply
                    # our area number into source and destination addresses.
                    self.srcnode = NodeId (self.parent.homearea,
                                           self.srcnode.tid)
                    if isinstance (pkt, ShortData):
                        self.dstnode = NodeId (self.parent.homearea,
                                               self.dstnode.tid)
                pkt.src = self
                self.parent.dispatch (pkt)
            elif isinstance (pkt, PtpHello) and self.node.phase > 2:
                if not testdata_re.match (pkt.testdata):
                    self.fmterr (pkt)
                    return self.restart ("invalid test data")
            else:
                self.fmterr (pkt)
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
                    self.t4 = self.hellotime * 3
                    self.tiver = None
                    self.node.timers.start (self, self.t4)
                    # Fake a datalink up notification to generate init packet
                    self.node.addwork (datalink.DlStatus (self, status = True))
                    self.node.addwork (Received (self, packet = pkt))
                    return self.ds
                return self.restart ("unexpected packet")
        elif isinstance (item, datalink.DlStatus):
            # Process datalink status.  Restart the datalink.
            return self.restart ("datalink status")
        elif isinstance (item, Shutdown):
            # operator "stop" command
            self.down ()
            self.datalink.close ()
            return self.ha

    def sendhello (self, unused):
        """CallbackTimer handler to send periodic hello messages.
        """
        if self.state == self.ru:
            self.datalink.send (self.hellomsg)
            self.node.timers.start (self.hellotimer, self.hellotime)

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
            neighbor = str (self.node.nodeinfo (self.nodeid))
        else:
            neighbor = ""
        ntype = ntypestrings[self.ntype]
        s = """<tr><td>{0.name}</td><td>{0.config.cost}</td>
        <td>{1}</td><td>{2}</td><td>{0.hellotime}</td><td>{0.blksize}</td>
        <td>{0.t4}</td><td>{0.tiver}</td>
        <td>{0.state.__name__}</dt></tr>""".format (self, neighbor, ntype)
        return hdr + s
    

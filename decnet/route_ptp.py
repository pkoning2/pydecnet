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

# These are too obscure for others to care about so we define them here
# rather than in routing_packets.

tiver_ph2 = Version (0, 0, 0)
nspver_ph2 = Version (3, 1, 0)

class NodeInit (packet.Packet):
    _layout = (( "b", "msgflag", 1 ),
               ( "b", "starttype", 1 ),
               ( "ex", "srcnode", 2 ),
               ( "i", "nodename", 6 ),
               ( "bm",
                 ( "int", 0, 3 )),
               ( "bm",
                 ( "verif", 0, 1 ),
                 ( "rint", 1, 2 )),
               ( "b", "blksize", 2 ),
               ( "b", "nspsize", 2 ),
               ( "b", "maxlnks", 2 ),
               ( Version, "routver" ),
               ( Version, "commver" ),
               ( "i", "sysver", 32 ))
    msgflag = 0x58
    starttype = 1
    # These two are field of Phase 3/4 messages, but are implied here.
    ntype = ENDNODE
    tiver = tiver_ph2

class NodeVerify (packet.Packet):
    _layout = (( "b", "msgflag", 1 ),
               # Yes, the spec says this is 2 bytes even though it's 1 in Init
               ( "b", "starttype", 2 ),
               ( "b", "password", 8 ))
    msgflag = 0x58
    starttype = 2
    
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
        self.hellotime = config.t3 or 60
        self.listentime = self.hellotime * 3
        self.hellotimer = timers.CallbackTimer (self.sendhello, None)
        self.datalink = datalink.create_port (self)
        self.initmsg = PtpInit (srcnode = parent.nodeid,
                                ntype = parent.ntype,
                                timer = self.hellotime,
                                tiver = tiver_ph4,
                                verif = 0,
                                blksize = MTU,
                                reserved = b'')
        self.hellomsg = PtpHello (srcnode = parent.nodeid,
                                  testdata = b'\252' * 10)

    def __str__ (self):
        return "{0.name}".format (self)

    def restart (self, msg = None):
        if msg:
            logging.trace ("%s restart due to %s", self.name, msg)
        self.datalink.close ()
        self.state = self.ha
        self.start ()
        return self.ha
    
    def start (self):
        # Put in some dummy values until we hear from the neighbor
        self.ntype = ENDNODE
        self.nodeid = 0
        self.node.addwork (Start (self))

    def stop (self):
        self.node.addwork (Shutdown (self))

    def send (self, pkt):
        if self.state == self.ru:
            if isinstance (pkt, LongData):
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
            hdr = packet.getbyte (buf)
            if hdr & 0x80:
                # Padding.  Skip over it.  Low 7 bits are the total pad
                # length, pad header included.
                buf = buf[pad & 0x7f:]
                hdr = packet.getbyte (buf)
                if hdr & 0x80:
                    logging.debug ("Double padded packet received on %s",
                                   self.name)
                    return datalink.DlStatus (status = False)
            p2route = None
            if (hdr & 0xf3) == 0x42:
                # Phase 2 routing header
                p2route = RouteHdr (buf)
                buf = p2route.payload
                hdr = packet.getbyte (buf)
            if hdr & 1:
                # Routing control packet.  Figure out which one
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
                    mver = packet.getbyte (buf, 6)
                    if mver == tiver_ph3[0]:
                        # Phase 3
                        work.packet = PtpInit3 (buf)
                    elif mver == tiver_ph4[0]:
                        work.packet = PtpInit (buf)
                    elif mver < tiver_ph3[0]:
                        logging.debug ("Unknown routing version %d", mver)
                        return datalink.DlStatus (status = False)
                    else:
                        return False    # Too high, ignore it
            else:
                code = hdr & 7
                if code == 6:
                    work.packet = LongData (buf, src = None)
                elif code == 2:
                    work.packet = ShortData (buf, src = None)
                elif (code & 3) == 0:
                    # Phase 2 packet.  Figure out what exactly.
                    if (hdr & 0x0f) == 8:
                        # Control packet
                        if hdr == 0x58:
                            # Node init or node verification
                            code = packet.getbyte (buf, 1)
                            if code == 1:
                                work.packet = NodeInit (buf)
                            elif code == 2:
                                work.packet = NodeVerify (buf)
                            else:
                                logging.debug ("Unknown Phase 2 control packet %x from %s",
                                               code, self.name)
                                return datalink.DlStatus (status = False)
                        elif hdr == 8:
                            return False    # NOP packet, ignore
                    else:
                        # Phase 2 data packet -- send to NSP
                        pass
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
            self.node.timers.start (self, self.listentime)
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
        if self.ph4:
            pkt.srcnode = self.parent.nodeid
        else:
            pkt.srcnode = self.parent.tid

    def ri (self, item):
        """Routing layer initialize state.  Wait for a point to point
        init message.
        """
        if isinstance (item, timers.Timeout):
            # Process timeout
            return self.restart ("timeout")
        elif isinstance (item, Received):
            # Process received packet
            pkt = item.packet
            if isinstance (pkt, (NodeInit, PtpInit3, PtpInit)):
                # Point to point init message. 
                if isinstance (pkt, PtpInit):
                    # Phase 4
                    self.t4 = pkt.timer * T3MULT
                    if pkt.ntype not in { ENDNODE, L1ROUTER, L2ROUTER } \
                           or pkt.blo:
                        # Log invalid packet (bad node type or blocking)
                        return self.restart ("bad ntype")
                else:
                    self.t4 = self.t3 * T3MULT
                    if pkt.ntype not in { ENDNODE, L1ROUTER }:
                        # Log invalid packet (bad node type)
                        return self.restart ("bad ntype for phase 3")
                    if isinstance (pkt, PtpInit3):
                        # Neighbor is Phase 3, send it a Phase 3 init
                        ntype = parent.ntype
                        if ntype == L2ROUTER:
                            ntype = L1ROUTER
                        initmsg = PtpInit3 (srcnode = parent.tid,
                                            ntype = ntype,
                                            tiver = tiver_ph3,
                                            verif = self.initmsg.verif,
                                            blksize = MTU)
                    else:
                        initmsg = NodeInit (srcnode = parent.tid,
                                            nodename = parent.name,
                                            verif = self.initmsg.verif,
                                            routver = tiver_ph2,
                                            commver = Version (3, 1, 0),
                                            blksize = MTU)
                    self.datalink.send (initmsg)
                self.ntype = pkt.ntype
                self.blksize = self.minrouterblk = pkt.blksize
                self.nodeid = pkt.srcnode
                self.tiver = pkt.tiver
                self.ph4 = self.tiver[0] == tiver_ph4[0]
                self.ph2 = self.tiver[0] == tiver_ph2[0]
                if pkt.verif:
                    # Verification requested
                    verif = self.verification
                    if self.tiver == tiver_ph2:
                        vpkt = NodeVerify (password = verif)
                    else:
                        vpkt = PtpVerify (fcnval = verif)
                    self.setsrc (vpkt)
                    self.datalink.send (vpkt)
                # If we requested verification, wait for that.
                if self.initmsg.verif:
                    return self.rv
                if not self.ph2:
                    self.node.timers.start (self, self.t4)
                self.node.timers.start (self.hellotimer, self.hellotime)
                self.up ()
                return self.ru
            else:
                # Some unexpected message
                return self.restart ("unexpected message")
        elif isinstance (item, datalink.DlStatus):
            # Process datalink status.  Restart the datalink.
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
            return self.restart ("timeout")
        elif isinstance (item, Received):
            # Process received packet
            pkt = item.packet
            if isinstance (pkt, PtpVerify):
                # todo: check verification value
                if not self.ph2:
                    self.node.timers.start (self, self.t4)
                self.node.timers.start (self.hellotimer, self.hellotime)
                self.up ()
                return self.ru
            else:
                return self.restart ("unexpected packet")
        elif isinstance (item, datalink.DlStatus):
            # Process datalink status.  Restart the datalink.
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
            # Process received packet.  Always restart the listen timer.
            if not self.ph2:
                self.node.timers.start (self, self.t4)
            pkt = item.packet
            if isinstance (pkt, (ShortData, LongData, L1Routing, L2Routing)):
                logging.trace ("%s data packet to routing: %s", self.name, pkt)
                # Note that just the packet is dispatched, not the work
                # item we received that wraps it.
                pkt.src = self
                self.parent.dispatch (pkt)
            elif isinstance (pkt, PtpHello):
                if not testdata_re.match (pkt.testdata):
                    return self.restart ("invalid test data")
            else:
                return self.restart ("unexpected packet")
        elif isinstance (item, datalink.DlStatus):
            # Process datalink status.  Restart the datalink.
            self.down ()
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
            

#!/usr/bin/env python3

"""DECnet routing point to point datalink dependent sublayer

"""

from .common import *
from .node import ApiRequest, ApiWork
from .config import scan_ver
from . import packet
from . import datalink
from . import timers
from . import statemachine

class ShortData (packet.Packet):
    _layout = (( "bm",
                 ( "sfpd", 0, 2 ),
                 ( "rqr", 3, 1 ),
                 ( "rts", 4, 1 ),
                 ( "pf", 7, 1 )),
               ( "b", "dstnode", 2 ),
               ( "b", "srcnode", 2 ),
               ( "bm",
                 ( "visit", 0, 6 )))
    sfpd = 2
    pf = 0

class CtlHdr (packet.Packet):
    _layout = (( "bm",
                 ( "control", 0, 1 ),
                 ( "type", 1, 3 ),
                 ( "pf", 7, 1 )),)
    control = 1
    pf = 0
    
class PtpPInit (CtlHdr):
    _layout = (( "b", "srcnode", 2 ),
               ( "bm",
                 ( "ntype", 0, 2 ),
                 ( "verif", 2, 1 ),
                 ( "blo", 3, 1 )),
               ( "b", "blksize", 2 ),
               ( "b", "tiver", 3 ),
               ( "b", "timer", 2 ),
               ( "i", "reserved", 64 ))
    type = 0
    blo = 0
    
class PtpVerify (CtlHdr):
    _layout = (( "b", "srcnode", 2 ),
               ( "i", "fcnval", 64 ))
    type = 1
    
class PtpHello (CtlHdr):
    _layout = (( "b", "srcnode", 2 ),
               ( "i", "testdata", 128 ))
    type = 2
    
class PtpCircuit (statemachine.StateMachine, Element):
    """A point to point circuit, i.e., the datalink dependent
    routing sublayer instance for a non-Ethernet type circuit.

    Arguments are "parent" (Routing instance), "name" (user visible name)
    and "datalink" (the datalink layer object for this circuit).
    """
    def __init__ (self, parent, name, datalink, config):
        statemachine.StateMachine.__init__ (self)
        Element.__init (self, parent)
        self.name = name
        self.config = config.circuits[name]
        self.listentimer = CallbackTimer (self.listentimeout, self)
        self.hellotime = self.config.t3 or 60
        self.listentime = self.hellotime * 3
        self.datalink = datalink
        i = self.initmsg = PtpInit (srcnode = parent.nodeid,
                                    ntype = parent.nodetype,
                                    verif = 0, blksize = 576)
        h = self.hellomsg = PtpHello (srcnode = parent.nodeid,
                                      testdata = b'\252' * 10)

    def restart (self):
        self.datalink.close ()
        self.start ()

    def start (self):
        self.datalink.open ()
        self.datalink.send (self.initmsg)
        timers.start (self, self.listentime)
        
    def s0 (arg):
        """Initial state: "off".
        """
        pass

    def ri (arg):
        """Routing layer initialize state.  Wait for a point to point
        init message.
        """
        if isinstance (arg, Timeout):
            # Process timeout
            pass
        elif isinstance (arg, DlReceive):
            # Process received packet
            msg = PtpInit (arg)
            if msg.control == 1 and msg.type == 0:
                # Point to point init message
                pass
            else:
                # Some unexpected message
                self.restart ()
        elif isinstance (arg, DlSendComplete):
            # Process transmit complete: no action required
            pass
        elif isinstance (arg, DlStatus):
            # Process datalink status (datalink down).  Restart
            # the datalink and resend the init.
            self.restart ()
        else:
            self.datalink.close ()
            self.state = self.s0

    

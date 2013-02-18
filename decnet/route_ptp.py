#!/usr/bin/env python3

"""DECnet routing point to point datalink dependent sublayer

"""

from .packet import *
from .config import executor
from .statemachine import *
from .datalink import *

class ShortData (Packet):
    _layout = (( "bm", "sfpd", 0, 2 ),
               ( "bm", "rqr", 3, 1 ),
               ( "bm", "rts", 4, 1 ),
               ( "bm", "v", 6, 1 ),
               ( "b", "dstnode", 2 ),
               ( "b", "srcnode", 2 ),
               ( "bm", "visit", 0, 6 ))
    
class PtpPInit (Packet):
    _layout = (( "bm", "control", 0, 1 ),
               ( "bm", "type", 1, 3 ),
               ( "b", "srcnode", 2 ),
               ( "bm", "ntype", 0, 2 ),
               ( "bm", "verif", 2, 1 ),
               ( "bm", "blo", 3, 1 ),
               ( "b", "blksize", 2 ),
               ( "b", "tiver", 3 ),
               ( "b", "timer", 2 ),
               ( "i", "reserved", 64 ))

class PtpVerify (Packet):
    _layout = (( "bm", "control", 0, 1 ),
               ( "bm", "type", 1, 3 ),
               ( "b", "srcnode", 2 ),
               ( "i", "fcnval", 64 ))

class PtpHello (Packet):
    _layout = (( "bm", "control", 0, 1 ),
               ( "bm", "type", 1, 3 ),
               ( "b", "srcnode", 2 ),
               ( "i", "testdata", 128 ))

class PtpCircuit (StateMachine):
    """A point to point circuit, i.e., the datalink dependent
    routing sublayer instance for a non-Ethernet type circuit.

    Arguments are "id" (circuit index), "name" (user visible name)
    and "datalink" (the datalink layer object for this circuit).
    """
    def __init__ (self, id, name, datalink):
        self.id = id
        self.name = name
        self.listentimer = CallbackTimer (self.listentimeout, self)
        self.hellotime = 15
        self.listentime = self.hellotime * 3
        self.datalink = datalink
        i = self.initmsg = PtpInit ()
        i.control = 1
        i.type = 0
        i.srcnode = executor.nodeid
        i.ntype = executor.type
        i.verif = 0
        i.blksize = 576
        h = self.hellomsg = PtpHello ()
        h.control = 1
        h.type = 2
        h.srcnode = executor.nodeid
        h.testdata = b'\252' * 10

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

    

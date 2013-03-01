#!/usr/bin/env python3

"""DECnet routing point to point datalink dependent sublayer

"""

import re

from .common import *
from . import packet
from .routing_packets import *
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
               ( "ex", "nodeid", 2 ),
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

class NodeVerify (packet.Packet):
    _layout = (( "b", "msgflag", 1 ),
               # Yes, the spec says this is 2 bytes even though it's 1 in Init
               ( "b", "starttype", 2 ),
               ( "b", "password", 8 ))
    msgflag = 0x58
    starttype = 2
    
# Extract from the Phase IV routing spec:
arch = """
7.3  Routing Layer Initialization Circuit States


The Routing Layer Initialization circuit states are:

(Symbol) State                Description

(RU) RUN                      The Routing Layer can use the circuit to
                              transmit packets between two nodes.

(CR) CIRCUIT REJECTED         The  circuit  is  degraded.   To   avoid
                              excessive  packet delay the circuit will
                              be declared down.  The Routing  Decision
                              Process  has not yet processed a circuit
                              down event.

(DS) DATA LINK START          The  circuit  is  undergoing  Data  Link
                              Layer initialization.

(RI) ROUTING LAYER INITIALIZE The circuit has  successfully  undergone
                              Data  Link initialization and is waiting
                              to    receive    a     Routing     Layer
                              Initialization Message.

(RV) ROUTING LAYER VERIFY     A  valid  Routing  Layer  Initialization
                              Message   has  been  received  for  this
                              circuit   and   the   circuit   requires
                              verification.

(RC) ROUTING LAYER COMPLETE   The Routing Layer has completed a  valid
                              exchange of Routing Layer Initialization
                              and possibly Routing Layer  Verification
                              Messages.

(OF) OFF                      The  Routing  Layer   cannot   use   the
                              circuit.   The  Routing Decision Process
                              has not yet  processed  a  circuit  down
                              event.

(HA) HALT                     The Routing Layer cannot  use  the  cir-
                              cuit.  A circuit down event is required.


7.4  Routing Layer Initialization Circuit Events


The Routing Layer Initialization circuit events are as follows:

(Symbol)  Description


(nri)     The  Routing  Layer  received  a  valid  new  Routing  Layer
          Initialization Message.

(nrv)     The  Routing  Layer  received  a  valid  new  Routing  Layer
          Verification Message.

(rt)      The Routing Layer timed out.

(sc)      The Routing Layer received a start complete notification (in
          other words, a transition from the initializing state to the
          running state) from the Data Link Layer.

(ste)     The Routing Layer received a start  notification  (in  other
          words,  a  transition  from  any state to the stop state) or
          threshold error notification from the Data Link Layer.

          In the case of X.25, a start notification is  given  by  the
          Data  Link  Layer  upon  receipt  of a "Clear Indication" or
          "Reset" packet, or when a data error is observed.

(opo)     Operator turned circuit on.

(opf)     Operator turned circuit off.

(im)      The  Routing  Layer  received  an  invalid   Routing   Layer
          Initialization Message or an unexpected message.

(rc)      The Routing  Layer  received  a  reject  complete  from  the
          circuit rejection component of the circuit monitor.

(cdc)     The Routing Layer Initialization  received  a  circuit  down
          complete  event  from  the  Decision  Process in the Routing
          Layer Control Sublayer.

(cuc)     The Routing  Layer  Initialization  received  a  circuit  up
          complete  event  from  the  Decision  Process in the Routing
          Layer Control Sublayer.

When the Data Link Layer has initialized,  a  timer  starts.   If  the
timer  expires  before the circuit accepted state is reached, then the
circuit is reinitialized.  If the  timer  expires  after  the  circuit
accepted state is reached, then the timer is ignored.


               Routing Layer Initialization State Table


This table shows each possible new state and action  relating  to  the
occurrence  of  each  event in each state.  The actions are shown by a
slash (/) followed by the number of the action.  A dash (-)  signifies
no action.  The actions numbers are defined above.


                              Old State
           RU     CR     DS     RI     RV     RC     OF     HA
  Event


   nri    CR/-   CR/-   DS/-   *      DS/1   DS/1   OF/-   HA/-

   nrv    CR/-   CR/-   DS/-   DS/1   RC/-   DS/1   OF/-   HA/-

   rt     RU/-   CR/-   DS/1   DS/1   DS/1   RC/-   OF/-   HA/-

   sc     CR/-   CR/-   RI/3   DS/1   DS/1   DS/1   OF/-   HA/-

   ste    CR/-   CR/-   DS/1   DS/1   DS/1   DS/1   OF/-   HA/-

   opo    RU/-   CR/-   DS/-   RI/-   RV/-   RC/-   CR/-   DS/1

   opf    OF/2   OF/-   HA/2   HA/2   HA/2   HA/2   OF/-   HA/-

   im     CR/-   CR/-   DS/-   DS/1   DS/1   DS/1   OF/-   HA/-

   rc     CR/-   CR/-   DS/-   RI/-   RV/-   DS/1   OF/-   HA/-

   cdc    RU/-   DS/1   DS/-   RI/-   RV/-   RC/-   HA/-   HA/-

   cuc    RU/-   CR/-   DS/-   RI/-   RV/-   RU/-   OF/-   HA/-


                                * NOTE

There are four possible new state/action sets for this transition,  as
follows:

     1.  Action:  4;   New  state:   RV;   Verification  requested  in
         received message;  verification required by this node.

     2.  Action:  4;   New  state:   RC;   Verification  requested  in
         received message;  verification not required by this node.

     3.  Action:  -;  New state:  RV;  Verification not  requested  in
         received message;  verification required by this node.

     4.  Action:  -;  New state:  RC;  Verification not  requested  in
         received message;  verification not required by this node.



The Routing Decision Process generates  circuit  down  events  in  the
states CR and OF.  It generates a circuit up event in the state RC.

Once  the  Recall  Timer  is  set,  it  must  expire  before   another
reinitialize command is given to the Data Link Layer.

The following figure shows the Routing Layer state transitions.

           .---------------------------------------------------------.
           |                                                         |
           v                                                         |
      .---------.           .----------.           .-----------.     |
      |         |---------->|          |---------->|           |     |
   .->|   RU    |    .----->|    CR    |   .------>|     DS    |<--. |
   |  |         |    |      |          |   |   .-->|           |   | |
   |  `---------'    |      `----------'   |   |   `-----------'   | |
   |       |         |                     |   |         A         | |
   |       |         |                     |   |         |         | |    
   |       |  .------'            .--------'   |         |         | |
   |       |  |                   |            |         |         | |
   |       v  v                   v            |         v         | |
   |  .---------.           .----------.       |   .-----------.   | |
   |  |         |           |          |       |   |           |   | |
   |  |   OF    |---------->|    HA    |<------|---|     RI    |---|-'
   |  |         |           |          |       | .-|           |   |
   |  `---------'           `----------'       | | `-----------'   |
   |       ^                      A            | |       |         |
   |       |                      |            | |       |         |
   |       |                      |            | |       |         |
   |       |                      |            | |       v         |
   |       |                .----------.       | | .-----------.   |
   |       -----------------|          |-------' | |           |   |
   `------------------------|    RC    |<--------' |     RV    |___'
                            |          |<----------|           |
                            `----------'           `-----------'

   Legend:

        .----.
        |    |  contains symbol representing Routing Initialization
        |    |  state
        `----'
   
   Note:  These state transitions are not guaranteed.

"""
          
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
                                    tiver = tiver_ph4,
                                    verif = 0, blksize = MTU)
        h = self.hellomsg = PtpHello (srcnode = parent.nodeid,
                                      testdata = b'\252' * 10)

    def restart (self):
        self.datalink.close ()
        self.start ()

    def start (self):
        self.datalink.open ()
        self.datalink.send (self.initmsg)
        timers.start (self, self.listentime)
        self.state = self.ri

    def validate (self, work):
        """Common processing.  If we're handling a packet, do the
        initial parse and construct the correct specific packet class.
        """
        if isinstance (work, datalink.DlReceive):
            buf = work.packet
            if not buf:
                logging.debug ("Null routing layer packet received on %s",
                               self.name)
                return False
            hdr = packet.getbyte (buf)
            if hdr & 0x80:
                # Padding.  Skip over it.  Low 7 bits are the total pad
                # length, pad header included.
                buf = buf[pad & 0x7f:]
                hdr = packet.getbyte (buf)
                if hdr & 0x80:
                    logging.debug ("Double padded packet received on %s",
                                   self.name)
                    return False
            p2route = None
            if (hdr & 0xf3) == 0x42:
                # Phase 2 routing header
                p2route = RouteHdr (buf)
                buf = p2route.payload
                hdr = packet.getbyte (buf)
            if hdr & 1:
                # Routing control packet.  Figure out which one
                code = (hdr >> 1) & 7
                try:
                    work.packet = ptpcontrolpackets[code] (buf, src = None)
                except KeyError:
                    logging.debug ("Unknown routing control packet %d from %s",
                                   code, self.name)
                    return False
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
                                return False
                        elif hdr == 8:
                            return False    # NOP packet, ignore
                    else:
                        # Phase 2 data packet -- send to NSP
                        pass
                else:
                    logging.debug ("Unknown routing packet %d from %s",
                                   code, self.name)
                    return False
        return True
                
    def s0 (self, item):
        """Initial state: "off".
        """
        pass

    def ri (self, item):
        """Routing layer initialize state.  Wait for a point to point
        init message.
        """
        if isinstance (item, Timeout):
            # Process timeout
            pass
        elif isinstance (item, DlReceive):
            # Process received packet
            msg = PtpInit (item)
            if msg.control == 1 and msg.type == 0:
                # Point to point init message
                pass
            else:
                # Some unexpected message
                self.restart ()
        elif isinstance (item, DlSendComplete):
            # Process transmit complete: no action required
            pass
        elif isinstance (item, DlStatus):
            # Process datalink status (datalink down).  Restart
            # the datalink and resend the init.
            self.restart ()
        else:
            self.datalink.close ()
            self.state = self.s0

    

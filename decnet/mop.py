#!

"""MOP support for DECnet/Python

"""

from random import randint
import logging
import time
import fcntl
import socket

from .common import *
from .node import ApiRequest
from . import packet
from . import datalink
from . import timers
from . import statemachine

class MopHdr (packet.Packet):
    layout = ( ( "b", "code", 1 ), )

_lastreceipt = randint (0, 0xffff)
def receipt ():
    global _lastreceipt
    _lastreceipt = (_lastreceipt + 1) & 0xffff
    return _lastreceipt

class SysId (MopHdr):
    layout = ( ( "res", 1 ),
               ( "b", "receipt", 2 ),
               ( "tlv", 2, 1, True,
                 { 1 : ( "bs", "version", 3 ),
                   2 : ( "bm",
                         ( "loop", 0, 1 ),
                         ( "dump", 1, 1 ),
                         ( "ploader", 2, 1 ),
                         ( "sloader", 3, 1 ),
                         ( "boot", 4, 1 ),
                         ( "carrier", 5, 1 ),
                         ( "counters", 6, 1 ),
                         ( "carrier_reserved", 7, 1 ),
                         ( "", 8, 8 ) ),
                   3 : ( "bs", "console_user", 6 ),
                   4 : ( "b", "reservation_timer", 2 ),
                   5 : ( "b", "console_cmd_size", 2 ),
                   6 : ( "b", "console_resp_size", 2 ),
                   7 : ( "bs", "hwaddr", 6 ),
                   8 : ( "bs", "time", 10 ),
                   100 : ( "b", "device", 1 ),
                   200 : ( "c", "software", 17 ),
                   300 : ( "b", "processor", 1 ),
                   400 : ( "b", "datalink", 1 ) } )
               )
    
    code = 7
    version = b"\x03\x00\x00"
    
    devices = { 0 : ( "DP", "DP11-DA (OBSOLETE)" ),
                1 : ( "UNA", "DEUNA multiaccess communication link" ),
                2 : ( "DU", "DU11-DA synchronous line interface" ),
                3 : ( "CNA", "DECNA Ethernet adapter" ),
                4 : ( "DL", "DL11-C, -E or -WA asynchronous line interface" ),
                5 : ( "QNA", "DEQNA Ethernet adapter" ),
                6 : ( "DQ", "DQ11-DA (OBSOLETE)" ),
                7 : ( "CI", "Computer Interconnect interface" ),
                8 : ( "DA", "DA11-B or -AL UNIBUS link" ),
                9 : ( "PCL", "PCL11-B multiple CPU link" ),
                10 : ( "DUP", "DUP11-DA synchronous line interface" ),
                11 : ( "LUA", "DELUA Ethernet adapter" ),
                12 : ( "DMC", "DMC11-DA/AR, -FA/AR, -MA/AL or -MD/AL interprocessor link" ),
                14 : ( "DN", "DN11-BA or -AA automatic calling unit" ),
                16 : ( "DLV", "DLV11-E, -F, -J, MXV11-A or - B asynchronous line interface" ),
                17 : ( "LQA", "DELQA Ethernet adapter" ),
                18 : ( "DMP", "DMP11 multipoint interprocessor link" ),
                20 : ( "DTE", "DTE20 PDP-11 to KL10 interface" ),
                22 : ( "DV", "DV11-AA/BA synchronous line multiplexer" ),
                24 : ( "DZ", "DZ11-A, -B, -C, or -D asynchronous line multiplexer" ),
                28 : ( "KDP", "KMC11/DUP11-DA synchronous line multiplexer" ),
                30 : ( "KDZ", "KMC11/DZ11-A, -B, -C, or -D asynchronous line multiplexer" ),
                32 : ( "KL", "KL8-J (OBSOLETE)" ),
                34 : ( "DMV", "DMV11 interprocessor link" ),
                36 : ( "DPV", "DPV11 synchronous line interface" ),
                38 : ( "DMF", "DMF-32 synchronous line unit" ),
                40 : ( "DMR", "DMR11-AA, -AB, -AC, or -AE interprocessor link" ),
                42 : ( "KMY", "KMS11-PX synchronous line interface with X.25 level 2 microcode" ),
                44 : ( "KMX", "KMS11-BD/BE synchronous line interface with X.25 level 2 microcode" ),
                75 : ( "LQA-T", "DELQA-T Ethernet adapter" ),
                }
    datalinks = { 1 : "Ethernet",
                  2 : "DDCMP",
                  3 : "LAPB (frame level of X.25)" }
    processors = { 1 : "PDP-11 (UNIBUS)",
                   2 : "Communication Server",
                   3 : "Professional" }

    def __str__ (self):
        ret = [ ]
        for f in ("srcaddr", "carrier", "console_user", "reservation_timer",
                  "hwaddr", "device", "processor", "datalink", "software"):
            v = getattr (self, f, None)
            if v:
                if f == "device":
                    v = self.devices.get (v, v)[1]
                elif f == "processor":
                    v = self.processors.get (v, v)
                elif f == "datalink":
                    v = self.datalinks.get (v, v)
                elif f in ("hwaddr", "console_user"):
                    v = format_macaddr (v)
                ret.append ("{0:<12}: {1}".format (f, v))
        return '\n'.join (ret)

    def encode_c (self, args):
        """Encode "field" according to the rules for the "software"
        protocol field.  If "field" is a string, encode it as for the
        "I" type. If it is an integer, it has to be in -2..0, and the
        encoding is just that one byte.
        """
        field, maxlen = args
        val = getattr (self, field)
        if isinstance (val, int):
            if val not in (0, -1, -2):
                raise ValueError ("MOP C-n field integer not in -2..0")
            val = val.to_bytes (1, packet.LE)
        else:
            if isinstance (val, str):
                val = bytes (val, "latin-1", "ignore")
            vl = len (val)
            if vl > maxlen:
                raise OverflowError ("Value too long for %d byte field" % maxlen)
            val = vl.to_bytes (1, packet.LE) + val
        return val

    def decode_c (self, buf, args):
        """Decode "field" according to the rules for the "software"
        protocol field.  Basically this is like an I-n field, but
        special values -1 and -2 are accepted in the first byte,
        and string values are taken to be text strings.
        """
        field, maxlen = args
        flen = packet.getbyte.unpack_from (buf)[0]
        if flen < -2:
            raise ValueError ("Image field with negative length %d" % flen)
        elif flen > maxlen:
            raise OverflowError ("Image field longer than max length %d" % maxlen)
        elif flen < 0:
            v = flen
            flen = 1
        else:
            v = buf[1:flen + 1]
            if len (v) != flen:
                raise ValueError ("Not %d bytes left for image field" % flen)
            v = bytes (v).decode ()
        setattr (self, field, v)
        return buf[flen + 1:]
        
class RequestId (MopHdr):
    layout = ( ( "res", 1 ),
               ( "b", "receipt", 2 ), )
    code = 5

class RequestCounters (MopHdr):
    layout = ( ( "b", "receipt", 2 ), )
    code = 9

class Counters (MopHdr):
    layout = ( ( "b", "receipt", 2 ), )
    code = 11

class ConsoleRequest (MopHdr):
    layout = ( ( "bv", "verification", 8 ), )
    code = 13

class ConsoleRelease (MopHdr):
    code = 15

class ConsoleCommand (MopHdr):
    layout = ( ( "bm",
                 ( "seq", 0, 1 ),
                 ( "break", 1, 1 ) ), )
    code = 17

class ConsoleResponse (MopHdr):
    layout = ( ( "bm",
                 ( "seq", 0, 1 ),
                 ( "cmd_lost", 1, 1 ),
                 ( "resp_lost", 2, 1 ) ), )
    code = 19

class LoopSkip (packet.Packet):
    layout = ( ( "b", "skip", 2 ), )
    
class LoopFwd (packet.Packet):
    function = 2
    layout = ( ( "b", "function", 2 ),
               ( "bv", "dest", 6 ) )

class LoopReply (packet.Packet):
    function = 1
    layout = ( ( "b", "function", 2 ),
               ( "b", "receipt", 2 ) )

class LoopDirect (LoopSkip):
    """A direct (not assisted) loop packet, as originally sent.
    """
    layout = ( ( "b", "fwd", 2 ),
               ( "bv", "dest", 6 ),
               ( "b", "reply", 2 ),
               ( "b", "receipt", 2 ) )
    fwd = LoopFwd.function
    reply = LoopReply.function
    skip = 0

# This message is largely constant.
loopmsg = LoopDirect ()
loopmsg.payload = b"*" * 100

# Dictionary of packet codes to packet layout classes
packetformats = { c.code : c for c in globals ().values ()
                  if type (c) is packet.packet_encoding_meta
                  and hasattr (c, "code") }

class Mop (Element):
    """The MOP layer.  It doesn't do much, other than being the
    parent of the per-datalink MOP objects.
    """
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        self.config = config
        self.reservation = None
        self.circuits = dict ()
        self.node.mop = self
        logging.debug ("Initializing MOP layer")
        loop = parent.register_api ("loop", self, "MOP Loop operation")
        loop.set_defaults (final_handler = "loophandler")
        loop.add_argument ("circuit", help = "Interface to loop")
        loop.add_argument ("dest", nargs = "?", default = LOOPMC,
                           type = scan_l2id,
                           help = "Destination (default = CF-00-00-00-00-00)")
        loop.add_argument ("-c", "--count", type = int, default = 1,
                           help = "Count of packets to loop (default: 1)")
        loop.add_argument ("-f", "--fast", action = "store_true", default = False,
                           help = "Send packets at full speed (default: 1/s)")
        dlcirc = self.node.datalink.circuits
        for name, c in config.circuit.items ():
            dl = dlcirc[name]
            try:
                self.circuits[name] = MopCircuit (self, name, dl, c)
                logging.debug ("Initialized MOP circuit %s", name)
            except Exception:
                logging.exception ("Error initializing MOP circuit %s", name)

    def start (self):
        logging.debug ("Starting MOP layer")
        for name, c in self.circuits.items ():
            try:
                c.start ()
                logging.debug ("Started MOP circuit %s", name)
            except Exception:
                logging.exception ("Error starting MOP circuit %s", name)
    
    def dispatch (self, work):
        """API requests come here.
        """
        if isinstance (work, ApiRequest):
            logging.debug ("Processing API request %s %s", work.command,
                           work.circuit)
            try:
                port = self.circuits[work.circuit]
            except KeyError:
                work.reject ("Unknown circuit %s" % work.circuit)
                return
            # Redirect this to the correct handler for final action
            h = getattr (port, work.final_handler, None)
            if h is None:
                work.reject ("No %s handler for circuit %s" % (work.command,
                                                               work.circuit))
                return
            del work.final_handler     # to make it die if we somehow loop
            self.node.addwork (work, h)
            
class MopCircuit (Element):
    """The parent of the protocol handlers for the various protocols
    and services enabled on a particular circuit (datalink instance).
    """
    def __init__ (self, parent, name, datalink, config):
        super ().__init__ (parent)
        self.config = config
        self.name = name
        self.datalink = datalink
        self.mop = parent
        
    def start (self):
        logging.debug ("starting mop for %s %s",
                       self.datalink.__class__.__name__, self.name)
        if isinstance (self.datalink, datalink.BcDatalink):
            # Do the following only on LANs
            self.loophandler = LoopHandler (self, self.datalink)
            # The various MOP console handlers share a port, so we'll
            # own it and dispatch received traffic.
            self.consport = consport = self.datalink.create_port (self, MOPCONSPROTO)
            consport.add_multicast (CONSMC)
            self.sysid = SysIdHandler (self, consport)
            self.carrier_client = CarrierClient (self, consport)
            if self.config.console:
                self.carrier_server = CarrierServer (self, consport, self.config)
            else:
                self.carrier_server = None

    def dispatch (self, work):
        if isinstance (work, datalink.DlReceive):
            buf = work.packet
            if not buf:
                logging.debug ("Null MOP packet received on %s", self.name)
                return
            header = MopHdr (buf)
            msgcode = header.code
            try:
                parsed = packetformats[msgcode] (buf)
            except KeyError:
                logging.debug ("MOP packet with unknown message code %d on %s",
                               msgcode, self.name)
                return
            parsed.src = work.src
        else:
            # Unknown request
            return
        self.sysid.dispatch (parsed)
        self.carrier_client.dispatch (parsed)
        if self.carrier_server:
            self.carrier_server.dispatch (parsed)

class SysIdHandler (Element, timers.Timer):
    """This class defines processing for SysId messages, both sending
    them (periodically and on request) and receiving them (multicast
    and directed).  We track received ones in a dictionary.
    """
    def __init__ (self, parent, port):
        Element.__init__ (self, parent)
        timers.Timer.__init__ (self)
        self.node.timers.start (self, self.id_self_delay ())
        self.port = port
        self.mop = parent.parent
        self.heard = dict ()
        logging.debug ("Initialized sysid handler for %s", parent.name)

    def id_self_delay (self):
        return randint (8 * 60, 12 * 60)
    
    def dispatch (self, pkt):
        if isinstance (pkt, packet.Packet):
            src = pkt.src
            if pkt.code == SysId.code:
                if src in self.heard:
                    logging.debug ("Sysid update on %s from %s",
                                   self.parent.name, format_macaddr (src))
                else:
                    logging.debug ("Sysid on %s from new node %s",
                                   self.parent.name, format_macaddr (src))
                self.heard[src] = pkt
            elif pkt.code == RequestId.code:
                self.send_id (src, pkt.receipt)
        elif isinstance (pkt, timers.Timeout):
            logging.debug ("Sending periodic sysid on %s", self.parent.name)
            self.send_id (CONSMC, 0)
            self.node.timers.start (self, self.id_self_delay ())

    def send_id (self, dest, receipt):
        sysid = SysId ()
        sysid.receipt = receipt
        sysid.hwaddr = self.port.parent.hwaddr
        sysid.loop = True
        #sysid.counters = True
        if self.parent.carrier_server:
            sysid.carrier = True
            sysid.reservation_timer = CarrierServer.reservation_timer
            sysid.console_cmd_size = sysid.console_resp_size = CarrierServer.msgsize
            if self.mop.reservation:
                sysid.carrier_reserved = True
                sysid.console_user = self.mop.reservation
        sysid.device = 9    # PCL, to freak out some people
        sysid.datalink = 1  # Ethernet
        sysid.processor = 2 # Comm server
        sysid.software = "DECnet/Python"  # Note: 16 chars max
        sysid.encode ()
        self.port.send (sysid, dest)

class CarrierClient (Element, statemachine.StateMachine):
    """The client side of the console carrier protocol.
    """
    def __init__ (self, parent, port):
        Element.__init__ (self, parent)
        statemachine.StateMachine.__init__ (self)
        logging.debug ("Initialized console carrier client for %s", parent.name)

    def dispatch (self, item):
        pass

    def s0 (self, data):
        pass
    
class CarrierServer (Element, timers.Timer):
    """The server side of the console carrier protocol.
    """
    reservation_timer = 15
    msgsize = 1024
    def __init__ (self, parent, port, config):
        Element.__init__ (self, parent)
        timers.Timer.__init__ (self)
        self.verification = config.console
        self.mop = parent.mop
        self.pty = None
        self.response = None
        self.pendingdata = None
        logging.debug ("Initialized console carrier server for %s", parent.name)

    def dispatch (self, item):
        if isinstance (item, timers.Timer):
            # Reservation timeout, clear any reservation
            if self.pty:
                self.pty.close ()
                self.pty = None
                self.mop.reservation = None
        elif isinstance (item, packet.Packet):
            # Some received packet.
            res = self.mop.reservation
            if res:
                # Console is reserved.  Ignore any packets from others
                if item.src != res:
                    return
            else:
                # Not reserved.  If it's a reserve console and the verification
                # matches, set reservation.  Ignore other packets.
                if isinstance (item, ConsoleRequest) and \
                   item.verification == self.verification:
                    self.mop.reservation = item.src
                    self.seq = 0
                    self.pendinginput = b""
                    try:
                        pid, fd = os.forkpty () #pty.fork ()
                        if pid:
                            # Parent process.  Save the pty fd and set it
                            # to non-blocking mode
                            logging.debug ("Started console client process %d", pid)
                            self.pendingoutput = b"Ctrl-] to exit\n"
                            self.ptyfd = fd
                            oldflags = fcntl (fd, F_GETFL, 0)
                            fcntl (fd, F_SETFL, oldflags | os.O_NONBLOCK)
                        else:
                            os.execlp ("login", "login")
                            sys._exit (1)
                    except Exception:
                        logging.exception ("Exception starting console client session")
                        self.mop.reservation = None
    
class LoopHandler (Element, timers.Timer):
    """Handler for loopback protocol
    """
    def __init__ (self, parent, datalink):
        Element.__init__ (self, parent)
        timers.Timer.__init__ (self)
        self.port = port = datalink.create_port (self, LOOPPROTO, pad = False)
        port.add_multicast (LOOPMC)
        self.pendingreq = None
        logging.debug ("Initialized loop handler for %s", parent.name)
        
    def dispatch (self, item):
        """Work item handler
        """
        if isinstance (item, datalink.DlReceive):
            buf = item.packet
            top = LoopSkip (buf)
            skip = top.skip
            if (skip & 1) or skip > len (buf) - 4:
                # Invalid skip count, ignore
                return
            # Guess it's a forward operation
            f = LoopFwd (buf[skip + 2:])
            if f.function == LoopFwd.function:
                if f.dest[0] & 1:
                    # Forward to multicast, invalid, ignore
                    return
                top.skip += 8
                top.encode ()
                self.port.send (top, f.dest)
            elif f.function == LoopReply.function:
                f = LoopReply (buf[skip + 2:])
                req = self.pendingreq
                if req and f.receipt == req.receipt:
                    delta = (time.time () - self.sendtime) * 1000.0
                    if req.dest[0] & 1:
                        # Original request was multicast, remember who replied
                        req.dest = item.src
                    elif item.src != req.dest:
                        # Reply from a different node, most likely a second
                        # reply to an assistance multicast loop.
                        return
                    try:
                        print ("%d bytes from %s, time= %.1f ms" %
                               (len (f.payload),
                                format_macaddr (item.src), delta),
                               file = req.wfile)
                    except (OSError, ValueError, socket.error):
                        logging.debug ("API socket closed")
                        req.finished (None)
                        self.pendingreq = None
                        self.node.timers.stop (self)
                        return
                    self.sendtime = 0
                    self.sendloop (req, req.fast)
        elif isinstance (item, timers.Timeout):
            req = self.pendingreq
            if req:
                if self.sendtime:
                    print ("Loop %d timed out" % self.loopcount, file = req.wfile)
                self.sendloop (req, True)
                
        elif isinstance (item, ApiRequest):
            if self.pendingreq:
                item.reject ("Loop busy")
            else:
                self.pendingreq = item
                item.accepted (None)
                self.loopcount = 0
                self.sendloop (item, True)
                
    def sendloop (self, req, now):
        if self.loopcount >= req.count:
            self.pendingreq = None
            self.node.timers.stop (self)
            req.done ()
        elif now:
            self.loopcount += 1
            loopmsg.dest = self.port.macaddr
            loopmsg.receipt = req.receipt = receipt ()
            loopmsg.encode ()
            self.sendtime = time.time ()
            self.port.send (loopmsg, req.dest)
            self.node.timers.stop (self)
            self.node.timers.start (self, 1)
    

#!

"""MOP support for DECnet/Python

"""

from random import randint

from .node import *
from .packet import *
from .datalink import *

class MopHdr (Packet):
    layout = ( ( "b", "code", 1 ), )

SYSIDTIME = 30 # temp

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
            val = val.to_bytes (1, LE)
        else:
            if isinstance (val, str):
                val = bytes (val, sys.getdefaultencoding ())
            vl = len (val)
            if vl > maxlen:
                raise OverflowError ("Value too long for %d byte field" % maxlen)
            val = vl.to_bytes (1, LE) + val
        return val

    def decode_c (self, buf, args):
        """Decode "field" according to the rules for the "software"
        protocol field.  Basically this is like an I-n field, but
        special values -1 and -2 are accepted in the first byte,
        and string values are taken to be text strings.
        """
        field, maxlen = args
        flen = getbyte.unpack_from (buf)[0]
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

class LoopSkip (Packet):
    layout = ( ( "b", "skip", 2 ), )
    
class LoopFwd (Packet):
    function = 2
    layout = ( ( "b", "function", 2 ),
               ( "bv", "dest", 6 ) )

class LoopReply (Packet):
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

# Requests we handle:

class LoopExchange (Exchange):
    """Loop to "dest", data is "payload", output goes to file "output".
    """
    
class IdExchange (Exchange):
    """Request SysId from "dest", output goes to file "output".
    """
    
class ConsoleExchange (Exchange):
    """Open console carrier session with "dest", output goes to file "output".
    Data to send is "payload".  
    """
    
# Dictionary of packet codes to packet layout classes
packetformats = { c.code : c for c in globals ().values ()
                  if type (c) is packet_encoding_meta
                  and hasattr (c, "code") }

class Mop (Element):
    """The MOP layer.  It doesn't do much, other than being the
    parent of the per-datalink MOP objects.
    """
    consmc = scan_macaddr ("AB-00-00-02-00-00")
    loopmc = scan_macaddr ("CF-00-00-00-00-00")

    def __init__ (self, parent):
        super ().__init__ (parent)
        self.reservation = None
        self.console_carrier = False

class MopCircuit (Element):
    """The parent of the protocol handlers for the various protocols
    and services enabled on a particular circuit (datalink instance).
    """
    def __init__ (self, parent, datalink):
        super ().__init__ (parent)
        if isinstance (datalink, BcDatalink):
            # Do the following only on LANs
            self.loophandler = LoopHandler (self, datalink)
            # The various MOP console handlers share a port, so we'll
            # own it and dispatch received traffic.
            self.consport = consport = datalink.create_port (self, 0x6002)
            consport.add_multicast (Mop.consmc)
            self.sysid = SysIdHandler (self, consport)
            self.carrier_client = CarrierClient (self, consport)
            if parent.console_carrier:
                self.carrier_server = CarrierServer (self, consport)
            else:
                self.carrier_server = None

    def dispatch (self, work):
        if isinstance (work, DlReceive):
            buf = work.packet
            if not buf:
                print ("Null MOP packet")
                return
            header = MopHdr (buf)
            try:
                parsed = packetformats[header.code] (buf)
            except KeyError:
                print ("Unknown message code", msgcode)
                return
            parsed.src = work.src
        elif isinstance (work, Exchange):
            parsed = work
            # We also send this to the loop handler so requesters
            # only need to know how to find the MopCircuit object to use
            self.loophandler.dispatch (work)
        else:
            # Unknown request
            return
        self.sysid.dispatch (parsed)
        self.carrier_client.dispatch (parsed)
        if self.carrier_server:
            self.carrier_server.dispatch (parsed)

class SysIdHandler (Element, Timer):
    """This class defines processing for SysId messages, both sending
    them (periodically and on request) and receiving them (multicast
    and directed).  We track received ones in a dictionary.
    """
    def __init__ (self, parent, port):
        Element.__init__ (self, parent)
        Timer.__init__ (self)
        self.node.timers.start (self, SYSIDTIME)
        self.port = port
        self.mop = parent.parent
        self.heard = dict ()
        
    def dispatch (self, pkt):
        if isinstance (pkt, Packet):
            src = pkt.src
            if pkt.code == SysId.code:
                if src in self.heard:
                    print ("update from", format_macaddr (src))
                else:
                    print ("new node heard from:", format_macaddr (src))
                self.heard[src] = pkt
            elif pkt.code == RequestId.code:
                self.send_id (src, pkt.receipt)
        elif isinstance (pkt, Timeout):
            self.send_id (Mop.consmc, 0)
            self.node.timers.start (self, SYSIDTIME)

    def send_id (self, dest, receipt):
        sysid = SysId ()
        sysid.receipt = receipt
        sysid.hwaddr = self.port.parent.hwaddr
        sysid.loop = True
        #sysid.counters = True
        if self.parent.carrier_server:
            sysid.carrier = True
            sysid.reservation_timer = ConsoleServer.reservation_timer
            sysid.console_cmd_size = sysid.console_resp_size = ConsoleServer.msgsize
            if self.mop.reservation:
                sysid.carrier_reserved = True
                sysid.console_user = self.mop.reservation
        sysid.device = 9    # PCL, for grins
        sysid.datalink = 1  # Ethernet
        sysid.processor = 2 # Comm server
        sysid.software = "DECnet/Python"  # Note: 16 chars max
        sysid.encode ()
        self.port.send (sysid, dest)

class CarrierClient (Element):
    """The client side of the console carrier protocol.
    """
    def __init__ (self, parent, port):
        super ().__init__ (parent)

    def dispatch (self, item):
        pass
    
class CarrierServer (Element):
    """The server side of the console carrier protocol.
    """
    def __init__ (self, parent, port):
        super ().__init__ (parent)

    def dispatch (self, item):
        pass
    
class LoopHandler (Element):
    """Handler for loopback protocol
    """
    def __init__ (self, parent, datalink):
        super ().__init__ (parent)
        self.port = port = datalink.create_port (self, 0x9000, pad = False)
        port.add_multicast (Mop.loopmc)
        self.pendingreq = None
        
    def dispatch (self, item):
        if isinstance (item, DlReceive):
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
                req = self.pendingreq
                if req:
                    f = LoopReply (buf[skip + 2:])
                    reply = str (bytes (f.payload), "ascii", "ignore")
                    req.output.write (reply + "\n")
                    self.pendingreq = None
        elif isinstance (item, LoopExchange):
            if self.pendingreq:
                item.output.write ("busy\n")
            else:
                self.pendingreq = item
                msg = LoopDirect ()
                msg.dest = self.port.macaddr
                msg.receipt = receipt ()
                msg.payload = item.payload[:1472]
                msg.encode ()
                self.port.send (msg, item.dest)
                

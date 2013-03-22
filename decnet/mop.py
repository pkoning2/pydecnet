#!

"""MOP support for DECnet/Python

"""

from random import randint
import time
from fcntl import *
import socket
import logging
import os

from .common import *
from .apiserver import ApiRequest, ApiWork
from . import packet
from . import datalink
from . import timers
from . import statemachine

# Some well known Ethernet addresses
CONSMC = Macaddr ("AB-00-00-02-00-00")
LOOPMC = Macaddr ("CF-00-00-00-00-00")

class MopHdr (packet.Packet):
    _layout = ( ( "b", "code", 1 ), )

_lastreceipt = randint (0, 0xffff)
def receipt ():
    global _lastreceipt
    _lastreceipt = (_lastreceipt + 1) & 0xffff
    return _lastreceipt

class SysId (MopHdr):
    _layout = ( ( "res", 1 ),
                ( "b", "receipt", 2 ),
                ( "tlv", 2, 1, True,
                  { 1 : ( Version, "version" ),
                    2 : ( "bm",
                          ( "loop", 0, 1 ),
                          ( "dump", 1, 1 ),
                          ( "ploader", 2, 1 ),
                          ( "sloader", 3, 1 ),
                          ( "boot", 4, 1 ),
                          ( "carrier", 5, 1 ),
                          ( "counters", 6, 1 ),
                          ( "carrier_reserved", 7, 1 ),
                          ( None, 8, 8 ) ),    # Reserved
                    3 : ( "bs", "console_user", 6 ),
                    4 : ( "b", "reservation_timer", 2 ),
                    5 : ( "b", "console_cmd_size", 2 ),
                    6 : ( "b", "console_resp_size", 2 ),
                    7 : ( Macaddr, "hwaddr" ),
                    8 : ( "bs", "time", 10 ),
                    100 : ( "b", "device", 1 ),
                    200 : ( "c", "software", 17 ),
                    300 : ( "b", "processor", 1 ),
                    400 : ( "b", "datalink", 1 ) } )
                )
    
    code = 7
    def_version = Version (3, 0, 0)
    
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

    def encode_c (self, field, maxlen):
        """Encode "field" according to the rules for the "software"
        protocol field.  If "field" is a string, encode it as for the
        "I" type. If it is an integer, it has to be in -2..0, and the
        encoding is just that one byte.
        """
        val = getattr (self, field)
        if isinstance (val, int):
            if val not in (0, -1, -2):
                logging.debug ("MOP C-n field integer not in -2..0")
                raise Event (fmt_err)
            val = val.to_bytes (1, packet.LE)
        else:
            if isinstance (val, str):
                val = bytes (val, "latin-1", "ignore")
            vl = len (val)
            if vl > maxlen:
                logging.debug ("Value too long for %d byte field", maxlen)
                raise Event (fmt_err)                
            val = vl.to_bytes (1, packet.LE) + val
        return val

    def decode_c (self, buf, field, maxlen):
        """Decode "field" according to the rules for the "software"
        protocol field.  Basically this is like an I-n field, but
        special values -1 and -2 are accepted in the first byte,
        and string values are taken to be text strings.
        """
        flen = packet.getbyte (buf)
        if flen < -2:
            logging.debug ("Image field with negative length %d", flen)
            raise Event (fmt_err)
        elif flen > maxlen:
            logging.debug ("Image field longer than max length %d", maxlen)
            raise Event (fmt_err)
        elif flen < 0:
            v = flen
            flen = 1
        else:
            v = buf[1:flen + 1]
            if len (v) != flen:
                logging.debug ("Not %d bytes left for image field", flen)
                raise Event (fmt_err)
            v = bytes (v).decode ()
        setattr (self, field, v)
        return buf[flen + 1:]

class RequestId (MopHdr):
    _layout = ( ( "res", 1 ),
                ( "b", "receipt", 2 ), )
    code = 5

class RequestCounters (MopHdr):
    _layout = ( ( "b", "receipt", 2 ), )
    code = 9

class Counters (MopHdr):
    _layout = ( ( "b", "receipt", 2 ),
                ( "deltat", "ctr_zero_time", 2 ),
                ( "ctr", "bytes_recd", 4 ),
                ( "ctr", "bytes_sent", 4 ),
                ( "ctr", "pkts_recd", 4 ),
                ( "ctr", "pkts_sent", 4 ),
                ( "ctr", "mcbytes_recd", 4 ),
                ( "ctr", "mcpkts_recd", 4 ),
                ( "res", 12 ),        # Frames sent, deferred, collision(s)
                ( "res", 8 ),         # Send/receive failures
                ( "ctr", "unk_dest", 2 ),
                ( "res", 6 ) )        # overrun, buffer unavailable
    code = 11

class ConsoleRequest (MopHdr):
    _layout = ( ( "bv", "verification", 8 ), )
    code = 13

class ConsoleRelease (MopHdr):
    code = 15

class ConsoleCommand (MopHdr):
    _layout = ( ( "bm",
                  ( "seq", 0, 1 ),
                  ( "break", 1, 1 ) ), )
    code = 17

class ConsoleResponse (MopHdr):
    _layout = ( ( "bm",
                  ( "seq", 0, 1 ),
                  ( "cmd_lost", 1, 1 ),
                  ( "resp_lost", 2, 1 ) ), )
    code = 19

class LoopSkip (packet.Packet):
    _layout = ( ( "b", "skip", 2 ), )
    
class LoopFwd (packet.Packet):
    _layout = ( ( "b", "function", 2 ),
                ( Macaddr, "dest" ) )

class LoopReply (packet.Packet):
    _layout = ( ( "b", "function", 2 ),
                ( "b", "receipt", 2 ) )

class LoopDirect (LoopSkip):
    """A direct (not assisted) loop packet, as originally sent.
    """
    _layout = ( ( "b", "fwd", 2 ),
                ( Macaddr, "dest" ),
                ( "b", "reply", 2 ),
                ( "b", "receipt", 2 ) )
    fwd = 2
    reply = 1
    skip = 0

# This message is largely constant.
loopmsg = LoopDirect (payload = b"Python! " * 12)

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
        self.node.mop = self
        logging.debug ("Initializing MOP layer")
        self.config = config
        self.reservation = None
        self.circuits = dict ()
        loop = parent.register_api ("loop", self, "MOP Loop operation")
        loop.set_defaults (final_handler = "loophandler")
        loop.add_argument ("circuit", help = "Interface to loop")
        loop.add_argument ("dest", nargs = "?", default = LOOPMC,
                           type = Macaddr,
                           help = "Destination (default = CF-00-00-00-00-00)")
        loop.add_argument ("-c", "--count", type = int, default = 1,
                           help = "Count of packets to loop (default: 1)")
        loop.add_argument ("-f", "--fast", action = "store_true", default = False,
                           help = "Send packets at full speed (default: 1/s)")
        cons = parent.register_api ("console", self, "MOP Console Carrier client")
        cons.set_defaults (final_handler = "carrier_client")
        cons.add_argument ("circuit", help = "Interface to use")
        cons.add_argument ("dest", type = Macaddr,
                           help = "Destination address")
        cons.add_argument ("verification", type = scan_ver,
                           help = "Verification value")
        showid = parent.register_api ("sysid", self, "Show SysId data")
        showid.set_defaults (final_handler = "sysid")
        showid.add_argument ("circuit", help = "Interface to query")
        showid.add_argument ("--brief", action = "store_const",
                             dest = "size", const = 0, default = 0,
                             help = "Brief display (default)")
        showid.add_argument ("--medium", action = "store_const",
                             dest = "size", const = 1,
                             help = "Medium display")
        showid.add_argument ("--full", action = "store_const",
                             dest = "size", const = 2,
                             help = "Extended display")
        reqctr = parent.register_api ("counters", self, "Request Counters")
        reqctr.set_defaults (final_handler = "sysid")
        reqctr.add_argument ("circuit", help = "Interface to query")
        reqctr.add_argument ("dest", type = Macaddr,
                             help = "Destination address")
        
        dlcirc = self.node.datalink.circuits
        for name, c in config.circuit.items ():
            dl = dlcirc[name]
            if isinstance (dl, datalink.BcDatalink):
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
        if isinstance (work, datalink.Received):
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

def format_sysid (id, config):
    """Format a sysid report, brief, regular, or full
    """
    ret = [ ]
    if config.size == 0:
        items = ( "hwaddr", )
    elif config.size == 2:
        items = ("srcaddr", "carrier", "console_user", "reservation_timer",
                 "hwaddr", "device", "processor", "datalink", "software")
    else:
        items = ( "srcaddr", "hwaddr", "device" )
    for f in items:
        v = getattr (id, f, None)
        if v:
            if f == "device":
                v = id.devices.get (v, v)[1]
            elif f == "processor":
                v = id.processors.get (v, v)
            elif f == "datalink":
                v = id.datalinks.get (v, v)
            ret.append ("{0:<12}: {1}".format (f, v))
    return '\n'.join (ret)

    
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
            if isinstance (pkt, SysId):
                if src in self.heard:
                    logging.debug ("Sysid update on %s from %s",
                                   self.parent.name, src)
                else:
                    logging.debug ("Sysid on %s from new node %s",
                                   self.parent.name, src)
                self.heard[src] = pkt
            elif isinstance (pkt, RequestId):
                self.send_id (src, pkt.receipt)
            elif isinstance (pkt, RequestCounters):
                self.send_ctrs (src, pkt.receipt)
        elif isinstance (pkt, timers.Timeout):
            logging.debug ("Sending periodic sysid on %s", self.parent.name)
            self.send_id (CONSMC, 0)
            self.node.timers.start (self, self.id_self_delay ())
        elif isinstance (pkt, ApiRequest):
            # Request for SysId data dump or request id
            if pkt.command == "sysid":
                if not self.heard:
                    reply = "No entries"
                else:
                    reply = '\n'.join (["{}: {}".format (k,
                                                         format_sysid (v, pkt))
                                        for k, v in self.heard.items ()])
                pkt.done (reply)
            elif pkt.command == "counters":
                self.port.send (RequestCounters (receipt = receipt ()),
                                pkt.dest)
                pkt.done ()
            else:
                pkt.reject ("unknown API request %s"% pkt.command)

    def send_id (self, dest, receipt):
        sysid = SysId (receipt = receipt,
                       version = SysId.def_version,
                       hwaddr = self.port.parent.hwaddr,
                       loop = True,
                       counters = True,
                       device = 9,    # PCL, to freak out some people
                       datalink = 1,  # Ethernet
                       processor = 2, # Comm server
                       software = "DECnet/Python"  # Note: 16 chars max
                       )
        if self.parent.carrier_server:
            sysid.carrier = True
            sysid.reservation_timer = CarrierServer.reservation_timer
            sysid.console_cmd_size = sysid.console_resp_size = CarrierServer.msgsize
            if self.mop.reservation:
                sysid.carrier_reserved = True
                sysid.console_user = self.mop.reservation
        self.port.send (sysid, dest)

    def send_ctrs (self, dest, receipt):
        reply = Counters (src = self.port.parent, receipt = receipt)
        self.port.send (reply, dest)
        
class CarrierClient (Element, statemachine.StateMachine):
    """The client side of the console carrier protocol.
    """
    def __init__ (self, parent, port):
        Element.__init__ (self, parent)
        statemachine.StateMachine.__init__ (self)
        self.req = None
        self.port = port
        logging.debug ("Initialized console carrier client for %s", parent.name)

    def validate (self, item):
        if self.state != self.s0 and isinstance (item, ApiRequest):
            item.reject ("Console client busy")
            return False
        return True

    def sendmsg (self, tries = 5):
        self.retries = tries
        self.node.timers.stop (self)
        self.node.timers.start (self, 1)
        self.port.send (self.msg, self.req.dest)
        
    def s0 (self, item):
        """Initial (inactive) state.  Look for API requests.
        """
        if isinstance (item, ApiRequest):
            self.req = item
            self.deststr = str (item.dest)
            self.msg = RequestId (receipt = receipt ())
            self.sendmsg ()
            return self.check

    def check (self, item):
        """Await SysId response, make sure console carrier is available.
        """
        if isinstance (item, SysId) and item.receipt == self.msg.receipt:
            self.node.timers.stop (self)
            if item.carrier and not item.carrier_reserved:
                # Looks good, proceed
                self.cmdsize = item.console_cmd_size
                self.respsize = item.console_resp_size
                self.restimer = item.reservation_timer
                # Now we send a reservation request followed by another
                # RequestId to see if it worked.
                self.msg2 = ConsoleRequest (verification = self.req.verification)
                self.port.send (self.msg2, self.req.dest)
                self.sendmsg ()
                return self.reserve
            if not item.carrier:
                self.req.reject ("Node %s does not support console carrier",
                                 self.deststr)
            else:
                self.req.reject ("Node %s console carrier reserved by %s",
                                 self.deststr, item.console_user)
            self.node.timers.stop (self)
            self.req = None
            return self.s0
        elif isinstance (item, timers.Timeout):
            # Timeout, try again if not at the limit
            self.retries -= 1
            if self.retries:
                self.sendmsg (self.retries)
            else:
                self.req.reject ("No response from node %s" % self.deststr)
                self.req = None
                return self.s0
            
    def reserve (self, item):
        """Verify that reservation was successful.
        """
        if isinstance (item, SysId) and item.receipt == self.msg.receipt:
            # If the reservation succeeded, switch to active state to
            # run the two-way console data stream.  
            if item.carrier_reserved and item.console_user == self.req.dest:
                self.seq = 0
                self.msg = None      # No poll message yet
                self.pendinginput = b""
                self.sendpoll ()
                self.req.accepted (self, binary = True)
                return self.active
        elif isinstance (item, timers.Timeout):
            # Timeout, try again if not at the limit
            self.retries -= 1
            if self.retries:
                # Resend a reservation request followed by another
                # RequestId to see if it worked.
                self.port.send (self.msg2, self.req.dest)
                self.sendmsg (self.retries)
            else:
                self.req.reject ("Reservation request timed out for node %s" % \
                                 self.deststr)
                self.req = None
                return self.s0

    def sendpoll (self):
        """Send a new poll, or retransmit the previous one.
        """
        tries = self.retries
        if not self.msg:
            tries = 5
            self.seq ^= 1
            indata = self.pendinginput[:self.cmdsize]
            self.pendinginput = self.pendinginput[self.cmdsize:]
            self.msg = ConsoleCommand (seq = self.seq, payload = indata)
        self.node.timers.stop (self)
        self.node.timers.start (self, 1)
        self.sendmsg (tries)

    def active (self, item):
        """Active (connected) state of the console carrier.
        """
        if isinstance (item, ConsoleResponse) and item.src == self.req.dest:
            # Response packet from our peer.  See if it's next in sequence
            if item.seq == self.seq:
                self.retries = 5
                try:
                    self.req.wfile.write (item.payload)
                except (OSError, ValueError, socket.error):
                    logging.debug ("API socket closed")
                    # Send a null data work item to self to close things down
                    self.node.addwork (ApiWork (self, data = None))
                self.msg = None
                # If there is more data to send, do so now
                if self.pendinginput:
                    self.sendpoll ()
                return
        if isinstance (item, (ConsoleResponse, timers.Timeout)):
            # Console response but not in sequence, or timeout: for
            # both, retransmit if it isn't time to give up.  If there is
            # no currently pending message, send the next one.
            self.retries -= 1
            if self.retries:
                self.sendpoll ()
            else:
                self.req.reject ("No answer from %s" % self.deststr)
                self.req = None
                return self.s0
        elif isinstance (item, ApiWork):
            # More data from API.  If we already have some or a message
            # is already pending, handle it later.  Otherwise send a
            # ConsoleCommand now.
            if not item.data:
                # API connection closed -- release the console
                self.msg2 = ConsoleRelease ()
                self.port.send (self.msg2, self.req.dest)
                self.msg = RequestId (receipt = receipt ())
                self.sendmsg ()
                return self.release
            elif self.pendinginput or self.msg:
                self.pendinginput += item.data
            else:
                self.pendinginput = item.data
                self.sendpoll ()
                
    def release (self, item):
        """Verify that release was successful.
        """
        if isinstance (item, SysId) and item.receipt == self.msg.receipt:
            # If the reservation succeeded, switch to active state to
            # run the two-way console data stream.  
            if not (item.carrier_reserved and item.console_user == self.req.dest):
                self.node.timers.stop (self)
                self.req = None
                self.msg = self.msg2 = None
                return self.s0
        elif isinstance (item, timers.Timeout):
            # Timeout, try again if not at the limit
            self.retries -= 1
            if self.retries:
                # Resend a release request followed by another
                # RequestId to see if it worked.
                self.port.send (self.msg2, self.req.dest)
                self.sendmsg (self.retries)
            else:
                self.req.reject ("Release request timed out for node %s" % \
                                 self.deststr)
                self.req = None
                return self.s0

class CarrierServer (Element, timers.Timer):
    """The server side of the console carrier protocol.
    """
    reservation_timer = 15
    msgsize = 512
    
    def __init__ (self, parent, port, config):
        Element.__init__ (self, parent)
        timers.Timer.__init__ (self)
        self.port = port
        self.verification = config.console
        self.mop = parent.mop
        self.pty = None
        self.response = None
        self.pendinginput = self.pendingoutput = None
        logging.debug ("Initialized console carrier server for %s", parent.name)

    def release (self):
        self.node.timers.stop (self)
        if self.pty:
            try:
                os.close (self.pty)
            except Exception:
                pass
        self.pty = self.pendinginput = self.pendingoutput = None
        self.response = None
        self.mop.reservation = None

    def dispatch (self, item):
        if isinstance (item, timers.Timer):
            # Reservation timeout, clear any reservation
            if self.pty:
                self.release ()
        elif isinstance (item, packet.Packet):
            # Some received packet.
            res = self.mop.reservation
            if res:
                # Console is reserved.  Ignore any packets from others
                if item.src != res:
                    return
                if isinstance (item, ConsoleRelease):
                    # Session ended
                    self.release ()
                elif isinstance (item, ConsoleCommand):
                    # Command/poll message.
                    self.node.timers.stop (self)
                    self.node.timers.start (self, self.reservation_timer)
                    if item.seq == self.seq:
                        # Retransmit, so resend the previous message
                        if self.response:
                            self.port.send (self.response, res)
                    else:
                        # New packet.  Save any input, check for output,
                        # build a response packet with pending output.
                        self.pendinginput += item.payload
                        try:
                            accepted = os.write (self.pty, self.pendinginput)
                        except Exception:
                            accepted = len (self.pendinginput)
                        self.pendinginput = self.pendinginput[accepted:]
                        self.seq ^= 1
                        lp = len (self.pendingoutput)
                        if lp < self.msgsize:
                            try:
                                self.pendingoutput += os.read (self.pty,
                                                               self.msgsize - lp)
                            except Exception:
                                pass
                        self.response = ConsoleResponse (seq = self.seq,
                                                         payload = self.pendingoutput)
                        self.pendingoutput = b""
                        self.port.send (self.response, res)
                        
            else:
                # Not reserved.  If it's a reserve console and the verification
                # matches, set reservation.  Ignore other packets.
                if isinstance (item, ConsoleRequest) and \
                   item.verification == self.verification:
                    self.mop.reservation = item.src
                    self.seq = self.pty = 0
                    self.pendinginput = b""
                    self.node.timers.start (self, self.reservation_timer)
                    try:
                        pid, fd = os.forkpty () #pty.fork ()
                        if pid:
                            # Parent process.  Save the pty fd and set it
                            # to non-blocking mode
                            logging.debug ("Started console client process %d", pid)
                            self.pendingoutput = b""
                            self.pty = fd
                            oldflags = fcntl (fd, F_GETFL, 0)
                            fcntl (fd, F_SETFL, oldflags | os.O_NONBLOCK)
                        else:
                            # Child process, send it off to login.
                            os.execlp ("login", "login")
                            sys._exit (1)
                    except Exception:
                        logging.exception ("Exception starting console client session")
                        self.release ()
    
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
        if isinstance (item, datalink.Received):
            buf = item.packet
            top = LoopSkip (buf)
            skip = top.skip
            if (skip & 1) or skip > len (buf) - 4:
                # Invalid skip count, ignore
                return
            # Get the function code
            fun = int.from_bytes (buf[skip + 2:skip + 4], packet.LE)
            if fun == LoopDirect.fwd:
                f = LoopFwd (buf[skip + 2:])
                if f.dest[0] & 1:
                    # Forward to multicast, invalid, ignore
                    return
                top.skip += 8
                self.port.send (top, f.dest)
            elif fun == LoopDirect.reply:
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
                               (len (f.payload), item.src, delta),
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
            self.sendtime = time.time ()
            self.port.send (loopmsg, req.dest)
            self.node.timers.stop (self)
            self.node.timers.start (self, 1)
    

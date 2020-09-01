#!

"""DDCMP datalink.

"""

import select
import socket
import queue
import errno

try:
    import serial
except ImportError:
    serial = None
try:
    from Adafruit_BBIO import UART
except ImportError:
    UART = None
    
import crc

from .common import *
from . import logging
from . import pktlogging
from . import timers
from . import datalink
from . import packet
from . import statemachine
from . import modulo

SvnFileRev = "$LastChangedRevision$"

# The CRC-16 polynomial; see section D.2 of the DDCMP spec.
class CRC16 (crc.CRC, poly = (16, 15, 2, 0)): pass

class HdrCrcError (DecodeError):
    "Invalid CRC for DDCMP header"
    
# DDCMP sequence numbers.  Note that these are mod 256 but not exactly
# RFC 1982 compatible, because the number of pending messages is allowed
# to go all the way to modulus - 1 rather than only up to modulus / 2.
class Seq (Field, modulo.Mod, mod = 256):
    @classmethod
    def decode (cls, buf):
        require (buf, 1)
        return cls (buf[0]), buf[1:]

    def encode (self):
        return self.to_bytes (1, packet.LE)

    def __bytes__ (self):
        return self.encode ()
    
# DDCMP byte codes that have specific meanings
SOH = 0o201        # SOH - start of data message
ENQ = 0o005        # ENQ - start of control message
DLE = 0o220        # DLE - start of maintenance message
SYN = 0o226        # SYN - synchronization code
DEL = 0o377        # DEL - pad after message trailer

SYN4 = bytes ([ SYN ] * 4)
DEL1 = byte (DEL)
DEL2 = DEL1 + DEL1

# Control message subtypes
ACK   = 1          # Acknowledgment
NAK   = 2          # Negative acknowledgment
REP   = 3          # Reply request
STRT  = 6          # Start
STACK = 7          # Start acknowledge

# NAK reason codes
R_HCRC = 1        # Header CRC error
R_CRC  = 2        # Data CRC error
R_REP  = 3        # Response to REP message
R_BUF  = 8        # No receive buffer available
R_OVER = 9        # Receive overrun
R_SHRT = 16       # Buffer too short for message
R_FMT  = 17       # Header format error

# Timeouts
ACKTMR = 1        # Timeout when waiting for data ACK
STACKTMR = 3      # Timeout when waiting for STACK during startup on TCP
UDPTMR = 60       # Timeout between retries of startup on UDP

class DMHdr (packet.Packet):
    "DDCMP packet common part -- the header including the header CRC"
    # For incoming packets, the caller may have checked the header
    # CRC, since that is part of packet framing (in stream input
    # modes).  Decoding will verify the Header CRC if "check" is True
    # (the default), but will skip it otherwise.  Outbound (encode),
    # the correct header CRC is always generated.
    classindex = { }
    classindexkey = "soh"
    _layout = (( packet.B, "soh", 1 ),)

    # Default.  For packet classes, True if this packet has a settable
    # "resp" field that the sender needs to fill in.
    setresp = True
    
    @classmethod
    def decode (cls, buf, recv = None, check = True):
        if check and not CRC16 (buf[:HDRLEN]).good:
            raise HdrCrcError
        ret, buf = super (__class__, cls).decode (buf, recv, check)
        return ret, buf[2:]

    def encode (self):
        # Supply the address.  Note that we don't enforce it on
        # receive.
        self.addr = 1
        ret = super ().encode ()
        crc = CRC16 (ret)
        return ret + bytes (crc)

class DataMsg (DMHdr):
    "A data message"
    # To allow for efficient processing of data messages in stream mode
    # connections, the decode method can accept just the header along
    # with a function that will deliver the data portion.
    _layout = (( packet.BM,
                 ( "count", 0, 14 ),
                 ( "qsync", 14, 1 ),
                 ( "select", 15, 1 )),
               ( Seq, "resp" ),
               ( Seq, "num" ),
               ( packet.B, "addr", 1 ))

    _addslots = ("payload", "crcok")
    soh = SOH

    @classmethod
    def decode (cls, buf, recv = None, check = True):
        # Optional argument recv is a function that will deliver the
        # next n bytes of packet data packet.  It is used to obtain
        # the data portion of the message.  If recv is supplied, buf
        # must be just the header.  If recv is omitted or None, buf
        # must be the entire packet including data CRC.  Data CRC is
        # always checked (the "check" argument is present in order to
        # match the signature of the base class decode method).
        #
        # Note that decode succeeds even for bad data CRC, because some
        # of the header fields still have to be acted on.
        ret, buf = super (__class__, cls).decode (buf)
        dl = ret.count
        if recv:
            assert not buf, "Too much data in header buffer"
            ret.payload = recv (dl)
            crc = CRC16 (ret.payload)
            crc.update (recv (2))
        else:
            require (buf, dl + 2)
            ret.payload = buf[:dl]
            crc = CRC16 (buf[:dl + 2])
            buf = buf[dl + 2:]
        ret.crcok = crc.good
        return ret, buf
            
    def encode (self):
        payload = makebytes (self.payload)
        self.count = len (payload)
        ret = [ super ().encode () ]
        ret.append (payload)
        crc = CRC16 (payload)
        ret.append (bytes (crc))
        return b"".join (ret)
    
class MaintMsg (DataMsg):
    # Maintenance message is like regular data message, but
    # different start byte and no sequence numbers.  We don't
    # simply subclass it from DataMsg because then it a maint
    # message would be an instance of DataMsg which will make
    # the code more confusing and error-prone.
    soh = DLE
    qsync = 1
    select = 1
    resp = Seq (0)
    num = Seq (0)
    setresp = False

# Control messages are similar but with type and subtype fields
# instead of the count field, since there is no payload.
class CtlMsg (DMHdr):
    _layout = (( packet.B, "type", 1 ),
               ( packet.BM,
                 ( "subtype", 0, 6 ),
                 ( "qsync", 6, 1 ),
                 ( "select", 7, 1 )),
               ( Seq, "resp" ),
               ( Seq, "num" ),
               ( packet.B, "addr", 1 ))

    classindex = { }
    classindexkey = "type"
    soh = ENQ

class AckMsg (CtlMsg):
    type = ACK
    subtype = 0
    num = Seq (0)

class NakMsg (CtlMsg):
    type = NAK
    num = Seq (0)

class RepMsg (CtlMsg):
    type = REP
    subtype = 0
    resp = Seq (0)
    setresp = False

class StartMsg (CtlMsg):
    type = STRT
    subtype = 0
    qsync = 1
    select = 1
    resp = Seq (0)
    num = Seq (0)
    setresp = False

class StackMsg (CtlMsg):
    type = STACK
    subtype = 0
    qsync = 1
    select = 1
    resp = Seq (0)
    num = Seq (0)
    setresp = False

HDRLEN = len (StartMsg ())

class Err (Work):
    """A work item that indicates a bad received message.  The "code" attribute
    says what specifically was wrong.  The code values are taken from the
    DDCMP protocol coding of NAK message reason codes.
    """
    def __init__ (self, owner, code):
        super ().__init__ (owner)
        self.code = code
        self.resp = None
        
class DDCMP (datalink.PtpDatalink, statemachine.StateMachine):
    """An implementation of the DDCMP protocol.  This conforms to the
    Digital Network Architecture DDCMP protocol spec, V4.1 (AA-K175A-TK).
    It is also interoperable with the DDCMP implementation in SIMH,
    see the source code in pdp11_dmc.c.

    The current implementation supports point to point full duplex mode
    only.  Half duplex and multipoint are TBD.

    Communication can be over UDP or TCP, or using a serial line (UART).
    If UDP, each packet corresponds exactly to a DDCMP message.  In TCP
    or on a serial line, the byte stream carries the DDCMP messages and
    this module will do packet framing using the "header CRC" method.
    SYN bytes are accepted but ignored while looking for start of
    packet.  On TCP, each transmitted packet is preceded by 4 SYN bytes.

    The device parameter is of the form proto:lport:host:rport.  Proto is
    "tcp", "udp" or "telnet".  Lport is the local port number (an integer).
    Host is the peer host name or address.  Rport is the peer port number.
    If TCP is used, the local port number is bound and outbound connections
    are attempted to the peer; whichever side establishes a connection first
    will have that connection used.  This matches what SIMH does in the
    sim_tmxr.c module.  (TBD: how are race conditions resolved?)  Incoming
    connections are accepted only from the specified peer.

    Alternatively, if module "pyserial" is installed, "proto" can also
    be "serial".  In that case, the device parameter takes the form
    serial:devname[:speed[:uart]] where devname is the device name of a
    UART port supported by pyserial, and speed is the line speed.  It
    defaults to 9600 if omitted.  On a BeagleBone system, the uart
    argument may be supplied to have the specified UART port on the
    system configured for use by Linux.  This requires the Adafruit_BBIO
    module to be installed.

    If UDP is used, traffic is between the specified local port and the
    peer address/port.  Incoming packets are accepted only from that peer.

    TELNET is a variant of TCP; in this mode, all-ones bytes are escaped
    according to TELNET protocol rules.  This supports connections via
    telnet servers to async ports running DDCMP.  That includes SIMH
    terminal connections accessed via TCP when in Telnet mode rather
    than raw mode.  Note that SIMH allows terminal ports to be
    configured with the "notelnet" attach argument, to suppress the
    default Telnet encapsulation.  This is slightly more efficient and
    is the preferred way of connecting to SIMH for DDCMP on serial
    ports.

    In TCP and serial modes, message resynchronization is done by the
    "Header CRC" method: the byte stream is searched for a valid start
    of header byte, and if the bytes starting at that point constitute a
    header with a valid Header CRC, it is assumed that we have framed
    the message correctly.  The transmitted byte stream contains four
    SYN bytes before each message (in TCP mode only) and one DEL byte
    after it, in conformance with the DDCMP spec recommendations.
    Resynchronization is only needed after an error; once sync has been
    established, it is presumed to remain in effect until an error
    occurs.  For example, a Header CRC error will be detected and
    counted as such if the link is in sync (but a second Header CRC
    error immediately following will not be, since at that point sync is
    not established).

    In UDP mode, framing is implicit: each UDP packet contains a DDCMP
    message.  The message may be preceded and/or followed by fill bytes
    (DEL or SYN); these are ignored.  Transmitted UDP packets contain no
    leading or trailing fillers.
    """
    port_type = 0    # DDCMP point
    
    def __init__ (self, owner, name, config):
        self.tname = "{}.{}".format (owner.node.nodename, name)
        self.rthread = None
        statemachine.StateMachine.__init__ (self)
        datalink.PtpDatalink.__init__ (self, owner, name, config)
        self.config = config
        self.qmax = config.qmax
        proto, *rest = config.device.split (':')
        proto = proto.lower ()
        if proto == "serial":
            if not serial:
                raise ValueError ("Serial port support not available")
            if not rest or len (rest) > 3:
                raise ValueError ("Invalid serial device spec {}".format (config.device))
            self.dev = rest[0]
            self.uart = None
            if len (rest) > 1:
                self.speed = int (rest[1])
                if len (rest) > 2:
                    if not UART:
                        raise ValueError ("BeagleBone UART module not available")
                    self.uart = rest[2]
            else:
                self.speed = 9600
            if self.uart:
                UART.setup (self.uart)
            self.serial = True
            self.tcp = False
            logging.trace ("DDCMP datalink {} initialized on uart {}"
                           " speed {}", self.name, self.dev, self.speed)
        else:
            self.serial = False
            lport, host, rport = rest
            if proto == "tcp" or proto == "telnet":
                self.tcp = True
                self.telnet = (proto == "telnet")
            elif proto == "udp":
                self.tcp = False
            else:
                raise ValueError ("Invalid protocol {}".format (proto))
            self.lport = int (lport)
            self.host = datalink.HostAddress (host)
            self.rport = int (rport)
            # All set
            logging.trace ("DDCMP datalink {} initialized using {} on "
                           "port {} to {}:{}", self.name, proto, self.lport,
                       host, self.rport)

    def open (self):
        # Open and close datalink are ignored, control is via the port
        # (the higher layer's handle on the datalink entity)
        pass

    def close (self):
        pass

    def cansend (self):
        return (self.n - self.a) < self.qmax
    
    def port_open (self):
        if self.state != self.s0 and self.state != self.reconnect:
            # Already open, ignore
            return
        # Initialize DDCMP protocol state; the names are by and large taken
        # from the DDCMP spec.  Note that T and X are not explicitly
        # represented here.  The effect of T is obtained simply by
        # retransmitting previously sent messages (in the "unack" queue
        # defined below).  X does not apply because (re) transmission simply
        # means giving the message to TCP or UDP to queue for transmission,
        # we don't explicitly see the actual transmissions or their completion.
        # Similarly, we don't have explicit send-nak or send-rep flags;
        # instead, those message are simply generated and sent immediately
        # when required.  Ack, on the other hand, does have a flag since
        # it is sent only when we have no data to send.
        self.r = Seq (0)    # Last sequence number received
        self.a = Seq (0)    # Last sent number acknowledged by peer
        self.n = Seq (0)    # Last sent number
        self.ackflag = False
        # Create new empty queues for unacked messages (sent but not yet
        # acked) and not yet sent (due to too many unacked).
        self.unack = [ None ] * 256
        self.notsent = queue.Queue ()
        # Create the receive thread
        self.rthread = StopThread (name = self.tname, target = self.run)
        if self.serial:
            # Just start receiving
            self.rthread.start ()
            logging.trace ("DDCMP {} listen on UART {} active",
                           self.name, self.dev)
            return
        if self.tcp:
            # We'll try for either outbound or incoming connections, whichever
            # appears first.  Create the inbound (listen) socket here.
            self.socket = socket.socket (socket.AF_INET)
        else:
            self.socket = socket.socket (socket.AF_INET, socket.SOCK_DGRAM,
                                         socket.IPPROTO_UDP)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Refresh the name to address mapping.  This isn't needed for the
        # initial open but we want this for a subsequent one, because
        # a restart of the circuit might well have been caused by an
        # address change of the other end.
        self.host.lookup ()
        try:
            self.socket.bind (("", self.lport))
            if self.tcp:
                self.socket.listen (1)
        except (AttributeError, OSError, socket.error):
            logging.trace ("DDCMP {} bind/listen failed", self.name)
            if self.socket:
                self.socket.close ()
            return
        self.rthread.start ()
        logging.trace ("DDCMP {} listen to {} active",
                       self.name, self.rport)

    def try_connect (self):
        # Get rid of any existing connect socket
        try:
            self.connsocket.close ()
        except Exception:
            pass
        # Refresh the host name to address mapping
        self.host.lookup ()
        self.connsocket = socket.socket (socket.AF_INET)
        self.connsocket.setblocking (False)
        try:
            self.connsocket.connect ((self.host.addr, self.rport))
            logging.trace ("DDCMP {} connect to {} {} in progress",
                           self.name, self.host.addr, self.rport)
        except socket.error as e:
            if e.errno == errno.EINPROGRESS:
                logging.trace ("DDCMP {} connect to {} {} in progress",
                               self.name, self.host.addr, self.rport)
            else:
                logging.trace ("DDCMP {} connect to {} {} rejected",
                               self.name, self.host.addr, self.rport)
                self.connsocket = None
        except AttributeError:
            self.connsocket = None
        # Wait a random time (60-120 seconds) for the outbound connection
        # to succeed.  If we get a timeout, give up on it and try again.
        self.node.timers.start (self, random.random () * UDPTMR + UDPTMR)

    def close_sockets (self):
        self.state = self.s0
        try:
            self.socket.close ()
        except Exception:
            pass
        try:
            self.connsocket.close ()
        except Exception:
            pass
        self.socket = self.connsocket = None
        
    def port_close (self):
        if self.state != self.s0:
            self.rthread.stop ()
            # Thread exit will queue a HALTED work item
            
    def disconnected (self):
        if self.state == self.running and self.port:
            self.node.addwork (datalink.DlStatus (self.port.owner,
                                                  status = datalink.DlStatus.DOWN))
        self.close_sockets ()

    def recvall (self, sz):
        """Receive "sz" bytes of data from the socket.  This waits until
        it has that much available.  If the connection was closed, raises
        OSError; otherwise, it returns exactly the amount requested.
        """
        p = b''
        while self.socket and len (p) < sz:
            b = self.socket.recv (sz - len (p))
            if not b:
                raise OSError
            if self.telnet:
                # Handle escapes.  Note that we only handles escaped
                # 377, not any other Telnet control codes.
                e = b.count (DEL1)
                if e & 1:
                    b2 = self.socket.recv (1)
                    if not b2:
                        raise OSError
                    b += b2
                if e:
                    b = b.replace (DEL2, DEL1)
            p += b
        if not self.socket:
            raise OSError
        return p
    
    def run (self):
        """This method runs the receive thread.  Here we look for connections
        (if in TCP mode) and receive the incoming data.  Message framing
        is done here.  Received messages and error indications are passed
        down to the DDCMP state machine which runs in the main thread.
        """
        logging.trace ("DDCMP datalink {} receive thread started", self.name)
        # Split out the three cases since they are rather different.
        if self.serial:
            self.run_serial ()
        else:
            if not self.socket:
                return
            if self.tcp:
                self.run_tcp ()
            else:
                self.run_udp ()
        # We come here when told to stop
        self.close_sockets ()
        logging.trace ("DDCMP datalink {} receive thread stopped", self.name)
        self.node.addwork (datalink.DlStatus (self,
                                              status = datalink.DlStatus.HALTED))

    def handle_pkt (self, pkt, c):
        # Handle a parsed packet
        tp = pkt.__class__.__name__
        if isinstance (pkt, CtlMsg):
            # Control packet.
            msg = "Received {} control packet on {}".format (tp, self.name)
            pktlogging.tracepkt (msg, c)
            self.node.addwork (Received (self, packet = pkt))
        elif pkt.crcok:
            # Data packet with good data CRC.
            msg = "Received {} packet on {}".format (tp, self.name)
            pktlogging.tracepkt (msg, c)
            self.node.addwork (Received (self, packet = pkt))
        else:
            # Fun complication: if the data CRC of a data
            # (not maintenance) message is bad, we're
            # still expected to act on the received ack
            # number (the "resp" field).  So pass that
            # along.
            e = Err (self, R_CRC)
            if not isinstance (pkt, MaintMsg):
                e.resp = pkt.resp
            msg = "{} packet with bad data CRC on {}".format (tp, self.name)
            pktlogging.tracepkt (msg, c)
            logging.debug (msg)
            self.node.addwork (e)
        
    def run_tcp (self):
        """Receive thread for the TCP case.
        """
        self.state = self.connecting
        self.insync = False
        self.try_connect ()
        poll = select.poll ()
        sfn = self.socket.fileno ()
        if self.connsocket:
            cfn = self.connsocket.fileno ()
            poll.register (cfn, select.POLLOUT | select.POLLERR)
        else:
            cfn = None
        poll.register (sfn, select.POLLIN | select.POLLERR)
        # We try to establish an outgoing connection while also looking
        # for an incoming one, so look for both ready to read on the
        # listen socket (incoming) and ready to write on the connect socket
        # (outbound connect completed).
        connected = False
        while not connected:
            plist = poll.poll (1)
            if self.rthread and self.rthread.stopnow:
                return
            for fd, event in plist:
                if event & select.POLLERR:
                    self.disconnected ()
                    self.state = self.reconnect
                    return
                if fd == cfn:
                    if event & select.POLLHUP:
                        # Connection was closed, ignore this
                        poll.unregister (cfn)
                        self.connsocket = None
                        continue
                    # Outbound connection went through.  Stop listening,
                    # and use that connection for data.
                    self.socket.close ()
                    self.socket = self.connsocket
                    self.socket.setblocking (True)
                    self.connsocket = None
                    logging.trace ("DDCMP {} outbound connection made", self.name)
                    # Drop out of the outer loop
                    connected = True
                    break
                elif fd == sfn:
                    # Ready on inbound socket.  Accept the connection.
                    try:
                        sock, ainfo = self.socket.accept ()
                        host, port = ainfo
                        if self.host.valid (host):
                            # Good connection, stop looking
                            self.socket.close ()
                            if self.connsocket:
                                self.connsocket.close ()
                            # The socket we use from now on is the data socket
                            self.socket = sock
                            self.connsocket = None
                            logging.trace ("DDCMP {} inbound connection accepted",
                                           self.name)
                            # Drop out of the outer loop
                            connected = True
                            break
                        # If the connect is from someplace we don't want
                        logging.trace ("DDCMP {} connect received from "
                                       "unexpected address {}", self.name, host)
                        sock.close ()
                    except (OSError, socket.error):
                        self.disconnected ()
                        self.state = self.reconnect
                        return
        logging.trace ("DDCMP {} connected", self.name)
        # At this point we're using just one socket, the data socket.
        # Update the poll object we're using
        poll = select.poll ()
        sock = self.socket
        sfn = sock.fileno ()
        poll.register (sfn, select.POLLIN | select.POLLERR)
        # We're connected.  Stop the timer, and start DDCMP protocol operation.
        self.node.timers.stop (self)
        self.state = self.Istart
        self.send_start ()
        # Start looking for messages.
        while True:
            plist = poll.poll (1)
            if self.rthread and self.rthread.stopnow:
                return
            for fd, event in plist:
                if event & select.POLLERR:
                    pstate = self.state
                    self.disconnected ()
                    if pstate == self.Istart:
                        self.state = self.reconnect
                    return
                # Not error, so it's incoming data.  Get the first byte.
                try:
                    c = sock.recv (1)
                except Exception:
                    c = None
                if not c:
                    pstate = self.state
                    self.disconnected ()
                    if pstate == self.Istart:
                        self.state = self.reconnect
                    return
                h = c[0]
                if h == SYN or h == DEL:
                    # sync or fill, skip it
                    continue
                if h == ENQ or h == SOH or h == DLE:
                    # Valid start of header.  Receive the header.
                    c += self.recvall (HDRLEN - 1)
                    # Check the Header CRC
                    crc = CRC16 (c)
                    if crc.good:
                        # Header CRC is valid.  Construct a packet object
                        # of the correct class.
                        if not self.insync:
                            logging.trace ("Back in sync on {}", self.name)
                        self.insync = True
                        # Decode via the header base class, which will
                        # identify the actual message type using packet
                        # class indexing and return that.  Tell decode
                        # that the header CRC has already been checked.
                        try:
                            pkt, x = DMHdr.decode (c, self.recvall, False)
                            self.handle_pkt (pkt, c)
                        except DecodeError as e:
                            msg = "Invalid packet: {}".format (e)
                            pktlogging.tracepkt (msg, c)
                    else:
                        # Header CRC is bad.  If we're in sync, report
                        # that as a bad header.  If not, treat it as
                        # message not framed correctly, and silently
                        # keep looking
                        msg = "bad header CRC on {}".format (self.name)
                        pktlogging.tracepkt (msg, c)
                        if self.insync:
                            self.insync = False
                            self.node.addwork (Err (self, R_HCRC))
                            logging.trace ("Lost sync on {}", self.name)
                        else:
                            logging.trace ("Out of sync, another HCRC error on {}", self.name)

    def run_udp (self):
        """Receive thread for the UDP case.
        """
        poll = select.poll ()
        sock = self.socket
        sfn = sock.fileno ()
        poll.register (sfn, select.POLLIN | select.POLLERR)
        self.state = self.Istart
        self.send_start ()
        # Start looking for messages.
        while True:
            plist = poll.poll (1)
            if self.rthread and self.rthread.stopnow:
                return
            for fd, event in plist:
                if event & select.POLLERR:
                    self.disconnected ()
                    return
                # Not error, so it's incoming data.  Get the UDP packet
                try:
                    # Allow for a max length DDCMP data message plus some sync
                    msg, addr = sock.recvfrom (16400)
                except OSError:
                    msg = None
                if not msg:
                    self.disconnected ()
                    return
                for i in range (len (msg)):
                    h = msg[i]
                    if h == SYN or h == DEL:
                        # sync or fill, skip it
                        continue
                    if h == ENQ or h == SOH or h == DLE:
                        # Packet start, process it
                        break
                    # Something else, error
                    i = len (msg)
                    break
                try:
                    c = msg[i:]
                    if not c:
                        # No valid header found, ignore whatever this is.
                        continue
                    pkt, x = DMHdr.decode (c)
                except HdrCrcError:
                    # Header CRC is bad.  Report it.
                    msg = "Header CRC error"
                    pktlogging.tracepkt (msg, c)
                    self.node.addwork (Err (self, R_HCRC))
                except DecodeError as e:
                    msg = "Invalid packet: {}".format (e)
                    pktlogging.tracepkt (msg, c)
                    self.node.addwork (Err (self, R_FMT))
                    continue
                self.handle_pkt (pkt, c)

    def run_serial (self):
        """Receive thread for the UART case.
        """
        # We have to open it here rather than earlier to make sure the
        # device is not closed if --daemon is used.
        self.serial = serial.Serial (port = self.dev, baudrate = self.speed,
                      parity = 'N', bytesize = 8, timeout = 5)
        logging.trace ("Opened serial port {}, speed {}", self.dev, self.speed)
        self.insync = False
        self.state = self.Istart
        self.send_start ()
        # Start looking for messages.
        while True:
            if self.rthread and self.rthread.stopnow:
                return
            # Get the first byte.
            try:
                c = self.serial.read (1)
            except Exception:
                c = None
            if not c:
                # Timeout, keep looking for start of frame
                continue
            h = c[0]
            if h == SYN or h == DEL:
                # sync or fill, skip it
                continue
            if h == ENQ or h == SOH or h == DLE:
                # Valid start of header.  Receive the header.
                c += self.serial.read (HDRLEN - 1)
                # Check the Header CRC
                crc = CRC16 (c)
                if crc.good:
                    # Header CRC is valid.  Construct a packet object
                    # of the correct class.
                    if not self.insync:
                        logging.trace ("Back in sync on {}", self.name)
                    self.insync = True
                    # Decode via the header base class, which will
                    # identify the actual message type using packet
                    # class indexing and return that.  Tell decode
                    # that the header CRC has already been checked.
                    try:
                        pkt, x = DMHdr.decode (c, self.serial.read, False)
                        self.handle_pkt (pkt, c)
                    except DecodeError as e:
                        msg = "Invalid packet: {}".format (e)
                        pktlogging.tracepkt (msg, c)
                else:
                    # Header CRC is bad.  If we're in sync, report
                    # that as a bad header.  If not, treat it as
                    # message not framed correctly, and silently
                    # keep looking
                    msg = "bad header CRC on {}".format (self.name)
                    pktlogging.tracepkt (msg, c)
                    if self.insync:
                        self.insync = False
                        self.node.addwork (Err (self, R_HCRC))
                        logging.debug ("Lost sync on {}", self.name)
                    else:
                        logging.debug ("Out of sync, another HCRC error on {}", self.name)

    def sendmsg (self, msg, timeout = ACKTMR):
        """Send the supplied message.  If the message has a "resp" field
        that needs to be filled in, it is filled in from the current
        state (the last correctly received message).

        For data messages, the "payload" attributes must contain the
        message payload.  Its length will be placed in the packet header
        during the encode process.  For all packet types, encode will
        insert the correct CRC values.

        The optional timeout argument specified what timeout to start after
        sending the message.  The default is one second.  Specify zero
        for no timeout.
        """
        # If the message has a "resp" field, set it.  Note that "hasattr"
        # does not work for this because, if it has never been set, the
        # object does not in fact have that attribute.
        if msg.setresp:
            msg.resp = self.r
            self.ackflag = False    # No more need for ACK
        # Just encode the message; CRCs are handled by the encoder.
        msg = msg.encode ()
        try:
            if self.serial:
                # Append a DEL byte.  No sync bytes in front, they
                # aren't useful for async connections.
                msg = msg + DEL1
                if logging.tracing:
                    pktlogging.tracepkt ("Sending packet on {}"
                                         .format (self.name), msg)
                self.serial.write (msg)
            elif self.tcp:
                msg = SYN4 + msg + DEL1
                if self.telnet:
                    msg = msg.replace (DEL1, DEL2)
                if logging.tracing:
                    pktlogging.tracepkt ("Sending packet on {}"
                                         .format (self.name), msg)
                self.socket.sendall (msg)
            else:
                if logging.tracing:
                    pktlogging.tracepkt ("Sending packet on {}"
                                         .format (self.name), msg)
                self.socket.sendto (msg, (self.host.addr, self.rport))
        except (OSError, AttributeError):
            # AttributeError happens if socket has been changed to "None"
            self.disconnected ()
            return
        if timeout:
            self.node.timers.start (self, timeout)

    @setlabel ("Halted")
    def s0 (self, data):
        """State machine for the Halted state -- ignore all received
        messages.  But handled HALTED status (completion of shutdown) by
        cleaning up some state.  We stay in halted state for that, the
        layer above will restart the circuit when it wants to.
        """
        if isinstance (data, datalink.DlStatus):
            if self.rthread:
                self.rthread.join (1)
            self.rthread = None
            # Pass this work item up to the routing layer
            self.node.addwork (data, self.port.owner)
        return None

    def reconnect (self, data):
        """State machine for the case where a connection failed (or was
        never really made) during Istart.  That connection is closed, and
        the receive thread exited, so we need to start that all over.
        """
        if isinstance (data, timers.Timeout):
            self.port_open ()
        # Anything other than timeout should not come here but is ignored.
        return None    # no change in state

    @setlabel ("TCP connecting")
    def connecting (self, data):
        """State machine for the connecting state -- this applies to TCP
        mode operation while we're still looking for a connection from
        the remote peer.  Since connection attempts go both ways, we handle
        timeouts here, and resend the connect attempt if so.
        """
        if isinstance (data, timers.Timeout):
            self.try_connect ()
        # Anything other than timeout should not come here but is ignored.
        return None    # no change in state

    @setlabel ("Starting")
    def Istart (self, data):
        """Istarted state -- we get here after the connection is up and we
        have sent the Start message.

        See DDCMP spec table 3, "Startup state table".
        """
        if isinstance (data, timers.Timeout):
            self.send_start ()
        elif isinstance (data, Received):
            data = data.packet
            if isinstance (data, StartMsg):
                self.send_stack ()
                return self.AStart
            elif isinstance (data, StackMsg):
                return self.running_state ()
            elif isinstance (data, MaintMsg):
                return self.Maint
            else:
                # Unexpected message, we use the option of ignoring it
                # (rather than resending the Start message immediately).
                # That way, we don't generate a message flood if things
                # get very confused.
                pass
        # By default, no state change
        return None

    @setlabel ("Start ACK")
    def AStart (self, data):
        """Astarted state -- we get here after the connection is up and we
        have sent the Stack message.

        See DDCMP spec table 3, "Startup state table".
        """
        if isinstance (data, (timers.Timeout, StartMsg)):
            self.send_stack ()
        elif isinstance (data, Received):
            pkt = data.packet
            if isinstance (pkt, StackMsg):
                return self.running_state ()
            elif isinstance (pkt, MaintMsg):
                # Set state to Maintenance, then process the message
                # as for that state
                self.state = self.Maint
                self.Maint (data)
                return self.state    # Make state change explicit in trace
            elif isinstance (pkt, (AckMsg, DataMsg)):
                # Set running state, stop the timer, then process
                # the received data or ACK message as usual
                self.state = self.running_state ()
                self.running (data)
                return self.state    # Make state change explicit in trace
            else:
                # Unexpected message, we use the option of ignoring it
                # (rather than resending the Stack message immediately).
                # That way, we don't generate a message flood if things
                # get very confused.
                pass
        # By default, no state change
        return None
        
    def running_state (self):
        """Enter running state.
        """
        # Tell the routing init layer that this datalink is running
        if self.port:
            self.node.addwork (datalink.DlStatus (self.port.owner,
                                                  status = datalink.DlStatus.UP))
        logging.trace ("Enter DDCMP running state on {}", self.name)
        self.node.timers.stop (self)
        # Send an ack to tell the other end
        self.send_ack ()
        # Return what we want for next state.
        return self.running

    @setlabel ("Running")
    def running (self, data):
        if isinstance (data, Received):
            data = data.packet
            if isinstance (data, MaintMsg):
                # Set state to Maintenance, then process the message
                # as for that state
                self.state = self.Maint
                self.Maint (data)
                return self.state    # Make state change explicit in trace
            elif isinstance (data, DataMsg):
                # Process the ack (the resp field) unconditionally
                self.process_ack (data)
                # Check the sequence number
                r1 = self.r + 1
                if data.num != r1:
                    # Ignore out of sequence packet
                    return
                # Update the outbound ack data
                self.r = r1
                self.ackflag = True
                # Pass the payload up to our client.
                msg = data.payload
                if logging.tracing:
                    logging.trace ("Received DDCMP message on {} len {}: {!r}",
                                   self.name, len (msg), msg)
                if self.port:
                    self.counters.bytes_recv += len (msg)
                    self.counters.pkts_recv += 1
                    self.node.addwork (Received (self.port.owner, packet = msg))
                else:
                    logging.trace ("Message discarded, no port open")
            elif isinstance (data, AckMsg):
                self.process_ack (data)
            elif isinstance (data, NakMsg):
                # A Nak acknowledges everything preceding the error
                if self.process_ack (data):
                    # Now retransmit the rest, given that it was a good Nak
                    # (i.e., resp field is in the correct range)
                    self.retransmit ()
            elif isinstance (data, RepMsg):
                if data.num == self.r:
                    self.ackflag = True
                else:
                    # Rep number does not match our latest, send NAK
                    self.send_nak (R_REP)
            elif isinstance (data, StartMsg):
                # Start while running, halt the circuit
                self.disconnected ()
                return
            elif isinstance (data, StackMsg):
                # Send another ACK
                self.ackflag = True
        elif isinstance (data, timers.Timeout):
            # DDCMP is different from most ARQ protocols: it doesn't
            # retransmit data on timeout, but instead asks the other
            # end to retransmit its current ACK or NAK.
            self.send_rep ()
        elif isinstance (data, Err):
            # Error notification from receive thread.
            if data.resp is not None:
                # If the header was good and has a "resp" field we have
                # to process that even though there was an error elsewhere.
                self.process_ack (data)
            self.send_nak (data.code)
        # Done processing the incoming event.  If we now have an ACK to
        # send, that means this wasn't satisfied by an outgoing data
        # message that resulted from what we just did, so send an
        # actual ACK message.
        if self.ackflag:
            self.send_ack ()

    # Helper routines for the various states

    def send_start (self):
        msg = StartMsg ()
        if self.tcp or self.serial:
            tmo = STACKTMR
        else:
            tmo = random.random () * UDPTMR + UDPTMR
        self.sendmsg (msg, tmo)

    def send_stack (self):
        msg = StackMsg ()
        self.sendmsg (msg, STACKTMR)

    def send_ack (self):
        msg = AckMsg ()
        # Don't start the timer...
        self.sendmsg (msg, 0)

    def send_nak (self, code):
        msg = NakMsg (subtype = code)
        # Don't start the timer...
        self.sendmsg (msg, 0)

    def send_rep (self):
        msg = RepMsg (num = self.n)
        self.sendmsg (msg)

    def process_ack (self, msg):
        # Process the ACK field (resp field) in the supplied message.
        # Returns True if it is valid (within the range of currently
        # outstanding messages), False if not.
        count = int (msg.resp - self.a)
        pend = int (self.n - self.a)
        if logging.tracing:
            logging.trace ("Processing DDCMP Ack on {}, count {}, pending count {}, "
                           "a={}, n={}", self.name, count, pend, self.a, self.n)
        if count > pend:
            # Because of sequence number wrapping, an "old" ACK will look
            # like one that acknowledges too much.  For example, one that's
            # old by one looks like an ACK for 255.
            return False
        for i in range (count):
            # Pick up the first not yet acked message
            self.a += 1
            cmsg = self.unack[self.a]
            assert (cmsg)
            # It is no longer pending
            self.unack[self.a] = None
            # The architecture shows notification of transmit complete
            # to the layer above, but in this implementation we don't
            # actually do that.
        if self.a != self.n:
            # Some messages remain pending, restart the timer
            self.node.timers.start (self, ACKTMR)
        else:
            # No transmits pending, stop timer
            self.node.timers.stop (self)
        # If we now can transmit more (because the number of pending
        # messages is < 255) and there are messages waiting, send
        # them now.  More precisely, if the message we just processed
        # was a NAK, append them to the end of the unacknowledged message
        # queue because the next action will be to retransmit all that is
        # pending.  Otherwise, just send the new messages.  The reason
        # for handling the NAK case this way is to ensure that the
        # retransmitted and new messages will appear in the correct
        # sequence number order.
        while self.cansend ():
            try:
                data = self.notsent.get_nowait ()
                self.send (data, queue = isinstance (msg, NakMsg))
            except queue.Empty:
                break
        # All done with a good ack, indicate that
        return True

    def retransmit (self):
        """Retransmit all currently pending messages.  This will restart
        the timeout as a side effect.
        """
        t = self.a
        pend = self.n - self.a
        for i in range (pend):
            t += 1
            msg = self.unack[t]
            assert (msg)
            self.sendmsg (msg)
            
    @setlabel ("Maintenance")
    def Maint (self, data):
        if isinstance (data, MaintMsg):
            # Pass the payload up to our client.
            msg = data.payload
            logging.trace ("Received DDCMP maintenance message on {} len {}: {!r}",
                           self.name, len (msg), msg)
            # We don't have any way to open maintenance ports yet, so
            # for now just discard the packet.
            if False: #self.port:
                self.counters.bytes_recv += len (msg)
                self.counters.pkts_recv += 1
                self.node.addwork (Received (self.port.owner, packet = msg))
            else:
                logging.trace ("Message discarded, no port open")
        elif isinstance (data, StartMsg):
            # The spec says to "notify" the user.  There isn't any
            # obvious way to do that, so instead let's halt if we get
            # a Start.
            self.disconnected ()
        return None
        
    def send (self, data, dest = None, queue = False):
        # Send a data message with the supplied payload, if we are in
        # running state.  (If not, discard it.)  If the message can't be
        # sent because 255 messages are already pending, queue it
        # instead.  If "queue" is True, append the message to the end
        # of the unacked message queue rather than transmitting it
        # right now; see "process_ack" above for why we need this.
        if self.state == self.running:
            if not self.cansend ():
                # Can't send now, queue it for when an ACK arrives
                self.notsent.put (data)
                return
            # Advance the next sequence number.
            n = self.n
            self.n += 1
            data = makebytes (data)
            mlen = len (data)
            if logging.tracing:
                logging.trace ("Sending DDCMP message #{} on {} len {}: {!r}",
                               n, self.name, mlen, data)
            self.counters.bytes_sent += mlen
            self.counters.pkts_sent += 1
            # Build a DDCMP Data message.
            msg = DataMsg (payload = data, num = self.n)
            # Put it into the unacked message list
            assert (self.unack[self.n] is None)
            self.unack[self.n] = msg
            if not queue:
                self.sendmsg (msg)
            

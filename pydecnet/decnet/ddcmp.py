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
from . import timers
from . import datalink
from . import packet
from . import modulo
from .nice_coding import CTM1
from . import host

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

# Control message types
ACK   = 1          # Acknowledgment
NAK   = 2          # Negative acknowledgment
REP   = 3          # Reply request
STRT  = 6          # Start
STACK = 7          # Start acknowledge

# NAK reason codes (in the subtype field)
R_HCRC = 1        # Header CRC error
R_CRC  = 2        # Data CRC error
R_REP  = 3        # Response to REP message
R_BUF  = 8        # No receive buffer available
R_OVER = 9        # Receive overrun
R_SHRT = 16       # Buffer too short for message
R_FMT  = 17       # Header format error

class DdcmpCounters (datalink.PtpCounters):
    def __init__ (self, owner):
        super ().__init__ (owner)
        self.data_errors_inbound = CTM1 ()
        self.data_errors_outbound = CTM1 ()
        self.remote_reply_timeouts = 0
        self.local_reply_timeouts = 0
        self.remote_buffer_errors = CTM1 ()

# Mapped counter bit definitions for the above:
DE_HCRC = 1
DE_CRC = 2
DE_REP = 4
BUF_UNAVAIL = 1
BUF_SML = 2

# Mapping from NAK reason codes to counter map bits.  Value is True for
# data error, False for buffer error, and the map bit.  Note that R_OVER
# and R_FMT are not currently mapped to anything.
nak_map = {
    R_HCRC : (True, DE_HCRC),
    R_CRC : (True, DE_CRC),
    R_REP : (True, DE_REP),
    R_BUF : (False, BUF_UNAVAIL),
    R_SHRT : (False, BUF_SML) }

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

class BaseDataMsg (DMHdr):
    "Base class for data or maintenance message"
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
            try:
                ret.payload = recv (dl)
                crc = CRC16 (ret.payload)
                crc.update (recv (2))
            except IOError:
                # Lost connection or stop requested, simulate packet
                # with bad data CRC.
                ret.payload = None
                ret.crcok = False
                return ret, buf
        else:
            if (len (buf) < dl + 2):
                # Not enough data.  Fake a CRC error because that's what
                # you'd get on the real system (it would read beyond the
                # supposed end of frame and pick up whatever follows,
                # producing a CRC error).
                ret.crcok = False
                ret.payload = b""
                return ret, b""
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

class DataMsg (BaseDataMsg):
    "A DDCMP Data message (normal acknowledged data)"
    soh = SOH
    
class MaintMsg (BaseDataMsg):
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
        
class _DDCMP (datalink.PtpDatalink):
    counter_class = DdcmpCounters
    
    """An implementation of the DDCMP protocol.  This conforms to the
    Digital Network Architecture DDCMP protocol spec, V4.1 (AA-K175A-TK).
    It is also interoperable with the DDCMP implementation in SIMH,
    see the source code in pdp11_dmc.c.

    The current implementation supports point to point full duplex mode
    only.  Half duplex and multipoint could be added but probably will
    not be since there is no obvious point in doing so.

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
        super ().__init__ (owner, name, config)
        self.config = config
        self.qmax = config.qmax
        # Timout values.  These are the ones that apply to the
        # connectionless case (UDP or serial link); the TCP subclass
        # overrides some of them.
        self.acktmr = Backoff (1, 60)
        self.stacktmr = Backoff (3, 120)
        self.init_state ()
        
    def init_state (self):
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
        # Stop any timer
        self.node.timers.stop (self)
        
    def cansend (self):
        return (self.n - self.a) < self.qmax
    
    def connected (self):
        # We're connected.  Stop the timer, and start DDCMP protocol
        # operation.
        self.init_state ()
        # Initialize the timeout values
        self.acktmr.reset ()
        self.stacktmr.reset ()
        # Send a start message
        self.send_start ()
        return self.Istart

    def do_restart (self):
        if self.state == self.running:
            # Tell the owner that we lost state
            self.report_down ()
        elif self.state == self.Maint:
            # TODO: Tell the owner that we lost state
            pass
        if self.state != self.Istart:
            # If we aren't already restarting, handle this much like
            # initial connection, we initialize the timers and restart
            # the protocol.
            logging.trace ("Restarting DDCMP")
            self.connected ()
            self.set_state (self.Istart)
        return self.Istart

    def header_search (self):
        """Search for the DDCMP header in the input stream (for serial
        and TCP modes).  The simple scheme of looking for a header start
        and then taking in 7 more bytes doesn't work if the other side
        is repeatedly sending the same control message just after sync
        was lost, and that message has what looks like a header start
        byte at some other offset in the header.
        """
        while True:
            # Get the first byte.
            c = self.readbytes (1)
            while c:
                h = c[0]
                if h == ENQ or h == SOH or h == DLE:
                    # Valid start of header.  Receive the rest of the header.
                    c += self.readbytes (HDRLEN - len (c))
                    # Check the Header CRC
                    crc = CRC16 (c)
                    if crc.good:
                        if not self.insync:
                            logging.trace ("Back in sync on {}", self.name)
                        self.insync = True
                        return c
                    # Header CRC is bad.  If we're in sync, report
                    # that as a bad header.  If not, treat it as
                    # message not framed correctly, and silently
                    # keep looking.
                    logging.tracepkt ("bad header CRC on {}",
                                      self.name, pkt = c)
                    if self.insync:
                        self.insync = False
                        self.node.addwork (Err (self, R_HCRC))
                        self.counters.data_errors_inbound += (1, DE_HCRC)
                        logging.trace ("Lost sync on {}", self.name)
                    else:
                        logging.trace ("Out of sync, another HCRC error on {}",
                                       self.name)
                # Search through the 8 bytes we just received to see if
                # any of them look like another valid header start.
                # Just keep stripping off bytes from the start one at a
                # time and re-examining the first of what's left to see
                # if that too looks like a header.
                c = c[1:]

    def handle_pkt (self, pkt, c):
        # Handle a parsed packet
        tp = pkt.__class__.__name__
        if isinstance (pkt, CtlMsg):
            # Control packet.
            logging.tracepkt ("Received {} control packet on {}",
                              tp, self.name, pkt = c)
            self.node.addwork (Received (self, packet = pkt))
        elif pkt.crcok:
            # Data packet with good data CRC.
            logging.tracepkt ("Received {} packet on {}",
                              tp, self.name, pkt = c)
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
            self.counters.data_errors_inbound += (1, DE_CRC)
            logging.tracepkt ("{} packet with bad data CRC on {}",
                              tp, self.name, pkt = c)
            logging.debug ("{} packet with bad data CRC on {}",
                           tp, self.name)
            self.node.addwork (e)
        
    def sendmsg (self, msg, timeout):
        """Do the common work for sending the supplied message.  If the
        message has a "resp" field that needs to be filled in, it is
        filled in from the current state (the last correctly received
        message).

        For data messages, the "payload" attributes must contain the
        message payload.  Its length will be placed in the packet header
        during the encode process.  For all packet types, encode will
        insert the correct CRC values.  This part will be handled by the 
        subclasses.

        The optional timeout argument is a Backoff object which will be
        used to obtain the timeout to start after sending the message.
        Specify zero or None for no timeout.
        """
        # If the message has a "resp" field, set it.  Note that "hasattr"
        # does not work for this because, if it has never been set, the
        # object does not in fact have that attribute.
        if msg.setresp:
            msg.resp = self.r
            self.ackflag = False    # No more need for ACK
        if timeout:
            self.node.timers.jstart (self, timeout.next ())

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
                self.stacktmr.reset ()
                self.send_stack ()
                return self.Astart
            elif isinstance (data, StackMsg):
                return self.running_state (True)
            elif isinstance (data, MaintMsg):
                self.init_state ()
                self.set_state (self.Maint)
                self.Maint (data)
                return self.Maint
            else:
                # Unexpected message, we use the option of ignoring it
                # (rather than resending the Start message immediately).
                # That way, we don't generate a message flood if things
                # get very confused.
                pass
        elif isinstance (data, datalink.ThreadExit):
            self.reconnect ()
        # By default, no state change.  Note that we don't need to
        # handle a Restart work item since we're in the right state
        # already.
        return None

    @setlabel ("Start ACK")
    def Astart (self, data):
        """Astarted state -- we get here after the connection is up and we
        have sent the Stack message.

        See DDCMP spec table 3, "Startup state table".
        """
        if isinstance (data, (timers.Timeout, StartMsg)):
            self.send_stack ()
        elif isinstance (data, Received):
            pkt = data.packet
            if isinstance (pkt, StackMsg):
                return self.running_state (True)
            elif isinstance (pkt, MaintMsg):
                # Set state to Maintenance, then process the message
                # as for that state
                self.init_state ()
                self.set_state (self.Maint)
                self.Maint (data)
                return self.state    # Make state change explicit in trace
            elif isinstance (pkt, (AckMsg, DataMsg)) and pkt.resp == 0:
                # Ack or data with RESP = 0, set running state, stop the
                # timer, then process the received data or ACK message
                # as usual
                self.set_state (self.running_state (False))
                self.running (data)
                return self.state    # Make state change explicit in trace
            else:
                # Unexpected message, we use the option of ignoring it
                # (rather than resending the Stack message immediately).
                # That way, we don't generate a message flood if things
                # get very confused.
                pass
        elif isinstance (data, datalink.Restart):
            # Restart the DDCMP protocol.
            return self.do_restart ()
        elif isinstance (data, datalink.ThreadExit):
            self.reconnect ()
        # By default, no state change
        return None
        
    def running_state (self, ack):
        """Enter running state.  "ack" is True to send Ack message.
        """
        # Tell the routing init layer that this datalink is running
        self.report_up ()
        logging.trace ("Enter DDCMP running state on {}", self.name)
        self.node.timers.stop (self)
        if ack:
            # Send an ack to tell the other end
            self.send_ack ()
        # Return what we want for next state.
        return self.running

    @setlabel ("Running")
    def running (self, data):
        if isinstance (data, Received):
            data = data.packet
            if isinstance (data, DataMsg):
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
                if self.port:
                    self.counters.bytes_recv += len (msg)
                    self.counters.pkts_recv += 1
                    self.node.addwork (Received (self.port.owner, packet = msg))
                else:
                    logging.trace ("Message discarded, no port open")
            elif isinstance (data, AckMsg):
                self.process_ack (data)
            elif isinstance (data, NakMsg):
                # Count the error reported by the other side
                try:
                    d_err, bit = nak_map[data.subtype]
                    if d_err:
                        self.counters.data_errors_outbound += (1, bit)
                    else:
                        self.counters.remote_buffer_errors += (1, bit)
                except KeyError:
                    pass
                # A Nak acknowledges everything preceding the error
                if self.process_ack (data):
                    # Now retransmit the rest, given that it was a good Nak
                    # (i.e., resp field is in the correct range)
                    self.retransmit ()
            elif isinstance (data, RepMsg):
                self.counters.remote_reply_timeouts += 1
                if data.num == self.r:
                    self.ackflag = True
                else:
                    # Rep number does not match our latest, send NAK
                    self.counters.data_errors_inbound += (1, DE_REP)
                    self.send_nak (R_REP)
            elif isinstance (data, MaintMsg):
                # Set state to Maintenance, then process the message
                # as for that state
                self.init_state ()
                self.report_down ()
                self.set_state (self.Maint)
                self.Maint (data)
                return self.state    # Make state change explicit in trace
            elif isinstance (data, StartMsg):
                # Start while running, restart the circuit
                self.do_restart ()
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
        elif isinstance (data, datalink.Restart):
            # Restart the protocol.
            return self.do_restart ()
        elif isinstance (data, datalink.ThreadExit):
            self.reconnect ()
            return None
        # Done processing the incoming event.  If we now have an ACK to
        # send, that means this wasn't satisfied by an outgoing data
        # message that resulted from what we just did, so send an
        # actual ACK message.
        if self.ackflag:
            self.send_ack ()

    # Helper routines for the various states

    def send_start (self):
        msg = StartMsg ()
        self.sendmsg (msg, self.stacktmr)

    def send_stack (self):
        msg = StackMsg ()
        self.sendmsg (msg, self.stacktmr)

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
        self.sendmsg (msg, self.acktmr)

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
            self.node.timers.jstart (self, self.acktmr.next ())
        else:
            # No transmits pending, stop timer
            self.node.timers.stop (self)
            # Reinitialize the backoff timer to the minimum
            self.acktmr.reset ()
        # If we now can transmit more (because the number of pending
        # messages is < qmax) and there are messages waiting, send
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
            self.sendmsg (msg, self.acktmr)
            
    @setlabel ("Maintenance")
    def Maint (self, data):
        if isinstance (data, Received):
            data = data.packet
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
                # obvious way to do that, so instead let's restart if we
                # get a Start.
                self.do_restart ()
        elif isinstance (data, datalink.Restart):
            # Restart the protocol.
            return self.do_restart ()
        elif isinstance (data, datalink.ThreadExit):
            self.reconnect ()
            return None
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
                self.sendmsg (msg, self.acktmr)

class _SerialDDCMP (_DDCMP):
    def __init__ (self, owner, name, config):
        super ().__init__ (owner, name, config)
        self.dev, *rest = config.device.split (":")
        if len (rest) > 2:
            raise ValueError ("Invalid serial device spec {}".format (config.device))
        self.uart = None
        if len (rest):
            self.speed = int (rest[0])
            if len (rest) > 1:
                if not UART:
                    raise ValueError ("BeagleBone UART module not available")
                self.uart = rest[1]
        else:
            self.speed = 9600
        if self.uart:
            UART.setup (self.uart)
        logging.trace ("DDCMP datalink {} initialized on device {}"
                       " speed {}", self.name, self.dev, self.speed)

    def connect (self):
        # Open the serial link.  Note that we're after the point where
        # the process is made into a daemon, if applicable, which is
        # important so open file descriptors stay open.
        self.serial = serial.Serial (port = self.dev, baudrate = self.speed,
                      parity = 'N', bytesize = 8, timeout = 5)
        logging.trace ("Opened serial port {}, speed {}", self.dev, self.speed)
    
    def disconnect (self):
        try:
            self.serial.close ()
        except Exception:
            pass
        self.serial = None

    def check_connection (self):
        logging.trace ("DDCMP {} listen on UART {} active",
                       self.name, self.dev)
        return True

    def readbytes (self, n):
        ret = b''
        while len (ret) < n:
            if self.rthread and self.rthread.stopnow:
                raise IOError
            ret += self.serial.read (n - len (ret))
        return ret
    
    def receive_loop (self):
        self.insync = False
        # Start looking for messages.
        while True:
            # Get a good header
            try:
                c = self.header_search ()
            except IOError:
                # Stop signal, quit
                return
            # Decode via the header base class, which will
            # identify the actual message type using packet
            # class indexing and return that.  Tell decode
            # that the header CRC has already been checked.
            try:
                pkt, x = DMHdr.decode (c, self.readbytes, False)
                self.handle_pkt (pkt, c)
            except DecodeError as e:
                logging.tracepkt ("Invalid packet: {}", e, pkt = c)

    def sendmsg (self, msg, timeout):
        super ().sendmsg (msg, timeout)
        # Just encode the message; CRCs are handled by the encoder.
        msg = msg.encode ()
        try:
            # Append a DEL byte.  No sync bytes in front, they
            # aren't useful for async connections.
            msg = msg + DEL1
            if logging.tracing:
                logging.tracepkt ("Sending packet on {}",
                                  self.name, pkt = msg)
            self.serial.write (msg)
        except (OSError, AttributeError):
            # AttributeError happens if self.serial has been changed
            # to "None"
            return

class _TcpDDCMP (_DDCMP):
    def __init__ (self, owner, name, config):
        super ().__init__ (owner, name, config)
        # TCP uses different timeouts because the underlying channel
        # also does retransmissions.
        self.acktmr = Backoff (5, 60)
        self.stacktmr = Backoff (5, 120)
        self.conntmr = Backoff (5, 120)
        self.telnet = (config.mode == "telnet")
        self.source = host.SourceAddress (config, config.source_port)
        if not self.source.can_listen:
            raise ValueError ("Source port must be specified")
        # This is the source address to bind to for the outgoing
        # connection, same as above but with the port number
        # defaulted.
        self.csource = host.SourceAddress (config, 0)
        self.dest = host.HostAddress (config.destination, config.dest_port,
                                      self.source, any = True)
        # All set
        logging.trace ("DDCMP datalink {} initialized on {} to {} ",
                       self.name, self.source, self.dest)

    def handle_reconnect (self, item):
        super ().handle_reconnect (item)
        
    def connect (self):
        # We'll try for either outbound or incoming connections, whichever
        # appears first.  Create the inbound (listen) socket here.
        self.socket = self.source.create_server ()
        logging.trace ("DDCMP {} listen on {} active",
                       self.name, self.source)
        # Start the connection, except in "any address" mode.
        if self.dest.can_connect:
            self.connsocket = self.dest.create_connection (self.csource)
            logging.trace ("DDCMP {} connect to {} in progress",
                           self.name, self.dest)
            # Next time around, try the next address, in case we have
            # several to try from.
            next (self.dest)
            # Wait a random time, initially in the 5 second range but
            # slowing down as we do more retries, for the outbound
            # connection to succeed.  If we get a timeout, give up on
            # it and try again.
            self.node.timers.jstart (self, self.conntmr.next ())
        else:
            self.connsocket = None
            logging.trace ("DDCMP {} not connecting, any-address mode",
                           self.name)

    def check_connection (self):
        self.insync = False
        poll = select.poll ()
        if self.connsocket:
            cfn = self.connsocket.fileno ()
            poll.register (cfn, datalink.REGPOLLOUT)
        else:
            cfn = None
        sfn = self.socket.fileno ()
        poll.register (sfn, datalink.REGPOLLIN)
        # We try to establish an outgoing connection while also looking
        # for an incoming one, so look for both ready to read on the
        # listen socket (incoming) and ready to write on the connect socket
        # (outbound connect completed).
        connected = False
        while not connected:
            plist = poll.poll (datalink.POLLTS)
            if self.rthread and self.rthread.stopnow:
                return False
            for fd, event in plist:
                if fd == cfn:
                    # Event on the connect socket.
                    if event & datalink.POLLERRHUP:
                        # Connection was closed or hit an error,
                        # ignore this.  Do the full cleanup just in
                        # case the OS likes it better that way.  The
                        # main thread will retry when it times out (if
                        # the listen doesn't give us a connection
                        # before then).
                        try:
                            self.connsocket.shutdown (socket.SHUT_RDWR)
                        except Exception:
                            pass
                        self.connsocket.close ()
                        self.connsocket = None
                        poll.unregister (cfn)
                        continue
                    # Outbound connection went through.  Stop listening,
                    # and use that connection for data.
                    self.socket.close ()
                    self.socket = self.connsocket
                    self.socket.setblocking (True)
                    self.connsocket = None
                    logging.trace ("DDCMP {} outbound connection made",
                                   self.name)
                    # Drop out of the outer loop
                    connected = True
                    break
                elif fd == sfn:
                    # Ready on inbound socket.  Accept the connection.
                    try:
                        sock, ainfo = self.socket.accept ()
                        if self.dest.valid (ainfo):
                            # Good connection, stop looking
                            self.socket.close ()
                            # Stop any timer
                            self.node.timers.stop (self)
                            if self.connsocket:
                                try:
                                    # Just in case there's an active
                                    # connection on that socket right
                                    # now.
                                    self.connsocket.shutdown (socket.SHUT_RDWR)
                                except Exception:
                                    pass
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
                        return False
        logging.trace ("DDCMP {} connected", self.name)
        self.conntmr.reset ()
        return True

    def readbytes (self, sz):
        """Receive "sz" bytes of data from the socket.  This waits until
        it has that much available.  If the connection was closed, raises
        OSError; otherwise, it returns exactly the amount requested.
        """
        if self.telnet:
            p = b''
            while len (p) < sz:
                b = self.recvall (sz - len (p))
                # Handle escapes.  Note that we only handles escaped
                # 377, not any other Telnet control codes.
                e = b.count (DEL1)
                if e & 1:
                    b2 = self.recvall (1)
                    b += b2
                if e:
                    b = b.replace (DEL2, DEL1)
                p += b
        else:
            p = self.recvall (sz)
        return p
    
    def receive_loop (self):
        poll = select.poll ()
        sock = self.socket
        poll.register (sock, datalink.REGPOLLIN)
        # Start looking for messages.
        while True:
            plist = poll.poll (datalink.POLLTS)
            for fd, event in plist:
                if event & datalink.POLLERRHUP:
                    # Error or disconnect, quit.
                    return
                # Not error, so it's incoming data.  Get a good header
                try:
                    c = self.header_search ()
                except IOError:
                    # Stop signal or connection lost, quit
                    return
                # Decode via the header base class, which will
                # identify the actual message type using packet
                # class indexing and return that.  Tell decode
                # that the header CRC has already been checked.
                try:
                    pkt, x = DMHdr.decode (c, self.readbytes, False)
                    if logging.tracing and isinstance (pkt, BaseDataMsg):
                        # We want to log the packet, make sure the
                        # payload is included as part of the log
                        # message.  (The "c" argument to handle_pkt is
                        # used for a tracepkt call; the message
                        # dispatching uses the "pkt" argument.)
                        c = (c, pkt.payload)
                    self.handle_pkt (pkt, c)
                except DecodeError as e:
                    logging.tracepkt ("Invalid packet: {}", e, pkt = c)

    def disconnect (self):
        try:
            self.socket.shutdown (socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.socket.close ()
        except Exception:
            pass
        try:
            self.connsocket.shutdown (socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.connsocket.close ()
        except Exception:
            pass
        self.socket = self.connsocket = None

    def sendmsg (self, msg, timeout):
        super ().sendmsg (msg, timeout)
        # Just encode the message; CRCs are handled by the encoder.
        msg = msg.encode ()
        try:
            msg = SYN4 + msg + DEL1
            if self.telnet:
                msg = msg.replace (DEL1, DEL2)
            if logging.tracing:
                logging.tracepkt ("Sending packet on {}",
                                  self.name, pkt = msg)
            self.socket.sendall (msg)
        except (OSError, AttributeError):
            # AttributeError happens if socket has been changed to "None"
            self.reconnect ()
            return

class _UdpDDCMP (_DDCMP):
    def __init__ (self, owner, name, config):
        super ().__init__ (owner, name, config)
        # Todo: ANY support
        self.source = host.SourceAddress (config, config.source_port)
        if not self.source.can_listen:
            raise ValueError ("Source port must be specified")
        self.dest = host.HostAddress (config.destination, config.dest_port,
                                      self.source)
        # All set
        logging.trace ("DDCMP datalink {} initialized using UDP on "
                       "port {} to {}", self.name, config.source_port,
                       self.dest)

    def connect (self):
        self.socket = self.dest.create_udp (self.source)

    def disconnect (self):
        try:
            self.socket.close ()
        except Exception:
            pass
        self.socket = None

    def check_connection (self):
        logging.trace ("DDCMP {} UDP on to {} active",
                       self.name, self.dest)
        return True
    
    def receive_loop (self):
        poll = select.poll ()
        sock = self.socket
        sfn = sock.fileno ()
        poll.register (sfn, datalink.REGPOLLIN)
        # Start looking for messages.
        while True:
            plist = poll.poll (datalink.POLLTS)
            if self.rthread and self.rthread.stopnow:
                return
            for fd, event in plist:
                if event & datalink.POLLERRHUP:
                    # Error (or disconnect, whatever that means)
                    return
                # Not error, so it's incoming data.  Get the UDP packet
                try:
                    # Allow for a max length DDCMP data message plus some sync
                    msg, addr = sock.recvfrom (16400)
                except OSError:
                    msg = None
                if not msg:
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
                    if len (c) < HDRLEN:
                        # Not enough data to make a valid DDCMP header.
                        # Call it a header CRC error since that's what
                        # the real hardware would do (it would read past
                        # the data we found, picking up garbage bytes to
                        # make up the missing amount).
                        raise HdrCrcError
                    pkt, x = DMHdr.decode (c)
                except HdrCrcError:
                    # Header CRC is bad.  Report it.
                    logging.tracepkt ("Header CRC error", pkt = c)
                    self.counters.data_errors_inbound += (1, DE_HCRC)
                    self.node.addwork (Err (self, R_HCRC))
                    continue
                except DecodeError as e:
                    logging.tracepkt ("Invalid packet: {}", e, pkt = c)
                    self.node.addwork (Err (self, R_FMT))
                    continue
                self.handle_pkt (pkt, c)

    def sendmsg (self, msg, timeout):
        super ().sendmsg (msg, timeout)
        # Just encode the message; CRCs are handled by the encoder.
        msg = msg.encode ()
        try:
            if logging.tracing:
                logging.tracepkt ("Sending packet on {}",
                                  self.name, pkt = msg)
            self.socket.sendto (msg, self.dest.sockaddr)
        except (OSError, AttributeError, TypeError):
            # AttributeError happens if socket has been changed to "None"
            self.reconnect ()
            return

# Factory class -- returns an instance of the appropriate _DDCMP
# subclass instance given the specific device flavor specified.
class DDCMP (datalink.Datalink):
    def __new__ (cls, owner, name, config):
        api = config.mode
        if not api:
            # Legacy configuration via device argument, convert that
            api, dev = config.device.split (":", 1)
            config.mode = api = api.lower ()
            if api == "serial":
                config.device = dev
            else:
                x, *rest = config.device.split (":")
                lport, config.destination, rport = rest
                config.source_port = int (lport)
                config.dest_port = int (rport)
        if api == "serial":
            if not serial:
                raise ValueError ("Serial port support not available")
            c = _SerialDDCMP
        elif api == "tcp" or api == "telnet":
            c = _TcpDDCMP
        elif api == "udp":
            c = _UdpDDCMP
        else:
            raise ValueError ("Unknown DDCMP circuit subtype {}".format (api))
        return c (owner, name, config)

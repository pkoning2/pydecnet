#!

"""DDCMP datalink.

"""

import select
import socket
import queue
import errno

import crc

from .common import *
from . import logging
from . import timers
from . import datalink
from . import packet
from . import statemachine
from . import modulo

SvnFileRev = "$LastChangedRevision$"

# The CRC-16 polynomial; see section D.2 of the DDCMP spec.
class CRC16 (crc.CRC, poly = (16, 15, 2, 0)): pass

# DDCMP sequence numbers.  Note that these are mod 256 but not exactly
# RFC 1982 compatible, because the number of pending messages is allowed
# to go all the way to modulus - 1 rather than only up to modulus / 2.
class Seq (modulo.Mod, mod = 256): pass
    
# DDCMP byte codes that have specific meanings
SOH = 0o201        # SOH - start of data message
ENQ = 0o005        # ENQ - start of control message
DLE = 0o220        # DLE - start of maintenance message
SYN = 0o226        # SYN - synchronization code
DEL = 0o377        # DEL - pad after message trailer

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

class DMMsg (packet.Packet):
    _addslots = { "payload" }
    # baselayout is the layout of the header without the Header CRC.
    # We need that so we can encode using that layout, to get the header
    # bytes over which to compute the CRC.
    baselayout = (( "b", "soh", 1 ),
               ( "bm",
                 ( "count", 0, 14 ),
                 ( "qsync", 14, 1 ),
                 ( "select", 15, 1 )),
               ( "b", "resp", 1 ),
               ( "b", "num", 1 ),
               ( "b", "addr", 1 ))
    _layout = baselayout + (( "bv", "hcrc", 2 ),)
    addr = 1
DMMsg.basetable = packet.process_layout (DMMsg, DMMsg.baselayout)

class DataMsg (DMMsg):
    soh = SOH

class MaintMsg (DMMsg):
    # Maintenance message is like regular data message, but
    # different start byte and no sequence numbers.  We don't
    # simply subclass it from DataMsg because then it a maint
    # message would be an instance of DataMsg which will make
    # the code more confusing and error-prone.
    soh = DLE
    qsync = 1
    select = 1
    resp = 0
    num = 0

# Control messages are similar but with type and subtype fields
# instead of the count field, since there is no payload.
class CtlMsg (packet.Packet):
    baselayout = (( "b", "enq", 1 ),
               ( "b", "type", 1 ),
               ( "bm",
                 ( "subtype", 0, 6 ),
                 ( "qsync", 6, 1 ),
                 ( "select", 7, 1 )),
               ( "b", "resp", 1 ),
               ( "b", "num", 1 ),
               ( "b", "addr", 1 ))
    _layout = baselayout + (( "bv", "hcrc", 2 ),)
    enq = ENQ
    addr = 1
CtlMsg.basetable = packet.process_layout (CtlMsg, CtlMsg.baselayout)

HDRLEN = len (CtlMsg ())

class AckMsg (CtlMsg):
    type = ACK
    subtype = 0
    num = 0

class NakMsg (CtlMsg):
    type = NAK
    num = 0

class RepMsg (CtlMsg):
    type = REP
    subtype = 0
    resp = 0

class StartMsg (CtlMsg):
    type = STRT
    subtype = 0
    qsync = 1
    select = 1
    resp = 0
    num = 0

class StackMsg (CtlMsg):
    type = STACK
    subtype = 0
    qsync = 1
    select = 1
    resp = 0
    num = 0

class Err (Work):
    """A work item that indicates a bad received message.  The "code" attribute
    says what specifically was wrong.  The code values are taken from the
    DDCMP protocol coding of NAK message reason codes.
    """
    def __init__ (self, code):
        self.code = code
        self.resp = None
        
ctlmsgs = { c.type : c for c in (AckMsg, NakMsg, RepMsg, StartMsg, StackMsg ) }

class DDCMP (datalink.PtpDatalink, statemachine.StateMachine):
    """An implementation of the DDCMP protocol.  This conforms to the
    Digital Network Architecture DDCMP protocol spec, V4.1 (AA-K175A-TK).
    It is also interoperable with the DDCMP implementation in SIMH,
    see the source code in pdp11_dmc.c.

    The current implementation supports point to point full duplex mode
    only.  Half duplex and multipoint are TBD.

    Communication is either via UDP or TCP.  If UDP, each packet corresponds
    exactly to a DDCMP message.  In TCP, the byte stream carries the DDCMP
    messages and this module will do the framing just as it is done on
    an asynchronous serial link.

    The device parameter is of the form proto:lport:host:rport.  Proto is
    "tcp", "udp" or "telnet".  Lport is the local port number (an integer).
    Host is the peer host name or address.  Rport is the peer port number.
    If TCP is used, the local port number is bound and outbound connections
    are attempted to the peer; whichever side establishes a connection first
    will have that connection used.  This matches what SIMH does in the
    sim_tmxr.c module.  (TBD: how are race conditions resolved?)  Incoming
    connections are accepted only from the specified peer.

    If UDP is used, traffic is between the specified local port and the
    peer address/port.  Incoming packets are accepted only from that peer.

    TELNET is a variant of TCP; in this mode, all-ones bytes are escaped
    according to TELNET protocol rules.  This supports connections via
    telnet servers to async ports running DDCMP.

    In TCP mode, message resynchronization is done by the "Header CRC" method: 
    the byte stream is searched for a valid start of header byte, and if the
    bytes starting at that point constitute a header with a valid Header CRC,
    it is assumed that we have framed the message correctly.  The transmitted
    byte stream contains four SYN bytes before each message and one DEL
    byte after it, in conformance with the DDCMP spec recommendations.
    Resynchronization is only needed after an error; once sync has been
    established, it is presumed to remain in effect until an error occurs.
    For example, a Header CRC error will be detected and counted as such
    if the link is in sync (but a second Header CRC error immediately following
    will not be, since at that point sync is not established).

    In UDP mode, framing is implicit: each UDP packet contains a DDCMP
    message.  The message may be preceded and/or followed by fill bytes
    (DEL or SYN); these are ignored.  Transmitted UDP packets contain no
    leading or trailing fillers.  
    """
    def __init__ (self, owner, name, config):
        self.tname = "{}.{}".format (owner.node.nodename, name)
        self.rthread = None
        statemachine.StateMachine.__init__ (self)
        datalink.PtpDatalink.__init__ (self, owner, name, config)
        self.config = config
        proto, lport, host, rport = config.device.split (':')
        proto = proto.lower ()
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
        if self.tcp:
            # We'll try for either outbound or incoming connections, whichever
            # appears first.  Create the inbound (listen) socket here.
            self.socket = socket.socket (socket.AF_INET)
        else:
            self.socket = socket.socket (socket.AF_INET, socket.SOCK_DGRAM,
                                         socket.IPPROTO_UDP)
        dont_close (self.socket)
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
        except (OSError, socket.error):
            logging.trace ("DDCMP {} bind/listen failed", self.name)
            self.socket.close ()
            return
        logging.trace ("DDCMP {} listen to {} active",
                       self.name, self.rport)
        self.rthread.start ()

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
            self.rthread.join (5)
            self.rthread = None
            self.close_sockets ()

    def disconnected (self):
        if self.state == self.running and self.port:
            self.node.addwork (datalink.DlStatus (self.port.owner,
                                                  status = False))
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
            p += b
        if not self.socket:
            raise OSError
        return p
    
    def ctlmsg (self, msg):
        """Convert the supplied message data (8 bytes) into the corresponding
        specific message (packet) object, wrapped in a Received work item.
        If it isn't a valid type, return an error object instead.
        """
        try:
            c = ctlmsgs[msg[1]]
            return Received (self, packet = c (msg))
        except KeyError:
            return Err (R_FMT)

    def run (self):
        """This method runs the receive thread.  Here we look for connections
        (if in TCP mode) and receive the incoming data.  Message framing
        is done here.  Received messages and error indications are passed
        down to the DDCMP state machine which runs in the main thread.
        """
        logging.trace ("DDCMP datalink {} receive thread started", self.name)
        if not self.socket:
            return
        # Split out the two cases since they are rather different.
        if self.tcp:
            self.run_tcp ()
        else:
            self.run_udp ()
        logging.trace ("DDCMP datalink {} receive thread stopped", self.name)

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
            if (self.rthread and self.rthread.stopnow):
                self.disconnected ()
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
            if (self.rthread and self.rthread.stopnow):
                self.disconnected ()
                return
            for fd, event in plist:
                if event & select.POLLERR:
                    pstate = self.state
                    self.disconnected ()
                    if pstate == self.Istart:
                        self.state = self.reconnect
                    return
                # Not error, so it's incoming data.  Get the first byte.
                c = sock.recv (1)
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
                        if h == ENQ:
                            # Control packet.
                            self.node.addwork (self.ctlmsg (c))
                            continue
                        if h == SOH:
                            c = DataMsg (c)
                        else:
                            c = MaintMsg (c)
                        # At this point we have parsed the header, but
                        # not yet received or checked the payload.  Given
                        # the header, we now have the payload length.
                        # Go receive the payload and data CRC.
                        data = self.recvall (c.count)
                        crc = CRC16 (data)
                        crc.update (self.recvall (2))
                        if crc.good:
                            # Good data CRC.
                            c.payload = data
                            self.node.addwork (Received (self, packet = c))
                        else:
                            # Fun complication: if the data CRC of a data
                            # (not maintenance) message is bad, we're
                            # still expected to act on the received ack
                            # number (the "resp" field).  So pass that
                            # along.
                            e = Err (R_CRC)
                            if h == SOH:
                                e.resp = c.resp
                            self.node.addwork (e)
                    else:
                        # Header CRC is bad.  If we're in sync, report
                        # that as a bad header.  If not, treat it as
                        # message not framed correctly, and silently
                        # keep looking
                        if self.insync:
                            self.insync = False
                            self.node.addwork (Err (R_HCRC))
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
            if (self.rthread and self.rthread.stopnow):
                self.disconnected ()
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
                # Check for format error (not good packet start, or not
                # enough data for a DDCMP header)
                if len (msg) - i < HDRLEN:
                    self.node.addwork (Err (R_FMT))
                    continue
                # Check the Header CRC
                hdr = msg[i:i + HDRLEN]
                crc = CRC16 (hdr)
                if crc.good:
                    # Header CRC is valid.  Construct a packet object
                    # of the correct class.
                    if h == ENQ:
                        # Control packet.
                        self.node.addwork (self.ctlmsg (hdr))
                        continue
                    if h == SOH:
                        c = DataMsg (hdr)
                    else:
                        c = MaintMsg (hdr)
                    # At this point we have parsed the header, but not
                    # yet checked the payload.  Given the header, we
                    # now have the payload length.  Go pick up the
                    # payload and data CRC.
                    i += HDRLEN
                    if len (msg) < i + c.count + 2:
                        # Packet too short for payload
                        self.node.addwork (Err (R_FMT))
                        continue
                    dlen = c.count
                    data = msg[i:i + dlen]
                    crc = CRC16 (data)
                    crc.update (msg[i + dlen:i + dlen + 2])
                    if crc.good:
                        # Good data CRC.
                        c.payload = data
                        self.node.addwork (Received (self, packet = c))
                    else:
                        # Fun complication: if the data CRC of a data
                        # (not maintenance) message is bad, we're
                        # still expected to act on the received ack
                        # number (the "resp" field).  So pass that
                        # along.
                        e = Err (R_CRC)
                        if h == SOH:
                            e.resp = c.resp
                        else:
                            e.resp = None
                        self.node.addwork (e)
                else:
                    # Header CRC is bad.  Report it.
                    self.node.addwork (Err (R_HCRC))

    def sendmsg (self, msg, timeout = ACKTMR):
        """Send the supplied message.  If the message has a "resp" field,
        that is filled in from the current state (the last correctly received
         message).  Then the header CRC is set, to allow that field and any
        other header fields to be modified as needed right up to the point
        that the message is sent.

        For data messages, the "payload" attributes must both the message
        payload and the data CRC, and the "count" field musg have been set
        to the message payload length (i.e., the length of the "payload" 
        data minus 2).

        The optional timeout argument specified what timeout to start after
        sending the message.  The default is one second.  Specify zero
        for no timeout.
        """
        # If the message has a "resp" field, set it.  Note that "hasattr"
        # does not work for this because, if it has never been set, the
        # object does not in fact have that attribute.  But Packet
        # instances all have __slots__, which is a set of the field names,
        # so we test that.
        if "resp" in msg.__allslots__:
            msg.resp = self.r
            self.ackflag = False    # No more need for ACK
        # Ask the encoder to encode just the part preceding the header CRC.
        hdr = msg.encode (msg.basetable)
        crc = CRC16 (hdr)
        # Set the Header CRC
        msg.hcrc = bytes (crc)
        if logging.tracing:
            logging.trace ("Sending DDCMP message on {}: {}", self.name, msg)
        # Now encode the whole message
        msg = bytes (msg)
        try:
            if self.tcp:
                self.socket.sendall (msg)
            else:
                self.socket.sendto (msg, (self.host.addr, self.rport))
        except (OSError, AttributeError):
            # AttributeError happens if socket has been changed to "None"
            self.disconnected ()
        if timeout:
            self.node.timers.start (self, timeout)
            
    def s0 (self, data):
        """State machine for the Halted state -- ignore all received messages.
        """
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
            elif isinstance (pkt, (AckMsg, DataMsg)):
                # Set running state, stop the timer, then process
                # the received data or ACK message as usual
                self.state = self.running_state ()
                self.running (data)
                return self.state    # Make state change explicit in trace
            elif isinstance (pkt, MaintMsg):
                # Set state to Maintenance, then process the message
                # as for that state
                self.state = self.Maint
                self.Maint (data)
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
                                                  status = True))
        logging.trace ("Enter DDCMP running state on {}", self.name)
        self.node.timers.stop (self)
        # Send an ack to tell the other end
        self.send_ack ()
        # Return what we want for next state.
        return self.running

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
        if self.tcp:
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
        count = msg.resp - self.a
        pend = self.n - self.a
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
        while self.n + 1 != self.a:
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
            
    def Maint (self, data):
        if isinstance (data, MaintMsg):
            # Pass the payload up to our client.
            msg = data.payload
            logging.trace ("Received DDCMP maintenance message on {} len {}: {!r}",
                           self.name, len (msg), msg)
            # We don't have any maintenance ports yet, so for now just
            # discard the packet
            if False: #self.port:
                self.counters.bytes_recv += len (msg)
                self.counters.pkts_recv += 1
                self.node.addwork (Received (self.port.owner, packet = msg))
            else:
                logging.trace ("Message discarded, no port open")
        elif isinstance (data, StartMsg):
            # The spec says to "notify" the user.  There isn't any obvious
            # way to do that, so instead let's halt if we get a Start.
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
            if self.n + 1 == self.a:
                # Can't send now, queue it for when an ACK arrives
                self.notsent.put (data)
                return
            # Advance the next sequence number.
            self.n += 1
            data = bytes (data)
            mlen = len (data)
            if logging.tracing:
                logging.trace ("Sending DDCMP message on {} len {}: {!r}",
                               self.name, mlen, data)
            self.counters.bytes_sent += mlen
            self.counters.pkts_sent += 1
            # Build a DDCMP Data message.
            crc = CRC16 (data)
            msg = DataMsg (payload = data + bytes (crc), count = mlen,
                           num = self.n)
            # Put it into the unacked message list
            assert (self.unack[self.n] is None)
            self.unack[self.n] = msg
            if not queue:
                self.sendmsg (msg)
            

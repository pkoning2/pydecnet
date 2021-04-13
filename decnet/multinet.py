#!

"""Multinet over TCP or UDP "datalink" implementation.

Multinet, even when run over TCP, fails to meet many of the
requirements the routing spec imposes on point to point datalinks.  In
particular, there is no data link startup at the protocol level, so a
remote datalink start is not visible.  The point to point datalink
dependent sublayer can work around that to some extent, given that it
is told to do so, by having"start_works" set to False in the port object.
"""

import re
import select
import socket

from .common import *
from . import datalink
from . import logging
from . import host

SvnFileRev = "$LastChangedRevision$"

class MultinetUdpPort (datalink.PtpPort):
    """Multinet is exactly like generic point to point except that the
    spurious start message workaround needs to be turned on if we use
    UDP.
    """
    start_works = False

dev_re = re.compile (r"(.*?):(\d*)(?:(:connect)|(:listen)|(:\d+))?$")

class _Multinet (datalink.PtpDatalink):
    """An implementation of the Multinet tunnel.  See multinet.c
    in the DECnet/Linux "dnprogs" source code for an earlier implementation
    that reasonably well describes how it works..

    In a nutshell: this uses UDP datagrams or a TCP connection.  For
    the UDP case, data packets are sent as UDP datagrams, preceded by
    a four byte header consisting of a two byte sequence number
    (little endian) plus two bytes of zero.  It's not clear that
    header is used by the receiver; it isn't in the Linux code.  The
    data then follows that header with no other processing.  For TCP,
    there is also a four byte header, but in this case the first
    two-byte field is the payload length (the amount of data after the
    4 byte header, little endian).
    
    The --device config parameter is required.  The device argument is
    "host" or "host:portnum"; if the port number is omitted the default
    (700) is assumed.  That is followed by ":connect" for the active end
    of a TCP connection, ":listen" for the passive end of a TCP
    connection, or neither for UDP mode where local and remote port
    numbers are the same, or the local port number if they do not match.
    For TCP listen mode, the host address may be omitted, in which case
    connections are accepted from any address.
    """
    # This serves as a default value if send or similar calls are
    # attemped before any socket has been created.
    socket = None
    
    def __init__ (self, owner, name, config):
        super ().__init__ (owner, name, config)
        self.config = config
        logging.debug ("Multinet datalink {} initialized:\n"
                       "  Mode:   {}\n"
                       "  Dest:   {}:{}\n"
                       "  Source: {}:{}",
                       self.name, config.mode,
                       config.destination, config.dest_port,
                       config.source, config.source_port)
        self.seq = 0

    def connected (self):
        # Tell the routing init layer that this datalink is running
        self.report_up ()
        return self.running

    def validate (self, item):
        if isinstance (item, datalink.Restart):
            # Treat Restart as Reconnect without holdoff
            item = datalink.Reconnect (self, True)
            self.set_state (self.handle_reconnect (item))
            return False
        return super ().validate (item)
    
    @setlabel ("Running")
    def running (self, data):
        # Running state.  This just passes up received messages.  We
        # come through the state to make sure all work is serialized
        # through the main thread.
        if isinstance (data, Received):
            msg = data.packet
            # Pass the message up to our client.
            if logging.tracing:
                logging.tracepkt ("Received Multinet message on {}",
                                  self.name, pkt = msg)
            if self.port:
                self.counters.bytes_recv += len (msg)
                self.counters.pkts_recv += 1
                self.node.addwork (Received (self.port.owner, packet = msg))
            else:
                logging.trace ("Message discarded, no port open")
        elif isinstance (data, datalink.ThreadExit):
            self.reconnect ()
        
class _TcpMultinet (_Multinet):
    def disconnect (self):
        if self.socket:
            # Shut down the socket, if any
            try:
                self.socket.shutdown (socket.SHUT_RDWR)
            except Exception:
                pass
            # Now close it
            try:
                self.socket.close ()
            except Exception:
                pass
            # Dereference the object (Linux wants this)
            self.socket = None
            
    def receive_loop (self):
        # Receive packets for the TCP modes, after the connection has
        # been made.
        while True:
            # Look for traffic.  Start with the header
            try:
                bc = self.recvall (4)
                bc = int.from_bytes (bc[:2], "little")
                # Now receive exactly the byte count mentioned
                msg = self.recvall (bc)
            except IOError:
                logging.trace ("Exception in receive loop", exc_info = True)
                return
            self.node.addwork (Received (self, packet = msg))
        
    def send (self, msg, dest = None):
        sock = self.socket
        if sock and self.state == self.running:
            msg = makebytes (msg)
            mlen = len (msg)
            if logging.tracing:
                logging.tracepkt ("Sending Multinet message on {}",
                                  self.name, pkt = msg)
            self.counters.bytes_sent += mlen
            self.counters.pkts_sent += 1
            # TCP mode
            hdr = mlen.to_bytes (2, "little") + b"\000\000"
            try:
                self.socket.send (hdr + msg)
            except (socket.error, AttributeError, OSError):
                # AttributeError happens if socket has been
                # changed to "None"
                logging.trace ("send error", exc_info = True)
                self.reconnect ()

class _ConnectMultinet (_TcpMultinet):
    def __init__ (self, owner, name, config):
        super ().__init__ (owner, name, config)
        self.conntmr = Backoff (5, 120)
        self.source = host.SourceAddress (config, config.source_port)
        self.dest = host.HostAddress (config.destination,
                                      config.dest_port, self.source)

    def connect (self):
        # Connect to the remote host
        try:
            self.socket = self.dest.create_connection (self.source)
            logging.trace ("Multinet {} connect to {} in progress",
                           self.name, self.dest)
        except (AttributeError, OSError, socket.error, TypeError) as e:
            # If we get a failure on the connect, log that but take no
            # other action.  The connection timer will still be
            # started and its timeout will cause a retry.  This
            # ensures we don't retry errors such as "interface down"
            # at high speed.  TypeError happens if host.addr is None,
            # which is the result we get from a failed name lookup.
            logging.trace ("Multinet {} connect to {} rejected",
                           self.name, self.dest)
            # Bad connect attempt, get rid of the failed socket
            if self.socket:
                self.socket.close ()
            self.socket = None
        # Next time we'll try the next address, if we have several.
        x=next (self.dest)
        logging.trace ("Next address is {}", x)
        # Wait a random time, initially in the 5 second range but
        # slowing down as we do more retries, for the outbound
        # connection to succeed.  If we get a timeout, give up on it and
        # try again.
        self.node.timers.jstart (self, self.conntmr.next ())

    def check_connection (self):
        # Wait for the socket to become writable, that means the
        # connection has gone through
        sock = self.socket
        if not sock:
            return False
        p = select.poll ()
        p.register (sock, datalink.REGPOLLOUT)
        while True:
            try:
                pl = p.poll (datalink.POLLTS)
            except select.error:
                logging.trace ("Poll error", exc_info = True)
                return False
            if self.rthread and self.rthread.stopnow:
                return False
            if not pl:
                continue
            fn, mask = pl[0]
            if mask & datalink.POLLERRHUP:
                return False
            if mask & select.POLLOUT:
                logging.trace ("Multinet {} connected", self.name)
                return True

class _ListenMultinet (_TcpMultinet):
    def __init__ (self, owner, name, config):
        super ().__init__ (owner, name, config)
        self.conntmr = Backoff (5, 120)
        self.source = host.SourceAddress (config, config.source_port)
        self.dest = host.HostAddress (config.destination,
                                      config.dest_port, self.source,
                                      any = True)
        
    def connect (self):
        try:
            self.socket = self.source.create_server ()
            logging.trace ("Multinet {} bind {} done",
                           self.name, self.source)
        except (AttributeError, OSError, socket.error):
            logging.trace ("Multinet {} bind {} failed",
                           self.name, self.source)
            # Start the connect timer to act as a retry holdoff timer.
            self.node.timers.jstart (self, self.conntmr.next ())
            return
        logging.trace ("Multinet {} listen to {} active",
                       self.name, self.source)

    def check_connection (self):
        sock = self.socket
        if not sock:
            return False
        p = select.poll ()
        p.register (sock, datalink.REGPOLLIN)
        while True:
            try:
                pl = p.poll (datalink.POLLTS)
            except select.error:
                logging.trace ("Poll error", exc_info = True)
                return False
            if self.rthread and self.rthread.stopnow:
                return False
            if not pl:
                continue
            fn, mask = pl[0]
            if mask & datalink.POLLERRHUP:
                return False
            if not (mask & select.POLLIN):
                continue
            try:
                sock, ainfo = sock.accept ()
                if self.dest.valid (ainfo):
                    # Good connection, stop looking
                    break
                # If the connect is from someplace we don't want
                logging.trace ("Multinet {} connect received from " \
                               "unexpected address {}",
                               self.name, ainfo)
                sock.close ()
            except (AttributeError, OSError, socket.error):
                logging.trace ("Close error", exc_info = True)
                return False
        logging.trace ("Multinet {} connected", self.name)
        # Stop listening:
        try:
            self.socket.close ()
        except AttributeError:
            # In case it was set to None
            pass
        # The socket we care about now is the data socket
        self.socket = sock
        return True
    
class _UdpMultinet (_Multinet):
    port_class = MultinetUdpPort

    def __init__ (self, owner, name, config):
        super ().__init__ (owner, name, config)
        if not config.source_port:
            raise ValueError ("Missing --source-port")
        # It would be possible to add "any address" support, but since
        # UDP Multinet is deprecated I don't think I'll bother.
        self.source = host.SourceAddress (config, config.source_port)
        self.dest = host.HostAddress (config.destination,
                                      config.dest_port, self.source)
        
    def connect (self):
        self.socket = self.dest.create_udp (self.source)
        logging.trace ("Multinet {} (UDP) bound to {}",
                       self.name, self.source)

    def disconnect (self):
        if self.socket:
            # Close the socket
            try:
                self.socket.close ()
            except Exception:
                pass
            # Dereference the object (Linux wants this)
            self.socket = None
            
    def check_connection (self):
        # Report "connected" immediately for connectionless operation
        return True
        
    def receive_loop (self):
        sock = self.socket
        p = select.poll ()
        p.register (sock, datalink.REGPOLLIN)
        while True:
            try:
                pl = p.poll (datalink.POLLTS)
            except select.error:
                logging.trace ("Poll error", exc_info = True)
                return False
            if self.rthread and self.rthread.stopnow:
                return
            if not pl:
                continue
            fn, mask = pl[0]
            if mask & datalink.POLLERRHUP:
                return
            if mask & select.POLLIN:
                # Receive a packet
                try:
                    msg, addr = sock.recvfrom (1500)
                except (AttributeError, OSError, socket.error) as e:
                    logging.trace ("Receive error {}", e)
                    return
                if not msg or len (msg) <= 4:
                    logging.trace ("Receive runt packet {!r}", msg)
                    continue
                if not self.dest.valid (addr):
                    # Not from peer, ignore
                    logging.trace ("Bad sender {}", addr)
                    continue
                # Check header?  For now just skip it.
                msg = msg[4:]
                self.node.addwork (Received (self, packet = msg))
                    
    def send (self, msg, dest = None):
        sock = self.socket
        if sock and self.state == self.running:
            msg = makebytes (msg)
            mlen = len (msg)
            if logging.tracing:
                logging.tracepkt ("Sending Multinet message on {}",
                                  self.name, pkt = msg)
            self.counters.bytes_sent += mlen
            self.counters.pkts_sent += 1
            # UDP mode
            hdr = self.seq.to_bytes (2, "little") + b"\000\000"
            self.seq = (self.seq + 1) & 0xffff
            try:
                sock.sendto (hdr + msg, self.dest.sockaddr)
            except (socket.error, AttributeError, OSError):
                # AttributeError happens if socket has been
                # changed to "None"
                logging.trace ("send error", exc_info = True)
            
# Factory class -- returns an instance of the appropriate _Multinet
# subclass instance given the specific device flavor specified.
class Multinet (datalink.Datalink):
    def __new__ (cls, owner, name, config):
        if not config.mode:
            # Legacy config via "device" argument, parse that
            m = dev_re.match (config.device)
            if not m:
                logging.error ("Invalid device value for Multinet datalink {}",
                               self.name)
                raise ValueError
            config.destination, port, cmode, lmode, lport = m.groups ()
            config.mode = lmode or cmode
            if not config.mode:
                config.mode = "udp"
            else:
                config.mode = config.mode[1:]
            if port:
                config.dest_port = int (port)
            else:
                config.dest_port = 700
            if config.mode == "listen":
                config.source_port = config.dest_port
                config.dest_port = 0
            else:
                if lport:
                    config.source_port = int (lport[1:])
                else:
                    config.source_port = 0
            if config.mode == "udp":
                if not config.source_port:
                    config.source_port = config.dest_port
        if config.mode == "listen":
            c = _ListenMultinet
        elif config.mode == "connect":
            c = _ConnectMultinet
        elif config.mode == "udp":
            # Warn that Multinet in UDP mode violates most of the
            # point to point datalink requirements.  The same goes for
            # TCP, but the consequences aren't quite so evil so there
            # we don't warn.
            logging.warning ("Multinet UDP mode not recommended since it violates DECnet architecture")
            if not config.source_port:
                config.source_port = config.dest_port
            c = _UdpMultinet
        else:
            raise ValueError ("Unknown Multinet mode {}".format (config.mode))
        return c (owner, name, config)

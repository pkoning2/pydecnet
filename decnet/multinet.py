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

# Multinet link states
OFF = 0
LISTEN = 1
RUN = 2

class MultinetPort (datalink.PtpPort):
    """Multinet is exactly like generic point to point except that the
    spurious start message workaround needs to be turned on.
    """
    start_works = False

dev_re = re.compile (r"(.*?):(\d*)(?:(:connect)|(:listen)|(:\d+))?$")

class Multinet (datalink.PtpDatalink):
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
    port_class = MultinetPort
    
    def __init__ (self, owner, name, config):
        self.tname = "{}.{}".format (owner.node.nodename, name)
        self.rthread = None
        super ().__init__ (owner, name, config)
        self.config = config
        m = dev_re.match (config.device)
        if not m:
            logging.error ("Invalid device value for Multinet datalink {}",
                           self.name)
            raise ValueError
        self.source = config.source
        host, port, cmode, lmode, lport = m.groups ()
        if port:
            port = int (port)
        else:
            port = 700
        self.portnum = self.lport = port
        self.mode = lmode or cmode
        self.host = datalink.HostAddress (host, any = self.mode == ":listen")
        if self.mode:
            mode = "TCP " + self.mode[1:]
            self.start_works = True
        else:
            mode = "UDP"
            # Tell the point to point datalink dependent sublayer to
            # work around the fact that Multinet in UDP mode violates
            # most of the point to point datalink requirements.
            logging.warning ("Multinet UDP mode not recommended since it violates DECnet architecture")
            self.start_works = False
            if lport:
                self.lport = int (lport[1:])
        logging.trace ("Multinet datalink {} initialized to {}:{}, {}",
                       self.name, host, port, mode)
        self.seq = 0
        self.status = OFF

    def open (self):
        # Open and close datalink are ignored, control is via the port
        # (the higher layer's handle on the datalink entity)
        pass

    def close (self):
        pass
    
    def port_open (self):
        logging.trace ("Multinet {} port_open status is {}", self.name, self.status)
        if self.status != OFF:
            # Already open, ignore
            return
        self.rthread = StopThread (name = self.tname, target = self.run)
        if self.mode:
            self.socket = socket.socket (socket.AF_INET)
        else:
            self.socket = socket.socket (socket.AF_INET, socket.SOCK_DGRAM,
                                         socket.IPPROTO_UDP)
        dont_close (self.socket)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.rthread.start ()

    def port_close (self):
        logging.trace ("Multinet {} port_close status is {}", self.name, self.status)
        if self.status != OFF:
            self.rthread.stop ()
            self.rthread = None
            self.status = OFF
            try:
                self.socket.close ()
                logging.trace ("Multinet {} socket closed by request", self.name)
            except Exception:
                logging.trace ("Multinet {} socket close exception", self.name)
            self.socket = None

    def disconnected (self):
        if self.status == RUN and self.port:
            self.node.addwork (datalink.DlStatus (self.port.owner,
                                                  status = False))
        if self.status != OFF:
            try:
                self.socket.close ()
                logging.trace ("Multinet {} socket closed for disconnect", self.name)
            except Exception:
                logging.trace ("Multinet {} socket close exception", self.name)
            self.socket = None
        self.status = OFF

    def run (self):
        logging.trace ("Multinet datalink {} receive thread started", self.name)
        sock = self.socket
        if not sock:
            return
        sellist = [ sock.fileno () ]
        if self.mode == ":connect":
            if self.source:
                self.socket.bind ((self.source, 0))
            # Connect to the remote host
            try:
                self.socket.connect ((self.host.addr, self.portnum))
                logging.trace ("Multinet {} connect to {} {} in progress",
                               self.name, self.host.addr, self.portnum)
            except socket.error:
                logging.trace ("Multinet {} connect to {} {} rejected",
                               self.name, self.host.addr, self.portnum)
                self.disconnected ()
                return            
            # Wait for the socket to become writable, that means
            # the connection has gone through
            while True:
                try:
                    r, w, e = select.select ([], sellist, sellist, 1)
                except select.error:
                    e = True
                if (self.rthread and self.rthread.stopnow) or e:
                    self.disconnected ()
                    return
                if w:
                    logging.trace ("Multinet {} connected", self.name)
                    break
        else:
            # Listen or UDP mode
            try:
                self.socket.bind ((self.source, self.lport))
                logging.trace ("Multinet {} bind {} done", self.name, self.lport)
            except (OSError, socket.error):
                logging.trace ("Multinet {} bind {} failed", self.name, self.lport)
                self.disconnected ()
                return
            if self.mode:
                # Listen mode, Wait for an incoming connection.
                self.status = LISTEN
                try:
                    self.socket.listen (1)
                except (OSError, socket.error):
                    logging.trace ("Multinet {} listen failed", self.name)
                    self.disconnected ()
                    return
                logging.trace ("Multinet {} listen to {} active",
                               self.name, self.lport)
                while True:
                    try:
                        r, w, e = select.select (sellist, [], sellist, 1)
                    except select.error:
                        e = True
                    if (self.rthread and self.rthread.stopnow) or e:
                        self.disconnected ()
                        return
                    if not r:
                        continue
                    try:
                        sock, ainfo = sock.accept ()
                        host, port = ainfo
                        if self.host.valid (host):
                            # Good connection, stop looking
                            break
                        # If the connect is from someplace we don't want
                        logging.trace ("Multinet {} connect received from " \
                                       "unexpected address {}",
                                       self.name, host)
                        sock.close ()
                    except (OSError, socket.error):
                        self.disconnected ()
                        return
                logging.trace ("Multinet {} connected", self.name)
                # Stop listening:
                self.socket.close ()
                # The socket we care about now is the data socket
                sellist = [ sock.fileno () ]
                self.socket.close ()
                self.socket = sock
            else:
                logging.trace ("Multinet {} (UDP) bound to {}",
                               self.name, self.lport)
        # Tell the routing init layer that this datalink is running
        self.status = RUN
        if self.port:
            self.node.addwork (datalink.DlStatus (self.port.owner,
                                                  status = True))
        while True:
            # Look for traffic
            try:
                r, w, e = select.select (sellist, [], sellist, 1)
            except select.error:
                e = True
            if (self.rthread and self.rthread.stopnow) or e:
                self.disconnected ()                
                return
            if r:
                if self.mode:
                    # TCP mode, look for header first
                    bc = b''
                    while len (bc) < 4:
                        try:
                            m = sock.recv (4 - len (bc))
                        except socket.error:
                            m = None
                        if not m:
                            self.disconnected ()
                            return
                        bc += m
                    bc = int.from_bytes (bc[:2], "little")
                    msg = b''
                    # Now receive exactly the byte count mentioned
                    while len (msg) < bc:
                        try:
                            m = sock.recv (bc - len (msg))
                        except socket.error:
                            m = None
                        if not m:
                            self.disconnected ()
                            return
                        msg += m
                else:
                    # UDP mode, receive a packet
                    try:
                        msg, addr = sock.recvfrom (1500)
                    except socket.error:
                        msg = None
                    if not msg or len (msg) <= 4:
                        self.disconnected ()
                        return
                    host, port = addr
                    if not self.host.valid (host):
                        # Not from peer, ignore
                        continue
                    # Check header?  For now just skip it.
                    msg = msg[4:]
                logging.trace ("Received Multilink message len {}: {!r}",
                               len (msg), msg)
                if self.port:
                    self.counters.bytes_recv += len (msg)
                    self.counters.pkts_recv += 1
                    self.node.addwork (Received (self.port.owner, packet = msg))
                else:
                    logging.trace ("Message discarded, no port open")
                    
    def send (self, msg, dest = None):
        sock = self.socket
        if sock and self.status == RUN:
            msg = bytes (msg)
            mlen = len (msg)
            logging.trace ("Sending Multinet message len {}: {!r}",
                           mlen, msg)
            self.counters.bytes_sent += mlen
            self.counters.pkts_sent += 1
            if self.mode:
                # TCP mode
                hdr = mlen.to_bytes (2, "little") + b"\000\000"
                try:
                    self.socket.send (hdr + msg)
                except socket.error:
                    self.disconnected ()
            else:
                # UDP mode
                hdr = self.seq.to_bytes (2, "little") + b"\000\000"
                self.seq += 1
                try:
                    sock.sendto (hdr + msg, (self.host.addr, self.portnum))
                except socket.error:
                    self.disconnected ()
            

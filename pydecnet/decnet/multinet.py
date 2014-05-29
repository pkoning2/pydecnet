#!

"""Multinet over UDP "datalink" implementation.

Since Multinet (or at least the subset implemented here) runs
over UDP, it fails to meet many of the requirements the routing
spec imposes on point to point datalinks.  In particular,
there is no data link startup at the protocol level, so a remote
datalink start is not visible.  The point to point datalink
dependent sublayer can work around that to some extent, given
that it is told to do so, by having "start_works" set to False in
the class.
"""

import re
import select
import socket

from .common import *
from . import datalink

# Multinet link states
OFF = 0
RUN = 2

dev_re = re.compile (r"(.+?):(\d*)(:connect|:listen)?$")

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
    
    The --device config parameter is required.  The device argument
    is "host" or "host:portnum"; if the port number is omitted the
    default (700) is assumed.  That is followed by ":connect" for
    the active end of a TCP connection, ":listen" for the passive
    end of a TCP connection, or neither for UDP mode.
    """
    def __init__ (self, owner, name, config):
        self.tname = "{}.{}".format (owner.node.nodename, name)
        self.rthread = None
        super ().__init__ (owner, name, config)
        self.config = config
        m = dev_re.match (config.device)
        if not m:
            logging.error ("Invalid --device value for Multinet datalink %s",
                           self.name)
            raise ValueError
        host, port, mode = m.groups ()
        if port:
            port = int (port)
        else:
            port = 700
        self.host = datalink.HostAddress (host)
        self.portnum = port
        self.mode = mode
        if mode:
            mode = "TCP " + mode[1:]
            self.start_works = True
        else:
            mode = "UDP"
            # Tell the point to point datalink dependent sublayer to
            # work around the fact that Multinet in UDP mode violates
            # most of the point to point datalink requirements.
            self.start_works = False
        logging.trace ("Multinet datalink %s initialized to %s:%d, %s",
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
        if self.mode == ":connect":
            try:
                self.socket.connect ((self.host.addr, self.portnum))
                logging.trace ("Multinet %s connect to %s %d in progress",
                               self.name, self.host.addr, self.portnum)
            except socket.error:
                logging.trace ("Multinet %s connect to %s %d rejected",
                               self.name, self.host.addr, self.portnum)
                self.status = OFF
                return
        else:
            try:
                self.socket.bind (("", self.portnum))
            except (OSError, socket.error):
                logging.trace ("Multinet %s bind failed", self.name)
                self.status = OFF
                return
            if self.mode:
                try:
                    self.socket.listen (1)
                except (OSError, socket.error):
                    logging.trace ("Multinet %s listen failed", self.name)
                    self.status = OFF
                    return
                logging.trace ("Multinet %s listen to %d active",
                               self.name, self.portnum)
            else:
                logging.trace ("Multinet %s (UDP) bound to %d",
                               self.name, self.portnum)
        self.rthread.start ()

    def port_close (self):
        if self.status != OFF:
            self.rthread.stop ()
            self.rthread = None
            self.status = OFF
            try:
                self.socket.close ()
            except Exception:
                pass
            self.socket = None

    def disconnected (self):
        if self.status == RUN and self.port:
            self.node.addwork (datalink.DlStatus (self.port.owner,
                                                  status = False))
        if self.status != OFF:
            try:
                self.socket.close ()
            except Exception:
                pass
            self.socket = None
        self.status = OFF

    def run (self):
        logging.trace ("Multinet datalink %s receive thread started", self.name)
        sock = self.socket
        if not sock:
            return
        sellist = [ sock.fileno () ]
        if self.mode == ":connect":
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
                    logging.trace ("Multinet %s connected", self.name)
                    break
        elif self.mode == ":listen":
            # Wait for an incoming connection.
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
                    logging.trace ("Multinet %s connect received from unexpected address %s", self.name, host)
                    sock.close ()
                except (OSError, socket.error):
                    self.disconnected ()
                    return
            logging.trace ("Multinet %s connected", self.name)
            # Stop listening:
            self.socket.close ()
            # The socket we care about now is the data socket
            sellist = [ sock.fileno () ]
            self.socket = sock
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
                logging.trace ("Received Multilink message len %d: %r",
                               len (msg), msg)
                if self.port:
                    self.node.addwork (Received (self.port.owner, packet = msg))
                else:
                    logging.trace ("Message discarded, no port open")
                    
    def send (self, msg, dest = None):
        sock = self.socket
        if sock and self.status == RUN:
            msg = bytes (msg)
            mlen = len (msg)
            logging.trace ("Sending Multinet message len %d: %r",
                           mlen, msg)
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
            

#!

"""Payload-only SIMH 3.9 "DMC emulation" datalink

"""

import select
import socket

from .common import *
from . import datalink

# SimhDMC link states
OFF = 0
INIT = 1
RUN = 2

class SimhDMC (datalink.PtpDatalink):
    """An implementation of the SIMH 3.9 payload-only DMC-11
    emulation.  See pdp11_dmc.c in the SIMH source code for the
    authoritative description.  Note that this protocol is only used
    in 3.9; in a later version it was removed and replaced by an
    implementation of the actual DDCMP protocol.

    In a nutshell: this uses a TCP connection.  One side is designated
    "primary", it issues the connect.  The "secondary" side listens for
    the connect.  Once connected, data packets are sent as TCP stream
    data prefixed by the packet length, as a two byte network order
    (big endian) integer.  There is no support for Maintenance mode.

    The --device config parameter is required.  The device argument is
    either "host:portnum" or "host:portnum:secondary", the former for
    primary mode.  For secondary mode, where connections are inbound,
    the host name/address is used to verify incoming connection addresses.
    """
    def __init__ (self, owner, name, config):
        self.tname = "{}.{}".format (owner.node.nodename, name)
        self.rthread = None
        super ().__init__ (owner, name, config)
        self.config = config
        host, port, *sec = config.device.split (':')
        if sec:
            if sec[0] == "secondary":
                self.primary = False
            else:
                raise RuntimeError ("Invalid device string %s" % config.device)
        else:
            self.primary = True
        self.host = datalink.HostAddress (host)
        self.portnum = int (port)
        logging.trace ("SimhDMC datalink %s initialized as %s to %s:%d",
                       self.name, ("secondary", "primary")[self.primary],
                       host, self.portnum)
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
        self.status = INIT
        self.socket = socket.socket (socket.AF_INET)
        dont_close (self.socket)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Refresh the name to address mapping.  This isn't needed for the
        # initial open but we want this for a subsequent one, because
        # a restart of the circuit might well have been caused by an
        # address change of the other end.
        self.host.lookup ()
        if self.primary:
            try:
                self.socket.connect ((self.host.addr, self.portnum))
                logging.trace ("SimhDMC %s connect to %s %d in progress",
                               self.name, self.host.addr, self.portnum)
            except socket.error:
                logging.trace ("SimhDMC %s connect to %s %d rejected",
                               self.name, self.host.addr, self.portnum)
                self.status = OFF
                return
        else:
            try:
                self.socket.bind (("", self.portnum))
                self.socket.listen (1)
            except (OSError, socket.error):
                logging.trace ("SimhDMC %s bind/listen failed", self.name)
                self.status = OFF
                return
            logging.trace ("SimhDMC %s listen to %d active",
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
        logging.trace ("SimhDMC datalink %s receive thread started", self.name)
        sock = self.socket
        if not sock:
            return
        sellist = [ sock.fileno () ]
        if self.primary:
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
                    logging.trace ("SimhDMC %s connected", self.name)
                    break
        else:
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
                    logging.trace ("SimhDMC %s connect received from unexpected address %s", self.name, host)
                    sock.close ()
                except (OSError, socket.error):
                    self.disconnected ()
                    return
            logging.trace ("SimhDMC %s connected", self.name)
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
            # All connected.
            try:
                r, w, e = select.select (sellist, [], sellist, 1)
            except select.error:
                e = True
            if (self.rthread and self.rthread.stopnow) or e:
                self.disconnected ()                
                return
            if r:
                try:
                    bc = sock.recv (2)
                except socket.error:
                    bc = None
                if not bc:
                    self.disconnected ()
                    return
                if len (bc) < 2:
                    bc += sock.recv (1)
                    if len (bc) < 2:
                        self.disconnected ()
                        return
                bc = int.from_bytes (bc, "big")
                msg = b''
                while len (msg) < bc:
                    try:
                        m = sock.recv (bc - len (msg))
                    except socket.error:
                        m = None
                    if not m:
                        self.disconnected ()
                        return
                    msg += m
                logging.trace ("Received DMC message len %d: %r",
                               len (msg), msg)
                if self.port:
                    self.bytes_recv += len (msg)
                    self.pkts_recv += 1
                    self.node.addwork (Received (self.port.owner, packet = msg))
                else:
                    logging.trace ("Message discarded, no port open")
                    
    def send (self, msg, dest = None):
        if self.status == RUN:
            msg = bytes (msg)
            logging.trace ("Sending DMC message len %d: %r", len (msg), msg)
            mlen = len (msg).to_bytes (2, "big")
            self.bytes_sent += len (msg)
            self.pkts_sent += 1
            try:
                self.socket.send (mlen + msg)
            except socket.error:
                self.disconnected ()
            

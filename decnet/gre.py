#!

"""Ethernet tunneled over GRE.

"""

import select
import socket

from .common import *
from . import logging
from . import datalink

SvnFileRev = "$LastChangedRevision$"

greflags = bytes (2)

class GREPort (datalink.BcPort):
    """DEC Ethernet port class for GRE-encapsulated Ethernet.
    """
    def __init__ (self, datalink, owner, proto, pad = True):
        super ().__init__ (datalink, owner, proto)
        self.pad = pad
        f = self.frame = bytearray (1504)
        f[0:2] = greflags
        f[2:4] = self.proto

    def set_promiscuous (self, promisc = True):
        raise RuntimeError ("GRE does not support promiscuous mode")
                
    def send (self, msg, dest):
        """Send an "Ethernet" frame to the specified address.  Since GRE
        is point to point, the address is ignored.
        """
        l = len (msg)
        if logging.tracing:
            logging.trace ("Sending {} byte {} packet",
                           l, msg.__class__.__name__)
        f = self.frame
        if self.pad:
            if l > 1498:
                raise ValueError ("Ethernet packet too long")
            f[4] = l & 0xff
            f[5] = l >> 8
            f[6:6 + l] = msg
            l += 6
        else:
            if l > 1500:
                raise ValueError ("Ethernet packet too long")
            f[4:4 + l] = msg
            l += 4
        self.counters.bytes_sent += l
        self.counters.pkts_sent += 1
        # We don't do padding, since GRE doesn't require it (it isn't
        # real Ethernet and doesn't have minimum frame lenghts)
        self.parent.send_frame (memoryview (f)[:l])

GREPROTO = 47
class GRE (datalink.BcDatalink, StopThread):
    """DEC Ethernet datalink tunneled over GRE encapsulation.

    The --device parameter is required.  Its value is the remote host
    address or name.  The GRE protocol id (47) is assumed and hardwired.
    """
    port_class = GREPort
    use_mop = False    # True if we want MOP to run on this type of datalink
    
    def __init__ (self, owner, name, config):
        tname = "{}.{}".format (owner.node.nodename, name)
        StopThread.__init__ (self, name = tname)
        datalink.BcDatalink.__init__ (self, owner, name, config)
        self.host = datalink.HostAddress (config.device)
        self.source = config.source
        
    def open (self):
        # Create the socket and start receive thread.  Note that we do not
        # set the HDRINCL option, so transmitted packets have their IP
        # header generated by the kernel.  (But received packets appear
        # with an IP header on the front, what fun...)
        self.socket = socket.socket (socket.AF_INET, socket.SOCK_RAW, GREPROTO)
        if self.source:
            self.socket.bind ((self.source, 0))
        self.start ()
        
    def close (self):
        self.stop ()
        if self.socket:
            self.socket.close ()
        self.socket = None
        
    def create_port (self, owner, proto, pad = True):
        return super ().create_port (owner, proto, pad)

    def send_frame (self, buf):
        """Send an GRE-encapsulated Ethernet frame.  Ignore any errors,
        because that's the DECnet way.
        """
        try:
            self.socket.sendto (buf, (self.host.addr, GREPROTO))
        except (AttributeError, IOError):
            pass
        
    def run (self):
        logging.trace ("GRE datalink {} receive thread started", self.name)
        sock = self.socket
        if not sock:
            return
        sellist = [ sock.fileno () ]
        while True:
            if self.stopnow:
                break
            try:
                r, w, x = select.select (sellist, [], sellist, 1)
            except select.error:
                x = True
            if x:
                logging.trace ("Error on socket for {}", self.name)
                return
            if r:
                try:
                    msg, addr = sock.recvfrom (1504)
                except (AttributeError, OSError, socket.error):
                    msg = None
                if not msg or len (msg) <= 4:
                    continue
                host, port = addr
                if not self.host.valid (host):
                    # Not from peer, ignore
                    continue
                # Skip past the IP header
                ver, hlen = divmod (msg[0], 16)
                if ver != 4:
                    # Sorry, we only support IPv4 for now
                    continue
                pos = 4 * hlen
                if logging.tracing:
                    logging.trace ("Received GRE message len {}: {!r}",
                                   len (msg), msg)
                if msg[pos:pos + 2] != greflags:
                    # Unexpected flags or version in header, ignore
                    logging.debug ("On {}, unexpected header {}",
                                   self.name, msg[pos:pos + 2])
                    continue
                proto = msg[pos + 2:pos + 4]
                try:
                    port = self.ports[proto]
                except KeyError:
                    # No protocol type match, ignore msg
                    self.counters.unk_dest += 1
                    continue
                plen = len (msg) - (pos + 4)
                port.counters.bytes_recv += plen
                port.counters.pkts_recv += 1
                if port.pad:
                    plen2 = msg[pos + 4] + (msg[pos + 5] << 8)
                    if plen < plen2:
                        logging.debug ("On {}, msg length field {} " \
                                       "inconsistent with msg length {}",
                                       self.name, plen2, plen)
                        continue
                    msg = memoryview (msg)[pos + 6:pos + 6 + plen2]
                else:
                    msg = memoryview (msg)[pos + 4:]
                self.node.addwork (Received (port.owner,
                                             src = None, packet = msg))

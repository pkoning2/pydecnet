#!

"""The Ethernet datalink layer.

"""

from fcntl import *
import random
import select
import socket
import struct
import os
import sys

from .common import *
from . import datalink
from . import pcap

FILL = b'\x42' * 60

class EthPort (datalink.BcPort):
    """DEC Ethernet port class.
    """
    def __init__ (self, datalink, owner, proto, pad = True):
        super ().__init__ (datalink, owner, proto)
        self.pad = pad
        f = self.frame = bytearray (1514)
        f[6:12] = self.macaddr
        f[12:14] = self.proto
                
    def set_macaddr (self, addr):
        addr = Macaddr (addr)
        super ().set_macaddr (addr)
        self.frame[6:12] = addr
        
    def send (self, msg, dest):
        destb = bytes (dest)
        if len (destb) != 6:
            raise ValueError ("Invalid destination address length")
        l = len (msg)
        logging.trace ("Sending %d byte %s packet to %s",
                       l, msg.__class__.__name__, dest)
        f = self.frame
        f[0:6] = destb
        if self.pad:
            if l > 1498:
                raise ValueError ("Ethernet packet too long")
            f[14] = l & 0xff
            f[15] = l >> 8
            f[16:16 + l] = msg
            l += 16
        else:
            if l > 1500:
                raise ValueError ("Ethernet packet too long")
            f[14:14 + l] = msg
            l += 14
        self.bytes_sent += l
        self.pkts_sent += 1
        # Always send packet padded to min of 60 if need be, whether
        # pad mode is specified or not.
        if l < 60:
            f[l:60] = FILL[l:60]
        l = max (l, 60)
        self.parent.send_frame (memoryview (f)[:l])

# ifr_name, ifru_flags
ifreq = struct.Struct ("=16sH")
sizeof_ifreq = 32
SIOCSIFFLAGS = 0x80000000 + (sizeof_ifreq << 16) + (ord ('i') << 8) + 16
SIOCGIFFLAGS = 0xc0000000 + (sizeof_ifreq << 16) + (ord ('i') << 8) + 17
ETH_MTU = 1518
ETH_TMO = 100    # ms

class _Ethernet (datalink.BcDatalink, StopThread):
    """DEC Ethernet datalink.
    """
    port_class = EthPort
    
    def __init__ (self, owner, name, dev, config):
        tname = "{}.{}".format (owner.node.nodename, name)
        StopThread.__init__ (self, name = tname)
        datalink.BcDatalink.__init__ (self, owner, name, config)
        self.dev = dev
        if config.random_address:
            r = (random.getrandbits (46) << 2) + 2
            self.hwaddr = Macaddr (r.to_bytes (6, "little"))
        else:
            self.hwaddr = NULLID
        self.randaddr = config.random_address
    
    def open (self):
        if not self.randaddr:
            for dname, desc, addrs, flags in pcap.findalldevs ():
                if dname == self.dev and addrs:
                    self.hwaddr = Macaddr (addrs[0][0])
        logging.debug ("Ethernet %s hardware address is %s",
                       self.name, self.hwaddr)
        # start receive thread
        self.start ()
        
    def close (self):
        self.stop ()
        
    def create_port (self, owner, proto, pad = True):
        return super ().create_port (owner, proto, pad)

    def receive (self, plen, packet, ts):
        if not packet:
            # pcap_next returns None if we got a timeout
            return
        if plen < 60:
            # Runt???
            return
        proto = packet[12:14]
        try:
            port = self.ports[proto]
        except KeyError:
            # No protocol type match, ignore packet
            self.unk_dest += 1
            return
        dest = packet[:6]
        # Note that we don't count packets that fail the address
        # filter, otherwise we'd count lots of stuff for others.
        if dest in port.destfilter:
            if dest[0] & 1:
                self.mcbytes_recv += plen
                self.mcpkts_recv += 1
            port.bytes_recv += plen
            port.pkts_recv += 1
            src = Macaddr (packet[6:12])
            if port.pad:
                plen2 = packet[14] + (packet[15] << 8)
                if plen < plen2 + 16:
                    logging.debug ("On %s, packet length field %d "
                                   "inconsistent with packet length %d",
                                   self.name, plen2, plen)
                    return
                packet = memoryview (packet)[16:16 + plen2]
            else:
                packet = memoryview (packet)[14:]
            self.node.addwork (Received (port.owner,
                                         src = src, packet = packet))

# API specific classes

class _TapEth (_Ethernet):
    def open (self):
        fd = os.open (self.dev, os.O_RDWR)
        dont_close (fd)
        oldflags = fcntl (fd, F_GETFL, 0)
        fcntl (fd, F_SETFL, oldflags | os.O_NONBLOCK)
        self.tap = fd
        self.sellist = ( fd, )
        # Turn the interface on -- needed only on Mac OS
        if sys.platform == "darwin":
            req = bytearray (sizeof_ifreq)
            devname = os.path.basename (self.dev)
            ifreq.pack_into (req, 0, devname.encode ("ascii"), 0)
            s = socket.socket (socket.AF_INET, socket.SOCK_DGRAM, 0)
            ioctl (s, SIOCGIFFLAGS, req)
            name, flags = ifreq.unpack_from (req)
            ifreq.pack_into (req, 0, name, flags | 1)
            ioctl (s, SIOCSIFFLAGS, req)
            s.close ()
        super ().open ()
        
    def close (self):
        super ().close ()
        os.close (self.tap)
        self.tap = None
        
    def send_frame (self, buf):
        """Send an Ethernet frame.  Ignore any errors, because that's
        the DECnet way.
        """
        try:
            os.write (self.tap, buf)
        except IOError:
            pass
        
    def run (self):
        while True:
            if self.stopnow:
                break
            try:
                try:
                    # ETH_TMO is in ms, but select timeout is in seconds.
                    r, w, x = select.select (self.sellist, (),
                                             self.sellist, ETH_TMO / 1000)
                except select.error as e:
                    r = True
                if not r:
                    continue
                pkt = os.read (self.tap, 1518)
                if not pkt:
                    continue
                self.receive (len (pkt), pkt, None)
            except OSError as e:
                break
            
class _PcapEth (_Ethernet):
    def __init__ (self, owner, name, dev, config):
        super ().__init__ (owner, name, dev, config)
        self.pcap = pcap.pcapObject ()

    def open (self):
        # Always set promiscuous mode
        self.pcap.open_live (self.dev, ETH_MTU, 1, ETH_TMO)
        dont_close (self.pcap)
        super ().open ()

    def close (self):
        super ().close ()
        # Don't do the close yet, it crashes for reasons yet unknown
        #self.pcap.close ()

    def send_frame (self, buf):
        """Send an Ethernet frame.  Ignore any errors, because that's
        the DECnet way.
        """
        try:
            l2 = self.pcap.inject (buf)
        except IOError:
            pass
        
    def run (self):
        while True:
            if self.stopnow:
                break
            try:
                cnt = self.pcap.dispatch (0, self.receive)
            except pcap._pcap.error:
                break

class _XBridgeEth (_Ethernet):
    """Class for talking to a Johnny Billquist bridge (somewhere else,
    external to this process), via UDP packets each carrying an
    Ethernet datagram.
    """
    def __init__ (self, owner, name, dev, config):
        super ().__init__ (owner, name, dev, config)
        lport, host, port = dev.split (":")
        self.lport = int (lport)
        self.port = int (port)
        self.host = datalink.HostAddress (host)
        logging.trace ("Ethernet xbridge %s initialized on %d, to %s:%d",
                       self.name, lport, host, self.port)
        
    def open (self):
        self.socket = socket.socket (socket.AF_INET, socket.SOCK_DGRAM,
                                     socket.IPPROTO_UDP)
        dont_close (self.socket)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super ().open ()
        
    def close (self):
        super ().close ()
        try:
            self.socket.close ()
        except Exception:
            pass
        self.socket = None

    def run (self):
        logging.trace ("Ethernet xbridge %s receive thread started", self.name)
        sock = self.socket
        if not sock:
            return
        sellist = [ sock.fileno () ]
        try:
            self.socket.bind (("", self.lport))
        except (OSError, socket.error):
            logging.trace ("Ethernet xbridge %s bind %d failed",
                           self.name, self.lport)
            return
        logging.trace ("Ethernet xbridge %s bound to %d",
                       self.name, self.lport)
        
        while True:
            # Look for traffic
            try:
                r, w, e = select.select (sellist, [], sellist, 1)
            except select.error:
                e = True
            if self.stopnow or e:
                break
            if r:
                try:
                    msg, addr = sock.recvfrom (1514)
                except socket.error:
                    msg = None
                if not msg or len (msg) <= 4:
                    self.disconnected ()
                    return
                host, port = addr
                if not self.host.valid (host):
                    # Not from peer, ignore
                    continue
                self.receive (len (msg), msg, None)

    def send_frame (self, buf):
        """Send an Ethernet frame.  Ignore any errors, because that's
        the DECnet way.
        """
        if not self.socket:
            return
        try:
            self.socket.sendto (buf, (self.host.addr, self.port))
        except (IOError, socket.error) as e:
            pass
        
class _IBridgeEth (_Ethernet):
    """Class for talking to an instance of Bridge (which is our
    implementation of the Johnny Billquist bridge protocol).
    """

# Factory class -- returns an instance of the appropriate _Ethernet
# subclass instance given the specific device flavor specified.
class Ethernet (datalink.Datalink):
    def __new__ (cls, owner, name, config):
        dev = config.device or name
        api, dev = dev.split (":", 1)
        if api == "tap":
            c = _TapEth
        elif api == "pcap":
            c = _PcapEth
        elif api == "xbridge" or api == "udp":
            # External bridge, i.e., IP connection to a bridge in
            # another host or process.  Allow "udp" because that's how
            # SIMH refers to it.
            c = _XBridgeEth
        elif api == "ibridge":
            # "Null modem" connection to a bridge port in this process
            c = _IBridgeEth
        else:
            raise ValueError ("Unknown Ethernet circuit subtype %s" % api)
        return c (owner, name, dev, config)

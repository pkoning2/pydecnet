#!

"""Classes for the datalink layer as used by DECnet routing.

"""

from abc import abstractmethod, ABCMeta
#import pcap
import time
import logging
import os
import sys
import select
from fcntl import *
import struct
import socket
import random

from .common import *
from . import pcap

class DatalinkLayer (Element):
    """The datalink layer.  This is mainly a container for the individual
    datalink circuits.
    """
    def __init__ (self, owner, config):
        """Initialize the Datalink layer.  "config" is the configuration.
        Establish our common state, then create Datalink objects for each
        circuit given in the configuration.
        """
        logging.debug ("Initializing data link layer")
        super ().__init__ (owner)
        self.config = config
        self.circuits = dict ()
        for name, c in config.circuit.items ():
            kind = globals ()[c.type]
            if not issubclass (kind, Datalink):
                logging.exception ("Invalid datalink type %r", kind)
            kindname = kind.__name__
            try:
                dl = kind (self, name, c)
                self.circuits[name] = dl
                logging.debug ("Initialized %s datalink %s", kindname, name)
            except Exception:
                logging.exception ("Error initializing %s datalink %s",
                                   kindname, name)

    def start (self):
        """Start the datalink layer, which means starting each of
        the circuits that were configured.
        """
        logging.debug ("Starting datalink layer")
        for name, c in self.circuits.items ():
            try:
                c.open ()
                logging.debug ("Started datalink %s", name)
            except Exception:
                logging.exception ("Error starting datalink %s", name)
    
    
    def stop (self):
        """Stop the datalink layer, which means stopping each of
        the circuits that were configured.
        """
        logging.debug ("Stopping datalink layer")
        for name, c in self.circuits.items ():
            try:
                c.close ()
                logging.debug ("Stopped datalink %s", name)
            except Exception:
                logging.exception ("Error stopping datalink %s", name)
    
    
class Datalink (Element, metaclass = ABCMeta):
    """Abstract base class for a DECnet datalink.
    """
    def __init__ (self, owner, name, config):
        """Initialize a Datalink instance.  "name" is the name of
        the instance; "owner" is its owner; "config" is the configuration
        data for this circuit.
        The owner will receive notifications of received data,
        transmit completions, and other applicable upcalls by calls
        to its dl_notification method.
        """
        super ().__init__ (owner)
        self.name = name
        self.owner = owner
        self.config = config
        
    @abstractmethod
    def create_port (self, *args):
        """Create a port.  Returns an instance of the Port subclass
        associated with this datalink.  Depending on the datalink
        type, there may be a limit on the number of ports that can
        exist at one time.
        """
        return self.port_class (self, *args)

    @abstractmethod
    def open (self):
        """Open the datalink.
        """
        pass
    
    @abstractmethod
    def close (self):
        """Close the datalink.
        """
        pass

class Port (Element, metaclass = ABCMeta):
    """Abstract base class for a DECnet datalink port
    """
    def __init__ (self, datalink, owner):
        super ().__init__ (datalink)
        self.owner = owner

    @abstractmethod
    def send (self, msg, dest = None):
        """Transmit a message.  
        """
        pass

class DlStatus (Work):
    """Notification of some sort of datalink event.  Attribute is
    "status".  The status attribute is True for up, False for down.
    """

# Point to point port

class PtpPort (Port):
    """Base class for a point to point datalink port.  A port
    describes an upper layer's use of the datalink.  In the point to
    point case, only one port is allowed at a time, since there is
    no multiplexing support.  (If maintenance mode is ever added,
    that might change.)
    """
    def __init__ (self, datalink, owner, proto = None):
        super ().__init__ (datalink, owner)
        # A subset of the counters defined by the architecture
        self.ctr_zero_time = time.time ()
        self.bytes_sent = self.pkts_sent = 0
        self.bytes_recd = self.pkts_recd = 0

    def open (self):
        self.parent.port_open ()

    def close (self):
        self.parent.port_close ()
        
    def send (self, msg, dest = None):
        self.parent.send (msg)
        
# Point to point datalink base class

class PtpDatalink (Datalink):
    """Base class for point to point datalinks.
    """
    port_class = PtpPort

    def __init__ (self, owner, name, config):
        super ().__init__ (owner, name, config)
        self.port = None
        
    def create_port (self, owner, proto = None, *args):
        port = super ().create_port (owner, proto, *args)
        if self.port:
            raise RuntimeError ("Creating second port on point to point datalink")
        self.port = port
        return port
    
# SimDMC link states
OFF = 0
INIT = 1
RUN = 2

class SimhDMC (PtpDatalink):
    """An implementation of the SIMH DMC-11 emulation.  See pdp11_dmc.c
    in the SIMH source code for the authoritative description.

    In a nutshell: this uses a TCP connection.  One side is designated
    "primary", it issues the connect.  The "secondary" side listens for
    the connect.  Once connected, data packets are sent as TCP stream
    data prefixed by the packet length, as a two byte network order
    (big endian) integer.  There is no support for Maintenance mode.

    The --device config parameter is required.  The device argument
    is either "host:portnum" or "secondary:portnum", the former for
    primary mode.
    """
    def __init__ (self, owner, name, config):
        self.tname = "{}.{}".format (owner.node.nodename, name)
        self.rthread = None
        super ().__init__ (owner, name, config)
        self.config = config
        host, port = config.device.split (':')
        if host == "secondary":
            self.primary = False
            logging.trace ("Simh DMC datalink %s initialized as secondary",
                           self.name)
        else:
            self.primary = True
            self.host = socket.gethostbyname (host)
            logging.trace ("Simh DMC datalink %s initialized as primary",
                           self.name)
        self.portnum = int (port)
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
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.primary:
            try:
                self.socket.connect ((self.host, self.portnum))
                logging.trace ("SimDMC %s connect to %s %d in progress",
                               self.name, self.host, self.portnum)
            except socket.error:
                logging.trace ("SimDMC %s connect to %s %d rejected",
                               self.name, self.host, self.portnum)
                self.status = OFF
                return
        else:
            self.socket.bind (("", self.portnum))
            self.socket.listen (1)
            logging.trace ("SimDMC %s listen to %d active",
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
            self.node.addwork (DlStatus (self.port.owner, status = False))
        if self.status != OFF:
            try:
                self.socket.close ()
            except Exception:
                pass
            self.socket = None
        self.status = OFF

    def run (self):
        logging.trace ("Simh DMC datalink %s receive thread started", self.name)
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
                    logging.trace ("Simh DMC %s connected", self.name)
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
                if r:
                    break
            sock, ainfo = sock.accept ()
            logging.trace ("Simh DMC %s connected", self.name)
            sellist = [ sock.fileno () ]
            self.socket = sock
        # Tell the routing init layer that this datalink is running
        self.status = RUN
        if self.port:
            self.node.addwork (DlStatus (self.port.owner, status = True))
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
                    m = sock.recv (bc - len (msg))
                    if not m:
                        self.disconnected ()
                        return
                    msg += m
                logging.trace ("Received DMC message len %d: %r",
                               len (msg), msg)
                if self.port:
                    self.node.addwork (Received (self.port.owner, packet = msg))
                else:
                    logging.trace ("Message discarded, no port open")
                    
    def send (self, msg, dest = None):
        if self.status == RUN:
            msg = bytes (msg)
            logging.trace ("Sending DMC message len %d: %r", len (msg), msg)
            mlen = len (msg).to_bytes (2, "big")
            try:
                self.socket.send (mlen + msg)
            except socket.error:
                self.disconnected ()
            
class Multinet (PtpDatalink):
    """An implementation of the Multinet tunnel.  See multinet.c
    in the DECnet/Linux "dnprogs" source code for an earlier implementation
    that reasonably well describes how it works..

    In a nutshell: this uses UDP datagrams.  Data packets are sent as
    UDP datagrams, preceded by a four byte header consisting of a two
    byte sequence number (little endian) plus two bytes of zero.
    It's not clear that header is used by the receiver; it isn't in the
    Linux code.  The data then follows that header with no other
    processing.
    
    The --device config parameter is required.  The device argument
    is "host" or "host:portnum"; if the port number is omitted the
    default (700) is assumed.
    """
    def __init__ (self, owner, name, config):
        self.tname = "{}.{}".format (owner.node.nodename, name)
        self.rthread = None
        super ().__init__ (owner, name, config)
        self.config = config
        hp = config.device.split (':')
        host = hp[0]
        if len (hp) == 1:
            port = 700
        else:
            port = int (hp[1])
        self.host = socket.gethostbyname (host)
        self.portnum = port
        logging.trace ("Multinet datalink %s initialized.", self.name)
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
        self.socket = socket.socket (socket.AF_INET, socket.SOCK_DGRAM,
                                     socket.IPPROTO_UDP)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind (("", self.portnum))
        logging.trace ("Multinet %s bound to %d", self.name, self.portnum)
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
            self.node.addwork (DlStatus (self.port.owner, status = False))
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
        # Tell the routing init layer that this datalink is running
        self.status = RUN
        if self.port:
            self.node.addwork (DlStatus (self.port.owner, status = True))
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
                try:
                    msg, addr = sock.recvfrom (1500)
                except socket.error:
                    msg = None
                host, port = addr
                if host != self.host:
                    # Not from peer, ignore
                    return
                if not msg or len (msg) < 4:
                    self.disconnected ()
                    return
                # Check header?  For now just skip it.
                msg = msg[4:]
                logging.trace ("Received Multilink message len %d: %r",
                               len (msg), msg)
                if self.port:
                    self.node.addwork (Received (self.port.owner, packet = msg))
                else:
                    logging.trace ("Message discarded, no port open")
                    
    def send (self, msg, dest = None):
        if self.status == RUN:
            msg = bytes (msg)
            logging.trace ("Sending Multinet message len %d: %r", len (msg), msg)
            hdr = self.seq.to_bytes (2, "little") + b"\000\000"
            try:
                self.socket.sendto (hdr + msg, (self.host, self.portnum))
            except socket.error:
                self.disconnected ()
            
# Broadcast datalink base class

class BcDatalink (Datalink):
    """Base class for broadcast (LAN) datalinks.
    """
    def __init__ (self, owner, name, config):
        super ().__init__ (owner, name, config)
        self.hwaddr = None
        self.ports = dict ()
        # A subset of the counters defined by the architecture
        self.ctr_zero_time = time.time ()
        # The traffic counters are derived from the per-port counters
        #self.bytes_sent = self.pkts_sent = 0
        #self.bytes_recd = seld.pkts_recd = 0
        self.mcbytes_recd = self.mcpkts_recd = 0
        self.unk_dest = 0

    @property
    def bytes_sent (self):
        return self.combine ("bytes_sent")
    
    @property
    def bytes_recd (self):
        return self.combine ("bytes_recd")
    
    @property
    def pkts_sent (self):
        return self.combine ("pkts_sent")
    
    @property
    def pkts_recd (self):
        return self.combine ("pkts_recd")

    def combine (self, attr):
        return sum (getattr (v, attr) for v in self.ports.values ())
    
    def create_port (self, owner, proto, *args):
        port = super ().create_port (owner, proto, *args)
        proto = port.proto
        if proto in self.ports:
            raise RuntimeError ("Creating port for proto %r which is in use" \
                                % proto)
        self.ports[proto] = port
        return port
    
# Broadcast datalink port

class BcPort (Port):
    """Base class for a broadcast (LAN) datalink port.  A port
    describes an upper layer's use of the datalink, specifically
    a particular protocol type, individual address, and set of
    multicast addresses.
    """
    def __init__ (self, datalink, owner, proto):
        super ().__init__ (datalink, owner)
        self.macaddr = datalink.hwaddr
        self.multicast = set ()
        self.destfilter = set ((self.macaddr, ))
        if isinstance (proto, int):
            proto = proto.to_bytes (2, "big")
        else:
            proto = bytes (proto)
            if len (proto) != 2:
                raise ValueError ("Protocol type length is wrong")
        self.proto = proto
        # A subset of the counters defined by the architecture
        self.ctr_zero_time = time.time ()
        self.bytes_sent = self.pkts_sent = 0
        self.bytes_recd = self.pkts_recd = 0
        
    def add_multicast (self, addr):
        addr = Macaddr (addr)
        if addr in self.multicast:
            raise KeyError ("Multicast address already enabled")
        self.multicast.add (addr)
        self.destfilter.add (addr)
        
    def remove_multicast (self, addr):
        self.multicast.remove (addr)
        self.destfilter.remove (addr)

    def set_macaddr (self, addr):
        self.macaddr = addr
        self.destfilter = set (self.multicast)
        self.destfilter.add (addr)

FILL = b'\x42' * 60

class EthPort (BcPort):
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
ETH_TMO = 100    # ms
ETH_MTU = 1518

class Ethernet (BcDatalink, StopThread):
    """DEC Ethernet datalink.
    """
    port_class = EthPort
    
    def __init__ (self, owner, name, config):
        tname = "{}.{}".format (owner.node.nodename, name)
        StopThread.__init__ (self, name = tname)
        BcDatalink.__init__ (self, owner, name, config)
        dev = config.device or name
        if dev.startswith ("tap:"):
            self.api = "tap"
            dev = dev[4:]
        else:
            self.api = "pcap"
        self.dev = dev
        if config.random_address:
            self.hwaddr = Macaddr (((random.getrandbits (46) << 2) + 2).to_bytes (6, "little"))
        else:
            self.hwaddr = NULLID
        self.randaddr = config.random_address
        self.pcap = pcap.pcapObject ()
    
    def open (self):
        if self.api == "pcap":
            # Always set promiscuous mode
            self.pcap.open_live (self.dev, ETH_MTU, 1, ETH_TMO)
        else:
            # tap
            fd = os.open (self.dev, os.O_RDWR)
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
        # Find our hardware address, if not generated
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
        # Don't do the close yet, it crashes for reasons yet unknown
        #self.pcap.close ()
        
    def create_port (self, owner, proto, pad = True):
        return super ().create_port (owner, proto, pad)

    def send_frame (self, buf):
        """Send an Ethernet frame.  Ignore any errors, because that's
        the DECnet way.
        """
        try:
            if self.api == "pcap":
                l2 = self.pcap.inject (buf)
            else:
                # tap
                os.write (self.tap, buf)
        except IOError:
            pass
        
    def run (self):
        if self.api == "pcap":
            while True:
                if self.stopnow:
                    break
                try:
                    cnt = self.pcap.dispatch (0, self.receive)
                except pcap._pcap.error:
                    break
        else:
            # tap
            while True:
                if self.stopnow:
                    break
                try:
                    # Note: for some reason, the timeout does nothing
                    # on Mac OS.
                    try:
                        r, w, x = select.select (self.sellist, (),
                                                 self.sellist, ETH_TMO)
                    except select.error:
                        x = True
                    if not r and not x:
                        continue
                    pkt = os.read (self.tap, 1518)
                    if not pkt:
                        continue
                    self.receive (len (pkt), pkt, None)
                except OSError:
                    break
            
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
        if dest in port.destfilter:
            if dest[0] & 1:
                self.mcbytes_recd += plen
                self.mcpkts_recd += 1
            port.bytes_recd += plen
            port.pkts_recd += 1
            src = Macaddr (packet[6:12])
            if port.pad:
                plen2 = packet[14] + (packet[15] << 8)
                if plen < plen2 + 16:
                    logging.debug ("On %s, packet length field %d inconsistent with packet length %d",
                                   self.name, plen2, plen)
                    return
                packet = memoryview (packet)[16:16 + plen2]
            else:
                packet = memoryview (packet)[14:]
            self.node.addwork (Received (port.owner,
                                         src = src, packet = packet))
                

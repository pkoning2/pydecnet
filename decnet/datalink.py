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
        self.node.datalink = self
        self.config = config
        self.circuits = dict ()
        for name, c in config.circuit.items ():
            kind = globals ()[c.type]
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
    def send (self, msg):
        """Transmit a message.  
        """
        pass

class DlReceive (Work):
    """Notification of a received packet.  Attributes are "packet"
    (the data) and, for LANs, "src" (the source address)
    """

class DlTransmitComplete (Work):
    """Notification of a packet transmit completion (successful or not).
    Attribute is "packet".
    """

class DlStatus (Work):
    """Notification of some sort of datalink event.  Attribute is
    "status".
    """

# Point to point datalink base class

class PtpDatalink (Datalink):
    """Base class for point to point datalinks.
    """

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
        dest = bytes (dest)
        if len (dest) != 6:
            raise ValueError
        l = len (msg)
        f = self.frame
        f[0:6] = dest
        if self.pad:
            if l > 1498:
                raise ValueError
            f[14] = l & 0xff
            f[15] = l >> 8
            f[16:16 + l] = msg
            l += 16
        else:
            if l > 1500:
                raise ValueError
            f[14:14 + l] = msg
            l += 14
        # Always send packet padded to min of 60 if need be, whether
        # pad mode is specified or not.
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
        StopThread.__init__ (self)
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
            self.pcap.open_live (self.name, ETH_MTU, 1, ETH_TMO)
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
                ifreq.pack_into (req, 0, self.name.encode ("ascii"), 0)
                s = socket.socket (socket.AF_INET, socket.SOCK_DGRAM, 0)
                ioctl (s, SIOCGIFFLAGS, req)
                name, flags = ifreq.unpack_from (req)
                ifreq.pack_into (req, 0, name, flags | 1)
                ioctl (s, SIOCSIFFLAGS, req)
        # Find our hardware address, if not generated
        if not self.randaddr:
            for dname, desc, addrs, flags in pcap.findalldevs ():
                if dname == self.name and addrs:
                    self.hwaddr = Macaddr (addrs[0][0])
        logging.debug ("Ethernet %s hardware address is %s",
                       self.name, self.hwaddr)
        # start receive thread
        self.start ()
        
    def close (self):
        #self.stop ()
        self.pcap.close ()
        
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
                    r, w, x = select.select (self.sellist, (),
                                             self.sellist, ETH_TMO)
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
            self.node.addwork (DlReceive (port.owner,
                                          src = src, packet = packet))
                

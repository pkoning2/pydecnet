#!

"""Classes for the datalink layer as used by DECnet routing.

"""

from abc import abstractmethod, ABCMeta
import pcap
import re
import time

from .node import *
from .packet import *
from .timers import *

_mac_re = re.compile ("[-:]")
def scan_macaddr (s):
    """Return a binary MAC address given its string representation
    """
    bl = _mac_re.split (s)
    if len (bl) != 6:
        raise ValueError ("Invalid MAC address string %s" % s)
    return bytes (int (f, 16) for f in bl)

def format_macaddr (b):
    return "{0[0]:02x}-{0[1]:02x}-{0[2]:02x}-{0[3]:02x}-{0[4]:02x}-{0[5]:02x}".format (b)

class Datalink (Element, metaclass = ABCMeta):
    """Abstract base class for a DECnet datalink.
    """
    def __init__ (self, owner, name):
        """Initialize a Datalink instance.  "name" is the name of
        the instance; "owner" is its owner.
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
        """Transmit a message.  Upon completion, a DlTransmitComplete
        will be passed to the owner.
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
    def __init__ (self, owner, name):
        super ().__init__ (owner, name)
        self.hwaddr = None
        self.ports = dict ()

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
        
    def add_multicast (self, addr):
        if isinstance (addr, str):
            addr = scan_macaddr (addr)
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
        super ().set_macaddr (addr)
        self.frame[6:12] = addr
        
    def send (self, msg, dest):
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
        self.parent.send (memoryview (f)[:l])

class Ethernet (BcDatalink, StopThread):
    """DEC Ethernet datalink.
    """
    port_class = EthPort
    
    def __init__ (self, owner, name):
        StopThread.__init__ (self)
        BcDatalink.__init__ (self, owner, name)
        self.hwaddr = bytes (6)
        for dname, desc, addrs, flags in pcap.findalldevs ():
            if dname == name and addrs:
                self.hwaddr = scan_macaddr (addrs[0][0])
        self.pcap = pcap.pcapObject ()
    
    def open (self):
        # Always set promiscuous mode
        self.pcap.open_live (self.name, 1600, 1, 100)
        # start receive thread
        self.start ()
        
    def close (self):
        #self.stop ()
        self.pcap.close ()
        
    def create_port (self, owner, proto, pad = True):
        return super ().create_port (owner, proto, pad)

    def send (self, buf):
        l2 = self.pcap.inject (buf)
        if l2 != len (buf):
            raise IOError
        
    def run (self):
        while True:
            if self.stopnow:
                break
            try:
                cnt = self.pcap.dispatch (0, self.receive)
            except pcap._pcap.error:
                break
            #print (cnt, "packets dispatched")

    def receive (self, plen, packet, ts):
        #print (plen, packet, ts)
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
            return
        dest = packet[:6]
        if dest in port.destfilter:
            src = packet[6:12]
            if port.pad:
                plen2 = packet[14] + (packet[15] << 8)
                if plen < plen2 + 16:
                    print ("Packet length field %d inconsistent with packet length %d" % (plen2, plen))
                    return
                packet = memoryview (packet)[16:16 + plen2]
            else:
                packet = memoryview (packet)[14:]
            self.node.addwork (DlReceive (port.owner,
                                          src = src, packet = packet))
                

#!

"""Classes for the datalink layer as used by DECnet routing.

"""

from abc import abstractmethod

class Datalink (object):
    """Abstract base class for a datalink used by DECnet routing.
    """
    def __init__ (self, name, owner):
        """Initialize a Datalink instance.  "name" is the name of
        the instance; "owner" is its owner (a routing layer circuit
        instance.  The owner will receive notifications of received data,
        transmit completions, and other applicable upcalls by calls
        to its dl_notification method.
        """
        self.name = name
        self.owner = owner

    @abstractmethod
    def send (self, msg):
        """Transmit a message.  Upon completion, a DlTransmitComplete
        will be passed to the owner.
        """
        pass

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

# Classes for datalink notifications to the routing datalink dependent
# sublayer

class DlNofication (object):
    @abstractmethod
    def __init__ (self, dl):
        self.datalink = dl

    def send (self):
        self.datalink.dl_nofication (self)
        
class DlReceive (DlNotification):
    """Notification of a received packet.
    """
    def __init__ (self, dl, msg):
        super ().__init__ (dl)
        self.msg = msg

class DlTransmitComplete (DlNotification):
    """Notification of a packet transmit completion (successful or not).
    """
    def __init__ (self, dl, msg):
        super ().__init__ (dl)
        self.msg = msg

class DlStatus (DlNotification):
    """Notification of some sort of datalink event.
    """
    def __init__ (self, dl, event):
        super ().__init__ (dl)
        self.event = event


# Point to point datalink base class

class PtpDatalink (Datalink):
    """Base class for point to point datalinks.
    """

# Broadcast datalink base class

class BcDatalink (Datalink):
    """Base class for broadcast (LAN) datalinks.
    """
    def __init__ (self, name, owner, proto):
        super ().__init__ (name, owner)
        self.macaddr = None
        self.proto = proto
        self.multicast = set ()

    @abstractmethod
    def add_multicast (self, addr):
        if addr in self.multicast:
            raise KeyError ("Multicast address already enabled")
        self.multicast.add (addr)

    @abstractmethod
    def remove_multicast (self, addr):
        self.multicast.remove (addr)

    @abstractmethod
    def set_macaddr (self, addr):
        self.macaddr = addr

class Ethernet (BcDatalink):
    """DEC Ethernet datalink class.
    """
    def __init__ (self, name, owner, proto, pad = True):
        super ().__init__ (dev, owner, proto)
        self.pad = pad
        f = self.frame = bytearray (1514)
        f[12] = proto >> 8
        f[13] = proto & 0xff
        self.hwaddr = None
        for name, desc, addrs, flags in pcap.findalldevs ():
            if addrs:
                self.hwaddr = addrs[0][0]
                self.set_macaddr (self.hwaddr)
                
    def open (self):
        p = pcap.pcapObject ()
        p.open_live (self.name, 1600, 0, 1000)
        p.setfilter ("ether proto 0x%04x" % self.proto, 0, 0)
        self.pcap = p
        # start receive thread

    def set_macaddr (self, addr):
        super ().set_macaddr (addr)
        self.frame[6:12] = addr
        
    def run (self):        
        while not self.stopnow:
            p.dispatch (1, receive_indication)
        
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
        l = min (l, 60)
        l2 = self.pcap.inject (memoryview (f)[:l])
        if l != l2:
            raise IOError

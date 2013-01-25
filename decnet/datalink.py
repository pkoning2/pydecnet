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
        
    def open (self):
        p = pcap.pcapObject ()
        p.open_live (self.name, 1600, 0, 1000)
        p.setfilter ("ether proto 0x%04x" % self.proto, 0, 0)
        self.pcap = p
        # start receive thread

    def run (self):        
        while not self.stopnow:
            p.dispatch (1, receive_indication)
        
    def send (self, msg, dest):
        if len (dest) != 6:
            raise ValueError
        l = len (msg)
        data = [ dest, self.macaddr, self.proto ]
        if self.pad:
            if l > 1498:
                raise ValueError
            data.append (struct.pack ("<H", l))
            data.append (msg)
            if l < 44:
                data.append (bytes (44 - l))
                l = 44
            l += 16
        else:
            if l > 1500 or l < 46:
                raise ValueError
            data.append (msg)
            l += 14
        l2 = self.pcap.inject (b''.join (data))
        if l != l2:
            raise IOError

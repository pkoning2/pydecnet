#!

"""Classes for the datalink layer as used by DECnet routing.

"""

from abc import abstractmethod, ABCMeta
import time
import os
import sys
import struct
import socket

from .common import *
from . import logging

class HostAddress (object):
    """A class for handling host addresses, including periodic refreshing
    of name lookup information.  Thanks to Rob Jarratt for the idea, in
    a note on the HECnet list.
    """
    def __init__ (self, name, interval = 3600):
        """Initialize a HostAddress object for the supplied name, which
        will be looked up now and re-checked every "interval" seconds.
        The default check interval is one hour.
        """
        self.name = name
        self.interval = interval
        self.next_check = 0
        self._addr = None
        self.lookup ()

    def lookup (self, pref = None):
        """Look up the name in DNS.  Return one of the IP addresses
        for the name.  If "pref" is supplied, return that value if it
        is still one of the valid addresses for the name.
        """
        try:
            alist = socket.gethostbyname_ex (self.name)[2]
        except socket.gaierror:
            # Error in name resolution.  Return pref as the fallback
            return pref
        self.aset = frozenset (alist)
        self.next_check = time.time () + self.interval
        if pref and pref in self.aset:
            self._addr = pref
        else:
            self._addr = random.choice (alist)
        return self.addr

    def valid (self, addr):
        """Verify that the supplied address is a valid address for
        the host, i.e., that it is in the set of IP addresses we found
        at the last lookup.
        """
        self.check_interval ()
        return addr in self.aset

    def check_interval (self):
        """Do another check, if needed.  If so, do another DNS lookup
        and select an address from among the set of addresses found.
        If the currently selected address is still valid, keep that one;
        otherwise pick a random one.
        """
        if time.time () > self.next_check:
            self.lookup (self._addr)

    @property
    def addr (self):
        """Return the currently chosen address to use when sending to
        this host.
        """
        self.check_interval ()
        return self._addr

    def __str__ (self):
        return str (self.addr)
    
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
        datalinks = { d.__name__ : d for d in Datalink.leafclasses () }
        for name, c in config.circuit.items ():
            try:
                kind = datalinks[c.type]
            except KeyError:
                logging.error ("Invalid datalink type {!r}", kind)
                continue
            kindname = kind.__name__
            try:
                dl = kind (self, name, c)
                self.circuits[name] = dl
                logging.debug ("Initialized {} datalink {}", kindname, name)
            except Exception:
                logging.exception ("Error initializing {} datalink {}",
                                   kindname, name)

    def start (self):
        """Start the datalink layer, which means starting each of
        the circuits that were configured.
        """
        logging.debug ("Starting datalink layer")
        for name, c in self.circuits.items ():
            try:
                c.open ()
                logging.debug ("Started datalink {}", name)
            except Exception:
                logging.exception ("Error starting datalink {}", name)
    
    
    def stop (self):
        """Stop the datalink layer, which means stopping each of
        the circuits that were configured.
        """
        logging.debug ("Stopping datalink layer")
        for name, c in self.circuits.items ():
            try:
                c.close ()
                logging.debug ("Stopped datalink {}", name)
            except Exception:
                logging.exception ("Error stopping datalink {}", name)
    
    
class Datalink (Element, metaclass = ABCMeta):
    """Abstract base class for a DECnet datalink.
    """
    use_mop = False    # True if we want MOP to run on this type of datalink

    def __init__ (self, owner, name, config):
        """Initialize a Datalink instance.  "name" is the name of
        the instance; "owner" is its owner; "config" is the configuration
        data for this circuit.
        The owner will receive notifications of received data,
        transmit completions, and other applicable events by work
        items delivered via the node work queue to the "dispatch"
        method of the owner.
        """
        super ().__init__ (owner)
        self.name = name
        self.owner = owner
        self.config = config

    @classmethod
    def leafclasses (cls):
        """Yield the leaf classes of Datalink -- these are the actually
        supported DECnet datalink types.
        """
        scl = cls.__subclasses__ ()
        if scl:
            for sc in scl:
                yield from sc.leafclasses ()
        elif cls.__name__[0] != '_':
            yield cls

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
    def __str__ (self):
        return "DLStatus: {}".format (self.status)
    
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
    # This attribute is True if datalink start obeys the required
    # semantics, i.e., data link requirement #2 "Detection of remote startup"
    # is implemented.
    start_works = True
    
    def __init__ (self, owner, name, config):
        super ().__init__ (owner, name, config)
        self.port = None
        # A subset of the counters defined by the architecture
        self.ctr_zero_time = time.time ()
        self.bytes_sent = self.pkts_sent = 0
        self.bytes_recv = self.pkts_recv = 0
        
    def create_port (self, owner, proto = None, *args):
        port = super ().create_port (owner, proto, *args)
        if self.port:
            raise RuntimeError ("Creating second port on point to point datalink")
        self.port = port
        return port
    
# Broadcast datalink base class

class BcDatalink (Datalink):
    """Base class for broadcast (LAN) datalinks.
    """
    use_mop = True     # True since we want MOP to run on this type of datalink

    def __init__ (self, owner, name, config):
        super ().__init__ (owner, name, config)
        # macaddr is the current MAC address, if in single address mode
        self.hwaddr = self.macaddr = None
        self.single_address = config.single_address
        self.ports = dict ()
        # A subset of the counters defined by the architecture
        self.ctr_zero_time = time.time ()
        # The traffic counters are derived from the per-port counters
        #self.bytes_sent = self.pkts_sent = 0
        #self.bytes_recv = seld.pkts_recv = 0
        self.mcbytes_recv = self.mcpkts_recv = 0
        self.unk_dest = 0

    @property
    def bytes_sent (self):
        return self.combine ("bytes_sent")
    
    @property
    def bytes_recv (self):
        return self.combine ("bytes_recv")
    
    @property
    def pkts_sent (self):
        return self.combine ("pkts_sent")
    
    @property
    def pkts_recv (self):
        return self.combine ("pkts_recv")

    def combine (self, attr):
        # Note that a given port can appear more than once in the
        # ports dictionary.  Count it only once here, under its
        # primary port number (the one given at port create time).
        return sum (getattr (v, attr) for k, v in self.ports.items ()
                    if v.proto == k)
    
    def create_port (self, owner, proto, *args):
        port = super ().create_port (owner, proto, *args)
        proto = port.proto
        if proto in self.ports:
            raise RuntimeError ("Creating port for proto {!r} which is in use".format (proto))
        self.ports[proto] = port
        return port
    
# Broadcast datalink port

class _Any (object):
    """Emulates a container that contains everything -- set this as
    the address filter to be promiscuous.
    """
    def __contains__ (self, other):
        return True

_any = _Any ()

class BcPort (Port):
    """Base class for a broadcast (LAN) datalink port.  A port
    describes an upper layer's use of the datalink, specifically
    a particular protocol type, individual address, and set of
    multicast addresses.
    """
    def __init__ (self, datalink, owner, proto):
        super ().__init__ (datalink, owner)
        self._macaddr = datalink.hwaddr
        self.multicast = set ()
        self.promisc = False
        self._update_filter ()
        proto = Ethertype (proto)
        self.proto = proto
        self.protoset = set ()
        self.protoset.add (proto)
        # A subset of the counters defined by the architecture (just
        # traffic counters, not error counters because those in
        # general don't make it into here).
        self.ctr_zero_time = time.time ()
        self.bytes_sent = self.pkts_sent = 0
        self.bytes_recv = self.pkts_recv = 0
        self.mcbytes_recv = self.mcpkts_recv = 0

    @property
    def macaddr (self):
        if self.parent.single_address:
            return self.parent.macaddr
        return self._macaddr

    @macaddr.setter
    def macaddr (self, addr):
        addr = Macaddr (addr)
        if addr.ismulti ():
            raise ValueError ("Address {} is not an individual address".format (addr))
        if self.parent.single_address:
            self.parent.macaddr = addr
        else:
            self._macaddr = addr
        
    def _update_filter (self):
        if self.promisc:
            self.destfilter = _any
        else:
            self.destfilter = self.multicast
        
    def set_promiscuous (self, promisc = True):
        """Set (default) or clear (promisc = False) promiscuous mode.
        """
        self.promisc = promisc
        logging.trace ("{} promiscuous mode set to {}", self, promisc)
        self._update_filter ()
        
    def add_multicast (self, addr):
        addr = Macaddr (addr)
        if not addr.ismulti ():
            raise ValueError ("Address {} is not a multicast address".format (addr))
        if addr in self.multicast:
            raise KeyError ("Multicast address already enabled")
        self.multicast.add (addr)
        logging.trace ("{} multicast address {} added", self, addr)
        self._update_filter ()
        
    def remove_multicast (self, addr):
        addr = Macaddr (addr)
        self.multicast.remove (addr)
        logging.trace ("{} multicast address {} removed", self, addr)
        self._update_filter ()

    def add_proto (self, proto):
        proto = Ethertype (proto)
        if proto in self.protoset:
            raise KeyError ("Protocol type already enabled")
        if proto in self.parent.ports:
            raise RuntimeError ("Protocol type in use by another port")
        self.parent.ports[proto] = self
        self.protoset.add (proto)
        logging.trace ("{} protocol {} added", self, proto)
        
    def remove_proto (self, proto):
        proto = Ethertype (proto)
        self.protoset.remove (proto)
        del self.parents.ports[proto]
        logging.trace ("{} protocol {} removed", self, proto)

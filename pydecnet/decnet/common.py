#!

"""Common things that don't depend on other decnet modules.

"""

import re
import threading
import struct

from . import logging

DNVERSION = "DECnet/Python V1.0"

# Defaults

DEFCONFIG = "pydecnet.conf"
DEFAPISOCKET = "decnetsocket"

# Important constants

MOPDLPROTO   = 0x6002
MOPCONSPROTO = 0x6002
ROUTINGPROTO = 0x6003
LATPROTO     = 0x6004   # used by bridge
LOOPPROTO    = 0x9000
HIORD = b"\xaa\x00\x04\x00"
T2 = 1
PTP_T3MULT = 2
BCT3MULT = 3
DRDELAY = 5
INFHOPS = 31
INFCOST = 1023

MTU = 576                # Max NPDU size
ETHMTU = MTU + 21 - 6    # Ditto, adjusted for long vs. short header
MSS = MTU - 13           # Max TSDU size

# Exceptions
class DNAException (Exception): pass

# Exceptions related to packet encode/decode
class DecodeError (DNAException): pass
class WrongValue (DecodeError):
    """Constant field in packet with wrong value."""
class ExtraData (DecodeError):
    """Unexpected data at end of packet."""
class MissingData (DecodeError):
    """Unexpected end of packet in decode."""
class FieldOverflow (DecodeError):
    """Value too large for field size."""
class InvalidTag (DecodeError):
    """Unknown TLV tag field."""
    
# List of file descriptors to keep open if we run as daemon
files_preserve = list ()
def dont_close (f):
    files_preserve.append (f)
    
class Element (object):
    """Element is the base class for most classes that define DECnet
    components.  The elements of a node form a tree, whose root is
    the Node object.
    """
    def __init__ (self, parent):
        self.parent = parent
        self.node = parent.node

# Classes used to send work to DECnet components.  We need these because
# we want the main processing to be done in the main thread, to avoid
# lots of locks and thread safety bugs.  Other threads, such as the timer
# thread, datalinks, etc., create Work objects and queue these onto the
# node work queue.  The node then calls the dispatch method, which sends
# the work to the dispatch method of the component (called the "owner").
# For example, the datalink receive thread will send received packets
# to the routing initialization layer instance for that circuit.
#
# Derived classes can override __init__ to add more attributes, but
# in many cases derived classes need nothing else.  Any keyword arguments
# on the constructor will produce attributes by those names, so overriding
# __init__ is only useful if you need something more complicated.

class Work (object):
    """Base class for work object
    """
    def __init__ (self, owner, **kwarg):
        self.owner = owner
        self.__dict__.update (kwarg)

    def dispatch (self):
        self.owner.dispatch (self)

    def __str__ (self):
        return "Work item: %s" % self.__class__.__name__

# Some common work item classes

class Shutdown (Work):
    """A work item that says "shut down".
    """
    
class Received (Work):
    """Notification of a received packet.  Attributes are "packet"
    (the data) and "src" (the source of the packet, of whatever form
    is meaningful to the consumer; for example, for datalink notifications
    it would be the MAC address, for Routing layer notifications it
    is the source node address).
    """
    def __str__ (self):
        try:
            return "Received from %s: %s" % (self.src, self.packet)
        except AttributeError:
            return "Received: %s" % self.packet

_nodeid_re = re.compile (r"^(?:(\d+)\.)?(\d+)$")
class Nodeid (int):
    """A DECnet Node ID.
    """
    def __new__ (cls, s, id2 = None):
        """Create a Nodeid from a string, an integer, a pair of integers,
        a Mac address, or anything that can be converted to a byte string
        of length 2.

        Note that this accepts some technically invalid values, such as
        node number of zero or area number of zero, to avoid running into
        trouble in some use cases.
        """
        if isinstance (s, str):
            m = _nodeid_re.match (s)
            if not m:
                raise ValueError ("Invalid node ID %s" % s)
            a, n = m.groups ()
            n = int (n)
            if a is None:
                # Phase 3 ID
                a = 0
            else:
                a = int (a)
        elif isinstance (s, int):
            if id2 is None:
                a, n = divmod (s, 1024)
            else:
                a, n = s, id2
        elif isinstance (s, Macaddr):
            if s[:4] != HIORD:
                raise ValueError ("Invalid DECnet Mac address %s" % s)
            a, n = divmod (int.from_bytes (s[4:], "little"), 1024)
        else:
            s = bytes (s)
            if len (s) != 2:
                raise DecodeError ("Invalid node ID %s" % s)
            a, n = divmod (int.from_bytes (s, "little"), 1024)
        if a > 63 or n > 1023:
            raise ValueError ("Invalid node ID %s" % s)
        return int.__new__ (cls, (a << 10) + n)

    @classmethod
    def decode (cls, buf):
        if len (buf) < 2:
            raise MissingData
        return cls (buf[:2]), buf[2:]

    @property
    def area (self):
        return int (self) >> 10

    @property
    def tid (self):
        return int (self) & 1023

    def split (self):
        return divmod (int (self), 1024)

    def __divmod__ (self, other):
        return divmod (int (self), other)
    
    def __str__ (self):
        a, t = self.split ()
        if a:
            return "{}.{}".format (a, t)
        else:
            return "{}".format (t)

    __repr__ = __str__
    
    def __bytes__ (self):
        return self.to_bytes (2, "little")
    
_mac_re = re.compile ("[-:]")
class Macaddr (bytes):
    """MAC address for Ethernet (or similar LAN).
    """
    def __new__ (cls, s):
        """Create a Macaddr instance from a string, a Nodeid, or
        any other object that can be converted to a bytes object of
        length 6.
        """
        if isinstance (s, str):
            bl = _mac_re.split (s)
            if len (bl) != 6:
                if _nodeid_re.match (s):
                    s = Nodeid (s)
                    if not s.area:
                        raise ValueError ("Invalid MAC address string %s" % s)
                    s = HIORD + bytes (s)
                else:
                    raise ValueError ("Invalid MAC address string %s" % s)
            else:
                s = bytes (int (f, 16) for f in bl)
        elif isinstance (s, Nodeid):
            s = HIORD + bytes (s)
        else:
            s = bytes (s)
            if len (s) != 6:
                raise DecodeError ("Invalid MAC address string %s" % s)
        return bytes.__new__ (cls, s)

    @classmethod
    def decode (cls, buf):
        if len (buf) < 6:
            raise MissingData
        return cls (buf[:6]), buf[6:]

    def __str__ (self):
        return "{0[0]:02x}-{0[1]:02x}-{0[2]:02x}-{0[3]:02x}-{0[4]:02x}-{0[5]:02x}".format (self)

    __repr__ = __str__
    
NULLID = Macaddr (bytes (6))

_version = struct.Struct ("<BBB")
class Version (bytes):
    """DECnet component version number -- 3 integers.
    """
    def __new__ (cls, v1, v2 = 0, v3 = 0):
        if isinstance (v1, str):
            v = v1.split ('.')
            if len (v) != 3:
                raise ValueError ("Invalid version string %s" % v1)
            v = _version.pack (*(int (i) for i in v))
        elif isinstance (v1, int):
            v = _version.pack (v1, v2, v3)
        else:
            v = bytes (v1)
            if len (v) != 3:
                raise ValueError ("Invalid version string %s" % v1)
        return super ().__new__ (cls, v)

    @classmethod
    def decode (cls, buf):
        if len (buf) < 3:
            raise MissingData
        return cls (buf[:3]), buf[3:]

    def __str__ (self):
        v1, v2, v3 = _version.unpack (self)
        return "{}.{}.{}".format (v1, v2, v3)

    __repr__ = __str__
    
def scan_ver (s):
    """Convert a string specifying the console carrier verification data
    to the protocol value (8 bytes).
    """
    if s.lower ().startswith ("0x"):
        v = int (s, 16).to_bytes (8, "big")
    else:
        v = s.encode ("latin-1", "ignore")
        l = len (v)
        if l > 8:
            raise ValueError ("Verification string %s too long" % s)
        if l < 8:
            v += bytes (8 - l)
    return v

_nodename_re = re.compile (r"[a-z0-9]*[a-z][a-z0-9]*$", re.I)
def nodename (s):
    """Accept a string that looks like a node name.
    """
    if _nodename_re.match (s) and len (s) <= 6:
        return s.upper ()
    raise ValueError ("Invalid node name %s" % s)

_circname_re = re.compile (r"[a-z]+[-0-9]*$", re.I)
def circname (s):
    """Accept a string that looks like a circuit name.
    """
    if _circname_re.match (s):
        return s.upper ()
    raise ValueError ("Invalid circuit name %s" % s)

class StopThread (threading.Thread):
    """A thread with stop method.  By default this will be
    a daemon thread.
    """
    def __init__ (self, **kwargs):
        super ().__init__ (**kwargs)
        self.stopnow = False
        self.daemon = True
        
    def stop (self, wait = False):
        """Stop the thread.  This is called from another thread. The actual
        handling of "stopnow" needs to go into the class that uses this.

        If "wait" is True, wait for the thread to exit.
        """
        if not self.stopnow and self.isAlive ():
            self.stopnow = True
            if wait:
                self.join (10)
                if self.is_alive ():
                    logging.error ("Thread %s failed to stop after 10 seconds",
                                   self.name)
                else:
                    logging.trace ("Thread %s stopped", self.name)


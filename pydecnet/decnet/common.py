#!

"""Common things that don't depend on other decnet modules.

"""

import re
import threading
import struct
import sys
import random
import time

WIN = "win" in sys.platform and "darwin" not in sys.platform

DNVERSION = "DECnet/Python V1.0"

# Defaults

DEFCONFIG = "pydecnet.conf"

# Important constants

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
class DNAException (Exception):
    def __str__ (self):
        if self.args:
            text, *args = self.args
            return text.format (*args)
        return self.__doc__

# Exceptions related to packet encode/decode
class DecodeError (DNAException):
    """Packet decode error."""
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

# Tuple of bytestring types (used in isinstance checks when we need
# to recognize some sort of byte buffer but don't know which specific
# one of several types for that purpose we're dealing with)
bytetypes = (bytes, bytearray, memoryview)

# Tuple of string/byte types, similar to the above but also includes str.
# Basically, these are types that collections.abc calls Sequence but that
# we would treat as non-sequence (single value).
strtypes = (str, bytes, bytearray, memoryview)

# It would be handy to have the bytes analog of chr() as a builtin,
# but there isn't one, so make one.
def byte (n):
    return bytes ((n,))

# List of file descriptors to keep open if we run as daemon
files_preserve = list ()
def dont_close (f):
    files_preserve.append (f)
    
class Entity (object):
    """Entity is the base class for most classes that define DECnet
    components.  This defines objects that can (potentially) be accessed
    by the API.
    """
    def getentity (self, ent):
        # Default method for getting the next entity in the path spec
        # of a JSON API request.
        return getattr (self, ent)

class AllEntries (object):
    def __init__ (self, parent):
        self.parent = parent

    def get_api (self):
        return { str (k) : v.get_api () for (k, v) in self.parent.items () }

class EntityDict (dict):
    """A dictionary subclass that allows access by the GET API.
    """
    def getentity (self, ent):
        if ent == "*":
            return AllEntries (self)
        return self[ent.upper ()]
    
    def get_api (self):
        # GET on the dictionary returns the list of its keys
        return list (self)
    
class Element (Entity):
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
        return "Work item: {}".format (self.__class__.__name__)

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
            return "Received from {}: {}".format (self.src, self.packet)
        except AttributeError:
            return "Received: {}".format (self.packet)

_nodeid_re = re.compile (r"^(?:(\d+)\.)?(\d+)$")
class Nodeid (int):
    """A DECnet Node ID.
    """
    def __new__ (cls, s, id2 = None):
        """Create a Nodeid from a string, an integer, a pair of integers,
        a Mac address, or anything that can be converted to a byte string
        of length 2.

        Node 0 is accepted for string or integer inputs; that is
        intended to represent the local node but that conversion has to
        be handled by the caller.
        """
        if isinstance (s, str):
            m = _nodeid_re.match (s)
            if not m:
                raise ValueError ("Invalid node ID {}".format (s))
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
                raise ValueError ("Invalid DECnet Mac address {}".format (s))
            a, n = divmod (int.from_bytes (s[4:], "little"), 1024)
            if n == 0 or a == 0:
                raise ValueError ("Invalid node ID {}".format (s))
        else:
            s = bytes (s)
            if len (s) != 2:
                raise DecodeError ("Invalid node ID {}".format (s))
            a, n = divmod (int.from_bytes (s, "little"), 1024)
            if n == 0:
                raise ValueError ("Invalid node ID {}".format (s))
        if a > 63 or n > 1023 or (n == 0 and a != 0):
            raise ValueError ("Invalid node ID {}".format (s))
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
                    b = Nodeid (s)
                    if not b.area:
                        raise ValueError ("Invalid MAC address string {}".format (s))
                    b = HIORD + bytes (b)
                else:
                    raise ValueError ("Invalid MAC address string {}".format (s))
            else:
                b = bytes (int (f, 16) for f in bl)
        elif isinstance (s, Nodeid):
            b = HIORD + bytes (s)
        else:
            b = bytes (s)
            if len (b) != 6:
                raise ValueError ("Invalid MAC address string {}".format (s))
        return bytes.__new__ (cls, b)

    @classmethod
    def decode (cls, buf):
        if len (buf) < 6:
            raise MissingData
        return cls (buf[:6]), buf[6:]

    def __str__ (self):
        return "{0[0]:02x}-{0[1]:02x}-{0[2]:02x}-{0[3]:02x}-{0[4]:02x}-{0[5]:02x}".format (self)

    __repr__ = __str__

    def islocal (self):
        """True if the address is from the locally administered address space."""
        return (self[0] & 0x02) != 0
    
    def ismulti (self):
        """True if the address is a multicast address."""
        return (self[0] & 0x01) != 0
    
NULLID = Macaddr (bytes (6))

class Ethertype (bytes):
    """Protocol type for Ethernet
    """
    def __new__ (cls, s):
        """Create an Ethertype instance from a string or any other
        object that can be converted to a bytes object of length 2.
        """
        if isinstance (s, str):
            bl = _mac_re.split (s)
            if len (bl) != 2:
                raise ValueError ("Invalid MAC address string {}".format (s))
            else:
                b = bytes (int (f, 16) for f in bl)
        elif isinstance (s, int):
            try:
                b = s.to_bytes (2, "big")
            except OverflowError:
                raise ValueError ("Invalid Ethertype value {}".format (s)) from None
        else:
            b = bytes (s)
            if len (b) != 2:
                raise ValueError ("Invalid Ethertype string {}".format (s))
        return bytes.__new__ (cls, b)

    @classmethod
    def decode (cls, buf):
        if len (buf) < 2:
            raise MissingData
        return cls (buf[:2]), buf[2:]

    def __str__ (self):
        return "{0[0]:02x}-{0[1]:02x}".format (self)

    __repr__ = __str__

# Well known protocol types
MOPDLPROTO   = Ethertype ("60-01")
MOPCONSPROTO = Ethertype ("60-02")
ROUTINGPROTO = Ethertype ("60-03")
LATPROTO     = Ethertype ("60-04")   # used by bridge
LOOPPROTO    = Ethertype ("90-00")

_version = struct.Struct ("<BBB")
class Version (bytes):
    """DECnet component version number -- 3 integers.
    """
    def __new__ (cls, v1, v2 = 0, v3 = 0):
        if isinstance (v1, str):
            v = v1.split ('.')
            if len (v) != 3:
                raise ValueError ("Invalid version string {}".format (v1))
            v = _version.pack (*(int (i) for i in v))
        elif isinstance (v1, int):
            v = _version.pack (v1, v2, v3)
        else:
            v = bytes (v1)
            if len (v) != 3:
                raise ValueError ("Invalid version string {}".format (v1))
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
            raise ValueError ("Verification string {} too long".format (s))
        if l < 8:
            v += bytes (8 - l)
    return v

_nodename_re = re.compile (r"[a-z0-9]*[a-z][a-z0-9]*$", re.I)
def nodename (s):
    """Accept a string that looks like a node name.
    """
    if _nodename_re.match (s) and len (s) <= 6:
        return s.upper ()
    raise ValueError ("Invalid node name {}".format (s))

_circname_re = re.compile (r"[a-z]+[-0-9]*$", re.I)
def circname (s):
    """Accept a string that looks like a circuit name.
    """
    if _circname_re.match (s):
        return s.upper ()
    raise ValueError ("Invalid circuit name {}".format (s))

class StopThread (threading.Thread):
    """A thread with stop method.  By default this will be
    a daemon thread.
    """
    def __init__ (self, **kwargs):
        super ().__init__ (**kwargs)
        self.stopnow = False
        self.daemon = True
        # This is a hack, but it avoids circular imports
        global logging
        from . import logging
        
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
                    logging.error ("Thread {} failed to stop after 10 seconds",
                                   self.name)
                else:
                    logging.trace ("Thread {} stopped", self.name)

class WorkHandler (object):
    """A simple object that accepts a work item as Element would, and
    delivers it to another thread that's waiting for it.
    """
    def __init__ (self):
        self.sem = threading.Semaphore (value = 0)
        self.item = None
        
    def dispatch (self, work):
        logging.trace ("WorkHandler work posted {}", repr (work))
        self.item = work
        self.sem.release ()

    def wait (self, timeout = 2):
        if self.sem.acquire (timeout = timeout):
            return self.item
        # Timeout
        return None

class ConnApiHelper (Element):
    """A helper class to implement the API for a connection class.
    """
    def __init__ (self, parent, connclass):
        super ().__init__ (parent)
        self.connclass = connclass
        
    def post_api (self, data):
        if "handle" in data:
            try:
                conn = self.parent.conn_clients[data["handle"]]
            except KeyError:
                return { "status" : "unknown handle" }
            conn.last_post = time.time ()
            return conn.post_api (data)
        listen = WorkHandler ()
        conn = self.connclass (self.parent, data, listen)
        return listen.wait (timeout = 60)
    
class BaseCounters (object):
    """Base class for counters.  This handles the time-since-zeroed
    element, and provides a method for copying the counters to another
    object (such as a packet) by copying fields with matching names.

    There is no "zero" operation; to implement that, simply replace the
    current counter object with a newly created one.
    """
    def __init__ (self, owner):
        self._owner = owner
        self._time_zeroed = time.time ()

    @property
    def time_since_zeroed (self):
        delta = int (time.time () - self._time_zeroed)
        if delta > 65535:
            delta = 65535
        return delta

    def copy (self, other):
        """This copies the counters to the destination, for each counter
        name that is a current attribute of "other".  Those names are
        taken from dir(other), which will give us all names in __slots__
        (such as packet fields), or attributes of the class, or
        attributes previously assigned to "other".
        """
        onames = set (dir (other))
        for k, v in self.makedict ().items ():
            if k in onames:
                setattr (other, k, v)
            else:
                print ("unknown counters field", k)
        
    def makedict (self):
        """Return the current counters, in the form of a dictionary.
        """
        return { k : getattr (self, k) for k in dir (self) if not k.startswith ("_")
                     and not callable (getattr (self, k)) }

    # We use the above to implement the API GET operation
    get_api = makedict

    def html (self):
        ret = [ "<td>{}</td>".format (self._owner.name) ]
        for f in self.html_fields:
            v = getattr (self, f, "")
            ret.append ("<td>{}</td}".format (v))
        return "".join (ret)
    
    

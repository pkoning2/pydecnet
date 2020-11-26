#!

"""Common things that don't depend on other decnet modules.

"""

import re
import threading
import struct
import sys
import random
import time
import socket
import abc
import datetime
import os.path
import json
import collections

WIN = "win" in sys.platform and "darwin" not in sys.platform

DNVERSION = "DECnet/Python V1.0"
CYEAR = "2020"
AUTHORS = "Paul Koning"

# Defaults

DEFCONFIG = "pydecnet.conf"

# Important constants

HIORD = b"\xaa\x00\x04\x00"
T2 = 1
# The .1 increment is not part of the DECnet architecture spec, but it
# adopts an idea seen in DECnet/RSX.  The result is that a listen
# timer will not normally happen unless 2 (point to point) or 3 (LAN)
# consecutive hellos are lost.  With the design in the architecture, a
# hello after a single (point to point) dropped hello might well
# arrive a fraction of a second after the listen timer expiration.
PTP_T3MULT = 2.1
BCT3MULT = 3.1
DRDELAY = 5
INFHOPS = 31
INFCOST = 1023

MTU = 576                # Max NPDU size
ETHMTU = MTU + 21 - 6    # Ditto, adjusted for long vs. short header
MSS = MTU - 13           # Max TSDU size

JIFFY = 0.1              # Timer increment in seconds

LE = "little"

# For rev tracking
SvnFileRev = "$LastChangedRevision$"

# Exceptions
class DNAException (Exception):
    def __str__ (self):
        if self.args:
            text, *args = self.args
            return text.format (*args)
        return self.__doc__

class InternalError (DNAException):
    """Internal PyDECnet error"""

# Exceptions related to packet encode/decode
class DecodeError (DNAException):
    """Packet decode error"""
class WrongValue (DecodeError):
    """Constant field in packet with wrong value"""
class ExtraData (DecodeError):
    """Unexpected data at end of packet"""
class MissingData (DecodeError):
    """Unexpected end of packet in decode"""
class FieldOverflow (DecodeError):
    """Value too large for field size"""
class InvalidTag (DecodeError):
    """Unknown TLV tag field"""
    
# Various functions return an interesting value or None to indicate
# "not found" or the like.  Sometimes more than one "failure" value is
# needed.  To make this easy, instances of the following type can be
# used.  All these test as False, so the usual "if retval:" check for
# "not a failure" still works, but they are distinct.
class Failure:
    def __init__ (self, name):
        self.name = name

    def __str__ (self):
        return self.name
    __repr__ = __str__
    
    def __bool__ (self):
        return False

# Tuple of bytestring types (used in isinstance checks when we need
# to recognize some sort of byte buffer but don't know which specific
# one of several types for that purpose we're dealing with)
bytetypes = (bytes, bytearray, memoryview)

# Tuple of string/byte types, similar to the above but also includes str.
# Basically, these are types that collections.abc calls Sequence but that
# we would treat as non-sequence (single value).
strtypes = (str, bytes, bytearray, memoryview)

# Make sure a value is byte-like.
def makebytes (v):
    if not isinstance (v, bytetypes):
        v = bytes (v)
    return v

# It would be handy to have the bytes analog of chr() as a builtin,
# but there isn't one, so make one.
def byte (n):
    return bytes ((n,))

def require (buf, minlen):
    if len (buf) < minlen:
        logging.debug ("Not {} bytes left in packet buffer", minlen)
        raise MissingData

class Field:
    """Abstract base class for fields in DECnet packets.

    Subclass this to define a particular field or substructure.  For
    individual fields, typically there is a second base class for the
    Python data type to be used to represent the field.  An example
    is Nodeid, which is derived from Field and int (since a DECnet
    node ID is an integer).  In some cases, the value has to be a
    data attribute of the class -- this applies when the data needed
    is from a class that does not support subclassing.  Any needed
    attributes should typically be mentioned in the __slots__ class
    attribute.

    Minimally a particular field has to define an encode method, to turn
    the field into a byte string, and a decode classmethod, to turn a
    prefix of the supplied byte string into an instance of the field.
    It can also supply a "__format__" method to define a particular
    way of displaying the field value.

    If the class defines class attribute "lastfield" to be True, that
    means fields of this type must be the last field in a  packet.
    Normally this applies to fields that consume the rest of the packet,
    for example "Payload" or the TLV field group.
    """
    __slots__ = ()
    lastfield = False

    @abc.abstractmethod
    def encode (self):
        pass

    @classmethod
    def checktype (cls, name, val, *args):
        """This method is called prior to encoding the value.  The "val"
        argument might be an instance of cls, or something else, or
        None.  If None, that means the field was not supplied; this
        method can substitute a default value, or return None to
        indicate the field should be omitted, or reject the call if the
        field is mandatory.  If the type is not what we want, it should
        be converted and the result returned.  Otherwise, just return
        the supplied value.
        """
        if isinstance (val, cls):
            return val
        if val is None:
            # Supply the default for this type.
            return cls ()
        return cls (val)

    @classmethod
    @abc.abstractmethod
    def decode (self, buf):
        pass

    @classmethod
    def makecoderow (cls, name, *args):
        """Return code table row data for the Packet encode/decode
        machinery to use, and some additional items.  The return value
        is a tuple consisting of field type, field name, any arguments,
        slot name information, and "wild" flag.  The slot name info is
        an iterable of slot names.  The wild flag is True if for field
        groups that accept arbitrary fields, as happens with TLV and
        NICE groups.  For simple fields that case never applies.
        """
        return cls, name, args, { name }, False

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

class IpAddr (str):
    """A string containing an IP address
    """
    def __new__ (cls, s):
        if s and socket.inet_aton (s) == bytes (4):
            # 0.0.0.0, replace by empty string
            s = ""
        return str.__new__ (cls, s)
            
_nodeid_re = re.compile (r"^(?:(\d+)\.)?(\d+)$")
class Nodeid (Field, int):
    """A DECnet Node ID.
    """
    def __new__ (cls, s = 0, id2 = None, wild = False):
        """Create a Nodeid from a string, an integer, a pair of integers,
        a Mac address, or anything that can be converted to a byte string
        of length 2.

        Node 0 is accepted for string or integer inputs; that is
        intended to represent the local node but that conversion has to
        be handled by the caller.

        For non-zero addresses, the node-in-area part must be non-zero 
        unless "wild" is True.
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
            s = makebytes (s)
            if len (s) != 2:
                raise DecodeError ("Invalid node ID {}".format (s))
            a, n = divmod (int.from_bytes (s, "little"), 1024)
            if n == 0 and not wild:
                raise DecodeError ("Invalid node ID {}".format (s))
        if a > 63 or n > 1023 or (n == 0 and a != 0 and not wild):
            raise ValueError ("Invalid node ID {}".format (s))
        return int.__new__ (cls, (a << 10) + n)

    @classmethod
    def decode (cls, buf):
        if len (buf) < 2:
            raise MissingData
        return cls (buf[:2]), buf[2:]

    def encode (self):
        return self.to_bytes (2, "little")
    
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
    
    def __iter__ (self):
        yield int (self)

class NiceNode (Nodeid):
    """A node address with optional node name. """
    def __new__ (cls, nodeid = 0, name = ""):
        n = Nodeid.__new__ (cls, nodeid)
        if not name:
            name = getattr (nodeid, "nodename", "")
        n.nodename = name
        n.executor = False
        return n

    def get_api (self):
        ret = { "address" : int (self) }
        if self.nodename:
            ret["name"] = self.nodename
        return ret
        
    def encode (self):
        ebit = 0x80 if self.executor else 0
        name = self.nodename or ""
        return super ().encode () + \
               byte (len (name) + ebit) + \
               bytes (name, "latin1")

    @classmethod
    def decode (cls, b, *x):
        n = int.from_bytes (b[:2], "little")
        ln = b[2]
        ebit = (ln & 0x80) != 0
        ln &= 0x7f
        name = str (b[3:3 + ln], "latin1")
        v = cls (n, name)
        v.executor = ebit
        return v, b[3 + ln:]

    def __str__ (self):
        if self.nodename:
            return "{} ({})".format (super ().__str__ (),
                                     self.nodename)
        return super ().__str__ ()

    def __iter__ (self):
        yield int (self)
        if self.nodename:
            yield self.nodename

_mac_re = re.compile ("[-:]")
class Macaddr (Field, bytes):
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
            b = makebytes (s)
            if len (b) != 6:
                raise ValueError ("Invalid MAC address string {}".format (s))
        return bytes.__new__ (cls, b)

    @classmethod
    def decode (cls, buf):
        if len (buf) < 6:
            raise MissingData
        return cls (buf[:6]), buf[6:]

    def encode (self):
        return self
    
    def __str__ (self):
        return "{0[0]:02x}-{0[1]:02x}-{0[2]:02x}-{0[3]:02x}-{0[4]:02x}-{0[5]:02x}".format (self)

    __repr__ = __str__

    def __format__ (self, f):
        """Convert the address to string form; the format character is
        the separator.  If omitted the default (dash) is used.  But "x"
        means to return it as a hex string with 0x prefix and no
        separators.
        """
        ret = str (self)
        if f == "x":
            ret = "0x" + ret.replace ("-", "")
        elif f:
            ret = ret.replace ("-", f)
        return ret
    
    def islocal (self):
        """True if the address is from the locally administered address space."""
        return (self[0] & 0x02) != 0
    
    def ismulti (self):
        """True if the address is a multicast address."""
        return (self[0] & 0x01) != 0
    
NULLID = Macaddr (bytes (6))

class Ethertype (Field, bytes):
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
            b = makebytes (s)
            if len (b) != 2:
                raise ValueError ("Invalid Ethertype string {}".format (s))
        return bytes.__new__ (cls, b)

    @classmethod
    def decode (cls, buf):
        if len (buf) < 2:
            raise MissingData
        return cls (buf[:2]), buf[2:]

    def encode (self):
        return self
    
    def __str__ (self):
        return "{0[0]:02x}-{0[1]:02x}".format (self)

    __repr__ = __str__

    def __format__ (self, f):
        """Convert the type to string form; the format character is
        the separator.  If omitted the default (dash) is used.  But "x"
        means to return it as a hex string with 0x prefix and no
        separators.
        """
        ret = str (self)
        if f == "x":
            ret = "0x" + ret.replace ("-", "")
        elif f:
            ret = ret.replace ("-", f)
        return ret
    
# Well known protocol types
MOPDLPROTO   = Ethertype ("60-01")
MOPCONSPROTO = Ethertype ("60-02")
ROUTINGPROTO = Ethertype ("60-03")
LATPROTO     = Ethertype ("60-04")   # used by bridge
LOOPPROTO    = Ethertype ("90-00")

_version = struct.Struct ("<BBB")
class Version (Field, bytes):
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
            v = makebytes (v1)
            if len (v) != 3:
                raise ValueError ("Invalid version string {}".format (v1))
        return super ().__new__ (cls, v)

    @classmethod
    def decode (cls, buf):
        if len (buf) < 3:
            raise MissingData
        return cls (buf[:3]), buf[3:]

    def encode (self):
        return self
    
    def __str__ (self):
        v1, v2, v3 = _version.unpack (self)
        return "{}.{}.{}".format (v1, v2, v3)

    __repr__ = __str__
    
maxint = [ (1 << (8 * i)) - 1 for i in range (9) ]

class Timestamp (Field):
    """Elapsed time.  Internally this stores the time of creation of
    the object, but when encoding or formatting that is converted to 
    delta time (truncated to whole seconds).  The encoding is that of
    a 2-byte DECnet counter, i.e., the delta time of 65535 if it is 
    too large.
    """
    __slots__ = ("start",)
    
    def __init__ (self, v = 0):
        """Initialize a new delta-t value.  The supplied value is the
        delta time (seconds before now) to be represented.  What we
        actually store is the corresponding start time, i.e., the
        current time minus the supplied delta.  The delta defaults to
        zero, so the default constructor produces a start time of "right
        now".
        """
        v = datetime.timedelta (seconds = -v)
        self.start = datetime.datetime.now () + v

    def startts (self):
        return int (self.start.timestamp ())
    
    def __int__ (self):
        delta = datetime.datetime.now () - self.start
        delta = int (delta.total_seconds ())
        return delta
    
    def encode (self, flen):
        return min (int (self), maxint[flen]).to_bytes (flen, LE)

    @classmethod
    def decode (cls, buf, flen):
        """Decode delta t from a packet.  This doesn't really work 
        well because of time skew but it's a reasonable approximation.
        """
        if len (buf) < flen:
            logging.debug ("Not {} bytes left for integer field", flen)
            raise MissingData
        return cls (int.from_bytes (buf[:flen], LE)), buf[flen:]

    def __format__ (self, format):
        delta = datetime.datetime.now () - self.start
        # Discard the microseconds
        delta = datetime.timedelta (delta.days, delta.seconds)
        return delta.__format__ (format)
    
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

        This method returns True if the thread was active, False if not.
        """
        if not self.is_alive ():
            return False
        if not self.stopnow:
            self.stopnow = True
            if wait:
                self.join (10)
                if self.is_alive ():
                    logging.error ("Thread {} failed to stop after 10 seconds",
                                   self.name)
                else:
                    logging.trace ("Thread {} stopped", self.name)
        return True

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
        self.time_since_zeroed = Timestamp ()

    def copy (self, other):
        """This copies the counters to the destination, for each counter
        name that is a current attribute of "other".  Those names are
        taken from dir(other), which will give us all names in __slots__
        (such as packet fields), or attributes of the class, or
        attributes previously assigned to "other".
        """
        onames = set (dir (other))
        for k, v in self.makedict ().items ():
            if k == "nodecounters":
                continue
            if k in onames:
                setattr (other, k, v)
        
    def makedict (self):
        """Return the current counters, in the form of a dictionary.
        """
        return { k : getattr (self, k) for k in dir (self)
                     if not k.startswith ("_")
                     and not callable (getattr (self, k)) }

    # We use the above to implement the API GET operation
    get_api = makedict

# Decorator to set nice_code attribute on functions/methods.  This is
# typically used with methods in a state machine.  Decorators with
# arguments are rather weird magic; refer to the Python reference
# manual for details.
def setcode (code):
    def sc (f):
        f.nice_code = code
        return f
    return sc

# Decorator to set label attribute on functions/methods, for with
# methods in a state machine.  The label is used by HTML output that
# shows the current state (such as routing circuit status).
def setlabel (lb):
    def sc (f):
        f.label = lb
        return f
    return sc
    
# Dummy context manager, used when we want to use a real context
# manager with some configurations but don't need it in others.  Using
# this one (via a variable reference to one of two classes) avoids
# lots of ugly conditional code.
class NullContext:
    def __init__ (self, *args, **kwds):
        pass
        
    def __enter__ (self):
        pass
    
    def __exit__ (self, exc_type, exc_val, exc_tb):
        # Always pass through any exceptions
        return False

def abspath (p):
    "Like os.path.abspath but also does expanduser to it"
    return os.path.abspath (os.path.expanduser (p))

class DNJsonDecoder (json.JSONDecoder):
    def __init__ (self):
        super ().__init__ (strict = False)

    def decode (self, s):
        if isinstance (s, (bytes, bytearray)):
            s = str (s, encoding = "latin1")
        return super ().decode (s)
    
class DNJsonEncoder (json.JSONEncoder):
    def __init__ (self, allow_nan = False, separators = (',', ':'), **kwargs):
        super ().__init__ (allow_nan = allow_nan, separators = separators,
                           **kwargs)
        
    def default (self, o):
        # Encode bytes and bytearray as latin-1 strings -- but not
        # their subclasses which are expected to supply their own
        # formatting mechanisms.  Macaddr is an example.
        if type (o) in { bytes, bytearray }:
            return str (o, encoding = "latin1")
        # If it's not something we know, see if the class supplies an
        # encoding method.
        try:
            return o.encode_json ()
        except AttributeError:
            pass
        # That didn't work, format it as a string if possible.
        try:
            return str (o)
        except Exception:
            pass
        return super ().default (o)
    
dnDecoder = DNJsonDecoder ()
dnEncoder = DNJsonEncoder ()

class Histogram (collections.Counter):
    "A histogram: buckets of counters supporting statistics"
    header = ( "Min", "Mean", "Median", "Max", "Samples" )
    
    def calc_stats (self):
        "Capture the current statistics"
        data = list (self.items ())
        data.sort ()
        self.min = data[0][0]
        self.max = data[-1][0]
        count = sum = 0
        for k, v in data:
            count += v
            sum += k * v
        self.mean = sum / count
        self.total = count
        h = count // 2
        count = 0
        for k, v in data:
            count += v
            if count >= h:
                self.median = k
                return

    def stats (self):
        "Return current statistics scaled by 0.1"
        return ( "{:.1f}".format (self.min / 10),
                 "{:.2f}".format (self.mean / 10),
                 "{:.1f}".format (self.median / 10),
                 "{:.1f}".format (self.max / 10),
                 "{}".format (self.total))

    def count (self, dt):
        "Count a delta-t value in 0.1 second increments"
        self[round (dt * 10)] += 1
        
class Backoff:
    "A simple object to provide binary exponential backoff values"
    def __init__ (self, low, high = None):
        """Like range() this takes one or two arguments.  If one
        argument is supplied, that is the upper bound and the lower
        bound is 1.  Otherwise, the first argument is the lower bound
        and the second is the upper bound.
        """
        if high is None:
            low, high = 1, low
        assert low < high and low > 0
        self.low = self.current = low
        self.high = high
        self.tries = 0

    def __next__ (self):
        ret = self.current
        self.current = min (self.current * 2, self.high)
        self.tries += 1
        return ret

    def reset (self):
        self.current = self.low
        self.tries = 0

    def next (self):
        # Because I always forget whether next is a function or a method
        return next (self)

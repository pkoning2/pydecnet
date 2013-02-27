#!

"""Common things that don't depend on other decnet modules.

"""

import re
import threading
import logging
import builtins
import struct

DNVERSION = "DECnet/Python V1.0"

# Defaults

DEFCONFIG = "pydecnet.conf"
DEFAPISOCKET = "decnetsocket"

# Important constants

MOPCONSPROTO = 0x6002
ROUTINGPROTO = 0x6003
LOOPPROTO = 0x9000
HIORD = b"\xaa\x00\x04\x00"
T2 = 1
T3MULT = 2
BCT3MULT = 3
DRDELAY = 5
INFCOST = 31
INFHOPS = 1023

MTU = 576

# Make a version of "bytes" that pays attention to __bytes__ even
# if the argument is an int.
class bytes (builtins.bytes):
    def __new__ (cls, o, *args):
        if not args:
            try:
                return o.__bytes__ ()
            except AttributeError:
                pass
        return builtins.bytes.__new__ (cls, o, *args)

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

class Shutdown (Work):
    """A work item that says "shut down".
    """
    
_nodeid_re = re.compile (r"^(?:(\d+)\.)?(\d+)$")
class Nodeid (int):
    """A DECnet Node ID.
    """
    _len = 2
    def __new__ (cls, s, id2 = None):
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
                n = s
                a = 0
            else:
                a, n = s, id2
        else:
            if len (s) != 2:
                raise ValueError ("Invalid node ID %s" % s)
            a, n = divmod (int.from_bytes (s, "little"), 1024)
        if a == 0:
            if n < 1 or n > 255:
                raise ValueError ("Invalid node ID %s" % s)
        else:
            if 1 <= a <= 63 and 1 <= n <= 1023:
                n = (a << 10) + n
            else:
                raise ValueError ("Invalid node ID %s" % s)
        return int.__new__ (cls, n)

    @property
    def area (self):
        return int (self) >> 10

    @property
    def tid (self):
        return int (self) & 1023
    
    def __str__ (self):
        a = self.area
        if a:
            return "{}.{}".format (a, self.tid)
        else:
            return "{}".format (self.tid)

    def __bytes__ (self):
        return self.to_bytes (2, "little")
    
_mac_re = re.compile ("[-:]")
class Macaddr (bytes):
    """MAC address for Ethernet (or similar LAN).
    """
    _len = 6
    def __new__ (cls, s):
        """Create a Macaddr instance from a string, a Nodeid, or
        any other object that can be converted to a bytes object of
        length 6.
        """
        if isinstance (s, str):
            bl = _mac_re.split (s)
            if len (bl) != 6:
                if _nodeid_re.match (s):
                    s = HIORD + bytes (Nodeid (s))
                else:
                    raise ValueError ("Invalid MAC address string %s" % s)
            else:
                s = bytes (int (f, 16) for f in bl)
        elif isinstance (s, Nodeid):
            s = HIORD + bytes (s)
        else:
            s = bytes (s)
            if len (s) != 6:
                raise ValueError ("Invalid MAC address string %s" % s)
        return bytes.__new__ (cls, s)

    def __str__ (self):
        return "{0[0]:02x}-{0[1]:02x}-{0[2]:02x}-{0[3]:02x}-{0[4]:02x}-{0[5]:02x}".format (self)
    
NULLID = Macaddr (bytes (6))

_version = struct.Struct ("<BBB")
class Version (bytes):
    """DECnet component version number -- 3 integers.
    """
    _len = 3
    
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

    def __str__ (self):
        v1, v2, v3 = _version.unpack (self)
        return "{}.{}.{}".format (v1, v2, v3)
    
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
            raise ValueEror ("Verification string %s too long" % s)
        if l < 8:
            v += bytes (8 - l)
    return v

_name_re = re.compile (r"\w+$")
def name (s):
    """Accept a string that looks like a name, which for our purposes
    means any alphanumeric string.  Yes, DECnet sometimes allows hyphens
    and such, but that's too much trouble.
    """
    if _name_re.match (s):
        return s
    raise ValueError ("Invalid name %s" % s)

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


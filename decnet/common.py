#!

"""Common things that don't depend on other decnet modules.

"""

import re
import threading
import logging

DNVERSION = "DECnet/Python V1.0"

# Defaults

DEFCONFIG = "pydecnet.conf"
DEFAPISOCKET = "decnetsocket"

# Important constants

MOPCONSPROTO = 0x6002
ROUTINGPROTO = 0x6003
LOOPPROTO = 0x9000
HIORD = b"\xaa\x00\x04\x00"

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

# Some well known Ethernet addresses
CONSMC = scan_macaddr ("AB-00-00-02-00-00")
LOOPMC = scan_macaddr ("CF-00-00-00-00-00")

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

_nodeid_re = re.compile (r"^(?:(\d+)\.)?(\d+)$")
def scan_nodeid (s):
    """Scan a node ID, return the resulting 16 bit value.  Accept either
    a phase 4 ID n.n, or a phase 3 id (just an integer).
    """
    m = _nodeid_re.match (s)
    if not m:
        raise ValueError ("Invalid node ID %s" % s)
    a, n = m.groups ()
    n = int (n)
    if a is None:
        # Phase 3 ID
        if 1 <= n <= 255:
            return n
    else:
        a = int (a)
        if 1 <= a <= 63 and 1 <= n <= 1023:
            return (a << 10) + n
    raise ValueError ("Invalid node ID %s" % s)
    
def format_nodeid (n):
    """Format a node ID.  Phase 3 IDs are formatted as a simple integer.
    """
    if n < 1024:
        return str (n)
    else:
        return "{:d}.{:d}".format (divmod (n, 1024))

def scan_l2id (s):
    """Accept either a MAC address or a node address; a node address
    is converted by the usual Phase IV rules.
    """
    if _nodeid_re.match (s):
        n = scan_nodeid (s)
        return HIORD + n.to_bytes (2, "little")
    return scan_macaddr (s)

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


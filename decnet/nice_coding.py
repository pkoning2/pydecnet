#!

"""NICE protocol encoding machinery
"""

import time
import struct

from .common import *
from . import packet

SvnFileRev = "$LastChangedRevision$"

# Base time for time code in event message
jbase = time.mktime (time.strptime ("1977-01-01", "%Y-%m-%d"))

class EntityBase (packet.Packet):
    _layout = (( "signed", "enum", 1 ),)
    classindex = { }
    classindexkey = "enum"

    def __init__ (self, arg = None):
        super ().__init__ ()
        if arg:
            self.ename = arg
            
    @classmethod
    def defaultclass (cls, x):
        return StringEntityBase
    
    @classmethod
    def decode (cls, b, *x):
        e = int.from_bytes (b[:1], "little", signed = True)
        cls = cls.findclass (e)
        v = cls ()
        b2 = packet.Packet.decode (v, b)
        return v, b2
    
    def __str__ (self):
        cname = self.__class__.__name__
        if cname.endswith ("Entity"):
            return "{} = {}".format (cname[:-6], self.ename)
        return "Entity #{} = {}".format (self.enum, self.ename)

    def __format__ (self, arg):
        return str (self)
    
    def __hash__ (self):
        return id (self)

class NoEntity (EntityBase):
    _singleton = None
    enum = -1

    def __new__ (cls):
        if cls._singleton is None:
            cls._singleton = EntityBase.__new__ (cls)
        return cls._singleton

    def __str__ (self):
        return ""

class NodeEntity (EntityBase):
    enum = 0
    _layout = (( NiceNode, "ename" ),)

    def __init__ (self, arg = None):
        super ().__init__ ()
        if arg:
            self.ename = NiceNode (arg)
            
    def __str__ (self):
        return "{}".format (self)

    def __format__ (self, arg):
        if arg:
            t = "Node"
        elif int (self.ename) == 0:
            t = "Loop node"
        elif self.ename.executor:
            t = "Executor node"
        else:
            t = "Remote node"
        return "{} = {}".format (t, self.ename)
    
class StringEntityBase (EntityBase):
    _layout = (( "a", "ename", 16 ),)

class LineEntity (StringEntityBase): enum = 1
class LoggingEntity (StringEntityBase): enum = 2
class CircuitEntity (StringEntityBase): enum = 3
class ModuleEntity (StringEntityBase): enum = 4
class AreaEntity (EntityBase):
    enum = 5
    _layout = (( "b", "ename", 1 ),)

class NiceType (packet.Indexed):
    # Base type for all the NICE data type codes
    classindex = { }
    classindexkey = "code"

    fmt = "{}"
    counter = False
    vlist = ()
    
    @classmethod
    def defaultclass (cls, code):
        """This method is called when findclass() is asked for a class
        that is not in the index.  If it's a valid code (for a
        length-dependent encoding but we didn't encouter that particular
        length yet) make a new class for that length and return it.
        Otherwise raise DecodeError to indicate we can't help.
        """
        if code & 0x80:
            bytecnt = code & 0x3f
        else:
            bytecnt = code & 0x0f
        if not bytecnt:
            raise DecodeError ("Invalid type code 0x{:0>2x}".format (code))
        basecode = code - bytecnt
        try:
            bc = cls.classindex[basecode + 1]
        except KeyError:
            raise DecodeError ("Invalid type code 0x{:0>2x}".format (code))
        name = "{}{}".format (bc.__name__[:-1], bytecnt)
        cdict = dict (bytecnt = bytecnt, code = code)
        # Note that the metaclass will add the new class to the classindex.
        c = type (name, (bc,), cdict)
        return c

    @classmethod
    def makenice (cls, v, *x):
        "If v is not already an instance of NiceType, make it an instance of cls."
        if not isinstance (v, NiceType):
            v = cls (v)
        return v
    
    def makenicelist (self, tlist):
        pass
    
    def format (self, *x):
        "Format the data value according to its defined data type"
        return self.fmt.format (self)
    
class DU1 (NiceType, int):
    bytecnt = 1
    signed = False
    code = 1
    
    def encode (self):
        "Encode the value, including the type code"
        return byte (self.code) + \
               self.to_bytes (self.bytecnt, "little", signed = self.signed)

    @classmethod
    def decode (cls, b, *x):
        "Decode the value, not including the type code"
        bc = cls.bytecnt
        f = b[0:bc]
        b = b[bc:]
        if len (f) < bc:
            raise MissingData
        return cls (int.from_bytes (f, "little", signed = cls.signed)), b

def zpr (left, right, pad = DU1):
    "Like zip() but if right is shorter than left, pad it with instances of pad."
    left = iter (left)
    for r in right:
        try:
            yield next (left), r
        except StopIteration:
            return
    for l in left:
        yield l, pad
        
class DS1 (DU1):
    signed = True
    code = 0x11

class H1 (DU1):
    fmt = "{0:0>{1}x}"
    code = 0x21

    def format (self, *x):
        # Not clear if this matches the letter of the spec, but for hex
        # integers it is helpful to show the full length value, with all
        # the leading zeroes.
        return self.fmt.format (self, self.bytecnt * 2)

class O1 (DU1):
    fmt = "{0:0>{1}o}"
    code = 0x31

    def format (self, *x):
        # Show the full length value, with all the leading zeroes.
        digits = (self.bytecnt * 8 + 2) // 3
        return self.fmt.format (self, digits)
    
class AI (NiceType, str):
    code = 0x40

    def encode (self):
        b = bytes (self, "latin1")
        return b"\x40" + byte (len (b)) + b

    @classmethod
    def decode (cls, b, *x):
        if not b:
            raise MissingData
        l = b[0]
        if len (b) < l + 1:
            raise MissingData
        return cls (b[1:l + 1], "latin1"), b[l + 1:]

class HI (NiceType, bytes):
    code = 0x20
    
    def format (self, *x):
        return "-".join ("{:02x}".format (i) for i in self)

    def encode (self):
        return b"\x20" + byte (len (self)) + self

    @classmethod
    def decode (cls, b, *x):
        if not b:
            raise MissingData
        l = b[0]
        if len (b) < l + 1:
            raise MissingData
        return cls (b[1:l + 1]), b[l + 1:]

class C1 (DU1):
    code = 0x81
    
    def format (self, vdict = {}):
        vdict = vdict or self.vlist
        try:
            v = vdict[self]
        except (IndexError, KeyError):
            v = "#{}".format (self)
        return v

class CM1 (NiceType, list):
    code = 0xc1
    bytecnt = 1
    delim = " "
    
    @classmethod
    def makenice (cls, v, tlist = ()):
        """If v is not already an instance of NiceType, make it an
        instance of cls.  Also do this to each of the list elements in
        v.
        """
        if not isinstance (v, NiceType):
            v = cls (v)
        v.makenicelist (tlist or cls.vlist)
        return v

    def makenicelist (self, tlist):
        for i, cls in zpr (range (len (self)), tlist):
            self[i] = cls.makenice (self[i])
        
    def format (self, tlist):
        return self.delim.join (i.format () for i in self)

    @classmethod
    def decode (cls, buf, tlist):
        if tlist:
            t = tlist[0]
            if not (isinstance (t, type) and issubclass (tlist[0], NiceType)):
                tlist = ()
        vl = [ ]
        for i, cls2 in zpr (range (cls.bytecnt), tlist or cls.vlist):
            cls2 = cls2.findclass (buf[0])
            v, buf = cls2.decode (buf[1:])
            vl.append (v)
        return cls (vl), buf

    def encode (self):
        vl = [ i.encode () for i in self ]
        return byte (0xc0 + len (vl)) + b"".join (vl)
    
# We refer to CM since that actually works for any count.
CM = CM1

# Make named classes for other lengths/counts.  On decode any needed
# classes are generated on the fly, but we'll want names for those
# referenced in the source code.  Use the class generator to make sure
# we'll do everything the same way all the time.
DU2 = DU1.findclass (2)
DU4 = DU1.findclass (4)
DS2 = DS1.findclass (0x12)
DS4 = DS1.findclass (0x14)
H8 = H1.findclass (0x28)
O2 = O1.findclass (0x32)
O4 = O1.findclass (0x34)
C2 = C1.findclass (0x82)
CM2 = CM1.findclass (0xc2)
CM3 = CM1.findclass (0xc3)
CM4 = CM1.findclass (0xc4)

# One byte counter; also the base class for all other counters.
class CTR1 (DU1):
    code = 0xa000
    counter = True
    maxval = 255
    maxstr = ">254"

    def format (self, *x):
        if self >= self.maxval:
            return self.maxstr
        return "{}".format (self)

    def format_qual (self, x):
        return ""
    
    def encode (self, pnum):
        return (pnum + self.code).to_bytes (2, "little") + \
               min (self, self.maxval).to_bytes (self.bytecnt, "little")

mapindent = " " * 19
mapsep = "\n" + mapindent

class Map:
    def format_qual (self, bmap = ()):
        bits = self.map
        if bits:
            v = ", including\n" + mapindent
            m = list ()
            for b in range (16):
                if not bits:
                    break
                if bits & 1:
                    try:
                        n = bmap[b]
                    except (KeyError, IndexError):
                        n = "Qualifier #{}".format (b)
                    m.append (n)
                bits >>= 1
            v += mapsep.join (m)
        return v

    def encode (self, pnum):
        return (pnum + self.code).to_bytes (2, "little") + \
               self.map.to_bytes (2, "little") + \
               min (self, self.maxval).to_bytes (self.bytecnt, "little")

    @classmethod
    def decode (cls, b, *x):
        bc = cls.bytecnt
        if len (b) < bc + 2:
            raise MissingData
        map = int.from_bytes (b[:2], "little")
        v = cls (int.from_bytes (b[2:2 + bc], "little"))
        v.map = map
        return v, b[2 + bc:]
    
class CTR2 (CTR1):
    code = 0xc000
    bytecnt = 2
    maxval = 65535
    maxstr = ">65534"
    
class CTR4 (CTR1):
    code = 0xe000
    bytecnt = 4
    maxval = 4294967295
    maxstr = ">4294967294"
    
class CTM1 (Map, CTR1): code = 0xb000
class CTM2 (Map, CTR2): code = 0xd000
class CTM4 (Map, CTR4): code = 0xf000

class NicePacket (packet.Packet):
    """Base class to add NICE data item processing to packet.Packet.
    This cannot actually be instantiated directly; derive from this
    class and add a _layout table to describe the fields in the packet.
    """
    _layout = ()     # To indicate that we don't have a real layout
    _addslots = ("__dict__",)

    def format_nice (self):
        """Format the NICE data block.  Fixed header fields are not
        processed, those should be handled by the caller.
        """
        e, d, niceargs = self._codetable[-1]
        ncdict, cdict, flist = niceargs
        assert e == self.__class__.encode_nice
        ret = [ ]
        # If there are non-standard fields, add made up entries for them
        # into the format list.
        xparams = self.xfields ()
        if xparams:
            xparams.sort (key = packet.fieldnum)
            xflist = [ ]
            for fn in xparams:
                v = getattr (self, fn)
                if v.counter:
                    dparam = "Counter #{}".format (packet.fieldnum (fn))
                else:
                    dparam = "Parameter #{}".format (packet.fieldnum (fn))
                xflist.append ((packet.fieldnum (fn), DU1, fn, dparam, ()))
            # Note: not += because that appends to the existing list,
            # modifying it.  This creates a new list in the local
            # variable.
            flist = flist + xflist
        for param, pcls, fn, desc, vals in flist:
            v = getattr (self, fn, None)
            if v is not None:
                v = pcls.makenice (v, vals)
                if v.counter:
                    s = "{:>11s} {}{}".format (v.format (), desc,
                                               v.format_qual (vals))
                else:
                    s = "{} = {}".format (desc, v.format (vals))
                ret.append (s)
        return "    " + "\n    ".join (ret)

    def encode_nice (self, ncdict, cdict, flist):
        ret = [ ]
        for param, pcls, fn, desc, vals in flist:
            v = getattr (self, fn, None)
            if v is not None:
                v = pcls.makenice (v, vals)
                if pcls.counter:
                    ret.append (v.encode (param))
                else:
                    ret.append (param.to_bytes (2, "little"))
                    ret.append (v.encode ())
        return b''.join (ret)

    def decode_nice (self, buf, ncdict, cdict, flist):
        """Decode the remainder of the buffer as a sequence of NICE
        fields.  Each value field is decoded according to the format
        code of the item, which is used to turn the data into an
        instance of a NiceData subclass.
        """
        pos = 0
        while buf:
            if len (buf) < 3:
                if self.tolerant:
                    return b''
                logging.debug ("Incomplete NICE data item at end of buffer")
                raise MissingData
            param = int.from_bytes (buf[0:2], "little")
            if param & 0x8000:
                # Counter, so the data code is in the upper bits
                code = param & 0xf000
                buf = buf[2:]
                d = cdict
            else:
                # Non-counter, type code is next byte
                code = buf[2]
                buf = buf[3:]
                d = ncdict
            param &= 0xfff    # Clear out reserved bits if non-counter
            try:
                pcls, fn, vals = d[param]
            except KeyError:
                # DU1 is used as a default in various places because it
                # is a valid type with a code attribute.  The actual
                # class used to decode will be governed by the decoded
                # data since we always check the buffer's code field.
                pcls = DU1
                fn = "field{}".format (param)
                vals = ()
                self._xfields = True
            if pcls ().code != code:
                # The packet has a different data code than the expected
                # code given in the decode tables.  Use the standard
                # class for the sender's code.
                pcls = NiceType.findclass (code)
            v, buf = pcls.decode (buf, vals)
            # Done with this data item; store it.
            setattr (self, fn, v)

# Subclasses of standard NICE type codes may be defined, which are used
# to specify alternate format methods.
class DUNode (DU2):
    "2 byte node number, formatted in standard area.node style."
    def format (self, *x):
        area, tid = divmod (self, 1024)
        if area:
            return "{}.{}".format (area, tid)
        return "{}".format (tid)

class CMNode (CM2):
    "Node address and name"
    vlist = (DUNode, AI)
    
    def format (self, *x):
        if len (self) == 2:
            return "{} ({})".format (self[0].format (), self[1].format ())
        return super ().format (*x)
    
class CMVersion (CM3):
    "CMn for version numbers, which will be printed with . separators."
    vlist = ( DU1, DU1, DU1 )
    delim = "."

class CMProc (CM4):
    "Source/dest process descriptor"
    vlist = (DU1, DU2, DU2, AI)
    
    def format (self, *x):
        if len (self) == 4:
            return "{} [{},{}]{}".format (*self)
        return super ().format (*x)
    
# NICE parameter definition lists for the various kinds of counters.
# These are broken out because they get used in several places -- not
# just the read information response, but also in events.
node_counters = [
    ( 0, CTR2, "Seconds Since Last Zeroed" ),
    ( 600, CTR4, "User Bytes Received" ),
    ( 601, CTR4, "User Bytes Sent" ),
    ( 602, CTR4, "User Messages Received" ),
    ( 603, CTR4, "User Messages Sent" ),
    ( 608, CTR4, "Total Bytes Received" ),
    ( 609, CTR4, "Total Bytes Sent" ),
    ( 610, CTR4, "Total Messages Received" ),
    ( 611, CTR4, "Total Messages Sent" ),
    ( 620, CTR2, "Connects Received" ),
    ( 621, CTR2, "Connects Sent" ),
    ( 630, CTR2, "Response Timeouts" ),
    ( 640, CTR2, "Received Connect Resource Errors" ),
    ( 700, CTR2, "Maximum Logical Links Active" ),
    ( 900, CTR1, "Aged Packet Loss" ),
    ( 901, CTR2, "Node Unreachable Packet Loss" ),
    ( 902, CTR1, "Node Out-of-range Packet Loss", "oor_loss" ),
    ( 903, CTR1, "Oversized Packet Loss" ),
    ( 910, CTR1, "Packet Format Error" ),
    ( 920, CTR1, "Partial Routing Update Loss" ),
    ( 930, CTR1, "Verification Reject" ),
    ( 2200, CTR2, "Current Reachable Nodes" ),
    ( 2201, CTR2, "Maximum Reachable Nodes" )
]   

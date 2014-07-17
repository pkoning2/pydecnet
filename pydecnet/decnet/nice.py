#!

"""NICE protocol definitions

"""

from collections.abc import Sequence

from .common import Nodeid

# NICE protocol function codes
LOAD = 15          # Request down-line load
DUMP = 16          # Request up-line dump
BOOT = 17          # Trigger bootstrap
TEST = 18          # Test
CHANGE = 19        # Change parameter
READ = 20          # Read information
ZERO = 21          # Zero counters
SYSSPEC = 22       # System-specific function

# Entities
NODE = 0
LINE = 1
LOGGING = 2
CIRCUIT = 3
MODULE = 4
AREA = 5

class NiceNode (object):
    """A node address with optional node name. """
    def __init__ (self, nodeid = 0, name = ""):
        self.nodeid = Nodeid (nodeid)
        self.nodename = name

    def nice_val (self):
        """Return the NICE parameter value(s) for this object."""
        if self.nodename:
            return (self.nodeid, self.nodename)
        return (self.nodeid,)
    
    def __str__ (self):
        if self.nodename:
            return "{0.nodeid} ({0.nodename})".format (self)
        return "{0.nodeid}".format (self)

class param_meta (type):
    def __new__ (cls, name, bases, classdict):
        values = classdict.get ("values", None)
        if values:
            vnames = { v : k.replace ("_", " ").capitalize ()
                       for k, v in values.items () }
            # If there is a vnames already in the class, its entries
            # override the computed names.
            cvnames = classdict.get ("vnames", dict ())
            vnames.update (cvnames)
            classdict["vnames"] = vnames
        return type.__new__ (cls, name, bases, classdict)
            
class Param (object, metaclass = param_meta):
    """Base class for NICE response and event message parameters.
    These come with codes that express how to format them.  Unknown
    parameters are formatted accordingly.  Derived classes can override
    the formatting to do special actions more appropriate for the
    parameter in question (e.g., area.id formatting for node addresses).
    """
    code = None
    fmt = None
    _name = None
    # Dictionaries to map between values and value names
    values = vnames = {}
    
    def __init__ (self, val = None, fmt = None, code = None):
        self.code = code or self.__class__.code
        fmt = fmt or self.__class__.fmt
        if isinstance (val, Sequence) and \
               not isinstance (val, (str, bytes, bytearray)):
            # Sequence, make it a coded multiple.  The format
            # must be specified (in the class or as an argument)
            # and must also be a sequence of the same length.
            l = len (val)
            if l > 0x3f:
                raise OverflowError ("Too many elements in sequence")
            if len (fmt) < l:
                raise ValueError ("Sequence values without matching format")
            val = [ ( self.initvalue (val, fmt), fmt )
                    for val, fmt in zip (val, fmt) ]
            fmt = 0xc0 + l
        elif val is not None:
            val = self.initvalue (val, fmt)
        self.val = val
        self.fmt = fmt

    def initvalue (self, val, fmt):
        """Convert a single value according to the supplied format.
        This handles such actions as converting HI-n parameters to
        bytes type, or converting C-n value labels to integer.
        """
        if fmt == 0x20:
            # HI-n, force bytes type
            if isinstance (val, str):
                val = bytes (val, encoding = "latin-1", errors = "ignore")
            else:
                val = bytes (val)
        elif (fmt & 0xc0) == 0x80:
            # C-n field, convert value name to number if name was given
            if not isinstance (val, int):
                val = self.values[val]
        return val
        
    @staticmethod
    def key (cls):
        return cls.code
    
    def __str__ (self):
        return self.format ()

    def format (self, val = None, fmt = None):
        """Format the NICE parameter value according to the format.
        By default, processes the value and format stored in the object,
        but can also be used with explicit value and format.   It calls
        itself recursively to format CM-n items.

        Override this to do item specific formatting in subclasses.
        """
        if val is None:
            val = self.val
        if fmt is None:
            fmt = self.fmt
        if fmt & 0x80:
            # Coded field
            if fmt & 0x40:
                # CM-n.  n is in the low bits, when transmitted in
                # the protocol, but we ignore that.  For CM-n,
                # the value is a sequence of pairs, which are the
                # value and format respectively of each item.
                return ' '.join ([ self.format (v, f) for v, f in val ])
            try:
                return self.vnames[val]
            except KeyError:
                return str (val)
        else:
            # Not coded.
            if fmt & 0x40:
                # ASCII field.
                return val
            # Binary of some sort.
            f = fmt & 0x30
            if f == 0:
                return "%u" % val
            if f == 0x10:
                return "%d" % val
            if f == 0x20:
                # Hex is used both as H-n (hex integer) and HI-n (byte string).
                # Byte string we want to format as a sequence of hex byte
                # values.
                if fmt == 0x20:
                    # HI-n, so format as hex byte string.
                    return "-".join ([ "%02x" % i for i in val ])
                return "%x" % val
            return "%o" % val

    @property
    def name (self):
        if self._name:
            return self._name
        if self.__class__.__base__ is object:
            # Param base class, so it's an unknown parameter
            return "Parameter # %d" % self.code
        else:
            return self.__class__.__name__.replace ("_", " ").capitalize ()
        
    def __repr__ (self):
        """Format the value preceded by the parameter name, in NICE standard
        tabular form.
        """
        return "%s = %s" % (self.name, self)
    
    def __bytes__ (self):
        return self.encode ()

    def valbytes (self, val, fmt):
        bits = val.bit_length ()
        signed = (fmt & 0xf0) == 0x10
        if signed:
            # Signed number, needs one additional bit for sign
            bits += 1
        fl = fmt & 0x0f
        l = (bits + 7) // 8
        if fl:
            if fl < l:
                raise OverflowError ("Numeric value too large for field")
            l = fl
        return val.to_bytes (l, "little", signed = signed)
    
    def encode (self, val = None, fmt = None):
        """Encode the NICE parameter value according to the format.
        By default, processes the value and format stored in the object,
        but can also be used with explicit value and format.
        """
        if val is None:
            val = self.val
        if fmt is None:
            fmt = self.fmt
        if fmt & 0x80:
            # Coded field
            if fmt & 0x40:
                # Coded multiple
                if isinstance (val, Sequence) and not isinstance (val, str):
                    b = b''.join ([ self.encode (v, f) for v, f in val ])
                    fmt = 0xc0 + len (val)
                else:
                    raise TypeError ("CM-n format but not sequence value")
            else:
                b = self.valbytes (val, fmt)
        else:
            # Not coded.
            if fmt & 0x40:
                # ASCII field.
                b = bytes (val)
                l = len (b)
                if l > 255:
                    raise OverflowError ("ASCII field too long")
                b = l.to_bytes (1, "little") + b
            else:
                # Binary of some sort.
                if isinstance (val, bytes):
                    b = val
                else:
                    b = self.valbytes (val, fmt)
                l = fmt & 0x0f
                if not l:
                    # Image field
                    b = len (b).to_bytes (1, "little") + b
        return fmt.to_bytes (1, "little") + b
    
    def decode (self, b):
        """Decode a byte string into a parameter. The argument is the
        NICE byte data stream starting with the DATA TYPE field.  In other
        words, by the time we get here the DATA ID field has already been
        processed.
        """
        if len (b) < 2:
            raise ValueError ("Data too short")
        fmt = b[0]
        b = b[1:]
        if fmt & 0x80:
            # coded
            n = fmt & 0x3f
            if fmt & 0x40:
                # CM-n
                val = list ()
                for i in range (n):
                    b = self.decode (b)
                    val.append ((self.val, self.fmt))
            else:
                # C-n
                if len (b) < n:
                    raise ValueError ("Data too short")
                val = int.from_bytes (b[:n], "little")
                b = b[n:]
        else:
            # not coded
            n = fmt & 0x0f
            if (fmt & 0x40) or n == 0:
                # ASCII or binary image, so length is next byte
                n = b[0]
                b = b[1:]
            if len (b) < n:
                raise ValueError ("Data too short")
            val = b[:n]
            b = b[n:]
            if fmt & 0x40:
                # ASCII
                val = str (val, encoding = "latin-1", errors = "ignore")
            elif (fmt & 0x30) == 0x10:
                val = int.from_bytes (val, "little", signed = True)
            elif fmt == 0x20:
                # HI-n, store the byte string directly
                pass
            else:
                val = int.from_bytes (val, "little")
        self.fmt = fmt
        self.val = val
        return b

# NICE parameter codes
def C (n): return 0x80 + n
def CM (n): return 0xc0 + n
def DU (n): return n
def DS (n): return 0x10 + n
def AI (n): return 0x40
def H (n): return 0x20 + n
def HI (n): return 0x20

class nicemsg_meta (type):
    def __new__ (cls, name, bases, classdict):
        pdict = dict ()
        for c in classdict.values ():
            if c is not Param and \
                   isinstance (c, param_meta) and \
                   issubclass (c, Param) \
                   and not hasattr (c, "send_only"):
                pdict[c.code] = c
        if pdict:
            classdict["pdict"] = pdict
        return type.__new__ (cls, name, bases, classdict)
    
class NiceMsg (metaclass = nicemsg_meta):
    """Base class for NICE messages, including event messages.
    """
    @classmethod
    def decode_params (cls, b):
        """Decode a buffer of NICE parameter data.  

        Return value is a list of parameter objects corresponding to the
        decoded data. 
        """
        ret = list ()
        while b:
            if len (b) < 2:
                raise ValueError ("Truncated DATA ID field")
            did = int.from_bytes (b[:2], "little")
            b = b[2:]
            if did & 0x8000:
                # Counter, TBD
                pass
            else:
                did &= 0x0fff
                pc = cls.pdict.get (did, Param)
                p = pc (code = did)
                b = p.decode (b)
                ret.append (p)
        return ret

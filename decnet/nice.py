#!

"""NICE protocol definitions

"""

from collections.abc import Sequence
from collections import namedtuple

from .common import *

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

class NiceNode (Nodeid):
    """A node address with optional node name. """
    def __new__ (cls, nodeid, name = ""):
        n = Nodeid.__new__ (cls, nodeid)
        if not name:
            name = getattr (nodeid, "nodename", None)
        n.nodename = name
        return n

    def nice_val (self, cls):
        """Return the NICE parameter value(s) for this object.
        Make the return value be one suitable for "cls"."""
        if self.nodename and not issubclass (cls, UIntParam):
            return (self, self.nodename)
        return self
    
    def __str__ (self):
        if self.nodename:
            return "{} ({})".format (super ().__str__ (),
                                                       self.nodename)
        return super ().__str__ ()

# NICE parameter codes
def C (n): return 0x80 + n
def CM (n): return 0xc0 + n
def DU (n): return n
def DS (n): return 0x10 + n
def AI (n): return 0x40
def H (n): return 0x20 + n
def HI (n): return 0x20

class codedparam_meta (type):
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

class Param (object):
    """Base class for NICE response and event message parameters.
    These come with codes that express how to format them.  Unknown
    parameters are formatted accordingly.  Derived classes can override
    the formatting to do special actions more appropriate for the
    parameter in question (e.g., area.id formatting for node addresses).
    """
    _code = None
    _fmt = None
    _name = None
    # Dictionaries to map between values and value names
    values = vnames = {}

    def __new__ (cls, val, *args):
        val = cls.getniceval (val)
        return super (__class__, cls).__new__ (cls, val)
    
    def __init__ (self, val, fmt = None, code = None):
        if code is None:
            code = self._code
        if fmt is None:
            fmt = self._fmt
        if not fmt:
            raise TypeError ("Missing format for parameter")
        if code is None:
            raise TypeError ("Missing code for parameter")
        self.fmt = fmt
        self.code = code

    @classmethod
    def getniceval (cls, val):
        try:
            return val.nice_val (cls)
        except AttributeError:
            return val

    @staticmethod
    def key (cls):
        return cls.code
    
    @property
    def name (self):
        if self._name:
            return self._name
        if self.__class__._code is not None:
            return self.__class__.__name__.replace ("_", " ").capitalize ()
        else:
            # Unknown parameter
            return "Parameter # %d" % self.code
        
    def nameformat (self):
        """Format the value preceded by the parameter name, in NICE standard
        tabular form.
        """
        return "%s = %s" % (self.name, self.format ())
    
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

    def encode (self):
        return self.code.to_bytes (2, "little") + self.encodeval ()
    
    @classmethod
    def decode (cls, b, code = None):
        """Decode a byte string into a parameter. The argument is the
        NICE byte data stream starting with the DATA TYPE field.  In other
        words, by the time we get here the DATA ID field has already been
        processed.

        Return value is a Param object containing the data, and the
        remaining buffer.
        """
        if len (b) < 2:
            raise MissingData ("Data too short")
        fmt = b[0]
        b = b[1:]
        dcls = fmtparamclass (fmt)
        if issubclass (dcls, cls):
            cls = dcls
        else:
            if not issubclass (cls, dcls):
                raise TypeError ("Wrong class for decoding format %d")
        val, fmt, b = cls.decodeval (b, fmt)
        p = cls (val, fmt, code)
        return p, b
    
class _IntParam (Param, int):
    _signed = False

    def __new__ (cls, val, *args):
        if isinstance (val, bytetypes):
            val = int.from_bytes (val, "little", signed = cls._signed)
        return super (__class__, cls).__new__ (cls, val)
        
    @classmethod
    def decodeval (cls, b, fmt):
        n = fmt & 0x0f
        if len (b) < n:
            raise MissingData ("Data too short for %d byte field" % n)
        return int.from_bytes (b[:n], "little", signed = cls._signed), \
               fmt, b[n:]

    def encodeval (self):
        n = self.fmt & 0x0f
        return byte (self.fmt) + self.to_bytes (n, "little",
                                                signed = self._signed)

class UIntParam (_IntParam):

    def format (self):
        f = self.fmt & 0x30
        if f == 0x20:
            return "%x" % self
        if f == 0x30:
            return "%o" % self
        return "%u" % self
    
class SIntParam (_IntParam):
    _signed = True
    
    def format (self):
        return "%d" % self

class CParam (_IntParam, metaclass = codedparam_meta):

    def __new__ (cls, val, *args):
        val = cls.getniceval (val)
        if not isinstance (val, int):
            val = cls.values[val]
        return super (__class__, cls).__new__ (cls, val)
    
    def format (self):
        try:
            return self.vnames[self]
        except KeyError:
            return str (self)

class StrParam (Param, str):

    @classmethod
    def decodeval (cls, b, fmt):
        n = b[0]
        b = b[1:]
        if len (b) < n:
            raise MissingData ("Data too short for %d byte field" % n)
        return str (b[:n], encoding = "latin1", errors = "ignore"), fmt, b[n:]

    def encodeval (self):
        b = bytes (self, encoding = "latin1", errors = "ignore")
        return byte (self.fmt) + byte (len (b)) + b

    def format (self):
        return str (self)
    
class CMParam (Param, tuple):

    def __new__ (cls, vals, fmts, *args):
        vals = cls.getniceval (vals)
        if not (isinstance (vals, Sequence) and not
                isinstance (vals, strtypes)):
            vals = (vals,)
        if len (vals) > len (fmts):
            raise TypeError ("Too few formats for values")
        vlist = list ()
        for v, f in zip (vals, fmts):
            c = fmtparamclass (f)
            # Third argument (code) is not used, but is required to
            # satisfy the constructor
            vlist.append (c (v, f, 9999))
        return tuple.__new__ (cls, vlist)
    
    @classmethod
    def decodeval (cls, b, fmt):
        n = fmt & 0x0f
        val = list ()
        rfmt = list ()
        for i in range (n):
            # "code" argument is not used, but is required to
            # satisfy the constructor
            p, b = Param.decode (b, code = 9999)
            val.append (p)
            rfmt.append (p.fmt)
        return val, rfmt, b

    def encodeval (self):
        ret = list ()
        for v, f in zip (self, self.fmt):
            ret.append (v.encodeval ())
        return byte (0xc0 + len (self)) + b''.join (ret)

    def format (self):
        return ' '.join ([ v.format () for v in self ])
        
class BytesParam (Param, bytes):

    @classmethod
    def decodeval (cls, b, fmt):
        n = b[0]
        b = b[1:]
        if len (b) < n:
            raise MissingData ("Data too short for %d byte field" % n)
        return b[:n], fmt, b[n:]

    def encodeval (self):
        b = bytes (self)
        return byte (self.fmt) + byte (len (b)) + b

    def format (self):
        return "-".join ([ "%02x" % i for i in self ])
        
def fmtparamclass (fmt):
    """Find the type-specific Param subclass for this format code.
    None means invalid format code."""
    if fmt == 0x40:
        # AI-n
        return StrParam
    if fmt == 0x20:
        # HI-n
        return BytesParam
    if fmt & 0x80:
        # coded
        n = fmt & 0x3f
        if not n:
            return None
        if fmt & 0x40:
            # CM-n
            return CMParam
        else:
            # C-n
            return CParam
    else:
        # not coded
        n = fmt & 0x0f
        if not n:
            return None
        if (fmt & 0xf0) == 0x10:
            # DS-n
            return SIntParam
        return UIntParam

class Counter (object):
    """Base class for DNA counters.
    """
    _code = None
    _width = None
    _bits = ( )

"""
                     Circuit Counters Kept for All Circuits

        Type    Bit
       Number  Width        Standard Text

            0   16    Seconds Since Last Zeroed
          800   32    Terminating Packets Received
          801   32    Originating Packets Sent
          802   16    Terminating Congestion Loss
          805    8    Corruption Loss
          810   32    Transit Packets Received
          811   32    Transit Packets Sent
          812   16    Transit Congestion Loss
          820    8    Circuit Down
          821    8    Initialization Failure


     The following Data Link counters apply to DDCMP circuits:


                                    Table 7
                 Data Link Circuit Counters for DDCMP Circuits

      Type      Bit                            Bit Number
     Number    Width     Standard Text           Standard Text

      1000      32    Bytes Received
      1001      32    Bytes Sent
      1010      32    Data Blocks Received
      1011      32    Data Blocks Sent
      1020       8    Data Errors Inbound      1 NAKs Sent, Data Field
                                                  Block Check error
                                               2 NAKs Sent, REP Response
      1021       8    Data Errors Outbound     0 NAKs Received, Header
                                                  Block Check error
                                               1 NAKs Received, Data Field
                                                  Block Check error
                                               2 NAKs Received, REP
                                                  Response
      1030       8    Remote Reply Timeouts
      1031       8    Local Reply Timeouts
      1040       8    Remote Buffer Errors     0 NAKs Received Buffer
                                                  Unavailable
                                               1 NAKs Received Buffer Too
                                                  Small
      1041       8    Local Buffer Errors      0 NAKs Sent Buffer
                                                  Unavailable
                                               1 NAKs Sent Buffer Too
                                                  Small
      1050      16    Selection Intervals
                       Elapsed
      1051       8    Selection Timeouts       0 No Reply to Select
                                               1 Incomplete Reply to
                                                  Select
     Parameter and Counter Binary Formats and Values


     The following Data Link counters apply to permanent X.25 circuits:


                                    Table 8
             Data Link Circuit Counters for Permanent X.25 Circuits

        Type    Bit
       Number  Width     Standard Text

        1000    32       Bytes received
        1001    32       Bytes sent
        1010    32       Data blocks received
        1011    32       Data blocks sent
        1240     8       Locally initiated resets
        1241     8       Remotely initiated resets
        1242     8       Network initiated resets


     The  following  table  specifies  Data  Link  counters  for   Ethernet
     circuits:


                                    Table 9
                Data Link Circuit Counters for Ethernet Circuits

        Type    Bit
       Number  Width     Standard Text

           0    16       Seconds Since Last Zeroed
        1000    32       Bytes Received
        1001    32       Bytes Sent
        1010    32       Data Blocks Received
        1011    32       Data Blocks Sent
        1065    16       User buffer unavailable

                     Data Link Line Counters for LAPB Lines

        Type    Bit                            Bit Number
       Number  Width     Standard Text           Standard Text

           0    16    Seconds Since Last Zeroed
        1000    32    Bytes Received
        1001    32    Bytes Sent
        1010    32    Data Blocks Received
        1011    32    Data Blocks Sent
        1020     8    Data Errors Inbound      3 Block too long
                                               4 Block check error
                                               5 REJ sent
        1021     8    Data Errors Outbound     3 REJ received
        1030     8    Remote Reply Timeouts
        1031     8    Local Reply Timeouts
        1040     8    Remote Buffer Errors     2 RNR received, buffer
                                                 unavailable
        1041     8    Local Buffer Errors      2 RNR sent, buffer
                                                 unavailable
        1100     8    Remote Station Errors    4 Invalid N(R) received
                                               5 FRMR sent, header
                                                 format error
        1101     8    Local Station Errors     2 Transmit underrun
                                               4 Receive overrun
                                               5 FRMR received, head
                                                 format error


     The following table specifies Data Link counters for DDCMP lines:


                                    Table 13
                    Data Link Line Counters for DDCMP Lines

        Type    Bit                            Bit Number
       Number  Width     Standard Text           Standard Text

        1020    8     Data Errors Inbound      0 NAKs sent, header block
                                                 check error
        1100    8     Remote Station Errors    0 NAKs received, receive
                                                 overrun
                                               1 NAKs sent, header
                                                 format error
                                               2 Selection address
                                                 errors
                                               3 Streaming tributaries
        1101    8     Local Station Errors     0 NAKs sent, receive
                                                 overrun
                                               1 Receive overruns, NAK
                                                 not sent
                                               2 Transmit underruns
                                               3 NAKs received, header
                                                 format error
     Parameter and Counter Binary Formats and Values


     The following table specifies Data Link counters for Ethernet lines:


                                   Table 13.1
                   Data Link Line Counters for Ethernet Lines

        Type    Bit                            Bit Number
       Number  Width     Standard Text           Standard Text

           0    16    Seconds Since Last Zeroed
        1000    32    Bytes Received
        1001    32    Bytes Sent
        1002    32    Multicast Bytes Received
        1010    32    Data Blocks Received
        1011    32    Data Blocks Sent
        1012    32    Multicast Blocks Received
        1013    32    Blocks sent, initially deferred
        1014    32    Blocks sent, single collision
        1015    32    Blocks sent, multiple collisions
        1060    16    Send failure             0 Excessive collisions
                                               1 Carrier check failed
                                               2 Short circuit
                                               3 Open circuit
                                               4 Frame too long
                                               5 Remote failure to defer
        1061    16    Collision detect check failure
        1062    16    Receive failure          0 Block check error
                                               1 Framing error
                                               2 Frame too long
        1063    16    Unrecognized frame destination
        1064    16    Data overrun
        1065    16    System buffer unavailable
        1066    16    User buffer unavailable
                                    Table 18
                         X.25 Protocol Module Counters

      Type       Bit
     Number     Width         Standard Text

        0        16     Seconds since last zeroed
     1000        32     Bytes received
     1001        32     Bytes sent
     1010        32     Data blocks received
     1011        32     Data blocks sent
     1200        16     Calls received
     1201        16     Calls sent
     1210        16     Fast selects received
     1211        16     Fast selects sent
     1220        16     Maximum switched circuits active
     1221        16     Maximum channels active
     1230        16     Received call resource errors
     1240         8     Locally initiated resets
     1241         8     Remotely initiated resets
     1242         8     Network initiated resets
     1250         8     Restarts



            X.25 Server Module Counters

     The following table specifies the X.25 server module counters.


                                    Table 19
                          X.25 Server Module Counters

        Type   Bit
       Number  Width     Standard Text

           0    16    Seconds since last zeroed
         200    16    Maximum circuits active
         210     8    Incoming calls rejected, no resources
         211     8    Logical links rejected, no resources



  Node counters:
       Appl.   Type Number  Bit width        Standard Text

        DN         0           16       Seconds Since Last Zeroed

        DN       600           32       User Bytes Received
        DN       601           32       User Bytes Sent
        DN       602           32       User Messages Received
        DN       603           32       User Messages Sent
        DN       608           32       Total Bytes Received
        DN       609           32       Total Bytes Sent
        DN       610           32       Total Messages Received
        DN       611           32       Total Messages Sent
        DN       620           16       Connects Received
        DN       621           16       Connects Sent
        DN       630           16       Response Timeouts
        DN       640           16       Received Connect Resource Errors
        E        700           16       Maximum Logical Links Active
     Parameter and Counter Binary Formats and Values


        E        900            8       Aged Packet Loss
        E        901           16       Node Unreachable Packet Loss
        E        902            8       Node Out-of-Range Packet Loss
        E        903            8       Oversized Packet Loss
        E        910            8       Packet Format Error
        E        920            8       Partial Routing Update Loss
        E        930            8       Verification Reject

"""
class nicemsg_meta (type):
    def __new__ (cls, name, bases, classdict):
        pdict = dict ()
        for c in classdict.values ():
            if c is not Param and \
                   isinstance (c, type) and \
                   issubclass (c, Param) \
                   and not hasattr (c, "send_only"):
                pdict[c._code] = c
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
                raise MissingData ("Truncated DATA ID field")
            did = int.from_bytes (b[:2], "little")
            b = b[2:]
            if did & 0x8000:
                # Counter, TBD
                pass
            else:
                did &= 0x0fff
                pc = cls.pdict.get (did, Param)
                p, b = pc.decode (b, code = did)
                ret.append (p)
        return ret

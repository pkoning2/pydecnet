#!

"""NICE protocol encoding machinery
"""

import time
import struct

from .common import *
from . import packet
from . import logging

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
    _layout = (( "res", 1 ),
               ( "b", "ename", 1 ))

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
            require (buf, 1)
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
CM5 = CM1.findclass (0xc5)
CM10 = CM1.findclass (0xca)

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

    def encode_nice_common (self, ncdict, cdict, flist, resp):
        ret = [ ]
        for param, pcls, fn, desc, vals in flist:
            v = getattr (self, fn, None)
            if v is not None:
                v = pcls.makenice (v, vals)
                if pcls.counter:
                    ret.append (v.encode (param))
                else:
                    ret.append (param.to_bytes (2, "little"))
                    e = v.encode ()
                    if resp:
                        ret.append (e)
                    else:
                        # request, omit the code field
                        ret.append (e[1:])
        return b''.join (ret)

    def decode_nice_common (self, buf, ncdict, cdict, flist, resp):
        """Decode the remainder of the buffer as a sequence of NICE
        fields.  Each value field is decoded according to the format
        code of the item, which is used to turn the data into an
        instance of a NiceData subclass.

        If "resp" is True, we're decoding a response (NML to NCP), in
        which all data items have code fields.  If False, we're decoding
        a request (NCP to NML), in that case non-image data is just
        parameter number and value, but no code.
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
            elif resp:
                # Non-counter in a response, type code is next byte
                code = buf[2]
                buf = buf[3:]
                d = ncdict
            else:
                # Non-counter in a request, data only
                code = None
                buf = buf[2:]
                d = ncdict
            param &= 0xfff    # Clear out reserved bits if non-counter
            try:
                pcls, fn, vals = d[param]
            except KeyError:
                # DU1 is used as a default in various places because it
                # is a valid type with a code attribute.  The actual
                # class used to decode will be governed by the decoded
                # data since we always check the buffer's code field.
                #
                # All this applies only to responses.  For requests,
                # only known parameters are accepted, partly because the
                # spec says so and partly because we have no way to know
                # how to parse unknown parameters (there is nothing to
                # tell us the data length).
                if not resp:
                    raise DecodeError ("Unknown parameter {} in request".format (param))
                pcls = DU1
                fn = "field{}".format (param)
                vals = ()
                self._xfields = True
            if code is None:
                # If decoding a request, the parameter number tells us
                # the expected code.
                code = pcls ().code
            elif pcls ().code != code:
                # The packet has a different data code than the expected
                # code given in the decode tables.  Use the standard
                # class for the sender's code.
                pcls = NiceType.findclass (code)
            v, buf = pcls.decode (buf, vals)
            # Done with this data item; store it.
            setattr (self, fn, v)

    def encode_nice (self, ncdict, cdict, flist):
        "Encode case for encoding a response (with code fields)"
        return self.encode_nice_common (ncdict, cdict, flist, True)

    def encode_nice_req (self, ncdict, cdict, flist):
        "Encode case for encoding a request (no code fields)"
        return self.encode_nice_common (ncdict, cdict, flist, False)

    def decode_nice (self, buf, ncdict, cdict, flist):
        "Decode case for decoding a response (with code fields)"
        return self.decode_nice_common (buf, ncdict, cdict, flist, True)

    def decode_nice_req (self, buf, ncdict, cdict, flist):
        "Decode case for decoding a request (no code fields)"
        return self.decode_nice_common (buf, ncdict, cdict, flist, False)

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
#
# The variable names need to match those used for the internal
# counters object defined in nsp.py and routing.py -- this makes the
# "copy" method work for transferring those internal counters into
# this NICE reply object.
node_counters = [
    ( 0, CTR2, "Seconds since last zeroed", "time_since_zeroed" ),
    ( 600, CTR4, "User bytes received", "byt_rcv" ),
    ( 601, CTR4, "User bytes sent", "byt_xmt" ),
    ( 602, CTR4, "User messages received", "msg_rcv" ),
    ( 603, CTR4, "User messages sent", "msg_xmt" ),
    ( 608, CTR4, "Total bytes received", "t_byt_rcv" ),
    ( 609, CTR4, "Total bytes sent", "t_byt_xmt" ),
    ( 610, CTR4, "Total messages received", "t_msg_rcv" ),
    ( 611, CTR4, "Total messages sent", "t_msg_xmt" ),
    ( 620, CTR2, "Connects received", "con_rcv" ),
    ( 621, CTR2, "Connects sent", "con_xmt" ),
    ( 630, CTR2, "Response timeouts", "timeout" ),
    ( 640, CTR2, "Received connect resource errors", "no_res_rcv" ),
    ( 700, CTR2, "Maximum logical links active", "peak_conns" ),
    ( 900, CTR1, "Aged packet loss", "aged_loss" ),
    ( 901, CTR2, "Node unreachable packet loss", "unreach_loss" ),
    ( 902, CTR1, "Node out-of-range packet loss", "node_oor_loss" ),
    ( 903, CTR1, "Oversized packet loss", "oversized_loss" ),
    ( 910, CTR1, "Packet format error", "fmt_errors" ),
    ( 920, CTR1, "Partial routing update loss", "partial_update_loss" ),
    ( 930, CTR1, "Verification reject", "ver_rejects" ),
    # RSTS/E specific codes
    ( 2200, CTR2, "Current reachable nodes" ),
    ( 2201, CTR2, "Maximum reachable nodes" )
]   

circuit_counters = [
    ( 0, CTR2, "Seconds since last zeroed", "time_since_zeroed" ),
    ( 800, CTR4, "Terminating packets received", "term_recv" ),
    ( 801, CTR4, "Originating packets sent", "orig_sent" ),
    ( 802, CTR2, "Terminating congestion loss" ),
    ( 805, CTR1, "Corruption loss" ),
    ( 810, CTR4, "Transit packets received", "trans_recv" ),
    ( 811, CTR4, "Transit packets sent", "trans_sent" ),
    ( 812, CTR2, "Transit congestion loss", "trans_cong" ),
    ( 820, CTR1, "Circuit down", "cir_down" ),
    ( 821, CTR1, "Initialization failure", "init_fail" ),
    ( 1000, CTR4, "Bytes received", "bytes_recv" ),
    ( 1001, CTR4, "Bytes sent" ),
    ( 1010, CTR4, "Data blocks received", "pkts_recv" ),
    ( 1011, CTR4, "Data blocks sent", "pkts_sent" ),
    ( 1020, CTM1, "Data errors inbound", None, 
            ( "NAKs sent, data field block check error",
              "NAKs sent, REP response" )),
    ( 1021, CTM1, "Data errors outbound", None,
            ( "NAKs received, header block check error",
              "NAKs received, data field block check error",
              "NAKs received, REP response" )),
    ( 1030, CTR1, "Remote reply timeouts" ),
    ( 1031, CTR1, "Local reply timeouts" ),
    ( 1040, CTM1, "Remote buffer errors", None,
            ( "NAKs received buffer unavailable",
              "NAKs received buffer too small" )),
    ( 1041, CTM1, "Local buffer errors", None,
            ( "NAKs sent buffer unavailable",
              "NAKs sent buffer too small" )),
    ( 1050, CTR2, "Selection intervals elapsed" ),
    ( 1051, CTM1, "Selection timeouts", None,
            ( "No reply to select",
              "Incomplete reply to select" )),
    ( 1065, CTR2, "User buffer unavailable" ),
    ( 1240, CTR1, "Locally initiated resets" ),
    ( 1241, CTR1, "Remotely initiated resets" ),
    ( 1242, CTR1, "Network initiated resets" )
]
    
line_counters = [
    ( 0, CTR2, "Seconds since last zeroed", "time_since_zeroed" ),
    ( 1000, CTR4, "Bytes received", "bytes_recv" ),
    ( 1001, CTR4, "Bytes sent" ),
    ( 1010, CTR4, "Data blocks received", "pkts_recv" ),
    ( 1011, CTR4, "Data blocks sent", "pkts_sent" ),
    ( 1012, CTR4, "Multicast blocks received" ),
    ( 1013, CTR4, "Blocks sent, initially deferred", "sent_def" ),
    ( 1014, CTR4, "Blocks sent, single collision", "sent_1col" ),
    ( 1015, CTR4, "Blocks sent, multiple collisions", "sent_mcol" ),
    ( 1020, CTM1, "Data errors inbound", None, 
            ( "NAKs sent, header block check error",
              "NAKs sent, REP response",
              "Block too long",
              "Block check error",
              "REJ sent" )),
    ( 1021, CTM1, "Data errors outbound", None,
            ( "NAKs received, header block check error",
              "NAKs received, data field block check error",
              "NAKs received, REP response",
              "REJ received" )),
    ( 1030, CTR1, "Remote reply timeouts" ),
    ( 1031, CTR1, "Local reply timeouts" ),
    ( 1040, CTM1, "Remote buffer errors", None,
            ( "NAKs received buffer unavailable",
              "NAKs received buffer too small",
              "RNR received, buffer unavailable" )),
    ( 1041, CTM1, "Local buffer errors", None,
            ( "NAKs sent buffer unavailable",
              "NAKs sent buffer too small",
              "RNR sent, buffer unavailable" )),
    ( 1060, CTM2, "Send failure", None,
            ( "Excessive collisions",
              "Carrier check failed",
              "Short circuit",
              "Open circuit",
              "Frame too long",
              "Remote failure to defer" )),
    ( 1061, CTR2, "Collision detect check failure" ),
    ( 1062, CTM2, "Receive failure", None,
            ( "Block check error",
              "Framing error",
              "Frame too long" )),
    ( 1063, CTR2, "Unrecognized frame destination" ),
    ( 1064, CTR2, "Data overrun" ),
    ( 1065, CTR2, "System buffer unavailable" ),
    ( 1066, CTR2, "User buffer unavailable" ),
    ( 1100, CTM1, "Remote station errors", None,
            ( "NAKs received, receive overrun",
              "NAKs sent, header format error",
              "Selection address errors",
              "Streaming tributaries",
              "Invalid N(R) received",
              "FRMR sent, header format error" )),
    ( 1101, CTM1, "Local station errors", None,
            ( "NAKs sent, receive overrun",
              "Receive overruns, NAK not sent",
              "Transmit underruns",
              "NAKs received, header format error",
              "Receive overrun",
              "FRMR received, head format error" ))
]            

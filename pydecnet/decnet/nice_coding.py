#!

"""NICE protocol encoding machinery
"""

import struct
from collections.abc import Iterable

from .common import *
from . import packet
from . import logging

SvnFileRev = "$LastChangedRevision$"

# Details about "entities" -- since the specs are not well written on
# this subject.
#
# Entities come in three flavors:
# 1. In NICE requests
# 2. In NICE responses
# 3. In event messages
#
# For NICE requests and event messages, the entity data itself is
# preceded by an "entity type" code, indicating what type of entity
# we're dealing with here.  In NICE responses, there is no type code;
# the entity type is determined by the request for which this is the
# response.  The entity type codes are the same for NICE and event
# messages but encoded differently: as a 3-bit field in NICE requests,
# but a signed integer byte in event messages.  In event messages, an
# additional type value occurs: -1 means "no entity".
#
# Note that there is a bug in the Phase IV Network Management spec; it
# says that event messages have a 2-byte type field.  In the Phase III
# spec, and in the implementations, it is a 1-byte field.
#
# In NICE responses and event messages, the entity data is typically a
# counted string, except for nodes where it is a 2-byte node number
# followed by the name as a counted string, and areas where it is TBD.
#
# In NICE requests, there is a distinction between a single entity and
# a request for multiples -- which is cases like "active" or "known".
# Individual entities are typically a counted string; multiples are
# represented by a single byte with negative value.  Special cases are
# specific node number, encoded as a byte of 0 followed by the two
# byte node number, and specific area, encoded as a byte of 0 followed
# by a one byte area number.  See the Phase IV Network Management
# specification, section 7.1 for the details; the NICE request case is
# clearly documented (the other two, not so much).

# Now define the NICE response entity classes
class EntityBase (packet.Field):
    def __format__ (self, arg):
        return "{} = {}".format (self.__class__.label, super ().__str__ ())
        
    def __hash__ (self):
        return id (self)

class NodeEntity (NiceNode, EntityBase):
    label = "Node"

    def __str__ (self):
        return "{}".format (super ().__str__ ())

    def __format__ (self, arg):
        if arg:
            t = "Node"
        elif int (self) == 0:
            t = "Loop node"
        elif self.executor:
            t = "Executor node"
        else:
            t = "Remote node"
        return "{} = {}".format (t, self.__str__ ())
    
class StringEntityBase (EntityBase, packet.A):
    # The spec does not give a length limit for the name, so make it
    # 255 (the max possible given the encoding).
    def encode (self):
        return super ().encode (255)

    @classmethod
    def decode (cls, buf):
        return super (__class__, cls).decode (buf, 255)

class LineEntity (StringEntityBase):
    label = "Line"

class LoggingEntity (StringEntityBase):
    label = "Logging"

class CircuitEntity (StringEntityBase):
    label = "Circuit"

class ModuleEntity (StringEntityBase):
    label = "Module"

class AreaEntity (EntityBase, int):
    label = "Area"
    def encode (self):
        return b"\000" + byte (self)

    @classmethod
    def decode (cls, buf):
        return cls (buf[1]), buf[2:]

class NiceType (packet.IndexedField):
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
        if code & 0x8000:
            # No defaults for counter types
            raise DecodeError ("Invalid type code 0x{:0>4x}".format (code))
        if code & 0x80:
            bytecnt = code & 0x1f
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
    def checktype (cls, name, v, tlist = None):
        """If v is not already an instance of NiceType, make it an
        instance of cls.
        """
        # Note this is different from the base class checktype, which
        # forces v to be an instance of cls.  We don't want that because
        # decoding a NICE packet will pick the type from what the packet
        # calls for.
        # The tlist argument is unused but sometimes passed, so we allow
        # for it.
        if not isinstance (v, NiceType):
            v = cls (v)
        return v
    
    def format (self, tlist = None):
        "Format the data value according to its defined data type"
        # Allow a tlist argument since some common code passes that.
        return self.fmt.format (self)
    
    @classmethod
    def makecoderow (cls, param, pcls, desc, *rest):
        """Process a row in the NICE parameter sequence.
        """
        # The NICE layout is given by a sequence of parameter descriptions.
        # Each entry is a tuple, which is processed by this method:
        #   Parameter number
        #   Data type (NICE parameter data class)
        #   Field description
        #   Optional field name to use in the class
        #   Optional value label sequence or dictionary
        #
        # Note that counters and non-counters have separate number spaces,
        # so a parameter number may occur twice, once for a counter, once
        # for a non-counter.  In addition, there may be multiple variable
        # names mapped to the same parameter number.  This is useful if
        # there are several encodings; an example is the "packet header"
        # argument in the routing events.  If this is done, the last
        # occurrence of the parameter number is the one used to decode
        # incoming packets (i.e., the one whose layout is used as the
        # template).
        #
        # If the field name is omitted or None, the name is generated from
        # the description by converting to lower case and changing all
        # spaces to underscore.
        #
        # The value label argument may be used for C (coded) and CTM
        # (mapped counter) data; the values are strings which are the
        # string to display for that value (C) or the name of that bit in
        # the bitmap (CTM).  If omitted the result is defined by a class
        # attribute (if subclassed) or as if an empty list was given,
        # which causes all strings to be the fallback (#number) instead.
        #
        # When decoding incoming data, the data type is indicated explicitly
        # in the binary data.  For that case, the data type (NICE data
        # class) is used only if it has the same data type code as is given
        # in the decoded data.  Otherwise, the type code is looked up in the
        # classindex to find the class matching that code.  This means that
        # a subclass with custom handling (for example alternate formatting,
        # see DUNode for an example) can be used for a DU-2 field, but if
        # the decoded data has some other type code, the DUNode class is
        # disregarded.
        #
        # The output is a tuple consisting of:
        # - parameter number, with bit 15 set if this is a counter
        # - parameter name
        # - a tuple to insert into the decode dictionary, consisting of
        #     data class, variable name, and value-label data
        # - a tuple to append to the encode and formatting list, consisting
        #     of the parameter number, data class, variable name, description,
        #     and value-label data.
        try:
            fn = rest[0]
        except IndexError:
            fn = None
        if not fn:
            fn = desc.lower ().replace (" ", "_")
        try:
            vals = rest[1]
        except IndexError:
            vals = ()
        if pcls.counter:
            param |= 0x8000
        return param, fn, (pcls, fn, vals), (param, pcls, fn, desc, vals)

class DU1 (NiceType, int):
    bytecnt = 1
    signed = False
    code = 1
    
    def encode (self, tlist = None):
        "Encode the value, including the type code"
        tlist = tlist or self.vlist
        return byte (self.code) + \
               self.to_bytes (self.bytecnt, "little", signed = self.signed)

    @classmethod
    def decode (cls, b, code, tlist = None):
        "Decode the value, not including the type code"
        tlist = tlist or cls.vlist
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

    def format (self, tlist = None):
        # Not clear if this matches the letter of the spec, but for hex
        # integers it is helpful to show the full length value, with all
        # the leading zeroes.
        return self.fmt.format (self, self.bytecnt * 2)

class O1 (DU1):
    fmt = "{0:0>{1}o}"
    code = 0x31

    def format (self, tlist = None):
        # Show the full length value, with all the leading zeroes.
        digits = (self.bytecnt * 8 + 2) // 3
        return self.fmt.format (self, digits)
    
class AI (NiceType, str):
    code = 0x40

    def encode (self, tlist = None):
        b = bytes (self, "latin1")
        return b"\x40" + byte (len (b)) + b

    @classmethod
    def decode (cls, b, code, tlist = None):
        if not b:
            raise MissingData
        l = b[0]
        if len (b) < l + 1:
            raise MissingData
        return cls (b[1:l + 1], "latin1"), b[l + 1:]

class HI (NiceType, bytes):
    code = 0x20

    def __new__ (cls, v):
        if isinstance (v, str):
            v = bytes (int (i, 16) for i in v.split ("-"))
        return bytes.__new__ (cls, v)
    
    def format (self, tlist = None):
        return "-".join ("{:02x}".format (i) for i in self)

    def encode (self, tlist = None):
        return b"\x20" + byte (len (self)) + self

    @classmethod
    def decode (cls, b, code, tlist = None):
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

def delimit (sl, delim):
    # Return the string of sl elements joined by delim, if a single
    # character, or by each of the characters in delim otherwise.
    if len (delim) == 1:
        return delim.join (sl)
    ret = list ()
    for s, d in zpr (sl, delim, delim[-1]):
        ret.append (s)
        ret.append (d)
    return "".join (ret[:-1])

class CM1 (NiceType, list):
    code = 0xc1
    bytecnt = 1
    delim = " "

    @classmethod
    def checktype (cls, name, val, tlist):
        tlist = tlist or cls.vlist        
        if not isinstance (val, cls):
            val = cls (val)
        for i, cls in zpr (range (len (val)), tlist):
            val[i] = cls.checktype (name, val[i])
        return val
    
    def format (self, tlist):
        vl = [ ]
        tlist = tlist or self.vlist
        for i, cls in zpr (self, tlist):
            vl.append (cls.checktype ("cm", i).format ())
        return delimit (vl, self.delim)

    @classmethod
    def decode (cls, buf, code, tlist):
        if tlist:
            t = tlist[0]
            if not (isinstance (t, type) and issubclass (t, NiceType)):
                tlist = ()
        vl = [ ]
        tlist = tlist or cls.vlist
        for i, cls2 in zpr (range (code & 0x1f), tlist):
            require (buf, 1)
            cls2 = cls2.findclass (buf[0])
            v, buf = cls2.decode (buf[1:], cls2.vlist)
            vl.append (v)
        return cls (vl), buf

    def encode (self, tlist):
        vl = [ ]
        tlist = tlist or self.vlist
        for i, cls in zpr (self, tlist):
            vl.append (cls.checktype ("cm", i).encode ())
        return byte (0xc0 + len (vl)) + b"".join (vl)
    
    @classmethod
    def makecoderow (cls, param, pcls, desc, fn, vals):
        """Process a row in the NICE parameter sequence for a CM-n field.
        """
        # The NICE layout is given by a sequence of parameter descriptions.
        # Each entry is a tuple, which is processed by this method:
        #   Parameter number
        #   Data type (NICE parameter data class)
        #   Field description
        #   Optional field name to use in the class
        #   Optional value label sequence or dictionary
        #
        # Here we handle the case for CM-n fields, where the fifth
        # argument instead gives a sequence of NICE field types that
        # make up the coded multiple data item.  This argument is
        # required (and therefore the preceding argument is also
        # required, but it can be None to get the default handling).
        # Note that the types must be non-counter types.
        if not fn:
            fn = desc.lower ().replace (" ", "_")
        return pcls.counter, param, fn, \
               (pcls, fn, vals), (param, pcls, fn, desc, vals)

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
H4 = H1.findclass (0x24)
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

    def format (self, tlist = None):
        if self >= self.maxval:
            return self.maxstr
        return "{}".format (self)

    def format_qual (self, tlist = None):
        return ""
    
    def encode (self, pnum):
        return (pnum | self.code).to_bytes (2, "little") + \
               min (self, self.maxval).to_bytes (self.bytecnt, "little")

mapindent = " " * 19
mapsep = "\n" + mapindent

class Map:
    def __init__ (self, val = 0):
        self.map = 0
        self.cmap = [ 0 ] * 16
        
    def __iadd__ (self, other):
        "Increment a mapped counter, and optionally OR in a bit"
        if isinstance (other, Iterable):
            n, bitnum = other
            ret = self.__class__ (self + n)
            ret.map = self.map | (1 << bitnum)
            ret.cmap = self.cmap
            ret.cmap[bitnum] += 1
        else:
            ret = self.__class__ (self + other)
            ret.map = self.map
        return ret
            
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
        else:
            v = ""
        return v

    def encode (self, pnum):
        return (pnum | self.code).to_bytes (2, "little") + \
               self.map.to_bytes (2, "little") + \
               min (self, self.maxval).to_bytes (self.bytecnt, "little")

    @classmethod
    def decode (cls, b, code, tlist = None):
        bc = cls.bytecnt
        if len (b) < bc + 2:
            raise MissingData
        map = int.from_bytes (b[:2], "little")
        v, b = super (__class__, cls).decode (b[2:], tlist)
        v.map = map
        return v, b
    
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

def addfield (s, compact, curline, ret):
    if not s:
        return curline
    if compact:
        s += ","
        if len (curline) + len (s) < compact:
            if curline:
                curline += " " + s
            else:
                curline = s
        else:
            if curline:
                ret.append (curline)
            curline = s
    else:
        ret.append (s)
    return curline
    
class NICE (packet.FieldGroup):
    lastfield = True
    
    @classmethod
    def makecoderow (cls, resp, *layouts):
        """Process the layout data for a NICE item.
        """
        # A layout entry for NICE consists of the "response" flag,
        # followed by a sequence of parameter descriptions.  The
        # response flag is False for request packets, True for response
        # or event packets.
        #
        # Refer to the comments in NiceType.makecoderow for a detailed
        # description of the parameter description contents.
        pdict = dict ()
        flist = list ()
        names = list ()
        for v in layouts:
            k, fn, v, f = NiceType.makecoderow (*v)
            names.append (fn)
            pdict[k] = v
            flist.append (f)
        return cls, None, ( resp, pdict, flist ), names, True

    @staticmethod
    def format (pkt, indent = "    ", compact = 0, hdr = "", fmtclass = None,
                omit = (), add = (), **kwds):
        """Format the NICE data block.  Fixed header fields are not
        processed, those should be handled by the caller.

        Optional arguments:
           indent: string to use as line indent, default to 4 spaces.
           compact: if non-zero, gather multiple fields into lines
             of up to the specified length.
           hdr: a string used to format a header line; typically this is 
             used for tabular output formatting.  The packet object is
             the first argument of the format call.
           omit: field names of fields to omit; typically this would
             list the fields mentioned in the "hdr" argument.  For that
             formatting to work, the named fields are given default
             values of "" (empty string) if not defined yet.
           add: additional fields to be included in the packet contents
             section (after the header), collected several to a line
             as controlled by the "compact" argument.
        Any other keyword arguments are passed as the second argument of
        the header format call, if the hdr argument is specified.
        """
        fmtclass = fmtclass or pkt
        ftype, fname, niceargs = fmtclass._codetable[-1]
        if issubclass (ftype, __class__):
            resp, pdict, flist = niceargs
        else:
            flist = ()
            pdict = {}
        for param in omit:
            pcls, fn, vals = pdict[param]
            fv = getattr (pkt, fn, None)
            if fv is None:
                setattr (pkt, fn, "")
            else:
                setattr (pkt, fn, fv.format (vals))
        ret = [ ]
        curline = ""
        firstindent = indent
        if compact:
            if compact is True:
                compact = 70
            compact -= len (indent) + 1
        if hdr:
            hdr = hdr.format (pkt, kwds).rstrip (" ")
            if hdr:
                ret = [ hdr ]
                firstindent = ""
        for s  in add:
            curline = addfield (s, compact, curline, ret)
        # If there are non-standard fields, add made up entries for them
        # into the format list.
        xparams = pkt.xfields ()
        if xparams:
            xflist = [ ]
            for fn in xparams:
                v = getattr (pkt, fn)
                fnum = packet.fieldnum (fn)
                if v.counter:
                    dparam = "Counter #{}".format (fnum)
                else:
                    dparam = "Parameter #{}".format (fnum)
                xflist.append ((fnum, DU1, fn, dparam, ()))
            # Note: not += because that appends to the existing list,
            # modifying it.  This creates a new list in the local
            # variable.
            flist = flist + xflist
            # The unknown fields will appear in the output list
            # according to their parameter number, rather than all at
            # the end.
            flist.sort ()
        fields = 0
        for param, pcls, fn, desc, vals in flist:
            if param in omit:
                continue
            v = getattr (pkt, fn, None)
            if v is not None:
                v = pcls.checktype (fn, v, vals)
                if v.counter:
                    s = "{:>11s} {}{}".format (v.format (), desc,
                                               v.format_qual (vals))
                else:
                    s = "{} = {}".format (desc, v.format (vals))
                curline = addfield (s, compact, curline, ret)
                fields += 1
        if curline:
            ret.append (curline)
        if ret:
            return firstindent + ("\n" + indent).join (ret).rstrip (",")
        return ""

    @classmethod
    def encode (cls, pkt, resp, pdict, flist):
        ret = [ ]
        for param, pcls, fn, desc, vals in flist:
            v = getattr (pkt, fn, None)
            if v is not None:
                v = pcls.checktype (fn, v, vals)
                if pcls.counter:
                    ret.append (v.encode (param))
                else:
                    ret.append (param.to_bytes (2, "little"))
                    e = v.encode (vals)
                    if resp:
                        ret.append (e)
                    else:
                        # request, omit the code field
                        ret.append (e[1:])
        # Add any unknown fields.  This isn't currently used but it
        # allows us to decode a packet and re-encode it with no loss of
        # data.
        xparams = pkt.xfields ()
        if xparams:
            xparams.sort (key = packet.fieldnum)
            for fn in xparams:
                param = packet.fieldnum (fn)
                v = getattr (pkt, fn)
                if v.counter:
                    ret.append (v.encode (param))
                else:
                    ret.append (param.to_bytes (2, "little"))
                    e = v.encode (())
                    if resp:
                        ret.append (e)
                    else:
                        # request, omit the code field
                        ret.append (e[1:])
        return b''.join (ret)

    @classmethod
    def decode (cls, buf, pkt, resp, pdict, flist):
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
                if cls.tolerant:
                    return b''
                logging.debug ("Incomplete NICE data item at end of buffer")
                raise MissingData
            code, pcls, fn, vals, buf = cls.decodepnum (buf, resp, pdict)
            v, buf = pcls.decode (buf, code, vals)
            # Done with this data item; store it.
            setattr (pkt, fn, v)
        return buf

    @classmethod
    def decodepnum (cls, buf, resp, pdict):
        """Decode the parameter number and, if applicable, the type code
        field.  Returns a tuple consisting of parameter code, parameter
        class, field name, values dict, and remaining buffer.
        """
        param = int.from_bytes (buf[0:2], "little")
        if param & 0x8000:
            # Counter, so the data code is in the upper bits
            code = param & 0xf000
            buf = buf[2:]
        elif resp:
            # Non-counter in a response, type code is next byte
            code = buf[2]
            buf = buf[3:]
        else:
            # Non-counter in a request, data only
            code = None
            buf = buf[2:]
        param &= 0x8fff    # Isolate param number and counter flag
        try:
            pcls, fn, vals = pdict[param]
        except KeyError:
            # For requests, only known parameters are accepted, partly
            # because the spec says so and partly because we have no
            # way to know how to parse unknown parameters (there is
            # nothing to tell us the data length).
            if not resp:
                raise DecodeError ("Unknown parameter {} in request".format (param))
            pcls = NiceType
            fn = "field{}".format (param)
            vals = ()
        # If it's a response, use the class index lookup to find the
        # right class.  This will be the one from the parameter
        # dictionary if it's acceptable for the parameter code in the
        # packet; otherwise, the class called for by the parameter code.
        if resp:
            pcls = pcls.findclass (code)
        return code, pcls, fn, vals, buf
    
# Subclasses of standard NICE type codes may be defined, which are used
# to specify alternate format methods.
class DUNode (DU2):
    "2 byte node number, formatted in standard area.node style."
    def format (self, tlist = None):
        area, tid = divmod (self, 1024)
        if area:
            return "{}.{}".format (area, tid)
        return "{}".format (tid)

class CMNode (CM2):
    "Node address and name"
    vlist = (DUNode, AI)
    classindexkeys = CM1.classindexkeys + CM2.classindexkeys
    
    def format (self, tlist = None):
        if len (self) == 2 and isinstance (self[1], AI):
            return "{} ({})".format (self[0].format (), self[1].format ())
        return super ().format (tlist)

    @classmethod
    def decode (cls, b, code, tlist = None):
        if code == CM1.code:
            return CM1.decode.__func__ (cls, b, code, tlist)
        return CM2.decode.__func__ (cls, b, code, tlist)
    
class CMVersion (CM3):
    "CMn for version numbers, which will be printed with . separators."
    vlist = ( DU1, DU1, DU1 )
    delim = "."

class CMProc (CM4):
    "Source/dest process descriptor"
    vlists = (None, (DU1,), (DU1, AI), None, (DU1, DU2, DU2, AI))
    formats = (None, "{}", "{} {}", None, "{} [{},{}]{}")

    @classmethod
    def checktype (cls, name, val, tlist):
        try:
            tlist2 = cls.vlists[len (val)]
            tlist = tlist2 or tlist
        except IndexError:
            pass
        return super (__class__, cls).checktype (name, val, tlist)
    
    @classmethod
    def decode (cls, b, code, tlist = None):
        count = code & 0x0f
        try:
            tlist2 = cls.vlists[count]
            tlist = tlist2 or tlist
        except IndexError:
            pass
        return super (__class__, cls).decode (b, code, tlist)
        
    def encode (self, tlist = None):
        try:
            tlist2 = self.vlists[len (self)]
            tlist = tlist2 or tlist
        except IndexError:
            pass
        return super ().encode (tlist)
        
    def format (self, tlist = None):
        fmt = self.formats[len (self)]
        if fmt:
            if len (self) != 2 or self[0]:
                return fmt.format (*self)
            return "{}".format (self[1])
        return super ().format (tlist)
    
# NICE parameter definition lists for the various kinds of counters.
# These are broken out because they get used in several places -- not
# just the read information response, but also in events.
#
# The variable names need to match those used for the internal
# counters object defined in nsp.py and routing.py -- this makes the
# "copy" method work for transferring those internal counters into
# this NICE reply object.
node_counters = (
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
)

circuit_counters = (
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
            { 1 : "NAKs sent, data field block check error",
              2 : "NAKs sent, REP response" }),
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
    ( 1242, CTR1, "Network initiated resets" ),
    # PyDECnet specific
    ( 3900, CTR2, "Seconds since last circuit up", "last_up" )
)
    
line_counters = (
    ( 0, CTR2, "Seconds since last zeroed", "time_since_zeroed" ),
    ( 1000, CTR4, "Bytes received", "bytes_recv" ),
    ( 1001, CTR4, "Bytes sent" ),
    ( 1002, CTR4, "Multicast bytes received", "mcbytes_recv" ),
    ( 1010, CTR4, "Data blocks received", "pkts_recv" ),
    ( 1011, CTR4, "Data blocks sent", "pkts_sent" ),
    ( 1012, CTR4, "Multicast blocks received", "mcpkts_recv" ),
    ( 1013, CTR4, "Blocks sent, initially deferred", "sent_def" ),
    ( 1014, CTR4, "Blocks sent, single collision", "sent_1col" ),
    ( 1015, CTR4, "Blocks sent, multiple collisions", "sent_mcol" ),
    ( 1020, CTM1, "Data errors inbound", None, 
            ( "NAKs sent, header block check error",
              # The items below are obsolete, now in circuit counters
              "NAKs sent, REP response",
              "Block too long",
              "Block check error",
              "REJ sent" )),
    # Items 1021 through 1041 are obsolete, now found in circuit counters
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
    ( 1063, CTR2, "Unrecognized frame destination", "unk_dest" ),
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
)

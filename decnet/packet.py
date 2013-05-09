#!/usr/bin/env python3

"""DECnet protocol implementation

Classes for packet layouts.
"""

import sys
import struct
import logging
import time

from .common import *

LE = "little"

# We need this ugliness because Python 3.2 has a bug in the memoryview
# class: it acts like bytes except that indexing a single element yields
# a length 1 memoryview, rather than an int.  Python 3.3 fixes this but
# to avoid requiring 3.2, we use this workaround

if sys.hexversion >= 0x03030000:
    def getbyte (buf, off = 0):
        return buf[off]
else:
    _getbyte = struct.Struct ("<B")
    def getbyte (buf, off = 0):
        return _getbyte.unpack_from (buf, off)[0]

maxint = [ (1 << (8 * i)) - 1 for i in range (9) ]

try:
    int.from_bytes
except AttributeError:
    raise ImportError ("Python 3.2 or later required")

def proc_layoutelem (cls, e):
    code, *args = e
    if isinstance (code, str):
        code = code.lower ()

    if code == "tlv":
        tlen, llen, wild, layoutdict = args
        codedict = { k : proc_layoutelem (cls, v)
                     for k, v in layoutdict.items () }
        return [ cls.encode_tlv, cls.decode_tlv,
                 ( tlen, llen, wild, codedict ) ]
    else:
        if isinstance (code, str):
            enc = getattr (cls, "encode_%s" % code)
            dec = getattr (cls, "decode_%s" % code)
        else:
            enc = getattr (cls, "encode_type")
            dec = getattr (cls, "decode_type")
            # Argument list should have one entry (the attribute name).
            # Make an argument list of attribute name and type
            if len (args) != 1:
                raise TypeError ("%s layout requires 1 argument" % code)
            args = [ args[0], code ]
        if code == "bm":
            # Find the field length in bytes
            topbit = -1
            fields = args
            for name, start, bits in fields:
                topbit = max (topbit, start + bits - 1)
            flen = (topbit + 8) // 8
            args = ( flen, [ ( name, start, bits)
                             for name, start, bits in fields if name ] )
        return [ enc, dec, args ]
        
def process_layout (cls, layout):
    """Process a layout definition and return the resulting
    encode/decode table.

    The layout is a sequence of tuples.  Each starts with a field code
    (case insensitive), followed by a description for that field.  The
    format of the description depends on the field code:

    "BM": description is a sequence of triples, which together make
    up the bit field elements of the protocol field.  Each triple 
    consists of name, start bit position, and bit count.
    The bit fields must be listed together and given in ascending order 
    of bit position.  The size of the field is taken to be the minimal 
    number of bytes needed to hold all the bit fields.

    "I", "B", "EX": description is name and length.  For I and EX,
    length means the maximum length.

    "SIGNED" is like "B" except that the value is interpreted as a
    signed rather than an unsigned integer.

    "BS" is byte string, i.e., same as "I" but with the length
    implied.  This is only used inside TLV items, where the length is
    part of the prefix rather than the value.  DECnet specs show I
    fields inside TLV structures, but in fact those are BS, not I.

    "BV" is a fixed length byte string.
    
    "TLV": description is the size of the type field, size of the length
    field, wildcard flag, and a dictionary of value codes.  The dictionary
    is keyed by the value type code, and the value is a layout tuple as
    described here.  If the wildcard flag is True, unrecognized type
    fields are accepted in decode, and turn into "fieldnnn" attributes
    containing the field value as a byte string.  If False, unrecognized
    type fields are an error.  Note that in encode, only known fields
    (those listed as keys of the fields dictionary) are encoded.

    The field code can also be the name of a class.  In that case, the
    class must have a _len attribute which gives the length of an
    encoded item of that type (this must be a constant).
    
    The code table is used by the "encode" and "decode" methods
    of the class being defined.  This generally means those methods
    as defined in the Packet base class, but it allows new encodings
    to be defined or existing ones to be overridden.
    """
    codetable = [ ]
    nomore = None
    for e in layout:
        code = e[0]
        if nomore:
            raise TypeError ("%s field must be last in layout" % nomore)
        if isinstance (code, str) and code.lower () == "tlv":
            nomore = "TLV"
        codetable.append (proc_layoutelem (cls, e))
    return codetable

def proc_slotelem (e):
    code, *args = e
    if isinstance (code, str):
        code = code.lower ()
    
    if code == "tlv":
        tlen, llen, wild, layoutdict = args
        ret = set ()
        for v in layoutdict.values ():
            ret |= proc_slotelem (v)
        return ret
    else:
        if code == "bm":
            return { name for name, start, bits in args if name }
        elif code == "res":
            return set ()
        else:
            return { args[0] }
        
def process_slots (layout):
    """Build the set of slots (attribute names) given by the supplied layout.
    """
    slots = set ()
    for e in layout:
        slots |= (proc_slotelem (e))
    return slots

class packet_encoding_meta (type):
    """Metaclass for "Packet" that will process the "_layout"
    for the packet into the necessary encoding and decoding
    tables.

    The layout is specified in class variable "_layout".
    The metaclass uses the layout definition to build an
    encode/decode table, which becomes class variable
    "_codetable".

    All fields mentioned in the layout, except those that are
    given values by class attributes, are mentioned in __slots__
    so they become valid instance attributes.
    """
    def __new__ (cls, name, bases, classdict):
        layout = classdict.get ("_layout", None)
        if layout:
            # This class defines a layout.  It's either the packet layout
            # (if there is no layout in its base classes) or additional
            # layout after the header defined by the base classes.
            # Build the set of new fields from that, which will be
            # the __slots__ class variable.
            slots = process_slots (layout)
            # Any attributes defined as class attributes will not be
            # allowed as instance attributes.
            slots -= set (classdict)
        else:
            slots = set ()
        # Add any extra slots requested by the class
        addslots = classdict.get ("_addslots", None)
        if addslots:
            slots |= set (addslots)
        classdict["__slots__"] = slots
        result = type.__new__ (cls, name, bases, classdict)
        # Look for an existing _codetable.  If we find one, that means
        # this class is derived from another Packet subclass, and we
        # will either use its layout as-is (if this class doesn't define
        # its own additional layout) or we will treat that base layout
        # as the header for any additional layout given here.
        baselayout = getattr (result, "_codetable", None)
        if layout:
            # This class defines a layout.  It's either the packet layout
            # (if there is no layout in its base classes) or additional
            # layout after the header defined by the base classes.
            # For the latter case, the header layout cannot end in a
            # TLV field, because those consume the entire packet.
            if baselayout and baselayout[-1][0] is result.encode_tlv:
                raise TypeError ("Packet header cannot end in TLV field")
            layout = process_layout (result, layout)
            if baselayout:
                layout = baselayout + layout
            result._codetable = layout
        return result
            
class Packet (metaclass = packet_encoding_meta):
    """Base class for DECnet packets.

    The packet layout is given by class variable "layout",
    which has to be set by the derived class definition.
    See the documentation for "process_layout" for details.
    """
    _addslots = { "src", "payload" }

    @classmethod
    def allslots (cls):
        """Return a set that contains the contents of the slots for
        this class and its base classes.
        """
        ret = set ()
        for c in cls.__mro__:
            s = getattr (c, "__slots__", None)
            if s:
                ret |= s 
        return ret
        
    def __init__ (self, buf = None, copy = None, **kwargs):
        """Construct a packet.  If "buf" is supplied, that buffer
        is decoded.  Otherwise, if "copy" is specified, its instance
        attributes are initialized from that object, to the extent
        that the copied-from object has the corresponding attributes.
        In either case, if other keyword arguments are supplied, they
        initialize attributes of those names.
        """
        super ().__init__ ()
        if not hasattr (self, "_codetable"):
            raise AttributeError ("Required attribute '_layout' not defined in class '%s'" % self.__class__.__name__)
        if buf:
            self.decode (buf)
        else:
            if copy:
                for attr in self.allslots ():
                    try:
                        v = getattr (copy, attr)
                    except (NameError, AttributeError):
                        continue
                    setattr (self, attr, v)
        if kwargs:
            for k, v in kwargs.items ():
                setattr (self, k, v)

    def __setattr__ (self, field, val):
        """Set an attribute.  If the attribute being set is the name
        of a class attribute, and that attribute is not None, the value
        being set must match that class attribute's value.  This enforces
        fixed field values when decoding incoming packets.
        """
        try:
            super ().__setattr__ (field, val)
        except AttributeError:
            prev = getattr (self, field, None)
            if prev is not None and prev != val:
                logging.debug ("Field %s required value mismatch, %s instead of %s",
                field, val, prev)
                raise Event (fmt_err)
                
    def encode_res (self, flen):
        """Encode a reserved field.
        """
        return bytes (flen)

    def decode_res (self, buf, flen):
        """Decode a reserved field.  Just skip it.
        """
        return buf[flen:]

    def encode_type (self, field, t):
        """Encode a given type.  Note that the type argument is not used.
        """
        val = getattr (self, field)
        return bytes (val)

    def decode_type (self, buf, field, t):
        """Decode a given type.  We use the type's attribute _len to
        know how many bytes to decode.
        """
        flen = t._len
        setattr (self, field, t (buf[:flen]))
        return buf[flen:]
    
    def encode_i (self, field, maxlen):
        """Encode "field" as an image field with max length "maxlen".
        If val is a string, it is encoded using the current default
        encoding.  If the value is too large, packet format error is
        signalled.
        """
        val = getattr (self, field)
        if isinstance (val, str):
            val = bytes (val, "latin-1", "ignore")
        vl = len (val)
        if vl > maxlen:
            logging.debug ("Value too long for %d byte field", maxlen)
            raise Event (fmt_err)
        return vl.to_bytes (1, LE) + val

    def decode_i (self, buf, field, maxlen):
        """Decode "field" from an image field with max length "maxlen".
        If the field is too large, packet format error is signalled.
        Returns the remaining buffer.
        """
        # This doesn't just pick up buf[0] because that's an int if
        # buf is bytes, but a length one bytes if buf is memoryview.
        # More precisely, it work that way in Python 3.2 and before;
        # this bug is fixed in Python 3.3.
        flen = getbyte (buf)
        if flen < 0:
            logging.debug ("Image field with negative length %d" , flen)
            raise Event (fmt_err)
        elif flen > maxlen:
            logging.debug ("Image field longer than max length %d", maxlen)
            raise Event (fmt_err)
        v = buf[1:flen + 1]
        if len (v) != flen:
            logging.debug ("Not %d bytes left for image field", flen)
            raise Event (fmt_err)
        setattr (self, field, v)
        return buf[flen + 1:]

    def encode_b (self, field, flen):
        """Encode "field" as a binary field with length "flen".
        The field value is assumed to be an unsigned integer.
        """
        return getattr (self, field).to_bytes (flen, LE)

    def decode_b (self, buf, field, flen):
        """Decode "field" from a binary field with length "flen".
        The field is decoded to a little endian unsigned integer.  Returns 
        the remaining buffer.
        """
        setattr (self, field, int.from_bytes (buf[:flen], LE, signed = True))
        return buf[flen:]

    def encode_signed (self, field, flen):
        """Encode "field" as a binary field with length "flen".
        The field value is assumed to be a signed integer.
        """
        return getattr (self, field).to_bytes (flen, LE)

    def decode_signed (self, buf, field, flen):
        """Decode "field" from a binary field with length "flen".
        The field is decoded to a little endian signed integer.  Returns 
        the remaining buffer.
        """
        setattr (self, field, int.from_bytes (buf[:flen], LE, signed = True))
        return buf[flen:]

    def encode_ctr (self, field, flen):
        """Encode "field" as a counter field with length "flen".
        The field value is assumed to be an integer.  This is the
        same as "b" except that values too large for the field
        are capped at the max.
        """
        return min (getattr (self, field), maxint[flen]).to_bytes (flen, LE)

    decode_ctr = decode_b

    def encode_deltat (self, field, flen):
        """Encode "field" as elapsed time with length "flen".  The
        field value is assumed to be the start time of the interval to
        be encoded This is the same as "ctr" except that we first convert
        the start time to a delta time.
        """
        delta = int (time.time () - getattr (self, field))
        return min (delta, maxint[flen]).to_bytes (flen, LE)

    decode_deltat = decode_b

    def encode_bm (self, flen, elements):
        """Encode a bitmap field.  "elements" is a sequence of
        triples: name, starting bit position, bit count.
        """
        field = 0
        for name, start, bits in elements:
            # For fields not defined in the object, substitute zero
            val = getattr (self, name, 0)
            if val >> bits:
                logging.debug ("Field %s value %d too large for %d bit field",
                               name, val, bits)
                raise Event (fmt_err)
            field |= val << start
        return field.to_bytes (flen, LE)

    def decode_bm (self, buf, flen, elements):
        """Decode a bitmap field.  "elements" is a sequence of
        triples: name, starting bit position, bit count.  The fields
        are decoded as integers.  Returns the remaining buffer.
        """
        field = int.from_bytes (buf[:flen], LE)
        for name, start, bits in elements:
            val = (field >> start) & ((1 << bits) - 1)
            setattr (self, name, val)
        return buf[flen:]

    def encode_ex (self, field, maxlen):
        """Encode "field" as an extensible field with max length "maxlen".
        The field value is assumed to be an integer.
        """
        val = getattr (self, field)
        retval = [ ]
        while val >> 7:
            retval.append (((val & 0x7f) | 0x80).to_bytes (1, LE))
            val >>= 7
        retval.append (val.to_bytes (1, LE))
        if len (retval) > maxlen:
            logging.debug ("Extensible field is longer than %d bytes", maxlen)
            raise Event (fmt_err)
        return b''.join (retval)
        
    def decode_ex (self, buf, field, maxlen):
        """Decode "field" as an extensible field with max length "maxlen".
        The field is decoded as an integer.  Returns the remaining buffer.
        """
        val = 0
        for i in range (maxlen):
            b = buf[i]
            val |= (b & 0x7f) << (7 * i)
            if b < 0x80:
                break
            if i == maxlen - 1:
                logging.debug ("Extensible field longer than %d", maxlen)
                raise Event (fmt_err)
        setattr (self, field, val)
        return buf[i + 1:]

    def encode_bs (self, field, flen):
        return bytes (getattr (self, field))

    def decode_bs (self, buf, field, flen):
        setattr (self, field, bytes (buf))
        return b""
    
    def encode_bv (self, field, flen):
        return bytes (getattr (self, field))
        l = len (retval)
        if l < flen:
            retval += bytes (flen - l)
        elif l > flen:
            retval = retval[:flen]
        return retval

    def decode_bv (self, buf, field, flen):
        setattr (self, field, bytes (buf[:flen]))
        return buf[flen:]
    
    def encode_tlv (self, tlen, llen, wild, codedict):
        retval = [ ]
        for k, v in codedict.items ():
            e, d, fieldargs = v
            if e is Packet.encode_bm:
                field = True
            else:
                field = getattr (self, fieldargs[0], None)
            if field:
                retval.append (k.to_bytes (tlen, LE))
                field = e (self, *fieldargs)
                retval.append (len (field).to_bytes (llen, LE))
                retval.append (field)
        return b''.join (retval)

    def decode_tlv (self, buf, tlen, llen, wild, codedict):
        """Decode the remainder of the buffer as a sequence of TLV
        (tag, length, value) fields where tlen and llen are the length
        of the tag and length fields.  Each value field is decoded
        according to the decode rules given by the codedict entry
        keyed by the tag value.
        """
        pos = 0
        blen = len (buf)
        while pos < blen:
            left = blen - pos
            if left < tlen + llen:
                logging.debug ("Incomplete TLV at end of buffer")
                raise Event (fmt_err)
            tag = int.from_bytes (buf[pos:pos + tlen], LE)
            pos += tlen + llen
            vlen = int.from_bytes (buf[pos - llen:pos], LE)
            if pos + vlen > blen:
                logging.debug ("TLV %d Value field extends beyond end of buffer",
                               tag)
                raise Event (fmt_err)
            try:
                e, d, fieldargs = codedict[tag]
            except KeyError:
                if wild:
                    e, d, fieldargs = ( Packet.encode_bs, Packet.decode_bs,
                                        ( "field%d" % tag, 255 ) )
                else:
                    logging.debug ("Unknown TLV tag %d", tag)
                    raise Event (fmt_err)
            buf2 = d (self, buf[pos:pos + vlen], *fieldargs)
            if buf2:
                logging.debug ("TLV %d Value field not fully parsed, left = %d",
                               tag, len (buf2))
                raise Event (fmt_err)
            pos += vlen
            
    def encode (self, layout = None):
        """Encode the packet according to the current attributes.  The
        resulting packet data is returned.
        
        If the "layout" argument is used, that layout table is used;
        otherwise the class layout table is used.   Also, in that
        case, if there is a "payload" attribute, that data is added
        to the end of the encoded data.
        """
        codetable = layout or self._codetable
        data = [ ]
        for e, d, args in codetable:
            try:
                data.append (e (self, *args))
            except Exception:
                logging.exception ("Error encoding %s", (e, d, args))
        if not layout:
            payload = getattr (self, "payload", None)
            if payload:
                data.append (bytes (payload))
        data = b''.join (data)
        return data

    def __bytes__ (self):
        """Convert to bytes.  We encode the data each time, since this
        doesn't happen often enough to bother with the rather hairy
        process of caching the answer.
        """
        return self.encode ()

    def __len__ (self):
        """Return the packet length, i.e., the length of the encoded
        packet data.
        """
        return len (bytes (self))

    def __bool__ (self):
        return True
    
    def __iter__ (self):
        """Return an iterator over the packet contents.
        """
        return iter (bytes (self))
    
    def decode (self, buf, layout = None):
        """Decode a packet buffer and set the packet object attributes
        from the fields that were found.

        If the "layout" argument is used, that layout table is used to
        do the decode.  Otherwise, the class layout table is used.

        If more data is present than accounted for in the layout
        definition, the remainder is returned.  This is useful for
        variable layout packets; in that case the class layout is used
        to define the header layout, and anything beyond the header
        is processed separately.

        If any layout fields have values set in the packet class, those
        values are required values and mismatches will generate an
        AttributeError exception.
        """
        codetable = layout or self._codetable
        for e, d, args in codetable:
            buf = d (self, buf, *args)
        if not layout:
            self.payload = buf
        #logging.debug ("packet parse: %s", self.__dict__)
        return buf

    def __str__ (self):
        ret = list ()
        for a in self.allslots ():
            v = getattr (self, a, None)
            if v is not None:
                ret.append ("{}={}".format (a, v))
        return "{}({})".format (self.__class__.__name__, ", ".join (ret))

    __repr__ = __str__

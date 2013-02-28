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
            # Insert the type to use as the first argument
            args.insert (0, code)
        if code == "bm":
            # Find the field length in bytes
            topbit = -1
            fields = args
            for name, start, bits in fields:
                topbit = max (topbit, start + bits - 1)
            flen = (topbit + 8) // 8
            args = ( flen, [ ( name, start, bits)
                             for name, start, bits in fields if name ] )
        elif len (args) == 1:
            args = args[0]
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
        # For the base class Packet, we do nothing special; the extra
        # work only kicks in for its derived classes.
        if name == "Packet":
            return type.__new__ (cls, name, bases, classdict)
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
            # Add any extra slots requested by the class
            addslots = classdict.get ("_addslots", None)
            if addslots:
                slots |= set (addslots)
        else:
            slots = set ()
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
        elif not baselayout:
            raise AttributeError ("Required attribute 'layout' not defined in class '%s'" % name)
        return result
            
class Packet (metaclass = packet_encoding_meta):
    """Base class for DECnet packets.

    The packet layout is given by class variable "layout",
    which has to be set by the derived class definition.
    See the documentation for "process_layout" for details.
    """
    __slots__ = { "src", "payload" }

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
        of a class attribute, the value being set must match that
        class attribute's value.  This enforces fixed field values
        when decoding incoming packets.
        """
        try:
            super ().__setattr__ (field, val)
        except AttributeError:
            prev = getattr (self, field, None)
            if prev is None:
                raise
            if prev != val:
                raise ValueError ("Field %s required value mismatch, %s instead of %s" % (field, val, prev))
                
    def encode_res (self, flen):
        """Encode a reserved field.
        """
        return bytes (flen)

    def decode_res (self, buf, flen):
        """Decode a reserved field.  Just skip it.
        """
        return buf[flen:]

    def encode_type (self, args):
        """Encode a given type.
        """
        t, field = args
        val = getattr (self, field)
        return bytes (val)

    def decode_type (self, buf, args):
        """Decode a given type.  We use the type's attribute _len to
        know how many bytes to decode.
        """
        t, field = args
        flen = t._len
        setattr (self, field, t (buf[:flen]))
        return buf[flen:]
    
    def encode_i (self, args):
        """Encode "field" as an image field with max length "maxlen".
        If val is a string, it is encoded using the current default
        encoding.  If the value is too large, OverflowError is raised.
        """
        field, maxlen = args
        val = getattr (self, field)
        if isinstance (val, str):
            val = bytes (val, "latin-1", "ignore")
        vl = len (val)
        if vl > maxlen:
            raise OverflowError ("Value too long for %d byte field" % maxlen)
        return vl.to_bytes (1, LE) + val

    def decode_i (self, buf, args):
        """Decode "field" from an image field with max length "maxlen".
        If the field is too large, OverflowError is raised.  Returns the
        remaining buffer.
        """
        field, maxlen = args
        # This doesn't just pick up buf[0] because that's an int if
        # buf is bytes, but a length one bytes if buf is memoryview.
        # More precisely, it work that way in Python 3.2 and before;
        # this bug is fixed in Python 3.3.
        flen = getbyte (buf)
        if flen < 0:
            raise ValueError ("Image field with negative length %d" % flen)
        elif flen > maxlen:
            raise OverflowError ("Image field longer than max length %d" % maxlen)
        v = buf[1:flen + 1]
        if len (v) != flen:
            raise ValueError ("Not %d bytes left for image field" % flen)
        setattr (self, field, v)
        return buf[flen + 1:]

    def encode_b (self, args):
        """Encode "field" as a binary field with length "flen".
        The field value is assumed to be an integer.
        """
        field, flen = args
        return getattr (self, field).to_bytes (flen, LE)

    def decode_b (self, buf, args):
        """Decode "field" from a binary field with length "flen".
        The field is decoded to a little endian integer.  Returns the
        remaining buffer.
        """
        field, flen = args
        setattr (self, field, int.from_bytes (buf[:flen], LE))
        return buf[flen:]

    def encode_ctr (self, args):
        """Encode "field" as a counter field with length "flen".
        The field value is assumed to be an integer.  This is the
        same as "b" except that values too large for the field
        are capped at the max.
        """
        field, flen = args
        return min (getattr (self, field), maxint[flen]).to_bytes (flen, LE)

    decode_ctr = decode_b

    def encode_deltat (self, args):
        """Encode "field" as elapsed time with length "flen".  The
        field value is assumed to be the start time of the interval to
        be encoded This is the same as "ctr" except that we first convert
        the start time to a delta time.
        """
        field, flen = args
        delta = int (time.time () - getattr (self, field))
        return min (delta, maxint[flen]).to_bytes (flen, LE)

    decode_deltat = decode_b

    def encode_bm (self, args):
        """Encode a bitmap field.  "elements" is a sequence of
        triples: name, starting bit position, bit count.
        """
        flen, elements = args
        field = 0
        for name, start, bits in elements:
            # For fields not defined in the object, substitute zero
            val = getattr (self, name, 0)
            if val >> bits:
                raise OverflowError ("Field %s value too large for %d bit field" % (name, bits))
            field |= val << start
        return field.to_bytes (flen, LE)

    def decode_bm (self, buf, args):
        """Decode a bitmap field.  "elements" is a sequence of
        triples: name, starting bit position, bit count.  The fields
        are decoded as integers.  Returns the remaining buffer.
        """
        flen, elements = args
        field = int.from_bytes (buf[:flen], LE)
        for name, start, bits in elements:
            val = (field >> start) & ((1 << bits) - 1)
            setattr (self, name, val)
        return buf[flen:]

    def encode_ex (self, args):
        """Encode "field" as an extensible field with max length "maxlen".
        The field value is assumed to be an integer.
        """
        field, maxlen = args
        val = getattr (self, field)
        retval = [ ]
        while val >> 7:
            retval.append (((val & 0x7f) | 0x80).to_bytes (1, LE))
            val >>= 7
        retval.append (val.to_bytes (1, LE))
        if len (retval) > maxlen:
            raise OverflowError ("Extensible field is longer than %d bytes" % maxlen)
        return b''.join (retval)
        
    def decode_ex (self, buf, args):
        """Decode "field" as an extensible field with max length "maxlen".
        The field is decoded as an integer.  Returns the remaining buffer.
        """
        field, maxlen = args
        val = 0
        for i in range (maxlen):
            b = buf[i]
            val |= (b & 0x7f) << (7 * i)
            if b < 0x80:
                break
            if i == maxlen - 1:
                raise OverflowError ("Extensible field longer than %d" % maxlen)
        setattr (self, field, val)
        return buf[i + 1:]

    def encode_bs (self, args):
        field, flen = args
        return bytes (getattr (self, field))

    def decode_bs (self, buf, args):
        field, flen = args
        setattr (self, field, bytes (buf))
        return b""
    
    def encode_bv (self, args):
        field, flen = args
        return bytes (getattr (self, field))
        l = len (retval)
        if l < flen:
            retval += bytes (flen - l)
        elif l > flen:
            retval = retval[:flen]
        return retval

    def decode_bv (self, buf, args):
        field, flen = args
        setattr (self, field, bytes (buf[:flen]))
        return buf[flen:]
    
    def encode_tlv (self, args):
        tlen, llen, wild, codedict = args
        retval = [ ]
        for k, v in codedict.items ():
            e, d, fieldargs = v
            if e is Packet.encode_bm:
                field = True
            elif e is Packet.encode_type:
                field = getattr (self, fieldargs[1], None)
            else:
                field = getattr (self, fieldargs[0], None)
            if field:
                retval.append (k.to_bytes (tlen, LE))
                field = e (self, fieldargs)
                retval.append (len (field).to_bytes (llen, LE))
                retval.append (field)
        return b''.join (retval)

    def decode_tlv (self, buf, args):
        """Decode the remainder of the buffer as a sequence of TLV
        (tag, length, value) fields where tlen and llen are the length
        of the tag and length fields.  Each value field is decoded
        according to the decode rules given by the codedict entry
        keyed by the tag value.
        """
        tlen, llen, wild, codedict = args
        pos = 0
        blen = len (buf)
        while pos < blen:
            left = blen - pos
            if left < tlen + llen:
                raise ValueError ("Incomplete TLV at end of buffer")
            tag = int.from_bytes (buf[pos:pos + tlen], LE)
            pos += tlen + llen
            vlen = int.from_bytes (buf[pos - llen:pos], LE)
            if pos + vlen > blen:
                raise ValueError ("TLV %d Value field extends beyond end of buffer" % tag)
            try:
                e, d, fieldargs = codedict[tag]
            except KeyError:
                if wild:
                    e, d, fieldargs = ( Packet.encode_bs, Packet.decode_bs,
                                        ( "field%d" % tag, 255 ) )
                else:
                    raise KeyError ("Unknown TLV tag %d" % tag)
            buf2 = d (self, buf[pos:pos + vlen], fieldargs)
            if buf2:
                raise ValueError ("TLV %d Value field not fully parsed, left = %d" % (tag, len (buf2)))
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
                data.append (e (self, args))
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
            buf = d (self, buf, args)
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

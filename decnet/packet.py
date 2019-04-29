#!/usr/bin/env python3

"""DECnet protocol implementation

Classes for packet layouts.
"""

import sys
import struct
import time

from .common import *
from . import events
from . import logging

LE = "little"

# Exceptions related to packet definitions
class InvalidField (DNAException):
    """Invalid field descriptor."""
    
maxint = [ (1 << (8 * i)) - 1 for i in range (9) ]

try:
    int.from_bytes
except AttributeError:
    raise ImportError ("Python 3.3 or later required")

# Checking for a bug in Python <= 3.2
if type (memoryview (b"ab")[0]) is not int:
    raise ImportError ("Python 3.3 or later required")
    
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
            try:
                enc = getattr (cls, "encode_{}".format (code))
                dec = getattr (cls, "decode_{}".format (code))
            except AttributeError:
                raise InvalidField ("Invalid type code {}".format (code)) from None
        else:
            if not hasattr (code, "decode"):
                raise InvalidField ("Field type code is class {} "
                                    "without decode method".format (code.__name__))
            enc = getattr (cls, "encode_type")
            dec = getattr (cls, "decode_type")
            # Argument list should have one entry (the attribute name).
            # Make an argument list of attribute name and type
            if len (args) != 1:
                raise InvalidField ("{} layout requires 1 argument".format (code))
            args = [ args[0], code ]
        if code == "bm":
            # Find the field length in bytes
            topbit = -1
            fields = args
            for name, start, bits, *ftype in fields:
                topbit = max (topbit, start + bits - 1)
            flen = (topbit + 8) // 8
            args = ( flen, [ ( name, start, bits, ftype[0] if ftype else None)
                             for name, start, bits, *ftype in fields if name ] )
        return [ enc, dec, args ]
        
def process_layout (cls, layout):
    """Process a layout definition and return the resulting
    encode/decode table.

    The layout is a sequence of tuples.  Each starts with a field code
    (case insensitive), followed by a description for that field.  The
    format of the description depends on the field code:

    "BM": description is a sequence of tuples, which together make
    up the bit field elements of the protocol field.  Each tuple
    consists of name, start bit position, bit count, and optionally
    the field type.  If omitted, the type is unsigned integer.
    The bit fields must be listed together and given in ascending order 
    of bit position.  The size of the field is taken to be the minimal 
    number of bytes needed to hold all the bit fields.

    "I", "A", "B", "EX": description is name and length.  For I, A,
    and EX, length means the maximum length.  "A" means the value is
    interpreted as text (str type); for the others, the value is
    type "bytes".

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
            raise InvalidField ("{} field must be last in layout".format (nomore))
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
            s, w = proc_slotelem (v)
            ret |= s
        return ret, wild
    else:
        if code == "bm":
            return { name for name, *rest in args if name }, False
        elif code == "res":
            return set (), False
        else:
            return { args[0] }, False
        
def process_slots (layout):
    """Build the set of slots (attribute names) given by the supplied layout.
    """
    slots = set ()
    for e in layout:
        newslots, wild = proc_slotelem (e)
        if newslots - slots != newslots:
            raise InvalidField ("Duplicate field in layout")
        slots |= newslots
        if wild:
            # We want to be able to add random attribute names
            slots.add ("__dict__")
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
            # created as instance attributes.
            slots -= set (classdict)
            # See if there is an attempt to redefine previous fields,
            # but ignore __dict__ in doing that check.
            tslots = slots - { "__dict__" }
            for c in bases:
                try:
                    if tslots - c.__slots__ != tslots:
                        raise InvalidField ("Layout redefines field "
                                            "from base class {}".format (c.__name__))
                except AttributeError:
                    pass
        else:
            slots = set ()
        # Add any extra slots requested by the class
        addslots = classdict.get ("_addslots", None)
        if addslots:
            addslots = set (addslots)
            slots |= addslots
        classdict["__slots__"] = slots
        result = type.__new__ (cls, name, bases, classdict)
        # Remember the set of all slots (of the inheritance hierarchy)
        # because sometimes we need to know whether a particular attribute
        # can be set in instances of this class, and a particular field
        # may be defined in a base class.
        result.__allslots__ = result.allslots () - set (classdict)
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
                raise InvalidField ("Packet header cannot end in TLV field")
            layout = process_layout (result, layout)
            if baselayout:
                layout = baselayout + layout
            result._codetable = layout
            # See if layout ends in TLV.  If so we can't have a
            # "payload" field.
            if layout and layout[-1][0] is result.encode_tlv:
                if addslots and "payload" in addslots:
                    raise InvalidField ("Packet with TLV fields can't have"
                                        " payload")
        elif bases and not baselayout:
            # No layout -- ok if this is the Packet abstract base class
            raise InvalidField ("Required attribute '_layout' "\
                                " not defined in class '{}'".format (name))
        return result
            
class ReadOnlyError (AttributeError): "Attempt to change a read-only attribute"

def encode_i_value (val, maxlen):
    if isinstance (val, str):
        val = bytes (val, "latin-1", "ignore")
    vl = len (val)
    if vl > maxlen:
        logging.debug ("Value too long for {} byte field", maxlen)
        raise FieldOverflow
    return byte (vl) + val

def decode_i_value (buf, maxlen):
    if not buf:
        logging.debug ("No data left for image field")
        raise MissingData
    flen = buf[0]
    if flen > maxlen:
        logging.debug ("Image field length {} longer than max length {}",
                       flen, maxlen)
        raise FieldOverflow (flen, maxlen)
    v = buf[1:flen + 1]
    if len (v) != flen:
        logging.debug ("Not {} bytes left for image field", flen)
        raise MissingData
    return flen, v

def decode_a_value (buf, maxlen):
    flen, v = decode_i_value (buf, maxlen)
    return flen, str (v, encoding = "latin1")

class Packet (metaclass = packet_encoding_meta):
    """Base class for DECnet packets.

    The packet layout is given by class variable "layout",
    which has to be set by the derived class definition.
    See the documentation for "process_layout" for details.
    """
    _addslots = { "src", "decoded_from" }

    # A subclass can override this to be True, in which case some
    # format errors are suppressed.  This is useful to accommodate
    # non-conforming packets seen in the wild.
    tolerant = False
    
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
        if not hasattr (self.__class__, "_codetable"):
            raise TypeError ("Can't instantiate object of "\
                             "class {}".format (self.__class__.__name__))
        super ().__init__ ()
        if buf:
            buf = self.decode (buf)
            if buf and not hasattr (self, "payload"):
                logging.debug ("Unexpected data for {} after parse: {}",
                               self.__class__.__name__, buf)
                raise ExtraData
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
        except AttributeError as a:
            prev = getattr (self, field, None)
            if prev is not None:
                if prev != val:
                    raise WrongValue ("Cannot change attribute {} " \
                                      "from {} to {}" \
                                      .format (field, prev, val)) from None
            else:
                raise
            
    def encode_res (self, flen):
        """Encode a reserved field.
        """
        return bytes (flen)

    def decode_res (self, buf, flen):
        """Decode a reserved field.  Just skip it.
        """
        if len (buf) < flen:
            logging.debug ("Not {} bytes left for reserved field", flen)
            raise MissingData
        return buf[flen:]

    def encode_type (self, field, t):
        """Encode a given type.
        """
        val = getattr (self, field, None)
        if val is None:
            return t.encode (None)
        elif not isinstance (val, t):
            val = t (val)
        try:
            return val.encode ()
        except AttributeError:
            return bytes (val)

    def decode_type (self, buf, field, t):
        """Decode a given type.  Uses the "decode" class method of the type.
        """
        v, buf = t.decode (buf)
        setattr (self, field, v)
        return buf
    
    def encode_i (self, field, maxlen):
        """Encode "field" as an image field with max length "maxlen".
        If val is a string, it is encoded using the current default
        encoding.  If the value is too large, packet format error is
        signalled.
        """
        val = getattr (self, field, b"")
        return encode_i_value (val, maxlen)

    def decode_i (self, buf, field, maxlen):
        """Decode "field" from an image field with max length "maxlen".
        If the field is too large, packet format error is signalled.
        Returns the remaining buffer.
        """
        flen, v = decode_i_value (buf, maxlen)
        setattr (self, field, v)
        return buf[flen + 1:]

    encode_a = encode_i
    def decode_a (self, buf, field, maxlen):
        """Decode "field" from an image field with max length "maxlen".
        If the field is too large, packet format error is signalled.
        The value found is converted to a Latin-1 string.
        Returns the remaining buffer.
        """
        flen, v = decode_a_value (buf, maxlen)
        setattr (self, field, v)
        return buf[flen + 1:]

    def encode_b (self, field, flen):
        """Encode "field" as a binary field with length "flen".
        The field value is assumed to be an unsigned integer.
        """
        return getattr (self, field, 0).to_bytes (flen, LE)

    def decode_b (self, buf, field, flen):
        """Decode "field" from a binary field with length "flen".
        The field is decoded to a little endian unsigned integer.  Returns 
        the remaining buffer.
        """
        if len (buf) < flen:
            logging.debug ("Not {} bytes left for integer field", flen)
            raise MissingData
        setattr (self, field, int.from_bytes (buf[:flen], LE))
        return buf[flen:]

    def encode_signed (self, field, flen):
        """Encode "field" as a binary field with length "flen".
        The field value is assumed to be a signed integer.
        """
        return getattr (self, field, 0).to_bytes (flen, LE, signed = True)

    def decode_signed (self, buf, field, flen):
        """Decode "field" from a binary field with length "flen".
        The field is decoded to a little endian signed integer.  Returns 
        the remaining buffer.
        """
        if len (buf) < flen:
            logging.debug ("Not {} bytes left for integer field", flen)
            raise MissingData
        setattr (self, field, int.from_bytes (buf[:flen], LE, signed = True))
        return buf[flen:]

    def encode_ctr (self, field, flen):
        """Encode "field" as a counter field with length "flen".
        The field value is assumed to be an integer.  This is the
        same as "b" except that values too large for the field
        are capped at the max.
        """
        return min (getattr (self, field, 0), maxint[flen]).to_bytes (flen, LE)

    decode_ctr = decode_b

    def encode_deltat (self, field, flen):
        """Encode "field" as elapsed time with length "flen".  The
        field value is assumed to be the start time of the interval to
        be encoded This is the same as "ctr" except that we first convert
        the start time to a delta time.
        """
        delta = int (time.time () - getattr (self, field, 0))
        return min (delta, maxint[flen]).to_bytes (flen, LE)

    decode_deltat = decode_b

    def encode_bm (self, flen, elements):
        """Encode a bitmap field.  "elements" is a sequence of
        tuples: name, starting bit position, bit count, field type.
        """
        field = 0
        for name, start, bits, ftype in elements:
            val = getattr (self, name, 0)
            if ftype:
                # If not integer already, convert to (little endian) integer
                val = int (val)
            if val >> bits:
                logging.debug ("Field {} value {} too large for {} bit field",
                               name, val, bits)
                raise FieldOverflow
            field |= val << start
        return field.to_bytes (flen, LE)

    def decode_bm (self, buf, flen, elements):
        """Decode a bitmap field.  "elements" is a sequence of
        tuples: name, starting bit position, bit count, field type.
        The fields are decoded according to ftype if give, otherwise
        as unsigned integers.  Returns the remaining buffer.
        """
        if len (buf) < flen:
            logging.debug ("Not {} bytes left for bit mapped field", flen)
            raise MissingData
        field = int.from_bytes (buf[:flen], LE)
        for name, start, bits, ftype in elements:
            val = (field >> start) & ((1 << bits) - 1)
            if ftype:
                val = ftype (val)
            setattr (self, name, val)
        return buf[flen:]

    def encode_ex (self, field, maxlen):
        """Encode "field" as an extensible field with max length "maxlen".
        The field value is assumed to be an unsigned integer.
        """
        val = getattr (self, field, 0)
        retval = [ ]
        while val >> 7:
            retval.append (byte ((val & 0x7f) | 0x80))
            val >>= 7
        retval.append (byte (val))
        if len (retval) > maxlen:
            logging.debug ("Extensible field is longer than {} bytes", maxlen)
            raise FieldOverflow
        return b''.join (retval)
        
    def decode_ex (self, buf, field, maxlen):
        """Decode "field" as an extensible field with max length "maxlen".
        The field is decoded as an unsigned integer.
        Returns the remaining buffer.
        """
        val = 0
        for i in range (maxlen):
            if i >= len (buf):
                logging.debug ("EX field extends beyond end of data")
                raise MissingData
            b = buf[i]
            val |= (b & 0x7f) << (7 * i)
            if b < 0x80:
                break
            if i == maxlen - 1:
                logging.debug ("Extensible field longer than {}", maxlen)
                raise FieldOverflow
        setattr (self, field, val)
        return buf[i + 1:]

    def encode_bs (self, field, flen):
        return bytes (getattr (self, field, b""))

    def decode_bs (self, buf, field, flen):
        setattr (self, field, bytes (buf))
        return b""
    
    def encode_bv (self, field, flen):
        retval = bytes (getattr (self, field, b""))
        l = len (retval)
        if l < flen:
            retval += bytes (flen - l)
        elif l > flen:
            retval = retval[:flen]
        return retval

    def decode_bv (self, buf, field, flen):
        if len (buf) < flen:
            logging.debug ("Not {} bytes left for bit string field", flen)
            raise MissingData
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
            if field is not None:
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
                if self.tolerant:
                    return b''
                logging.debug ("Incomplete TLV at end of buffer")
                raise MissingData
            tag = int.from_bytes (buf[pos:pos + tlen], LE)
            pos += tlen + llen
            vlen = int.from_bytes (buf[pos - llen:pos], LE)
            if pos + vlen > blen:
                logging.debug ("TLV {} Value field extends beyond end of buffer",
                               tag)
                raise MissingData
            try:
                e, d, fieldargs = codedict[tag]
                if d is Packet.decode_bm:
                    fieldargs = vlen, fieldargs[1]
                elif d is not Packet.decode_type:
                    fieldargs = fieldargs[0], vlen
            except KeyError:
                if wild:
                    e, d, fieldargs = ( Packet.encode_bs, Packet.decode_bs,
                                        ( "field{}".format (tag), vlen ) )
                else:
                    logging.debug ("Unknown TLV tag {}", tag)
                    raise InvalidTag from None
            buf2 = d (self, buf[pos:pos + vlen], *fieldargs)
            if buf2:
                if not self.tolerant:
                    logging.debug ("TLV {} Value field not fully parsed, left = {}",
                                   tag, len (buf2))
                    raise ExtraData
            pos += vlen
            
    def encode (self, layout = None):
        """Encode the packet according to the current attributes.  The
        resulting packet data is returned.
        
        If the "layout" argument is used, that layout table is used;
        otherwise the class layout table is used.   Also, in that
        case, if there is a "payload" attribute, that data is added
        to the end of the encoded data.

        For every field category except those defined by a type (class),
        the default value is supplied if the corresponding attribute does
        not exist in the packet object.  The default is 0 for numeric
        data and empty string for strings.  For fields defined by a type,
        the default is given by the type constructor with no arguments,
        if that constructor is permitted; otherwise, such a field cannot
        be defaulted.
        """
        codetable = layout or self._codetable
        data = [ ]
        for e, d, args in codetable:
            try:
                data.append (e (self, *args))
            except Exception:
                logging.exception ("Error encoding {}", (e, d, args))
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
        values are required values and mismatches will raise an Event
        that is a subclass of DecodeError.
        """
        self.decoded_from = buf
        codetable = layout or self._codetable
        for e, d, args in codetable:
            try:
                buf = d (self, buf, *args)
            except ReadOnlyError:
                logging.debug ("Field required value mismatch: {}", args)
                raise WrongValue from None
            except ValueError:
                logging.debug ("Invalid field value: {}", args)
                raise WrongValue from None
        if not layout:
            try:
                self.payload = buf
            except AttributeError:
                # No payload attribute for this class or its bases,
                # that's ok.  It might mean that we don't expect
                # extra data, but that's up to the caller to sort out.
                pass
        # Override this method to implement additional checks after
        # individual field parse
        self.check ()
        #logging.debug ("packet parse: {}", self.__dict__)
        return buf

    def check (self):
        """Override this method to implement additional checks after
        individual field parse.  It should raise an exception if there
        is a problem, or return if all is well.
        """
        pass
    
    def format (self, exclude = {}):
        ret = list ()
        for a in self.allslots ():
            if a in exclude:
                continue
            v = getattr (self, a, None)
            if v is not None:
                ret.append ("{}={}".format (a, v))
        return "{}({})".format (self.__class__.__name__, ", ".join (ret))

    def __str__ (self):
        return self.format ()
    
    __repr__ = __str__

    def __eq__ (self, other):
        return bytes (self) == bytes (other)

    def __ne__ (self, other):
        return bytes (self) != bytes (other)

#!/usr/bin/env python3

"""DECnet protocol implementation

Classes for packet layouts.
"""

import sys
import struct
import time
from collections import OrderedDict

from .common import *
from . import logging

SvnFileRev = "$LastChangedRevision$"

# Exceptions related to packet definitions
class InvalidField (DNAException):
    """Invalid field descriptor."""
    
class ReadOnlyError (AttributeError): "Attempt to change a read-only attribute"

try:
    int.from_bytes
except AttributeError:
    raise ImportError ("Python 3.3 or later required")

# Checking for a bug in Python <= 3.2
if type (memoryview (b"ab")[0]) is not int:
    raise ImportError ("Python 3.3 or later required")

def fieldnum (fn):
    # Return the number part of "fieldnnn" as an integer
    return int (fn[5:])

def checkrowargs (ftype, name, args):
    "Verify that args (output from makecoderow) has the proper length"
    # Note we don't handle arg = defaultvar or *args yet (not needed
    # at the moment)
    for m, extra in (ftype.encode, 0), (ftype.decode, 1):
        # Check that encode/decode is correctly defined
        if hasattr (m, "__isabstractmethod__"):
            raise TypeError ("{}.{} is abstract".format (ftype.__name__,
                                                         m.__name__))
        maxcount = m.__code__.co_argcount - extra
        if name:
            # encode signature is encode (self, arg, ...)
            maxcount -= 1
        else:
            # encode signature is encode (ftype, packet, arg, ...)
            maxcount -= 2
        mincount = maxcount
        if m.__defaults__:
            mincount -= len (m.__defaults__)
        if m.__code__.co_flags & 4:
            # *x type argument give, so no max
            maxcount = 999999
        if not mincount <= len (args) <= maxcount:
            raise TypeError ("Wrong argument count {} for {} {}, expecting {} to {}".format (len (args), ftype.__name__, name, mincount, maxcount))
    
class FieldGroup (Field):
    """Abstract base class for packet elements that turn into several
    named fields.  These include BM, TLV, and NICE items.
    """
    __slots__ = ()

    def encode (self, packet):
        # Note that for these elements, the packet encoder passes an
        # additional argument (the packet object).
        assert False, "Subclass must supply encode"

    @classmethod
    def decode (self, buf, packet):
        # Note that for these elements, the packet decoder passes an
        # additional argument (the packet object).
        assert False, "Subclass must supply decode"
    
class I (Field, bytes):
    __slots__ = ()

    def encode (self, maxlen):
        vl = len (self)
        if vl > maxlen:
            logging.debug ("Value too long for {} byte field", maxlen)
            raise FieldOverflow
        return byte (vl) + self

    @classmethod
    def decode (cls, buf, maxlen):
        if not buf:
            logging.debug ("No data left for image field")
            raise MissingData
        flen = buf[0]
        if flen > maxlen:
            logging.debug ("Image field length {} longer than max length {}",
                           flen, maxlen)
            raise FieldOverflow
        v = buf[1:flen + 1]
        if len (v) != flen:
            logging.debug ("Not {} bytes left for image field", flen)
            raise MissingData
        return cls (v), buf[flen + 1:]

    def __format__ (self, format):
        return "-".join ("{:02x}".format (i) for i in self)

class A (Field, str):
    __slots__ = ()

    def encode (self, maxlen):
        v = bytes (self, encoding = "latin1")
        vl = len (v)
        if vl > maxlen:
            logging.debug ("Value too long for {} byte field", maxlen)
            raise FieldOverflow
        return byte (vl) + v

    @classmethod
    def decode (cls, buf, maxlen):
        if not buf:
            logging.debug ("No data left for image field")
            raise MissingData
        flen = buf[0]
        if flen > maxlen:
            logging.debug ("Image field length {} longer than max length {}",
                           flen, maxlen)
            raise FieldOverflow
        v = buf[1:flen + 1]
        if len (v) != flen:
            logging.debug ("Not {} bytes left for image field", flen)
            raise MissingData
        return cls (str (v, encoding = "latin1")), buf[flen + 1:]

class RES (FieldGroup):
    """A reserved field (ignored on input, zeroes on output).  We
    pretend this is a group field because it doesn't have a name.
    """
    __slots__ = ()

    @classmethod
    def encode (cls, packet, flen, pad):
        return pad

    @classmethod
    def decode (cls, buf, packet, flen, pad):
        if len (buf) < flen:
            logging.debug ("Not {} bytes left for reserved field", flen)
            raise MissingData
        return buf[flen:]
        
    @classmethod
    def makecoderow (cls, flen):
        # We calculate the pad (encoded value) at compile time because
        # it never changes, so there is no reason to recreate that bytes
        # object for every packet.
        return cls, None, (flen, bytes (flen)), (), False

class B (Field, int):
    "An unsigned integer of fixed length"
    __slots__ = ()

    def encode (self, flen):
        return self.to_bytes (flen, LE)

    @classmethod
    def decode (cls, buf, flen):
        if len (buf) < flen:
            logging.debug ("Not {} bytes left for integer field", flen)
            raise MissingData
        return cls (int.from_bytes (buf[:flen], LE)), buf[flen:]
        
class SIGNED (Field, int):
    "A signed integer of fixed length"
    __slots__ = ()

    def encode (self, flen):
        return self.to_bytes (flen, LE, signed = True)

    @classmethod
    def decode (cls, buf, flen):
        if len (buf) < flen:
            logging.debug ("Not {} bytes left for integer field", flen)
            raise MissingData
        return cls (int.from_bytes (buf[:flen], LE, signed = True)), buf[flen:]

class CTR (B):
    "Counter: like unsigned integer but capped at the max value for the size"
    __slots__ = ()

    def encode (self, flen):
        if self <= maxint[flen]:
            return super ().encode (flen)
        return maxint[flen].to_bytes (flen, LE)

class BM (FieldGroup):
    __slots__ = ()

    @classmethod
    def encode (cls, packet, flen, elements):
        """Encode a bitmap field.  "elements" is a sequence of
        tuples: name, starting bit position, bit count.
        """
        field = 0
        for name, start, bits, etype in elements:
            val = getattr (packet, name, 0)
            # If not of the correct type already, convert to (little
            # endian) integer.
            if not isinstance (val, etype):
                if val is None:
                    val = etype ()
                else:
                    val = etype (val)
            if val >> bits:
                logging.debug ("Field {} value {} too large for {} bit field",
                               name, val, bits)
                raise FieldOverflow
            field |= val << start
        return field.to_bytes (flen, LE)

    @classmethod
    def decode (cls, buf, packet, flen, elements):
        """Decode a bitmap field.  "elements" is a sequence of
        tuples: name, starting bit position, bit count type.  The
        fields are decoded according to ftype (which is int if not
        otherwise specified in the layout).  Returns the remaining
        buffer.
        """
        if len (buf) < flen:
            logging.debug ("Not {} bytes left for bit mapped field", flen)
            raise MissingData
        obj = cls ()
        field = int.from_bytes (buf[:flen], LE)
        for name, start, bits, etype in elements:
            val = etype ((field >> start) & ((1 << bits) - 1))
            try:
                setattr (packet, name, val)
            except ReadOnlyError:
                logging.debug ("Field required value mismatch: {}", name)
                raise WrongValue from None
            except ValueError:
                logging.debug ("Invalid field value: {}", name)
                raise WrongValue from None
        return buf[flen:]

    @classmethod
    def makecoderow (cls, *args):
        elements = list ()
        names = set ()
        # Find the field length in bytes
        topbit = -1
        fields = args
        for name, start, bits, *etype in args:
            if etype:
                etype = etype[0]
            else:
                etype = int
            topbit = max (topbit, start + bits - 1)
            elements.append ((name, start, bits, etype))
            names.add (name)
        flen = (topbit + 8) // 8
        return cls, None, (flen, elements), names, False
    
class EX (Field, int):
    "Extensible field"
    __slots__ = ()

    def encode (self, maxlen):
        val = int (self)
        retval = [ ]
        while val >> 7:
            retval.append (byte ((val & 0x7f) | 0x80))
            val >>= 7
        retval.append (byte (val))
        if len (retval) > maxlen:
            logging.debug ("Extensible field is longer than {} bytes", maxlen)
            raise FieldOverflow
        return b''.join (retval)

    @classmethod
    def decode (cls, buf, maxlen):
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
        return cls (val), buf[i + 1:]
            
class I_tlv (I):
    """A byte string inside a TLV item (shown as "I" in the specs)"""
    __slots__ = ()

    def encode (self, flen):
        return self

    @classmethod
    def decode (cls, buf, flen):
        return cls (buf), b""

class BV (I):
    "A fixed length byte string"
    __slots__ = ()

    def encode (self, flen):
        retval = makebytes (self)
        l = len (retval)
        if l < flen:
            retval += bytes (flen - l)
        elif l > flen:
            logging.debug ("Value too long for {} byte field", flen)
            raise FieldOverflow
        return retval
        
    @classmethod
    def decode (cls, buf, flen):
        if len (buf) < flen:
            logging.debug ("Not {} bytes left for bit string field", flen)
            raise MissingData
        return cls (buf[:flen]), buf[flen:]

class PAYLOAD (Field):
    "The remainder of the buffer"
    lastfield = True
    __slots__ = ("buf",)
    
    # Ideally PAYLOAD would be a subclass of memoryview, but subclassing
    # memoryview isn't allows at the moment so fake it.
    def __init__ (self, buf):
        buf = makebytes (buf)
        self.buf = buf

    def __bytes__ (self):
        return self.buf

    def encode (self):
        return self.buf
    
    @classmethod
    def decode (cls, buf):
        # We return the bufer itself, because often it's a memoryview
        # and we don't want to convert that.  If it has to be encoded
        # later on, the "checktype" method will take care of making it a
        # PAYLOAD object at that point.
        return buf, b""

# This is how we write an entry for payload in a layout list.  It
# supplies the type and the standard field name "payload".
Payload = (PAYLOAD, "payload")

class LIST (Field, list):
    "A list of items of a specified type"
    __slots__ = ()

    def encode (self, etype, count = None, *eargs):
        # Count is unused but present to match the decode signature
        return b"".join ((etype.checktype ("list", e)).encode (*eargs)
                         for e in self)

    @classmethod
    def decode (cls, buf, etype, count = None, *eargs):
        ret = cls ()
        if count is None:
            while buf:
                e, buf = etype.decode (buf, *eargs)
                ret.append (e)
        else:
            for i in range (count):
                e, buf = etype.decode (buf, *eargs)
                ret.append (e)
        return ret, buf
    
class TLV (FieldGroup):
    __slots__ = ()
    lastfield = True

    @classmethod
    def encode (cls, packet, tlen, llen, wild, codedict):
        retval = [ ]
        for k, v in codedict.items ():
            ftype, fname, fargs = v
            if fname:
                # Simple field
                v = getattr (packet, fname, None)
                if v is not None:
                    v = ftype.checktype (fname, v)
                    v = v.encode (*fargs)
            else:
                v = ftype.encode (packet, *fargs)
            if v is not None:
                retval.append (k.to_bytes (tlen, LE))
                retval.append (len (v).to_bytes (llen, LE))
                retval.append (v)
        return b''.join (retval)

    @classmethod
    def decode (cls, buf, packet, tlen, llen, wild, codedict):
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
                if packet.tolerant:
                    return b''
                logging.debug ("Incomplete TLV at end of buffer")
                raise MissingData
            tag = int.from_bytes (buf[pos:pos + tlen], LE)
            pos += tlen + llen
            vlen = int.from_bytes (buf[pos - llen:pos], LE)
            if pos + vlen > blen:
                logging.debug ("TLV {} Value field extends beyond end of buffer", tag)
                raise MissingData
            try:
                ftype, fname, fargs = codedict[tag]
            except KeyError:
                if wild:
                    ftype = I_tlv
                    fname = "field{}".format (tag)
                    packet._xfields = True
                    fargs = (llen,)
                else:
                    logging.debug ("Unknown TLV tag {}", tag)
                    raise InvalidTag from None
            if fname:
                # Simple field
                v, buf2 = ftype.decode (buf[pos:pos + vlen], *fargs)
                try:
                    setattr (packet, fname, v)
                except ReadOnlyError:
                    logging.debug ("Field required value mismatch: {}", fname)
                    raise WrongValue from None
                except ValueError:
                    logging.debug ("Invalid field value: {}", fname)
                    raise WrongValue from None
            else:
                buf2 = ftype.decode (buf[pos:pos + vlen], packet, *fargs)
            if buf2:
                if not packet.tolerant:
                    logging.debug ("TLV {} Value field not fully parsed, left = {}",
                                   tag, len (buf2))
                    raise ExtraData
            pos += vlen
        return None
    
    @classmethod
    def makecoderow (cls, *args):
        names = set ()
        tlen, llen, wild, *layout = args
        codedict = dict ()
        for k, ftype, *fargs in layout:
            if ftype is I:
                ftype = I_tlv
            if not issubclass (ftype, Field):
                raise InvalidField ("Invalid field type {}".format (ftype.__name__))
            ftype, fname, fargs, fnames, x  = ftype.makecoderow (*fargs)
            checkrowargs (ftype, fname, fargs)
            dups = names & fnames
            if dups:
                dups = ", ".join (n for n in dups)
                raise InvalidField ("Duplicate fields {} in layout".format (n))
            if ftype.lastfield:
                raise TypeError ("Invalid type {} inside TLV".format (ftype))
            names.update (fnames)
            codedict[k] = (ftype, fname, fargs)
        return cls, None, (tlen, llen, wild, codedict), names, wild
    
class indexer (type):
    """Metaclass that builds an index of the classes it creates, for use
    by packet code dependent class lookup.

    An indexed class is derived from a base class that has attribute
    "classindexkey".  It may be a class method, or a string.  If a class
    method, it is called with the new class as its argument to get the
    class index.  If a string, it will be used as the name of an
    attribute of the new class in which to find the index.  If the new
    class does not have that attribute but one of its base classes does,
    that value is used, but only if the index is not already in the
    index dictionary.  If successful and the result is not None, the
    class is then entered into the dictionary given by class attribute
    "classindex".

    Note that the base class (where "classindexkey" is defined) is not
    itself entered in its index.  But if it is a subclass of an earlier
    indexed class, it is entered there.  This allows the creation of
    multiple levels of indexing, where the first level finds a new class
    which in turn can be used to find a class in the second level.

    The Packet class can use this index mechanism to create different
    related packet formats that have a common header, and are recognized
    by the value of certain fields.  The Packet.decode method will
    automatically identify the correct class; see below for the
    details.
    """
    def __new__ (cls, name, bases, classdict):
        result = type.__new__ (cls, name, bases, classdict)
        try:
            # Look up attribute classindexkey in the base classes of the
            # new class.
            key = super (result, result).classindexkey
        except AttributeError:
            # Plain class, we're done.
            return result
        # Found it, but is it None to say "not actually indexed"?
        if not key:
            return result
        # Indexed class, find the index dictionary
        classindex = super (result, result).classindex
        if callable (key):
            idx = key ()
        else:
            # Attribute name.  Accept it (enter this class) if it
            # has a value for that name.  If not, use the value in
            # its base classes, if any, but only if there isn't
            # already an entry for that key.
            #
            # The result of this rule is that you can subclass
            # indexed classes and those subclasses will not replace
            # the base as the class index entries.  But you can form
            # indexed classes by inheriting from a root class and a
            # second base class that provides the key value; see
            # nice_coding.EventEntityBase and its subclasses for an
            # example.
            idx = classdict.get (key, None)
            if idx is None:
                idx2 = getattr (result, key, None)
                if idx2 not in classindex:
                    idx = idx2
        if idx is not None:
            classindex[idx] = result
        return result

class Indexed (metaclass = indexer):
    __slots__ = ()
    classindexkey = None
    
    @classmethod
    def defaultclass (cls, idx):
        """Return a default class if the class index doesn't list the
        supplied index value.  This method may return a particular
        default class, or it may generate a new class, or (as this
        method does) return None to indicate there isn't a class.
        """
        return None

    @classmethod
    def findclass (cls, idx):
        """Return the class whose index value matches the supplied one.

        If the supplied class has an index value and that matches what's
        requested, return this class as the preferred answer.  Otherwise
        return the class with matching index, if there is one.  If not,
        return what the defaultclass method returns for this index.
        """
        key = cls.classindexkey
        if callable (key):
            clsidx = key ()
        else:
            clsidx = getattr (cls, key, None)
        if clsidx == idx:
            return cls
        return cls.classindex.get (idx, None) or cls.defaultclass (idx)

class packet_encoding_meta (indexer):
    """Metaclass for "Packet" that will process the "_layout"
    for the packet into the necessary encoding and decoding
    tables.

    The layout is specified in class variable "_layout".
    The metaclass uses the layout definition to build an
    encode/decode table, which becomes class variable
    "_codetable".

    All fields mentioned in the layout, except those that are given
    values by class attributes, are mentioned in __slots__ so they
    become valid instance attributes.  However, if a TLV field group
    marked as "wild", or a NICE field group, is present in the layout,
    then generated field names may appear when decoding a packet with
    unknown elements, and in that case the __slots__ attribute is
    omitted from the class so any attribute name will be allowed.
    """
    def __new__ (cls, name, bases, classdict):
        packetbase = None
        for b in bases:
            # By the rules for __slots__, we allow just one base class
            # that defines a layout
            if isinstance (b, cls):
                assert packetbase is None, "Multiple Packet base classes"
                packetbase = b
        if packetbase is None:
            # Not a subclass of Packet, we're done
            return indexer.__new__ (cls, name, bases, classdict)
        allslots = set (packetbase._allslots)
        codetable = list (packetbase._codetable)
        # Remember if we have a field that must come last
        last = codetable and codetable[-1][0].lastfield
        if hasattr (packetbase, "__slots__"):
            # Base packet class has slots, we'll have them also unless
            # this layout is wild.
            slots = set ()
        else:
            # Base packet class has no slots, we don't either.
            slots = None
        layout = classdict.get ("_layout", ())
        classnames = frozenset (classdict)
        for ftype, fname, *args in layout:
            # Process the rows of the layout table
            if last:
                # Something after a "last" field
                raise InvalidField ("Extra field {} {}".format (ftype.__name__, fname))
            if not issubclass (ftype, Field):
                raise InvalidField ("Invalid field type {}".format (ftype.__name__))
            if fname:
                # Simple field.
                if fname in allslots:
                    raise InvalidField ("Duplicate field {} in layout".format (fname))
                if fname in classnames:
                    # Fixed value.  Make sure the class attribute has
                    # the correct type.  This isn't really required
                    # (since encode will force the correct type) but it
                    # avoids doing that fixup at runtime.
                    classdict[fname] = ftype.checktype (fname, classdict[fname])
            ftype, fname, args, newslots, wild = ftype.makecoderow (fname, *args)
            checkrowargs (ftype, fname, args)
            last = ftype.lastfield
            codetable.append ((ftype, fname, args))
            # Any attributes defined as class attributes will not be
            # created as instance attributes.
            newslots = set (newslots)
            newslots -= classnames
            allslots |= newslots
            slots |= newslots
            if wild:
                slots.add ("__dict__")
        # Must end up with some layout
        addslots = classdict.get ("_addslots", None)
        if not codetable and addslots is None:
            raise InvalidField ("Required attribute '_layout' "\
                                " not defined in class '{}'".format (name))
        # Add any extra slots requested by the class, then set __slots__
        if addslots:
            slots.update (addslots)
        classdict["__slots__"] = tuple (slots)
        classdict["_codetable"] = tuple (codetable)
        classdict["_allslots"] = tuple (allslots)
        return indexer.__new__ (cls, name, bases, classdict)
            
class Packet (Field, Indexed, metaclass = packet_encoding_meta):
    """Base class for DECnet packets.

    The packet layout is given by class variable "layout",
    which has to be set by the derived class definition.
    See below for detailed documentation.

    A packet object is essentially a struct, with elements of specified
    type in a specified order.  Usually it is used by itself, but it can
    also be used as an element in a (larger) packet object.  This is
    used in some places to handle common parts of a packet.

    The _layout class attribute is a sequence of tuples.  Each starts
    with the class name for this field (a subclass of Field), followed
    by a description for that field.  The format of the description
    depends on the field code:

    BM: description is a sequence of tuples, which together make up the
    bit field elements of the protocol field.  Each tuple consists of
    name, start bit position, bit count, and optionally the field type.
    If omitted, the type is unsigned integer.  The bit fields must be
    listed together and given in ascending order of bit position.  The
    size of the field is taken to be the minimal number of bytes needed
    to hold all the bit fields.

    I, A, B, EX: description is name and length.  For I, A, and EX,
    length means the maximum length.  A means the value is interpreted
    as text (str type); for the others, the value is type "bytes".

    SIGNED is like B except that the value is interpreted as a signed
    rather than an unsigned integer. 

    CTR is like B except that when encoding a value too large for the
    specified field size, the maximum value (all ones of that length) is
    supplied.  This matches the behavior of counters which "saturate" at
    the max value.

    BV is a fixed length byte string. Description is field name and
    length.
    
    RES is a reserved field.  Description is the field length.  Reserved
    fields are ignored on receipt and sent as bytes of zero.

    TLV: description is the size of the type field, size of the length
    field, wildcard flag, followed by a sequence of value codes.  Each
    value code consists of the value type code for that value, the value
    type, and value description as for any other Packet field.  If the
    wildcard flag is True, unrecognized type fields are accepted in
    decode, and turn into "fieldnnn" attributes containing the field
    value as a byte string.  If False, unrecognized type fields are an
    error.  

    PAYLOAD is the rest of the packet.  By convention it is written as
    the layout item "Payload" which is a shorthand for the tuple
    (PAYLOAD, "payload"), i.e., the rest of the packet deliverd to the 
    field named "payload".

    The code table is used by the "encode" and "decode" methods of the
    class being defined.  This generally means those methods as defined
    in the Packet base class.  The way a given field is encoded is
    defined by the encode and decode methods of the field class, which
    makes it easy to add new types or specialized encodings for standard
    types.
    """
    __slots__ = _allslots = ( "src", "decoded_from" )
    _codetable = ()
    _xfields = False
    
    # A subclass can override this to be True, in which case some
    # format errors are suppressed.  This is useful to accommodate
    # non-conforming packets seen in the wild.
    tolerant = False

    def __new__ (cls, buf = None, *args, **kwargs):
        """Create a Packet object.
        """
        if cls == __class__:
            # Instantiating this class (the base class), reject
            raise TypeError ("Can't instantiate object of "\
                             "class {}".format (cls.__name__))
        if buf:
            ret, buf = cls.decode (buf)
            if buf:
                logging.debug ("Unexpected data for {} after parse: {}",
                               cls.__name__, buf)
                raise ExtraData
            return ret
        return super (__class__, cls).__new__ (cls)
    
    def __init__ (self, buf = None, copy = None, **kwargs):
        """Initialize a Packet object.

        If "buf" is supplied, that buffer is decoded.  Otherwise, if
        "copy" is specified, its instance attributes are initialized
        from that object, to the extent that the copied-from object has
        the corresponding attributes.  In either case, if other keyword
        arguments are supplied, they initialize attributes of those
        names.
        """
        super ().__init__ ()
        if buf:
            pass    # handled in __new__ method
        elif copy:
            for attr in self._allslots:
                v = getattr (copy, attr, None)
                if v is not None:
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

    def encode (self):
        """Encode the packet according to the current attributes.  The
        resulting packet data is returned.
        """
        data = [ ]
        for ftype, fname, args in self._codetable:
            try:
                if fname:
                    # Simple field, get its value
                    val = getattr (self, fname, None)
                    # Check type and/or supply default
                    val = ftype.checktype (fname, val)
                    if val is not None:
                        data.append (val.encode (*args))
                else:
                    # Composite like TLV
                    data.append (ftype.encode (self, *args))
            except Exception:
                logging.exception ("Error encoding {} {}",
                                   ftype.__name__, fname)
                raise
        return b''.join (data)

    @classmethod
    def decode (cls, buf, *decodeargs):
        """Decode a packet buffer and return a pair of the resulting
        Packet instance and the remaining buffer.

        If more data is present than accounted for in the layout
        definition, the remainder is returned.  This is useful for
        variable layout packets; in that case the class layout is used
        to define the header layout, and anything beyond the header
        is processed separately.

        If any layout fields have values set in the packet class, those
        values are required values and mismatches will raise an
        Exception that is a subclass of DecodeError.
        """
        ret = cls ()
        buf = makebytes (buf)
        # Save the buffer in case we want to redo the decode for a
        # indexed subclass.
        buf2 = buf
        # Start filling in the object data as instructed by the code
        # table.
        ret.decoded_from = buf
        for ftype, fname, args in ret._codetable:
            if fname:
                val, buf = ftype.decode (buf, *args)
                try:
                    setattr (ret, fname, val)
                except ReadOnlyError:
                    logging.debug ("Field required value mismatch: {}", fname)
                    raise WrongValue from None
                except ValueError:
                    logging.debug ("Invalid field value: {}", fname)
                    raise WrongValue from None
            else:
                buf = ftype.decode (buf, ret, *args)
        while True:
            ret.check ()
            # See if this is an indexed class
            key = ret.classindexkey
            if not key:
                break
            if callable (key):
                idx = ret.instanceindexkey ()
            else:
                idx = getattr (ret, key, None)
            if idx is None:
                break
            cls2 = ret.findclass (idx)
            if cls2 and not isinstance (ret, cls2):
                # We want a different class; create an instance of
                # that one and redo the decode with it.
                ret, buf = cls2.decode (buf2, *decodeargs)
            else:
                break
        return ret, buf
    
    def __bytes__ (self):
        """Convert to bytes.  We encode the data each time, since this
        doesn't happen often enough to bother with the rather hairy
        process of caching the answer.
        """
        return self.encode ()

    def __len__ (self):
        """Return the packet length, i.e., the length of the encoded
        packet data.  Note that this builds the encoding, so this is not
        all that efficient and should be used sparingly.
        """
        return len (bytes (self))

    def __bool__ (self):
        return True
    
    def __iter__ (self):
        """Return an iterator over the packet contents.
        """
        return iter (bytes (self))

    def check (self):
        """Override this method to implement additional checks after
        individual field parse.  It should raise an exception if there
        is a problem, or return if all is well.
        """
        pass

    def format (self, exclude = { "decoded_from" }):
        # By default we omit the "decoded_from" field because that
        # rarely contains anything useful and can make the string
        # absurdly large.
        ret = list ()
        for a in self._allslots:
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

    def xfields (self, sortlist = False):
        """Return a list of the "fieldnnn" attributes of this object,
        sorted in numerical order if requested.
        """
        if not self._xfields:
            return [ ]
        try:
            ret = [ n for n in self.__dict__ if n.startswith ("field") ]
        except AttributeError:
            return [ ]
        if sortlist and ret:
            ret.sort (key = fieldnum)
        return ret

    @staticmethod
    def fieldlabel (fn, desc = None):
        """Convert a field name to a user-friendly label string.
        """
        if desc:
            return desc
        if fn.startswith ("field"):
            return "Parameter #{}".format (fn[5:])
        fn = fn.replace ("_", " ")
        fn = fn[0].upper () + fn[1:]
        return fn


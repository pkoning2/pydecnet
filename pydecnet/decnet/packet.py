#!/usr/bin/env python3

"""DECnet protocol implementation

Classes for packet layouts.
"""

import sys
import struct
import time

from .common import *
from . import logging

SvnFileRev = "$LastChangedRevision$"

# Exceptions related to packet definitions
class InvalidField (DNAException):
    """Invalid field descriptor."""

# Exception to add detail to decode problems
class AtField (DecodeError):
    """Error decoding field '{}'"""
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
    # at the moment).
    #
    # But skip the check if the supplied field is indexed, because then
    # it typically is the root of an indexed class tree and that root
    # may well be abstract, or not have a matching encode/decode.
    if hasattr (ftype, "classindex"):
        return
    for m, extra in (ftype.encode, 0), (ftype.decode, 1):
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
    
class ROField:
    "Descriptor class for read-only packet fields"
    def __init__ (self, name, val):
        self.name = name
        self.val = val

    def __get__ (self, instance, owner):
        return self.val

    def __set__ (self, instance, value):
        if value == self.val:
            return
        raise WrongValue ("Can't change '{}' from {} to {}".format (self.name, self.val, value))

    def __delete__ (self, instance):
        raise TypeError ("Can't delete attribute '{}'".format (self.name))

class ROAnyField (ROField):
    "Descriptor class for read-only classindexkey fields"
    # We simply nop out the __set__ method rather than doing more
    # complicated checking such as checking for equality under mask,
    # or set membership.  The reason is that the classindexkey is used
    # to look up the class in the classindex, so by the time we get to
    # decoding (which is where assignment to attributes is done) we
    # know the value is correct.
    def __set__ (self, instance, value):
        pass
        
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
        require (buf, 1)
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
        require (buf, 1)
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
        require (buf, flen)
        return buf[flen:]
        
    @classmethod
    def length (cls, flen, pad):
        return flen
    
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
        require (buf, flen)
        return cls (int.from_bytes (buf[:flen], LE)), buf[flen:]
        
    @classmethod
    def length (cls, flen):
        return flen
    
    @classmethod
    def makegetindex (cls, name, off, fname, flen):
        # If "name" is not the name of this field, return the field
        # length and None.  If it is, return 0 and a function that
        # will return the field given the buffer, as an int.
        if name != fname:
            return flen, None
        off2 = off + flen
        if flen == 1:
            def instanceindexkey (buf):
                require (buf, off2)
                return buf[off]
        else:
            def instanceindexkey (buf):
                require (buf, off2)
                return int.from_bytes (buf[off:off2], LE)
        # Give the newly created function a doc string.  Why?  Because
        # we can...
        instanceindexkey.__doc__ = "Get key value of {}, {} byte unsigned int at offset {}".format (name, flen, off)
        return 0, instanceindexkey
    
class SIGNED (Field, int):
    "A signed integer of fixed length"
    __slots__ = ()

    def encode (self, flen):
        return self.to_bytes (flen, LE, signed = True)

    @classmethod
    def decode (cls, buf, flen):
        require (buf, flen)
        return cls (int.from_bytes (buf[:flen], LE, signed = True)), buf[flen:]

    @classmethod
    def length (cls, flen):
        return flen
    
    @classmethod
    def makegetindex (cls, name, off, fname, flen):
        # If "name" is not the name of this field, return the field
        # length and None.  If it is, return 0 and a function that
        # will return the field given the buffer, as an int.
        if name != fname:
            return flen, None
        off2 = off + flen
        def instanceindexkey (buf):
            require (buf, off2)
            return int.from_bytes (buf[off:off2], LE, signed = True)
        instanceindexkey.__doc__ = "Get key value of {}, {} byte signed int at offset {}".format (name, flen, off)
        return 0, instanceindexkey
    
class CTR (B):
    "Counter: like unsigned integer but capped at the max value for the size"
    __slots__ = ()

    def encode (self, flen):
        if self <= maxint[flen]:
            return super ().encode (flen)
        return maxint[flen].to_bytes (flen, LE)

class BM (FieldGroup):
    __slots__ = ()

    # The next two methods can be overridden in a subclass to
    # encode/decode the combined value of all the fields in a
    # different way.
    @classmethod
    def valtobytes (cls, val, flen):
        return val.to_bytes (flen, LE)

    @classmethod
    def bytestoval (cls, buf, flen):
        require (buf, flen)
        return int.from_bytes (buf[:flen], LE), buf[flen:]
    
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
        return cls.valtobytes (field, flen)

    @classmethod
    def decode (cls, buf, packet, flen, elements):
        """Decode a bitmap field.  "elements" is a sequence of
        tuples: name, starting bit position, bit count type.  The
        fields are decoded according to ftype (which is int if not
        otherwise specified in the layout).  Returns the remaining
        buffer.
        """
        obj = cls ()
        field, buf = cls.bytestoval (buf, flen)
        for name, start, bits, etype in elements:
            val = etype ((field >> start) & ((1 << bits) - 1))
            setattr (packet, name, val)
        return buf

    @classmethod
    def length (cls, flen, elements):
        return flen

    @classmethod
    def makegetindex (cls, name, off, fname, flen, elements):
        # If "name" is not a field name listed in the elements of this
        # BM, return the BM field length and None.  If it is, return 0
        # and a function that will return that field given the buffer,
        # as an int (not the class given in the BM field row).
        for n, start, bits, etype in elements:
            if n == name:
                break
        else:
            return flen, None
        mask = (1 << bits) - 1
        off2 = off + flen
        def instanceindexkey (buf):
            require (buf, off2)
            field = int.from_bytes (buf[off:off2], LE)
            return (field >> start) & mask
        instanceindexkey.__doc__ = "Get key value of {}, int bitfield at offset {} bits {}..{}".format (name, off, start, start + bits - 1)
        return 0, instanceindexkey
    
    @classmethod
    def makecoderow (cls, *args):
        elements = list ()
        names = set ()
        namelist = list ()
        # Find the field length in bytes
        topbit = -1
        for name, start, bits, *etype in args:
            if bits < 1:
                raise TypeError ("Invalid bit count {} for {}".format (bits, name))
            if name in names:
                raise TypeError ("Duplicate name {}".format (name))
            if etype:
                etype = etype[0]
            else:
                etype = int
            topbit = max (topbit, start + bits - 1)
            elements.append ((name, start, bits, etype))
            names.add (name)
            namelist.append (name)
        flen = (topbit + 8) // 8
        return cls, None, (flen, elements), namelist, False
    
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
        require (buf, flen)
        return cls (buf[:flen]), buf[flen:]

    @classmethod
    def length (cls, flen):
        return flen
    
class PAYLOAD (Field):
    "The remainder of the buffer"
    lastfield = True
    __slots__ = ("buf",)
    
    # Ideally PAYLOAD would be a subclass of memoryview, but subclassing
    # memoryview isn't allows at the moment so fake it.
    def __init__ (self, buf = b""):
        buf = makebytes (buf)
        self.buf = buf

    def __bytes__ (self):
        return self.buf

    def encode (self):
        return getattr (self, "buf", b"")
    
    @classmethod
    def decode (cls, buf):
        # We return the buffer itself, because often it's a memoryview
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
                    fargs = (llen,)
                else:
                    logging.debug ("Unknown TLV tag {}", tag)
                    raise InvalidTag from None
            if fname:
                # Simple field
                v, buf2 = ftype.decode (buf[pos:pos + vlen], *fargs)
                setattr (packet, fname, v)
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
        namelist = list ()
        tlen, llen, wild, *layout = args
        codedict = dict ()
        for k, ftype, *fargs in layout:
            if ftype is I:
                ftype = I_tlv
            if not issubclass (ftype, Field):
                raise InvalidField ("Invalid field type {}".format (ftype.__name__))
            ftype, fname, fargs, fnamelist, x  = ftype.makecoderow (*fargs)
            checkrowargs (ftype, fname, fargs)
            namelist.extend (fnamelist)
            fnames = set (fnamelist)
            dups = names & fnames
            if dups:
                dups = ", ".join (n for n in dups)
                raise InvalidField ("Duplicate fields {} in layout".format (n))
            if ftype.lastfield:
                raise TypeError ("Invalid type {} inside TLV".format (ftype))
            names.update (fnames)
            codedict[k] = (ftype, fname, fargs)
        return cls, None, (tlen, llen, wild, codedict), namelist, wild
    
class indexer (type):
    """Metaclass that builds an index of the classes it creates, for use

    by packet code dependent class lookup.

    An indexed class is derived from a base class that has attribute
    "classindexkey"which must be a string.  It will be used as the name
    of an attribute of the new class in which to find the index.  If the
    new class does not have that attribute but one of its base classes
    does, that value is used, but only if the index is not already in
    the index dictionary.  If successful and the result is not None, the
    class is then entered into the dictionary given by class attribute
    "classindex".

    Note that the base class (where "classindexkey" is defined) is not
    itself entered in its index.  But if it is a subclass of an earlier
    indexed class, it is entered there.  This allows the creation of
    multiple levels of indexing, where the first level finds a new class
    which in turn can be used to find a class in the second level.

    The IndexedPacket class uses this index mechanism to create
    different related packet formats that have a common header, and are
    recognized by the value of certain fields.  The IndexedPacket.decode
    method will automatically identify the correct class; see below for
    the details.  Similarly, IndexedField can be used as a base class
    for fields identified by some sort of field code; an example is NICE
    packets.
    """
    def __new__ (cls, name, bases, classdict):
        # Is this the root of a tree of indexed classes?
        key = classdict.get ("classindexkey", None)
        if key is not None:
            # It is, so we also need to have a classindex attribute
            index = classdict.get ("classindex", None)
            if index is None:
               raise TypeError ("classindexkey but no classindex")
            if not isinstance (index, (dict, list)):
               raise TypeError ("classindex must be dict or list")
        # Create the new class.  Further work will be done using that
        # class (rather than operating on the classdict and base
        # classes directly)
        result = type.__new__ (cls, name, bases, classdict)
        try:
            # Look up attribute classindexkey in the base classes of the
            # new class.
            key = super (result, result).classindexkey
        except AttributeError:
            # Plain class, we're done.
            return result
        # Indexed class, find the index dictionary
        classindex = super (result, result).classindex
        # If "classindexkeys" is an attribute of this class (not its
        # bases), that is the set of index values for this class.  If
        # not, find the index value through the "classindexkey"
        # attribute of the base class, and make class attribute
        # "classindexkeys" a one-member tuple containing that value,
        # or a set of values if a classindexmask is specified.
        classindexkeys = classdict.get ("classindexkeys", None)
        if classindexkeys is None:
            # Not an explicitly listed iterable of key values for this
            # class.  See if the attribute named by the index root
            # class's "classindexkey" is an attribute of this class.
            # If yes, get its value.
            idx = classdict.get (key, None)
            if idx is not None:
                # It might be a descriptor, so get the value via
                # attribute access.
                idx = getattr (result, key, None)
            if idx is None:
                # This class is not indexed
                return result
            # If there is a mask defined, apply that to get the entire
            # set of values
            mask = result.classindexmask
            if mask:
                if isinstance (classindex, list):
                    limit = len (classindex)
                else:
                    limit = result.classindexlimit
                i2 = idx & mask
                nmask = ~mask
                classindexkeys = { i2 | (i & nmask) for i in range (limit) }
            else:
                classindexkeys = ( idx, )
        # Enter this class into the index for each of its key values.
        result.classindexkeys = classindexkeys
        for i in classindexkeys:
            classindex[i] = result
        return result

class Indexed (metaclass = indexer):
    __slots__ = ()
    classindex = None
    classindexkey = None
    classindexkeys = None
    
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
        if "classindex" not in cls.__dict__ and idx in cls.classindexkeys:
            return cls
        try:
            ret = cls.classindex[idx]
        except IndexError:
            raise DecodeError ("Index {} out of range".format (idx)) from None
        except KeyError:
            ret = None
        return ret or cls.defaultclass (idx)

    @classmethod
    def findclassb (cls, buf):
        """Return the class using index lookup with the supplied buffer.

        Unlike findclass, this handles nested index lookup, iterating by
        fetching the next index value and from that the next class,
        until the process converges on the final class.
        """
        # See if the supplied class is not an indexed class root, and it
        # is a valid class for this index value as indicated by its
        # classindexkeys set.  If yes, we'll use that class.  The check
        # for index root is because the root is not itself indexed in
        # its own index, but it may be indexed in a superclass -- in
        # which case its classindexkeys set indicates the index values
        # valid for it in that tree.
        #
        # The purpose of this check is to allow the caller to invoke
        # class methods (such as decode) on a specific class that can
        # handle the index value but isn't the class normally used for
        # that.  A typical scenario is that the class is a subclass of
        # the class listed in the index, perhaps one with a special text
        # representation.  NICE encoding has some examples where this is
        # used.
        idx = cls.instanceindexkey
        if "classindex" not in cls.__dict__ and idx (buf) in cls.classindexkeys:
            return cls
        previdx = None
        cls2 = cls
        # The class lookup may yield a class that is itself the root of
        # an indexed class tree, for cases where several fields control
        # a hierarchical decode.  To deal with that we loop through
        # index value and class lookup until we find something that
        # isn't a root.
        while idx is not previdx:
            idxval = idx (buf)
            try:
                cls3 = cls2.classindex[idxval]
            except IndexError:
                raise DecodeError ("Index {} out of range".format (idxval)) from None
            except KeyError:
                cls3 = None
            cls3 = cls3 or cls2.defaultclass (idxval)
            if not cls3:
                raise DecodeError ("No class found in {} for index {}".format (cls2.__name__, idxval))
            cls2 = cls3
            previdx = idx
            idx = cls2.instanceindexkey
        return cls2
    
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
            # that is a subclass of Packet (i.e., an instance of this
            # metaclass).
            if isinstance (b, __class__):
                assert packetbase is None, "Multiple Packet base classes"
                packetbase = b
        if packetbase is None:
            # Not a subclass of Packet, we're done
            return indexer.__new__ (cls, name, bases, classdict)
        allslots = list (packetbase._allslots)
        allslotset = set (allslots)
        codetable = list (packetbase._codetable)
        # See if we're making a subclass of an indexed class, i.e.,
        # the packet base class has a "classindexkey" attribute.
        classindexkey = getattr (packetbase, "classindexkey", None)
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
        # Start with the set of base class fields that have fixed
        # values given to them in this class.
        fixedvals = allslotset & classnames
        for ftype, fname, *args in layout:
            # Process the rows of the layout table
            if last:
                # Something after a "last" field
                raise InvalidField ("Extra field {} {}".format (ftype.__name__, fname))
            if not issubclass (ftype, Field):
                raise InvalidField ("Invalid field type {}".format (ftype.__name__))
            ftype, fname, args, newslots, wild = ftype.makecoderow (fname, *args)
            if fname:
                # Simple field.
                if fname in allslotset:
                    raise InvalidField ("Duplicate field {} in layout".format (fname))
                if fname in classnames:
                    # Fixed value.  Make sure the class attribute has
                    # the correct type.  A little later we'll drop
                    # that value into a descriptor.
                    classdict[fname] = ftype.checktype (fname, classdict[fname])
            checkrowargs (ftype, fname, args)
            last = ftype.lastfield
            codetable.append ((ftype, fname, args))
            # Any attributes defined as class attributes will not be
            # created as instance attributes.
            newslotset = set (newslots)
            fixedvals |= newslotset & classnames
            newslotset -= classnames
            allslotset |= newslotset
            slots |= newslotset
            for n in newslots:
                if n in newslotset:
                    allslots.append (n)
            if wild:
                slots.add ("__dict__")
        # Handle fixed values.  These are given in the class
        # definition as class attributes with the fixed value assigned
        # to them, and since they don't appear in __slots__ they would
        # normally refuse assignment.  That messes up decoding because
        # that wants to assign every field found in the layout.  So we
        # replace these by descriptors, instances of ROField, which
        # produces a constant value but one that permits assignment so
        # long as the value matches.
        for fname in fixedvals:
            fval = classdict[fname]
            if fname == classindexkey:
                # It's the class index attribute, so use a different
                # property class.
                desc = ROAnyField (fname, fval)
            else:
                desc = ROField (fname, fval)
            classdict[fname] = desc
        # Must end up with some layout
        addslots = classdict.get ("_addslots", None)
        if not codetable and addslots is None and "_allowempty" not in classdict:
            raise InvalidField ("Required attribute '_layout' "\
                                " not defined in class '{}'".format (name))
        # Add any extra slots requested by the class, then set __slots__
        if addslots:
            slots.update (addslots)
            for a in addslots:
                allslots.append (a)
        # If this is the root class of a tree of indexed classes,
        # create an instanceindexkey function if this class didn't
        # specify one explicitly.  The method we create will fetch the
        # value of whatever packet field is named by the
        # "classindexkey" attribute.
        key = classdict.get ("classindexkey", None)
        if key and "instanceindexkey" not in classdict:
            off = 0
            for ftype, fname, args in codetable:
                flen, getindex = ftype.makegetindex (key, off, fname, *args)
                if getindex is None:
                    # This field isn't the one we're looking for.
                    # If its length is known, keep going.
                    # Otherwise, we can't determine where in the
                    # packet we need to look for the index value,
                    # so we have to give up.  In that case the
                    # class needs to specify the needed
                    # instanceindexkey function itself.
                    if not flen:
                        raise TypeError ("Can't make getindex function")
                    off += flen
                else:
                    break
            else:
                raise TypeError ("classindexkey {} not found in layout for {}".format (key, name))
            classdict["instanceindexkey"] = getindex
        classdict["__slots__"] = tuple (slots)
        classdict["_codetable"] = tuple (codetable)
        classdict["_allslots"] = tuple (allslots)
        return indexer.__new__ (cls, name, bases, classdict)
            
class Packet (Field, metaclass = packet_encoding_meta):
    """Base class for DECnet packets.

    The packet layout is given by class variable "layout",
    which has to be set by the derived class definition.
    See comments below for detailed documentation.
    """
    # A packet object is essentially a struct, with elements of
    # specified type in a specified order.  Usually it is used by
    # itself, but it can also be used as an element in a (larger)
    # packet object.  This is used in some places to handle common
    # parts of a packet.

    # The _layout class attribute is a sequence of tuples.  Each
    # starts with the class name for this field (a subclass of Field),
    # followed by a description for that field.  The format of the
    # description depends on the field code:

    # BM: description is a sequence of tuples, which together make up
    # the bit field elements of the protocol field.  Each tuple
    # consists of name, start bit position, bit count, and optionally
    # the field type.  If omitted, the type is unsigned integer.  The
    # bit fields must be listed together and given in ascending order
    # of bit position.  The size of the field is taken to be the
    # minimal number of bytes needed to hold all the bit fields.
    #
    # I, A, B, EX: description is name and length.  For I, A, and EX,
    # length means the maximum length.  A means the value is
    # interpreted as text (str type); for the others, the value is
    # type "bytes".
    #
    # SIGNED is like B except that the value is interpreted as a
    # signed rather than an unsigned integer.
    #
    # CTR is like B except that when encoding a value too large for
    # the specified field size, the maximum value (all ones of that
    # length) is supplied.  This matches the behavior of counters
    # which "saturate" at the max value.
    #
    # BV is a fixed length byte string. Description is field name and
    # length.
    # 
    # RES is a reserved field.  Description is the field length.
    # Reserved fields are ignored on receipt and sent as bytes of
    # zero.
    #
    # TLV: description is the size of the type field, size of the
    # length field, wildcard flag, followed by a sequence of value
    # codes.  Each value code consists of the value type code for that
    # value, the value type, and value description as for any other
    # Packet field.  If the wildcard flag is True, unrecognized type
    # fields are accepted in decode, and turn into "fieldnnn"
    # attributes containing the field value as a byte string.  If
    # False, unrecognized type fields are an error.
    #
    # PAYLOAD is the rest of the packet.  By convention it is written
    # as the layout item "Payload" which is a shorthand for the tuple
    # (PAYLOAD, "payload"), i.e., the rest of the packet deliverd to
    # the field named "payload".
    #
    # The code table is used by the "encode" and "decode" methods of
    # the class being defined.  This generally means those methods as
    # defined in the Packet base class.  The way a given field is
    # encoded is defined by the encode and decode methods of the field
    # class, which makes it easy to add new types or specialized
    # encodings for standard types.
    __slots__ = _allslots = ( "src", "decoded_from" )
    _codetable = ()
    
    # A subclass can override this to be True, in which case some
    # format errors are suppressed.  This is useful to accommodate
    # non-conforming packets seen in the wild.
    tolerant = False

    # A subclass can override this to be a static method (or, if
    # necessary, a class method) that takes the buffer to be decoded
    # as argument, and returns the key value to be used in the
    # classindex lookup.
    instanceindexkey = None
    
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
        buf = makebytes (buf)
        ret = cls ()
        return ret, ret.decode_data (buf, *decodeargs)

    def decode_data (self, buf, *decodeargs):
        "Decode the packet data into this (newly constructed) object"
        # Start filling in the object data as instructed by the code
        # table.
        self.decoded_from = buf
        for ftype, fname, args in self._codetable:
            if fname:
                try:
                    val, buf = ftype.decode (buf, *args)
                    setattr (self, fname, val)
                except Exception:
                    raise AtField (fname)
            else:
                buf = ftype.decode (buf, self, *args)
        # All decoded, do any class-specific checking.
        self.check ()
        return buf

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

class IndexedPacket (Indexed, Packet):
    _addslots = ()
    
    @classmethod
    def decode (cls, buf, *decodeargs):
        """Decode a packet buffer and return a pair of the resulting
        Packet instance and the remaining buffer.

        Here we use the index to find the class we actually want; then
        the superclass method is invoked on that class to create the
        object and fill it in from the supplied data.
        """
        buf = makebytes (buf)
        # Find a suitable decode class via the index
        cls2 = cls.findclassb (buf)
        # See if the class we found is the class on which we were
        # called.  If not, call its decode method to do the actual work.
        # If yes, then that decode method called down here (via super())
        # and we want to go down to our baseclass for the rest of the
        # job.
        if cls2 is cls:
            return super (__class__, cls).decode (buf, *decodeargs)
        return cls2.decode (buf, *decodeargs)

class IndexedField (Indexed, Field):
    pass

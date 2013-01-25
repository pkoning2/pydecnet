#!/usr/bin/env python3

"""DECnet protocol implementation

Classes for packet layouts.
"""

import sys

LE = "little"

try:
    int.from_bytes
except AttributeError:
    raise ImportError ("Python 3.2 or later required")


def process_layout (layout):
    """Process a layout definition and return the resulting
    encode/decode table.

    The layout is a sequence of tuples.  Usually, each tuple
    is a field code, field name, and field length.  In the
    case of a bit map field, it is field code, field name,
    start bit position, and bit count.  Field codes are as
    given in the DECnet specs: "I", "B", "EX", and so on;
    these codes are case insensitive.

    The code table is used by the "encode" and "decode" methods
    of the "Packet" class.
    """
    codetable = [ ]
    item = [ ]
    for code, name, *flen in layout:
        code = code.lower ()
        if code == "i":
            f = Packet.encode_i, Packet.decode_i, name, flen[0]
        elif code == "b":
            f = Packet.encode_b, Packet.decode_b, name, flen[0]
        elif code == "bm":
            f = ( name, ) + tuple (flen)
        elif code == "ex":
            f = Packet.encode_ex, Packet.decode_ex, name, flen[0]
        else:
            raise ValueError ("Unrecognized field code %s" % code.upper ())
        if code == "bm":
            item.append (f)
        else:
            if item:
                codetable.append ([ Packet.encode_bm, Packet.decode_bm ] + item)
                item = [ ]
            codetable.append (f)
    if item:
        codetable.append ([ Packet.encode_bm, Packet.decode_bm ] + item)
    return codetable
    
class _packet_encoding (type):
    """Metaclass for "Packet" that will process the "layout"
    for the packet into the necessary encoding and decoding
    tables.

    The layout is specified in class variable "layout".
    The metaclass uses the layout definition to build an
    encode/decode table, which becomes class variable
    "codetable".
    """
    def __new__ (cls, name, bases, classdict):
        result = type.__new__ (cls, name, bases, classdict)
        try:
            layout = result.layout
        except AttributeError:
            raise AttributeError ("Required attribute 'layout' not defined in class '%s'" % name)
        result.codetable = process_layout (layout)
        return result
            
class Packet (bytearray, metaclass = _packet_encoding):
    """Base class for DECnet packets.

    The packet layout is given by class variable "layout",
    which has to be set by the derived class definition.
    See the documentation for "process_layout" for details.
    """
    layout = ()

    def __init__ (self, buf = None):
        """Construct a packet.  If "buf" is supplied, that buffer
        is decoded.
        """
        super ().__init__ ()
        if buf:
            self.decode (buf)
            
    def encode_i (self, field, maxlen):
        """Encode "field" as an image field with max length "maxlen".
        If val is a string, it is encoded using the current default
        encoding.  If the value is too large, OverflowError is raised.
        """
        val = getattr (self, field)
        if isinstance (val, str):
            val = bytes (val, sys.getdefaultencoding ())
        vl = len (val)
        if vl > maxlen:
            raise OverflowError ("Value too long for %d byte field" % maxlen)
        return vl.to_bytes (1, LE) + val

    def decode_i (self, buf, field, maxlen):
        """Decode "field" from an image field with max length "maxlen".
        If the field is too large, OverflowError is raised.  Returns the
        remaining buffer.
        """
        flen = buf[0]
        if flen > maxlen:
            raise OverflowError ("Image field longer than max length %d" % maxlen)
        v = buf[1:flen + 1]
        if len (v) != flen:
            raise ValueError ("Not %d bytes left for image field" % flen)
        setattr (self, field, v)
        return buf[flen + 1:]

    def encode_b (self, field, flen):
        """Encode "field" as a binary field with length "flen".
        The field value is assumed to be an integer.
        """
        return getattr (self, field).to_bytes (flen, LE)

    def decode_b (self, buf, field, flen):
        """Decode "field" from a binary field with length "flen".
        The field is decoded to a little endian integer.  Returns the
        remaining buffer.
        """
        setattr (self, field, int.from_bytes (buf[:flen], LE))
        return buf[flen:]

    def encode_bm (self, *elements):
        """Encode a bitmap field.  "elements" is a sequence of
        triples: name, starting bit position, bit count.
        """
        field = 0
        topbit = -1
        for name, start, bits in elements:
            val = getattr (self, name)
            if val >> bits:
                raise OverflowError ("Field %s value too large for %d bit field" % (name, bits))
            topbit = max (topbit, start + bits - 1)
            field |= val << start
        flen = (topbit + 8) // 8
        return field.to_bytes (flen, LE)

    def decode_bm (self, buf, *elements):
        """Decode a bitmap field.  "elements" is a sequence of
        triples: name, starting bit position, bit count.  The fields
        are decoded as integers.  Returns the remaining buffer.
        """
        topbit = -1
        for e in elements:
            name, start, bits = e
            topbit = max (topbit, start + bits - 1)
        flen = (topbit + 8) // 8
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
            raise OverflowError ("Extensible field is longer than %d bytes" % maxlen)
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
                raise OverflowError ("Extensible field longer than %d" % maxlen)
        setattr (self, field, val)
        return buf[i + 1:]

    def encode (self, layout = None):
        """Encode the packet according to the current attributes.  The
        resulting packet data is returned.
        
        If the"layout" argument is used, that layout table is used;
        otherwise the class layout table is used, and in that case the
        bytearray of the object is set to the encoded data.   Also,
        in that case, if there is a "payload" attribute, that data
        is added to the end of the encoded data.
        """
        codetable = layout or self.codetable
        data = [ ]
        for e, d, *args in codetable:
            data.append (e (self, *args))
        if not layout:
            try:
                data.append (self.payload)
            except AttributeError:
                pass
        data = b''.join (data)
        if not layout:
            self[:] = data
        return data

    def decode (self, buf, layout = None):
        """Decode a packet buffer and set the packet object attributes
        from the fields that were found.

        If the "layout" argument is used, that layout table is used to
        do the decode.  Otherwise, the class layout table is used, and
        the bytearray base of the object is set to the supplied buffer.

        If more data is present than accounted for in the layout
        definition, the remainder is returned.  This is useful for
        variable layout packets; in that case the class layout is used
        to define the header layout, and anything beyond the header
        is processed separately.
        """
        codetable = layout or self.codetable
        if not layout:
            self[:] = buf
        for e, d, *args in codetable:
            buf = d (self, buf, *args)
        if not layout:
            self.payload = buf
        return buf
    
# Delete these two because we want them to come only from derived classes
del Packet.layout
del Packet.codetable

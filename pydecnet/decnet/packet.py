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

def proc_layoutelem (e):
    code, *args = e
    code = code.lower ()

    if code == "tlv":
        tlen, llen, wild, layoutdict = args
        codedict = { k : proc_layoutelem (v) for k, v in layoutdict.items () }
        return [ Packet.encode_tlv, Packet.decode_tlv,
                 tlen, llen, wild, codedict ]
    else:
        enc = getattr (Packet, "encode_%s" % code)
        dec = getattr (Packet, "decode_%s" % code)
        if code == "bm":
            # Find the field length in bytes
            topbit = -1
            fields = args
            for name, start, bits in fields:
                topbit = max (topbit, start + bits - 1)
            flen = (topbit + 8) // 8
            args = [ flen ]
            for name, start, bits in fields:
                if name:
                    args.append ((name, start, bits))
        return [ enc, dec ] + args
        
def process_layout (layout):
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

    "BS" is byte string, i.e., same as "I" but with the length implied.
    Typically this is used inside TLV items, where the length is part of
    the prefix rather than the value.  DECnet specs show I fields inside
    TLV structures, but in fact those are BS, not I.

    "TLV": description is the size of the type field, size of the length
    field, wildcard flag, and a dictionary of value codes.  The dictionary
    is keyed by the value type code, and the value is a layout tuple as
    described here.  If the wildcard flag is True, unrecognized type
    fields are accepted in decode, and turn into "fieldnnn" attributes
    containing the field value as a byte string.  If False, unrecognized
    type fields are an error.  Note that in encode, only known fields
    (those listed as keys of the fields dictionary) are encoded.

    The code table is used by the "encode" and "decode" methods
    of the "Packet" class.
    """
    codetable = [ ]
    nomore = None
    for e in layout:
        code = e[0].lower ()
        if nomore:
            raise TypeError ("%s field must be last in layout" % nomore)
        if code == "tlv":
            nomore = "TLV"
        codetable.append (proc_layoutelem (e))
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

    def encode_res (self, flen):
        """Encode a reserved field.
        """
        return bytes (flen)

    def decode_res (self, buf, flen):
        """Decode a reserved field.  Just skip it.
        """
        return buf[flen:]
    
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

    def encode_bm (self, flen, *elements):
        """Encode a bitmap field.  "elements" is a sequence of
        triples: name, starting bit position, bit count.
        """
        field = 0
        for name, start, bits in elements:
            val = getattr (self, name)
            if val >> bits:
                raise OverflowError ("Field %s value too large for %d bit field" % (name, bits))
            field |= val << start
        return field.to_bytes (flen, LE)

    def decode_bm (self, buf, flen, *elements):
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

    def encode_bs (self, field, flen):
        retval = bytes (getattr (self, field))
        l = len (retval)
        if l < flen:
            retval += bytes (flen - l)
        elif l > flen:
            retval = retval[:flen]
        return retval

    def decode_bs (self, buf, field, flen):
        setattr (self, field, buf[:flen])
        return buf[flen:]
    
    def encode_tlv (self, tlen, llen, wild, codedict):
        retval = [ ]
        for k, v in codedict.items ():
            e, d, *fieldargs = v
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
                raise ValueError ("Incomplete TLV at end of buffer")
            tag = int.from_bytes (buf[pos:pos + tlen], LE)
            pos += tlen + llen
            vlen = int.from_bytes (buf[pos - llen:pos], LE)
            if pos + vlen > blen:
                raise ValueError ("TLV %d Value field extends beyond end of buffer" % tag)
            try:
                e, d, *fieldargs = codedict[tag]
            except KeyError:
                if wild:
                    e, d, *fieldargs = ( Packet.encode_bs, Packet.decode_bs,
                                         "field%d" % tag, 255 )
                else:
                    raise KeyError ("Unknown TLV tag %d" % tag)
            buf2 = d (self, buf[pos:pos + vlen], *fieldargs)
            if buf2:
                raise ValueError ("TLV %d Value field not fully parsed, left = %d" % (tag, len (buf2)))
            pos += vlen
            
    def encode (self, layout = None):
        """Encode the packet according to the current attributes.  The
        resulting packet data is returned.
        
        If the "layout" argument is used, that layout table is used;
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
            payload = getattr (self, "payload", None)
            if payload:
                data.append (payload)
        data = b''.join (data)
        if not layout:
            self[:] = data
        return data

    __bytes__ = encode
    
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

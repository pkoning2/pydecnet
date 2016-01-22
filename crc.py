#!

"""Compute CRC

This defines a general mechanism to compute CRCs for any polynomial, using
the well known 256 entry lookup table technique.

Credit for some of the details goes to Ross Williams; refer to his document
"A Painless Guide to CRC Error Detection Algorithms" at
http://www.ross.net/crc/crcpaper.html for more details.
"""

import collections.abc

def _reverse (value, width):
    ret = 0
    for i in range (width):
        ret = (ret << 1) | (value & 1)
        value >>= 1
    return ret

def _maketable (poly, width, reflect):
    # The easiest way to make this work consistently is to have the
    # "reversed" case be the normal one, i.e., shift bits out the bottom
    # rather than the top.  That way one bit of logic works for all cases,
    # including those where the polynomial is less than 8 bits wide.
    ret = list ()
    poly = _reverse (poly, width)
    for i in range (256):
        if not reflect:
            i = _reverse (i, 8)
        for j in range (8):
            if i & 1:
                i = (i >> 1) ^ poly
            else:
                i >>= 1
        if not reflect:
            i = _reverse (i, width)
        ret.append (i)
    return ret

class _CRCMeta (type):
    """Metaclass for CRC.  
    """
    def __new__ (cls, name, bases, classdict, poly = None, initial = 0,
                 final = 0, reversed = True, width = 0):
        if not bases:
            # "CRC" base class (essentially abstract)
            return type.__new__ (cls, name, bases, classdict)
        if isinstance (poly, collections.abc.Iterable):
            # Polynomial given as a sequence of the powers of the polynomial
            # The highest power is ignored; that gives the width.
            *powers, width = sorted (poly)
            poly = 0
            for p in powers:
                poly |= 1 << p
        elif width == 0:
            # Width not specified, try to guess it from the polynomial value.
            for width in 8, 16, 32, 64:
                if poly < (1 << width):
                    break
        crcmask = (1 << width) - 1
        if poly > crcmask:
            raise ValueError ("Width is too small for specified polynomial")
        if initial is True:
            initial = crcmask
        if final is True:
            final = crcmask
        classdict["width"] = width
        classdict["widthb"], classdict["rbits"] = divmod (width, 8)
        classdict["poly"] = poly
        classdict["initial"] = initial
        classdict["final"] = final
        classdict["crcmask"] = crcmask
        classdict["reversed"] = reversed
        classdict["crctable"] = _maketable (poly, width, reversed)
        nc = type.__new__ (cls, name, bases, classdict)
        # Now nc is the new class.
        # Define the "update" method.  We do it this way to avoid
        # having to check "reversed" each time a CRC is calculated.
        # Note we do it via class attribute access rather than by
        # operating on the classdict because we need to access
        # methods defined in the base class, not the new class.
        doc = nc.update.__doc__
        if reversed:
            if width <= 8:
                nc.update = nc._update_short_reversed
            else:
                nc.update = nc._update_reversed
        else:
            if width <= 8:
                nc.update = nc._update_short_forward
            else:
                nc.update = nc._update_forward
        nc.update.__doc__ = doc
        # Make an instance of that so we can find the "good CRC" check
        # value.
        c1 = nc (b'\x00')
        c1.update_bits (c1.value, width)
        check = c1.value
        # Confirm it
        c2 = nc (b"\x01\x42")
        c2.update_bits (c2.value, width)
        if check != c2.value:
            raise RuntimeError ("Unable to find good CRC check value")
        nc.goodvalue = check
        return nc

    def __init__ (cls, *args, **kwds):
        pass

class CRC (metaclass = _CRCMeta):
    """A base class for defining CRC generators/checkers.  To use this, derive
    a subclass from CRC, with the following keyword arguments:
    
    poly: the CRC polynomial.  This may be specified as a sequence of the
        powers of the polynomial (including the highest one in the formal
        definition, which corresponds to the CRC width).  Or it may be
        given as an integer whose bits correspond to the terms of the
        polynomial other than the highest one.  This argument is required.
    initial: initial state of the CRC, defaults to zero.  Special value 
        "True" means that the initial CRC is all ones -- as is done for
        example in the Ethernet CRC (CRC32).
    final: value to XOR into the final value of the CRC state to produce 
        the actual CRC value,  defaults to zero.  As with initial, "True" 
        means to complement the value (XOR with all ones).
    reversed: True if the CRC is defined to operate on the data bits in
        order from least to most significant.  Defaults to True, which
        is the choice used for many well known CRCs.
    width: width in bits of the CRC.  Unused if the polynomial is given as
        a sequence, and may be omitted if the width is 8, 16, 32, or 64 and
        obvious from the polynomial (i.e., the correct value is the smallest
        width that will hold the polynomial's value).  Width may be any
        integer > 0.

    Some example polynomials:
        0x8005:     CRC-16
        0x04c11db7: CRC32 (with initial = True, final = True)
        0x1edc6f41: CRC32C (with initial = True, final = True)
        
    """
    def __init__ (self, data = b''):
        """Create a CRC generator/checker.  The "data" argument is the
        data buffer to process (defaults to empty buffer).
        """
        # If this is the CRC base class, complain that we can't
        # instantiate that. 
        if self.__class__.__bases__ == (object,):
            raise TypeError ("Can't instantiate object of " \
                             "class %s" % self.__class__.__name__)
        self._value = self.initial
        self.update (data)

    @property
    def value (self):
        """The CRC value for the data processed so far, as an integer."""
        return self._value ^ self.final

    def __bytes__ (self):
        """The CRC value for the data processed so far, as a byte string."""
        if self.reversed:
            if self.rbits:
                return self.value.to_bytes (self.widthb + 1, "little")
            return self.value.to_bytes (self.widthb, "little")
        # Forward
        if self.rbits:
            v = self.value << (8 - self.rbits)
            return self.value.to_bytes (self.widthb + 1, "big")
        return self.value.to_bytes (self.widthb, "big")
    
    @property
    def good (self):
        """True if the data processed so far ends in the correct CRC for
        the preceding data, False otherwise.
        """
        return self.value == self.goodvalue

    def update_bits (self, data, bits):
        """Update the CRC state using the first "bits" bits in the
        supplied data.  This is like "update" if "bits" is a multiple
        of 8.  If not, then the first bits/8 bytes of the buffer are
        the initial bits, and the last mod(bits, 8) bits of data are
        in the final byte (in the low order bits if the default reversed
        mode is in effect, or in the high order bits if not).
        """
        by, bi = divmod (bits, 8)
        tb = (bits + 7) // 8
        if isinstance (data, int):
            if self.reversed:
                data = data.to_bytes (tb, "little")
            else:
                if bi:
                    # Left-align the last bits in the last byte
                    data <<= 8 - bi
                data = data.to_bytes (tb, "big")
        elif len (data) < tb:
                raise ValueError ("Data too short for bit count")
        # See if just whole bytes
        if not bi:
            self.update (data)
            return
        # The whole bytes come first, so process those now.
        self.update (data[:by])
        # Now process the remaining bits in the last byte, serially
        b = data[by]
        v = self._value
        if self.reversed:
            p = self.crctable[128]
            for i in range (bi):
                if (b ^ v) & 1:
                    v = (v >> 1) ^ p
                else:
                    v >>= 1
                b >>= 1
        else:
            for i in range (bi):
                # shift the next bit of the data and the top bit
                # of the CRC both down to the bottom for testing
                # their XOR:
                if ((b >> (7 - i)) ^ (v >> (self.width - 1))) & 1:
                    v = (v << 1) ^ self.poly
                else:
                    v <<= 1
                v &= self.crcmask
        self._value = v

    def update (self, data):
        """Update the CRC state with the additional data supplied.
        This will adjust "value" and "good" to reflect the new data.
        """
        # Will be replaced at subclass definition time by one of the
        # four following methods.

    # Update the CRC register from a sequence of bytes, for regular
    # and reversed bit order respectively.
    def _update_forward (self, data):
        c = self._value
        sh = self.width - 8
        for b in data:
            c = self.crctable[(c >> sh) ^ b] ^ ((c << 8) & self.crcmask)
        self._value = c
        
    def _update_reversed (self, data):
        c = self._value
        for b in data:
            c = self.crctable[(c & 0xff) ^ b] ^ (c >> 8)
        self._value = c
        
    # Update the CRC register from a sequence of bytes when the CRC
    # width is 8 or less, for regular and reversed bit order
    # respectively.
    def _update_short_forward (self, data):
        c = self._value
        sh = 8 - self.width
        for b in data:
            c = self.crctable[((c << sh) & 0xff) ^ b]
        self._value = c

    def _update_short_reversed (self, data):
        c = self._value
        for b in data:
            c = self.crctable[c ^ b]
        self._value = c

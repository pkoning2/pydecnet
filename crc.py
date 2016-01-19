#!

"""Compute CRC

This defines a general mechanism to compute CRCs for any polynomial, using
the well known 256 entry lookup table technique.

Credit for some of the details goes to Ross Williams; refer to his document
"A Painless Guide to CRC Error Detection Algorithms" for more details.
"""

import collections.abc

def _reverse (value, width):
    ret = 0
    for i in range (width):
        ret = (ret << 1) | (value & 1)
        value >>= 1
    return ret

def _maketable (poly, width, reflect):
    ret = list ()
    tb = 1 << (width - 1)
    for i in range (256):
        if reflect:
            i = _reverse (i, 8)
        i <<= width - 8
        for j in range (8):
            if i & tb:
                i = (i << 1) ^ poly
            else:
                i <<= 1
        if reflect:
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
        if not poly < (1 << width):
            raise ValueError ("Width is too small for specified polynomial")
        if width not in (8, 16, 32, 64):
            raise ValueError ("Width is not 8, 16, 32, or 64")
        if initial is True:
            initial = (1 << width) - 1
        if final is True:
            final = (1 << width) - 1
        classdict["width"] = width
        classdict["widthb"] = width // 8  # width in bytes
        classdict["poly"] = poly
        classdict["initial"] = initial
        classdict["final"] = final
        classdict["crctable"] = maketable (poly, width, reversed)
        nc = type.__new__ (cls, name, bases, classdict)
        # Now nc is the new class.
        # Define the "update" method.  We do it this way to avoid
        # having to check "reversed" each time a CRC is calculated.
        if reversed:
            nc.update = nc._update_reversed
        else:
            nc.update = nc._update_forward
        # Make an instance of that so we can find the "good CRC" check
        # value.
        c1 = nc (b'\x00')
        c1.update (bytes (c1))
        check = c1.value
        # Confirm it
        c2 = nc (b"\x01")
        c2.update (bytes (c2))
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
        order from least to most significant.  Defaults to True.
    width: width in bits of the CRC.  Unused if the polynomial is given as
        a sequence, and may be omitted if the width is obvious from the
        polynomial as an integer value.  Legal values are currently
        8, 16, 32, or 64.

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
        return self.value.to_bytes (self.widthb, "little")
    
    @property
    def good (self):
        """True if the data processed so far ends in the correct CRC for
        the preceding data, False otherwise.
        """
        return self.value == self.goodvalue

    def update (self, data):
        """Update the CRC state with the additional data supplied.
        This will adjust "value" and "good" to reflect the new data.
        """
        # Will be replaced at subclass definition time by one of the
        # two following methods.

    def _update_forward (self, data):
        c = self._value
        sh = self.width - 8
        for b in data:
            c = self.crctable[(c >> sh) ^ b] ^ (c << 8)
        self._value = c
        
    def _update_reversed (self, data):
        c = self._value
        for b in data:
            c = self.crctable[(c & 0xff) ^ b] ^ (c >> 8)
        self._value = c
        

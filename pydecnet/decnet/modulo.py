#!

"""Modular arithmetic class.

This is a subclass of "int" that implements modular arithmetic.
At the moment it doesn't do all of that, just enough for sequence
number arithmetic (as in RFC 1982).
"""

class _mod_meta (type):
    # Metaclass for modular arithmetic.  It implements the
    # "mod" keyword when defining subclasses of "Mod".
    def __new__ (cls, name, bases, classdict, mod = None):
        if not mod:
            if bases != ( int, ):
                raise TypeError ("No modulus defined for class %s" % name)
        else:
            classdict["modulus"] = mod
            q, r = divmod (mod, 2)
            if r:
                undef = None
            else:
                undef = q
                q -= 1
            classdict["maxdelta"] = q
            classdict["undef"] = undef
            classdict["__doc__"] = "Integers conforming to sequence number " \
                                   "arithmetic per RFC 1982, " \
                                   "modulo {}".format (mod)
        classdict["__slots__"] = ()
        return type.__new__ (cls, name, bases, classdict)
            
    def __init__ (cls, *args, **kwds):
        pass
    
class Mod (int, metaclass = _mod_meta):
    """Modular arithmetic, specifically sequence number arithmetic.

    To use this, subclass Mod with the keyword argument "mod" which is
    the modulus to be used.  That subclass then implements sequence
    number arithmetic modulo "mod".  For example, for TCP sequence
    numbers:
        class Seq (Mod, mod = 1 << 32): pass

    Comparisons are done according to the rules of sequence number
    arithmetic, when both operands are instances of this class, and
    the moduli are the same.  If the moduli are different, the values
    are not ordered.  If one is a plain (not modular) int, comparison
    is done as plain ints.
    """
    def __new__ (cls, val):
        if not hasattr (cls, "modulus"):
            raise TypeError ("Can't instantiate object of " \
                             "class %s" % cls.__name__)
        if 0 <= val < cls.modulus:
            return int.__new__ (cls, val)
        raise OverflowError

    def _comparable (self, other):
        return self.modulus == other.modulus
        
    def __lt__ (self, other):
        if not hasattr (other, "modulus"):
            return int (self) < other
        if not self._comparable (other):
            return NotImplemented
        delta = (int (other) - int (self)) % self.modulus
        if delta == self.undef:
            return NotImplemented
        return 0 < delta <= self.maxdelta

    def __le__ (self, other):
        if not hasattr (other, "modulus"):
            return int (self) <= other
        if not self._comparable (other):
            return NotImplemented
        delta = (int (other) - int (self)) % self.modulus
        if delta == self.undef:
            return NotImplemented
        return delta <= self.maxdelta

    def __gt__ (self, other):
        if not hasattr (other, "modulus"):
            return int (self) > other
        if not self._comparable (other):
            return NotImplemented
        delta = (int (self) - int (other)) % self.modulus
        if delta == self.undef:
            return NotImplemented
        return 0 < delta <= self.maxdelta

    def __ge__ (self, other):
        if not hasattr (other, "modulus"):
            return int (self) >= other
        if not self._comparable (other):
            return NotImplemented
        delta = (int (self) - int (other)) % self.modulus
        if delta == self.undef:
            return NotImplemented
        return delta <= self.maxdelta

    def __add__ (self, other):
        return self.__class__ ((int (self) + int (other)) % self.modulus)

    def __sub__ (self, other):
        return self.__class__ ((int (self) - int (other)) % self.modulus)

    def __mul__ (self, other):
        return self.__class__ ((int (self) * int (other)) % self.modulus)

    def __floordiv__ (self, other):
        return self.__class__ ((int (self) // int (other)) % self.modulus)
        
    def __mod__ (self, other):
        return self.__class__ ((int (self) % int (other)) % self.modulus)
        
    def __lshift__ (self, other):
        return self.__class__ ((int (self) << int (other)) % self.modulus)

    def __truediv__ (self, other):
        "Not supported"
        return NotImplemented
    
    def __and__ (self, other):
        "Not supported"
        return NotImplemented
    
    def __or__ (self, other):
        "Not supported"
        return NotImplemented
    
    def __xor__ (self, other):
        "Not supported"
        return NotImplemented

    def __divmod__ (self, other):
        return self / other, self % other
    
    def __pow__ (self, other, modulo = None):
        if modulo is not None:
            return NotImplemented
        return self.__class__ (pow (int (self), int (other), self.modulus))
        

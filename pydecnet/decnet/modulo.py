#!

"""Modular arithmetic class.

This is a subclass of "int" that implements modular arithmetic.
At the moment it doesn't do all of that, just enough for sequence
number arithmetic (as in RFC 1982).
"""

class _mod_meta (type):
    """Metaclass for modular arithmetic.  It implements the
    "mod" keyword when defining subclasses of "Mod".
    """
    def __new__ (cls, name, bases, classdict, mod = None):
        classdict["modulus"] = mod
        if mod:
            classdict["maxdelta"] = (mod - 1) // 2
        return type.__new__ (cls, name, bases, classdict)
            
    def __init__ (cls, *args, **kwds):
        pass
    
class Mod (int, metaclass = _mod_meta):
    """Modular arithmetic, specifically sequence number arithmetic.
    """
    def __new__ (cls, val):
        if cls.modulus is None:
            raise TypeError ("No modulus defined for class %s" % cls.__name__)
        if 0 <= val < cls.modulus:
            return int.__new__ (cls, val)
        raise OverflowError

    def __lt__ (self, other):
        delta = (int (other) - int (self)) % self.modulus
        return delta <= self.maxdelta

    def __gt__ (self, other):
        delta = (int (self) - int (other)) % self.modulus
        return delta <= self.maxdelta

    def __le__ (self, other):
        return not self > other

    def __ge__ (self, other):
        return not self < other

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
        return NotImplemented
    __and__ = __truediv__
    __or__ = __truediv__
    __xor__ = __truediv__

    def __divmod__ (self, other):
        return self / other, self % other
    
    def __pow__ (self, other, modulo = None):
        if modulo is not None:
            return NotImplemented
        return self.__class__ (pow (int (self), int (other), self.modulus))
        

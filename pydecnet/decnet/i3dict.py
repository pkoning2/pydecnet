#!

"""Abbreviated keyword tools for applications.

"""

class i3dict (dict):
    """A dictionary that matches on 3-character case insensitive
    abbreviations of the key but verifies that the whole supplied key is
    correct.

    Not all standard dict methods are implemented since some aren't needed.
    """
    def __init__ (self, other = None, **kwargs):
        if other:
            if isinstance (other, dict):
                for k, v in other.items ():
                    self[k] = v            
            else:
                for k, v in other:
                    self[k] = v            
        for k, v in kwargs.items ():
            self[k] = v
            
    def __contains__ (self, key):
        try:
            self[key]
            return True
        except KeyError:
            return False

    def __delitem__ (self, key):
        try:
            self[key]
            super ().__delitem__ (key[:3].lower ())
        except KeyError:
            raise KeyError (key) from None

    def __getitem__ (self, key):
        keyl = key.lower ()
        try:
            k, v = super ().__getitem__ (keyl[:3])
        except KeyError:
            raise KeyError (key) from None
        if not k.startswith (keyl):
            raise KeyError (key)
        return v

    def __setitem__ (self, key, val):
        keyl = key.lower ()
        super ().__setitem__ (keyl[:3], (keyl, val))

    def __str__ (self):
        return str ({ k : v  for (k, v) in self.items () })

    __repr__ = __str__

    @classmethod
    def fromkeys (cls, i, val = None):
        raise NotImplementedError
    
    def keys (self):
        for k, v in super ().items ():
            yield v[0]
            
    def values (self):
        for v in super ().values ():
            yield v[1]
            
    def items (self):
        yield from super ().values ()

    def pop (self, *args):
        raise NotImplementedError

    popitem = pop

    def setdefault (self, key, val):
        key = key.lower ()
        return super ().setdefault (keyl[:3], (key, val))

def i3eq (a, b):
    "Compare token a with expected b, or list of a with expected list b"
    if isinstance (a, str):
        return b.startswith (a.lower ())
    if len (a) < len (b):
        return False
    for ae, be in zip (a, b):
        if not i3eq (ae, be):
            return False
    return True


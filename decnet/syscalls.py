#!

"""Some syscalls that aren't part of the "os" module.

"""

from ctypes import *
import ctypes.util

_clib = CDLL (ctypes.util.find_library ("c"))

daemon = _clib.daemon
daemon.argtypes = (c_int, c_int)
daemon.restype = c_int

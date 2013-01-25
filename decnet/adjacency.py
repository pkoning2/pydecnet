#!/usr/bin/env python3

"""DECnet common adjacency handling

"""

from .packet import *
from .util import *

class Adjacency (object):
    """Base class for DECnet adjacencies.
    """
    def __init__ (self, nodeid):
        self.nodeid = nodeid

        

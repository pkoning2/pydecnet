#!/usr/bin/env python3

"""DECnet routing, executor (top level object)

This module defines the Executor class, which acts as the root of the
class hierarchy for the DECnet node implementation.  It contains the
state that DECnet thinks of as Executor state, and it also points to
all the other relevant components such as circuits, timer handling,
the various other routing layer modules, and so on.
"""

#from .timers import *

class Executor (object):
    """The root of the class hierarchy for the DECnet node
    implementation.  It contains the state that DECnet thinks of as
    Executor state, and it also points to all the other relevant
    components such as circuits, timer handling, the various other
    routing layer modules, and so on.
    """

    def __init__ (self, nodeid, nodename = None):
        if nodeid < 1 * 1024 + 1 or nodeid > 63 * 1024 + 1023 \
           or (nodeid & 1023) == 0:
            raise ValueError ("Invalid node ID %0x" % nodeid)
        self.nodeid = nodeid
        self.nodename = nodename
        self.circuits = [ ]
        #self.forward = Forwarding (self)
        #self.update = Update (self)
        #self.decision = Decision (self)
        #self.timers = TimerWheel (1, 600)
        

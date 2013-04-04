#!

"""NSP (End Communications and Session Control layers) for DECnet/Python

"""

from .common import *
from .routing_packets import ShortData, LongData
from .events import *
from . import timers
from . import statemachine

class Connection (Element, statemachine.StateMachine):
    """An NSP connection.
    """
    pass

class NSP (Element):
    """The NSP Entity.  This owns all the connections.  It implements
    the ECL (formerly NSP) layer of the DECnet Network Architecture.
    """
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        logging.debug ("Initializing NSP")
        self.connections = dict ()

    def start (self):
        logging.debug ("Starting NSP")
        self.routing = self.parent.routing

    def stop (self):
        logging.debug ("Stopping NSP")

    def dispatch (self, item):
        if isinstance (item, Received):
            # Arriving packet delivered up from Routing.
            logging.trace ("NSP packet received from %s: %s",
                           item.src, item.packet)

class Connection (Element):
    free_ids = set (range (1, 4096))
    
    def __init__ (self, parent):
        super ().__init__ (parent)
        self.srcaddr = self.get_id ()

    def __del__ (self):
        self.ret_id (self.srcaddr)

    @classmethod
    def get_id (cls):
        return cls.free_ids.pop ()

    @classmethod
    def ret_id (cls, id):
        if id in cls.free_ids:
            raise ValueError ("Freeing a free ID")
        cls.free_ids.add (id)

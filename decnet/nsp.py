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
    """The NSP Entity.  This owns all the connections.  It performs the
    duties both of the ECL and the Session Control layer in DNA, since
    those are closely coupled.
    """
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        logging.debug ("Initializing NSP")
        self.connections = dict ()

    def start (self):
        logging.debug ("Starting NSP")
        self.routing = self.parent.routing

    def dispatch (self, item):
        if isinstance (item, Received):
            # Arriving packet delivered up from Routing.
            logging.trace ("NSP packet received from %s: %s",
                           item.src, item.packet)

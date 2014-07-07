#!/usr/bin/env python3

from tests.dntest import *

import logging

from decnet.routing_packets import *
from decnet import route_eth
from decnet import datalink
from decnet.timers import Timeout
from decnet.node import Nodeinfo

rcount = 5000
rmin = 1
rmax = 30
    
class etest (DnTest):
    def setUp (self):
        super ().setUp ()
        self.node.nodeid = Nodeid (1, 5)
        self.node.homearea, self.node.tid = self.node.nodeid.split ()
        self.node.nodename = "testnd"
        self.node.addwork.side_effect = self.t_addwork
        self.dl = unittest.mock.Mock ()
        self.cp = unittest.mock.Mock ()
        self.dl.create_port.return_value = self.cp
        self.config = unittest.mock.Mock ()
        self.config.t3 = 10
        self.config.cost = 1
        self.node.ntype = self.ntype
        self.node.name = b"TEST"
        self.c = route_eth.EndnodeLanCircuit (self.node, "lan-0",
                                              self.dl, self.config)
        self.c.up = unittest.mock.Mock ()
        self.c.down = unittest.mock.Mock ()
        self.c.parent = self.node
        self.c.node = self.node
        self.c.t3 = 15
        self.c.start ()
        #self.c.dispatch (datalink.DlStatus (owner = self.c, status = True))
        
    def tearDown (self):
        self.c.stop ()
        #self.assertEqual (self.c.up.call_count, self.c.down.call_count)
        super ().tearDown ()

    def pad (self, d):
        if len (d) < 46:
            d += bytes (46 - len (d))
        return d

    def assertState (self, name):
        self.assertEqual (self.c.state.__name__, name, "Circuit state")
    
    def t_addwork (self, work, handler = None):
        if handler is not None:
            work.owner = handler
        work.dispatch ()

class test_end (etest):
    ntype = ENDNODE

    def test_one (self):
        pass
    
if __name__ == "__main__":
    unittest.main ()

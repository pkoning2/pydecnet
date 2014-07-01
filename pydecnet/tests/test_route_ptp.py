#!/usr/bin/env python3

import unittest, unittest.mock

import sys
import os
import logging

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet.routing_packets import *
from decnet import route_ptp
from decnet import datalink
from decnet import events
from decnet.common import Nodeid, Version, Macaddr

# Custom testcase loader to load only Test* classes, not base classes
# that are not in themselves a complete test.
def load_tests (loader, tests, pattern):
    suite = unittest.TestSuite ()
    for k, v in globals().items():
        if type (v) is type and k.startswith ("test_"):
            tests = loader.loadTestsFromTestCase (v)
            suite.addTests (tests)
    return suite

def trace (fmt, *args):
    print ("trace:", fmt % args)

def debug (fmt, *args):
    print ("debug:", fmt % args)

def t_addwork (work, handler = None):
    if handler is not None:
        work.owner = handler
    work.dispatch ()
    
class rtest (unittest.TestCase):
    def setUp (self):
        self.lpatch = unittest.mock.patch ("decnet.route_ptp.logging")
        self.spatch = unittest.mock.patch ("decnet.route_ptp.statemachine.logging")
        self.lpatch.start ()
        self.spatch.start ()
        #route_ptp.logging.trace.side_effect = trace
        #route_ptp.statemachine.logging.trace.side_effect = trace
        #route_ptp.logging.debug.side_effect = debug
        self.tnode = unittest.mock.Mock ()
        self.tnode.node = self.tnode
        self.tnode.nodeid = Nodeid (1, 5)
        self.tnode.homearea, self.tnode.tid = self.tnode.nodeid.split ()
        self.tnode.ntype = L2ROUTER
        self.tnode.tiver = tiver_ph4
        self.tnode.phase = 4
        self.tnode.addwork.side_effect = t_addwork
        self.dl = unittest.mock.Mock ()
        self.cp = unittest.mock.Mock ()
        self.dl.create_port.return_value = self.cp
        self.config = unittest.mock.Mock ()
        self.config.t3 = 10
        self.config.cost = 1
        
    def tearDown (self):
        self.c.stop ()
        self.lpatch.stop ()
        self.spatch.stop ()

    def lastsent (self, calls):
        self.assertEqual (self.cp.send.call_count, calls)
        a, k = self.cp.send.call_args
        w = a[0]
        self.assertIsInstance (w, packet.Packet)
        return w

    def pad (self, d):
        if len (d) < 46:
            d += bytes (46 - len (d))
        return d
    
class test_ph2 (rtest):
    def test_noverify (self):
        self.tnode.phase = 2
        self.tnode.tiver = tiver_ph2
        self.tnode.ntype = PHASE2
        self.tnode.name = b"TEST"
        self.c = route_ptp.PtpCircuit (self.tnode, "ptp-0", self.dl, self.config)
        self.c.start ()
        self.assertEqual (self.c.state, self.c.ds)
        self.c.dispatch (datalink.DlStatus (owner = self.c, status = True))
        self.assertEqual (self.c.state, self.c.ri)
        p = self.lastsent (1)
        self.assertIsInstance (p, NodeInit)
        self.assertEqual (p.nodename, b"TEST")
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)

class test_ph3 (rtest):
    def test_noverify (self):
        self.tnode.phase = 3
        self.tnode.tiver = tiver_ph3
        self.tnode.ntype = L1ROUTER
        self.c = route_ptp.PtpCircuit (self.tnode, "ptp-0", self.dl, self.config)
        self.c.start ()
        self.assertEqual (self.c.state, self.c.ds)
        self.c.dispatch (datalink.DlStatus (owner = self.c, status = True))
        self.assertEqual (self.c.state, self.c.ri)
        p = self.lastsent (1)
        self.assertIsInstance (p, PtpInit3)
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)

class test_ph4 (rtest):
    def test_noverify (self):
        self.c = route_ptp.PtpCircuit (self.tnode, "ptp-0", self.dl, self.config)
        self.c.start ()
        self.assertEqual (self.c.state, self.c.ds)
        self.c.dispatch (datalink.DlStatus (owner = self.c, status = True))
        self.assertEqual (self.c.state, self.c.ri)
        p = self.lastsent (1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 0)
        
if __name__ == "__main__":
    unittest.main ()

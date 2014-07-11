#!/usr/bin/env python3

from tests.dntest import *

import logging

from decnet.routing_packets import *
from decnet import adjacency
from decnet.timers import Timeout
from decnet.node import Nodeinfo

class adjtest (DnTest):
    blksize = 500
    prio = 40
    timer = 20
    T3MULT = 2
    name = "test-0"

    def setUp (self):
        super ().setUp ()
        self.node.nodeid = Nodeid (1, 5)
        self.node.homearea, self.node.tid = self.node.nodeid.split ()
        self.node.nodename = "testnd"
        self.node.addwork.side_effect = self.t_addwork
        self.parent = self.node
        self.id = self.node.nodeid
        self.adj = adjacency.Adjacency (self, self)
        self.datalink = unittest.mock.Mock ()
        
    def t_addwork (self, work, handler = None):
        if handler is not None:
            work.owner = handler
        work.dispatch ()
    
class test_lan (adjtest):
    pkttype = LongData
    tiver = tiver_ph4
    ntype = L1ROUTER
    
    def test_send (self):
        pkt = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (1, 17),
                         srcnode = Nodeid (1, 1), visit = 1,
                         payload = b"new payload")
        self.adj.send (pkt)
        p, dest = self.lastsent (self.datalink, 1)
        self.assertEqual (dest, Macaddr (Nodeid (1, 5)))
        self.assertIsInstance (p, LongData)
        self.assertEqual (p.rqr, pkt.rqr)
        self.assertEqual (p.rts, pkt.rts)
        self.assertEqual (p.srcnode, pkt.srcnode)
        self.assertEqual (p.dstnode, pkt.dstnode)
        self.assertEqual (p.visit, pkt.visit)
        self.assertEqual (p.payload, pkt.payload)
        self.assertFalse (p.ie)
        # Try long data
        s = LongData (rqr = 1, rts = 0, ie = 1, dstnode = Nodeid (1, 17),
                      srcnode = Nodeid (1, 1), visit = 1,
                      payload = b"new payload")
        self.adj.send (s)
        p, dest = self.lastsent (self.datalink, 2)
        self.assertIs (s, p)

class test_ptp (adjtest):
    pkttype = ShortData
    tiver = tiver_ph3
    ntype = L1ROUTER
    
    def test_send (self):
        pkt = LongData (rqr = 1, rts = 0, dstnode = Nodeid (1, 17),
                        srcnode = Nodeid (1, 1), visit = 1,
                        payload = b"new payload")
        self.adj.send (pkt)
        p, dest = self.lastsent (self.datalink, 1)
        self.assertEqual (dest, Macaddr (Nodeid (1, 5)))
        self.assertIsInstance (p, ShortData)
        self.assertEqual (p.rqr, pkt.rqr)
        self.assertEqual (p.rts, pkt.rts)
        self.assertEqual (p.srcnode, pkt.srcnode)
        self.assertEqual (p.dstnode, pkt.dstnode)
        self.assertEqual (p.visit, pkt.visit)
        self.assertEqual (p.payload, pkt.payload)
        # Try short data
        s = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (1, 17),
                       srcnode = Nodeid (1, 1), visit = 1,
                       payload = b"new payload")
        self.adj.send (s)
        p, dest = self.lastsent (self.datalink, 2)
        self.assertIs (s, p)

class test_ph2 (adjtest):
    pkttype = ShortData
    tiver = tiver_ph2
    ntype = PHASE2
    
    def test_send (self):
        pkt = LongData (rqr = 1, rts = 0, dstnode = Nodeid (1, 17),
                        srcnode = Nodeid (1, 1), visit = 1,
                        payload = b"new payload")
        self.adj.send (pkt)
        p, dest = self.lastsent (self.datalink, 1, ptype = type (b""))
        self.assertEqual (p, pkt.payload)
        # Try short data
        s = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (1, 17),
                       srcnode = Nodeid (1, 1), visit = 1,
                       payload = b"new payload")
        self.adj.send (s)
        p, dest = self.lastsent (self.datalink, 2, ptype = type (b""))
        self.assertEqual (p, s.payload)

if __name__ == "__main__":
    unittest.main ()

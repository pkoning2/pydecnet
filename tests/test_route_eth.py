#!/usr/bin/env python3

from tests.dntest import *

import logging

from decnet.routing_packets import *
from decnet import route_eth
from decnet import datalink
from decnet.timers import Timeout
from decnet.node import Nodeinfo

rcount = 5000
rmin = 0
rmax = 40
    
class lantest (DnTest):
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
        self.node.tiver = tiver_ph4
        self.node.name = b"TEST"
        self.c = route_eth.EndnodeLanCircuit (self.node, "lan-0",
                                              self.dl, self.config)
        self.c.up = unittest.mock.Mock ()
        self.c.down = unittest.mock.Mock ()
        self.c.parent = self.node
        self.c.node = self.node
        self.c.t3 = 15
        self.c.name = "lan-0"
        self.c.start ()
        
    def tearDown (self):
        self.c.stop ()
        super ().tearDown ()

    def assertState (self, name):
        self.assertEqual (self.c.state.__name__, name, "Circuit state")
    
    def t_addwork (self, work, handler = None):
        if handler is not None:
            work.owner = handler
        work.dispatch ()

class etest (lantest):
    def setUp (self):
        super ().setUp ()
        self.c.Adjacency = unittest.mock.Mock ()
        self.c.Adjacency.side_effect = self.__class__.makeadj
        p = self.lastsent (self.cp, 1)
        p, dest = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, EndnodeHello)
        self.assertEqual (p.id, Nodeid (1, 5))
        self.assertEqual (p.tiver, tiver_ph4)
        self.assertEqual (p.blksize, ETHMTU)
        self.assertEqual (p.timer, 10)
        self.assertRegex (p.testdata, b"^\252+$")
        self.assertEqual (p.neighbor, NULLID)
        self.assertEqual (dest, Macaddr ("AB-00-00-03-00-00"))
        

    def makeadj (self, item):
        self.adj = unittest.mock.Mock ()
        self.adj.macid = Macaddr (item.id)
        return self.adj
    
class test_end (etest):
    ntype = ENDNODE

    def test_dr (self):
        self.assertIsNone (self.c.dr)
        # out of area hello
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x08\x02" \
              b"\x10\x02\x40\x00\x80\x00\x00" \
              b"\x0f\x00\x00\x00\x00\x00\x00\x00" \
              b"\x07\xaa\x00\x04\x00\x07\x04\x9f"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        self.assertIsNone (self.c.dr)
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x04\x02" \
              b"\x10\x02\x40\x00\x80\x00\x00" \
              b"\x0f\x00\x00\x00\x00\x00\x00\x00" \
              b"\x07\xaa\x00\x04\x00\x07\x04\x9f"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        self.assertEqual (self.c.dr.macid, Macaddr ("aa:00:04:00:02:04"))
        # Note that change of DR doesn't generate a new endnode hello,
        # so do a hello timer expiration to get one.
        self.c.dispatch (Timeout (owner = self.c))
        p, dest = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, EndnodeHello)
        self.assertEqual (p.neighbor, Macaddr ("aa:00:04:00:02:04"))
        self.assertEqual (dest, Macaddr ("AB-00-00-03-00-00"))
        # DR timeout is in the common routing code, which isn't tested here.
        # So prod the relevant API call instead of doing the actual timeout.
        self.c.dr_down ()
        self.c.dispatch (Timeout (owner = self.c))
        p, dest = self.lastsent (self.cp, 3)
        self.assertIsInstance (p, EndnodeHello)
        self.assertEqual (p.neighbor, NULLID)
        self.assertEqual (dest, Macaddr ("AB-00-00-03-00-00"))
        
    def test_shortdata (self):
        pkt = b"\x02\x03\x04\x01\x08\x11abcdef payload"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        spkt = self.lastdispatch (1)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (2, 1))
        self.assertEqual (spkt.dstnode, Nodeid (1, 3))
        self.assertEqual (spkt.visit, 17)
        self.assertEqual (len (self.c.prevhops), 1)
        self.assertEqual (self.c.prevhops[Nodeid (2, 1)].prevhop,
                          Macaddr (Nodeid (1, 2)))
        # ditto but with padding
        pkt = b"\x88Testing\x02\x03\x04\x01\x08\x11abcdef payload"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:07:04"),
                                   packet = pkt))
        spkt = self.lastdispatch (2)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (2, 1))
        self.assertEqual (spkt.dstnode, Nodeid (1, 3))
        self.assertEqual (spkt.visit, 17)
        # Check that the previous hop cache was updated
        self.assertEqual (len (self.c.prevhops), 1)
        self.assertEqual (self.c.prevhops[Nodeid (2, 1)].prevhop,
                          Macaddr (Nodeid (1, 7)))

    def test_longdata (self):
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x03\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        spkt = self.lastdispatch (1)
        self.assertIsInstance (spkt, LongData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (2, 1))
        self.assertEqual (spkt.dstnode, Nodeid (1, 3))
        self.assertEqual (spkt.visit, 17)
        self.assertEqual (len (self.c.prevhops), 1)
        self.assertEqual (self.c.prevhops[Nodeid (2, 1)].prevhop,
                          Macaddr (Nodeid (1, 2)))
        # ditto but with padding
        pkt = b"\x88Testing\x26\x00\x00\xaa\x00\x04\x00\x03\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x02\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:07:04"),
                                   packet = pkt))
        spkt = self.lastdispatch (2)
        self.assertIsInstance (spkt, LongData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (2, 2))
        self.assertEqual (spkt.dstnode, Nodeid (1, 3))
        self.assertEqual (spkt.visit, 17)
        self.assertEqual (len (self.c.prevhops), 2)
        self.assertEqual (self.c.prevhops[Nodeid (2, 2)].prevhop,
                          Macaddr (Nodeid (1, 7)))
        # Original entry should be untouched
        self.assertEqual (self.c.prevhops[Nodeid (2, 1)].prevhop,
                          Macaddr (Nodeid (1, 2)))
        # Expire a cache entry
        self.c.prevhops[Nodeid (2, 2)].dispatch (Timeout (self.c))
        # Only the other entry should remain
        self.assertEqual (len (self.c.prevhops), 1)
        self.assertEqual (self.c.prevhops[Nodeid (2, 1)].prevhop,
                          Macaddr (Nodeid (1, 2)))
        

    def test_send (self):
        pkt = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (1, 17),
                         srcnode = Nodeid (1, 1), visit = 1,
                         payload = b"new payload")
        self.c.send (pkt, pkt.dstnode)
        p, dest = self.lastsent (self.cp, 2)
        self.assertEqual (dest, Macaddr (Nodeid (1, 17)))
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
        self.c.send (s, s.dstnode)
        p, dest = self.lastsent (self.cp, 3)
        self.assertIs (s, p)
        # Deliver a packet from that destination
        incoming = b"\x02\x05\x04\x11\x04\x11abcdef payload"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:01:04"),
                                   packet = incoming))
        self.assertEqual (len (self.c.prevhops), 1)
        self.assertEqual (self.c.prevhops[Nodeid (1, 17)].prevhop,
                          Macaddr (Nodeid (1, 1)))
        # Send the packet again, should go to prev hop
        self.c.send (pkt, pkt.dstnode)
        p, dest = self.lastsent (self.cp, 4)
        self.assertEqual (dest, Macaddr (Nodeid (1, 1)))
        # Deliver a router hello to set DR
        rhi = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x04\x02" \
              b"\x10\x02\x40\x00\x80\x00\x00" \
              b"\x0f\x00\x00\x00\x00\x00\x00\x00" \
              b"\x07\xaa\x00\x04\x00\x07\x04\x9f"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = rhi))
        self.assertEqual (self.c.dr.macid, Macaddr (Nodeid (1, 2)))
        # Send the packet again, should still go by previous hop
        self.c.send (pkt, pkt.dstnode)
        p, dest = self.lastsent (self.cp, 5)
        self.assertEqual (dest, Macaddr (Nodeid (1, 1)))
        # Expire the cache entry
        self.c.prevhops[Nodeid (1, 17)].dispatch (Timeout (self.c))
        self.assertFalse (self.c.prevhops)
        # Send again, this should go to DR
        self.c.send (pkt, pkt.dstnode)
        p, dest = self.lastsent (self.c.dr, 1)
        
    def test_rnd (self):
        for i in range (rcount):
            pkt = randpkt (rmin, rmax)
            self.c.dispatch (Received (owner = self.c,
                                       src = Macaddr ("aa:00:04:00:02:04"),
                                       packet = pkt))
        
if __name__ == "__main__":
    unittest.main ()

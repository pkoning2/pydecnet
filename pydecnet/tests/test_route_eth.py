#!/usr/bin/env python3

from tests.dntest import *

from decnet.routing_packets import *
from decnet import route_eth
from decnet import routing
from decnet import datalink
from decnet.timers import Timeout
from decnet.node import Nodeinfo
from decnet import logging

rcount = 5000
rmin = 0
rmax = 40
    
class lantest (DnTest):
    def setUp (self):
        super ().setUp ()
        self.r = unittest.mock.Mock ()
        self.r.node = self.node
        # Counters:
        self.r.unreach_loss = self.r.aged_loss = self.r.node_oor_loss = 0
        self.r.oversized_loss = self.r.partial_update_loss = 0
        self.r.fmt_errors = self.r.ver_rejects = 0        
        self.r.nodeid = Nodeid (1, 5)
        self.r.nodemacaddr = Macaddr (self.r.nodeid)
        self.r.homearea, self.r.tid = self.r.nodeid.split ()
        self.r.nodename = "testnd"
        self.node.addwork.side_effect = self.t_addwork
        self.dl = unittest.mock.Mock ()
        self.cp = unittest.mock.Mock ()
        self.dl.create_port.return_value = self.cp
        self.config = container ()
        self.config.t3 = 10
        self.config.t1 = 15
        self.config.cost = 1
        self.config.priority = 32
        self.config.nr = 3
        self.r.ntype = self.ntype
        self.r.tiver = tiver_ph4
        self.r.name = b"TEST"
        self.r.minhops, self.r.mincost = routing.allocvecs (100)
        self.c = self.ctype (self.r, "lan-0", self.dl, self.config)
        self.c.parent = self.r
        self.c.node = self.node
        self.c.t3 = 15
        self.c.term_recv = self.c.orig_sent = 0
        self.c.trans_recv = self.c.trans_sent = 0
        self.c.cir_down = self.c.adj_down = self.c.init_fail = 0
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

    def last2sent (self, count, dest1, dest2):
        p1, d1 = self.lastsent (self.cp, count)
        p2, d2 = self.lastsent (self.cp, count, back = 1)
        self.assertTrue ((d1 == dest1 and d2 == dest2) or
                         (d1 == dest2 and d2 == dest1))
        self.assertEqual (bytes (p1), bytes (p2))
        return p1
    
class test_end (lantest):
    ntype = ENDNODE
    ctype = routing.LanEndnodeCircuit

    def setUp (self):
        super ().setUp ()
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
        self.assertEvent (events.adj_up, adjacent_node = Nodeid (1, 2))
        # Note that change of DR doesn't generate a new endnode hello,
        # so do a hello timer expiration to get one.
        self.c.dispatch (Timeout (owner = self.c))
        p, dest = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, EndnodeHello)
        self.assertEqual (p.neighbor, Macaddr ("aa:00:04:00:02:04"))
        self.assertEqual (dest, Macaddr ("AB-00-00-03-00-00"))
        # Send timeout to DR adjacency object
        self.c.dr.dispatch (Timeout (owner = self.c.dr))
        self.assertEvent (events.adj_down, reason = "listener_timeout",
                          adjacent_node = Nodeid (1, 2))
        # Force another hello
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
        spkt = self.lastdispatch (1, element = self.r)
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
        spkt = self.lastdispatch (2, element = self.r)
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
        spkt = self.lastdispatch (1, element = self.r)
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
        spkt = self.lastdispatch (2, element = self.r)
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
        p, dest = self.lastsent (self.cp, 6)
        self.assertEqual (dest, Macaddr (Nodeid (1, 2)))

    def test_rnd (self):
        for i in range (rcount):
            pkt = randpkt (rmin, rmax)
            self.c.dispatch (Received (owner = self.c,
                                       src = Macaddr ("aa:00:04:00:02:04"),
                                       packet = pkt))

class test_routing (lantest):
    ntype = L1ROUTER
    ctype = routing.LanL1Circuit

    def setUp (self):
        super ().setUp ()
        self.c.nr = 2
        self.c.minrouterblk = ETHMTU
        p = self.lastsent (self.cp, 1)
        p, dest = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, RouterHello)
        self.assertEqual (p.id, Nodeid (1, 5))
        self.assertEqual (p.tiver, tiver_ph4)
        self.assertEqual (p.blksize, ETHMTU)
        self.assertEqual (p.timer, 10)
        self.assertEqual (dest, Macaddr ("AB-00-00-03-00-00"))
        rslist = Elist (p.elist).rslist
        self.assertFalse (rslist)

    def test_ehello (self):
        self.assertEqual (len (self.c.adjacencies), 0)
        # Out of area hello
        p1 = b"\x0d\x02\x00\x03\xaa\x00\x04\x00\x02\x08\x03\x04\x02" \
             b"\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
             b"\xaa\x00\x04\x00\xff\x0c\x14\x00\x00\x02\252\252"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:08"),
                                   packet = p1))
        self.assertEqual (len (self.c.adjacencies), 0)
        # In area hello
        p1 = b"\x0d\x02\x00\x03\xaa\x00\x04\x00\x02\x04\x03\x04\x02" \
             b"\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
             b"\xaa\x00\x04\x00\xff\x0c\x14\x00\x00\x02\252\252"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = p1))
        self.assertEqual (len (self.c.adjacencies), 1)
        a = self.c.adjacencies[Nodeid (1, 2)]
        self.assertEqual (a.state, route_eth.UP)
        self.assertEqual (a.ntype, ENDNODE)
        self.assertEvent (events.adj_up, adjacent_node = Nodeid (1, 2))
        # Another one
        p2 = b"\x0d\x02\x00\x03\xaa\x00\x04\x00\x03\x04\x03\x04\x02" \
             b"\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
             b"\xaa\x00\x04\x00\xff\x0c\x14\x00\x00\x02\252\252"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:03:04"),
                                   packet = p2))
        self.assertEvent (events.adj_up, adjacent_node = Nodeid (1, 3))
        self.assertEqual (len (self.c.adjacencies), 2)
        a = self.c.adjacencies[Nodeid (1, 2)]
        self.assertEqual (a.state, route_eth.UP)
        self.assertEqual (a.ntype, ENDNODE)
        b = self.c.adjacencies[Nodeid (1, 3)]
        self.assertEqual (b.state, route_eth.UP)
        self.assertEqual (b.ntype, ENDNODE)
        # Time out that adjacency
        b.dispatch (Timeout (owner = b))
        self.assertEvent (events.adj_down, reason = "listener_timeout",
                          adjacent_node = Nodeid (1, 3))
        self.assertEqual (len (self.c.adjacencies), 1)
        # Test bad hello
        pb = p1[:-1] + b"\251"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pb))
        self.assertEqual (len (self.c.adjacencies), 0)
        self.assertEvent (events.adj_down, reason = "listener_invalid_data",
                          adjacent_node = Nodeid (1, 2))
        
    def rhello (self):
        self.assertFalse (self.c.adjacencies)
        # out of area L1 router hello
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x08\x02" \
              b"\x10\x02\x40\x00\x80\x00\x00" \
              b"\x0f\x00\x00\x00\x00\x00\x00\x00" \
              b"\x07\xaa\x00\x04\x00\x07\x04\x9f"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:08"),
                                   packet = pkt))
        self.assertFalse (self.c.adjacencies)
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x04\x02" \
              b"\x10\x02\x40\x00\x80\x00\x00" \
              b"\x08\x00\x00\x00\x00\x00\x00\x00\x00"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        self.assertEqual (len (self.c.adjacencies), 1)
        self.assertEqual (self.eventcount (events.adj_up), 0)
        a = self.c.adjacencies[Nodeid (1, 2)]
        self.assertEqual (a.ntype, L1ROUTER)
        self.assertEqual (a.priority, 64)
        self.assertNotEqual (a.state, route_eth.UP)
        self.assertEqual (self.c.minrouterblk, 528)
        # That other router will be DR
        self.assertFalse (self.c.isdr)
        self.assertEqual (self.c.dr, a)
        # The received hello should trigger a new hello at T2 expiration,
        # so deliver that expiration.
        self.c.dispatch (Timeout (owner = self.c))
        p, dest = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, RouterHello)
        self.assertEqual (dest, Macaddr ("AB-00-00-03-00-00"))
        rslist = Elist (p.elist).rslist
        self.assertTrue (rslist)
        rsent = RSent ()
        rslist = rsent.decode (rslist)
        self.assertFalse (rslist)
        self.assertEqual (rsent.router, Nodeid (1, 2))
        self.assertEqual (rsent.prio, 64)
        self.assertFalse (rsent.twoway)
        # Send the hello with 2-way connectivity
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x04\x02" \
              b"\x10\x02\x40\x00\x80\x00\x00" \
              b"\x0f\x00\x00\x00\x00\x00\x00\x00" \
              b"\x07\xaa\x00\x04\x00\x05\x04\xa0"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        # Now adjacency should be up
        self.assertEqual (len (self.c.adjacencies), 1)
        self.assertEvent (events.adj_up, adjacent_node = Nodeid (1, 2))
        a = self.c.adjacencies[Nodeid (1, 2)]
        self.assertEqual (a.ntype, L1ROUTER)
        self.assertEqual (a.priority, 64)
        self.assertEqual (a.state, route_eth.UP)
        # The received hello should trigger yet another hello at T2 expiration,
        # so deliver that expiration.
        self.c.dispatch (Timeout (owner = self.c))
        p, dest = self.lastsent (self.cp, 3)
        self.assertIsInstance (p, RouterHello)
        self.assertEqual (dest, Macaddr ("AB-00-00-03-00-00"))
        rslist = Elist (p.elist).rslist
        self.assertTrue (rslist)
        rsent = RSent ()
        rslist = rsent.decode (rslist)
        self.assertFalse (rslist)
        self.assertEqual (rsent.router, Nodeid (1, 2))
        self.assertEqual (rsent.prio, 64)
        self.assertTrue (rsent.twoway)

    def test_rhello_change2rtr (self):
        # Fully bring up that router adjacency
        self.rhello ()
        # Change router type
        # Send the hello with 2-way connectivity
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x04\x01" \
              b"\x10\x02\x40\x00\x80\x00\x00" \
              b"\x0f\x00\x00\x00\x00\x00\x00\x00" \
              b"\x07\xaa\x00\x04\x00\x05\x04\xa0"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        # Adjacency will disappear the first time around
        self.assertEqual (len (self.c.adjacencies), 0)
        self.assertEvent (events.adj_down, reason = "address_change",
                          adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c.minrouterblk, ETHMTU)
        self.assertIsNone (self.c.dr)
        # We're going to be DR, but not yet
        self.assertFalse (self.c.isdr)
        # Expire the DR holdoff
        self.c.drtimer.dispatch (Timeout (self.c))
        self.assertTrue (self.c.isdr)
        # The received hello should trigger a new hello at T2 expiration,
        # so deliver that expiration.  More precisely, two of them since
        # we're now DR.
        self.c.dispatch (Timeout (owner = self.c))
        p1 = self.last2sent (5, Macaddr ("AB-00-00-03-00-00"),
                             Macaddr ("AB-00-00-04-00-00"))
        self.assertIsInstance (p1, RouterHello)
        rslist = Elist (p1.elist).rslist
        self.assertFalse (rslist)
        # The second hello will bring it back as L2 router
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        self.assertEqual (len (self.c.adjacencies), 1)
        self.assertEvent (events.adj_up, adjacent_node = Nodeid (1, 2))
        a = self.c.adjacencies[Nodeid (1, 2)]
        self.assertEqual (a.state, route_eth.UP)
        self.assertEqual (a.ntype, L2ROUTER)
        
    def test_rhello_changeprio (self):
        # Fully bring up that router adjacency
        self.rhello ()
        # Change router priority
        # Send the hello with 2-way connectivity
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x04\x02" \
              b"\x10\x02\x41\x00\x80\x00\x00" \
              b"\x0f\x00\x00\x00\x00\x00\x00\x00" \
              b"\x07\xaa\x00\x04\x00\x05\x04\xa0"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        # Adjacency will disappear the first time around
        self.assertEqual (len (self.c.adjacencies), 0)
        self.assertEvent (events.adj_down, reason = "address_change",
                          adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c.minrouterblk, ETHMTU)
        self.assertIsNone (self.c.dr)
        # We're going to be DR, but not yet
        self.assertFalse (self.c.isdr)
        # Expire the DR holdoff
        self.c.drtimer.dispatch (Timeout (self.c))
        self.assertTrue (self.c.isdr)
        # The received hello should trigger a new hello at T2 expiration,
        # so deliver that expiration.  More precisely, two of them since
        # we're now DR.
        self.c.dispatch (Timeout (owner = self.c))
        p1 = self.last2sent (5, Macaddr ("AB-00-00-03-00-00"),
                             Macaddr ("AB-00-00-04-00-00"))
        self.assertIsInstance (p1, RouterHello)
        rslist = Elist (p1.elist).rslist
        self.assertFalse (rslist)
        # The second hello will bring it back with different priority
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        self.assertEqual (len (self.c.adjacencies), 1)
        self.assertEvent (events.adj_up, adjacent_node = Nodeid (1, 2))
        a = self.c.adjacencies[Nodeid (1, 2)]
        self.assertEqual (a.state, route_eth.UP)
        self.assertEqual (a.ntype, L1ROUTER)
        self.assertEqual (a.priority, 65)
        
    def test_rhello_change2end (self):
        # Fully bring up that router adjacency
        self.rhello ()
        # Change that neighbor to be endnode instead
        pkt = b"\x0d\x02\x00\x03\xaa\x00\x04\x00\x02\x04\x03\x04\x02" \
              b"\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
              b"\xaa\x00\x04\x00\xff\x0c\x14\x00\x00\x02\252\252"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        # Adjacency will disappear the first time around
        self.assertEqual (len (self.c.adjacencies), 0)
        self.assertEvent (events.adj_down, reason = "address_change",
                          adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c.minrouterblk, ETHMTU)
        self.assertIsNone (self.c.dr)
        # We're going to be DR, but not yet
        self.assertFalse (self.c.isdr)
        # Expire the DR holdoff
        self.c.drtimer.dispatch (Timeout (self.c))
        self.assertTrue (self.c.isdr)
        # The received hello should trigger a new hello at T2 expiration,
        # so deliver that expiration.  More precisely, two of them since
        # we're now DR.
        self.c.dispatch (Timeout (owner = self.c))
        p1 = self.last2sent (5, Macaddr ("AB-00-00-03-00-00"),
                             Macaddr ("AB-00-00-04-00-00"))
        self.assertIsInstance (p1, RouterHello)
        rslist = Elist (p1.elist).rslist
        self.assertFalse (rslist)
        # The second hello will bring it back as endnode
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        self.assertEqual (len (self.c.adjacencies), 1)
        self.assertEvent (events.adj_up, adjacent_node = Nodeid (1, 2))
        a = self.c.adjacencies[Nodeid (1, 2)]
        self.assertEqual (a.state, route_eth.UP)
        self.assertEqual (a.ntype, ENDNODE)

    def test_rhello_multi (self):
        # Fully bring up first router adjacency
        self.rhello ()
        # Bring up a second one.
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x06\x04\x01" \
              b"\x10\x02\x40\x00\x80\x00\x00" \
              b"\x08\x00\x00\x00\x00\x00\x00\x00\x00"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:06:04"),
                                   packet = pkt))
        self.assertEqual (len (self.c.adjacencies), 2)
        self.assertEqual (self.eventcount (events.adj_up), 1)
        b = self.c.adjacencies[Nodeid (1, 6)]
        self.assertEqual (b.ntype, L2ROUTER)
        self.assertEqual (b.priority, 64)
        self.assertNotEqual (b.state, route_eth.UP)
        self.assertEqual (self.c.minrouterblk, 528)
        # The second router will be DR
        self.assertFalse (self.c.isdr)
        self.assertEqual (self.c.dr, b)
        # Send the hello with 2-way connectivity
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x06\x04\x01" \
              b"\x10\x02\x40\x00\x80\x00\x00" \
              b"\x0f\x00\x00\x00\x00\x00\x00\x00" \
              b"\x07\xaa\x00\x04\x00\x05\x04\xa0"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:06:04"),
                                   packet = pkt))
        self.assertEqual (len (self.c.adjacencies), 2)
        self.assertEvent (events.adj_up, adjacent_node = Nodeid (1, 6))
        b = self.c.adjacencies[Nodeid (1, 6)]
        self.assertEqual (b.state, route_eth.UP)
        self.assertEqual (b.ntype, L2ROUTER)
        # Try to bring up a third one, same priority, lower ID.  It is
        # rejected.
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x01\x04\x01" \
              b"\x10\x02\x40\x00\x80\x00\x00" \
              b"\x08\x00\x00\x00\x00\x00\x00\x00\x00"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:01:04"),
                                   packet = pkt))
        self.assertEqual (len (self.c.adjacencies), 2)
        self.assertFalse (Nodeid (1, 1) in self.c.adjacencies)
        self.assertEvent (events.adj_rej, adjacent_node = Nodeid (1, 1))
        # The second router is still DR
        self.assertFalse (self.c.isdr)
        self.assertEqual (self.c.dr, b)
        # Try to bring up a third one, higher priority, lower ID.  The
        # lower of the earlier two is rejected
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x01\x04\x01" \
              b"\x10\x02\x41\x00\x80\x00\x00" \
              b"\x08\x00\x00\x00\x00\x00\x00\x00\x00"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:01:04"),
                                   packet = pkt))
        self.assertEqual (len (self.c.adjacencies), 2)
        self.assertFalse (Nodeid (1, 2) in self.c.adjacencies)
        self.assertEvent (events.adj_rej, adjacent_node = Nodeid (1, 2))
        c = self.c.adjacencies[Nodeid (1, 1)]
        self.assertEqual (c.state, route_eth.INIT)
        self.assertEqual (c.ntype, L2ROUTER)
        # The third router is now DR
        self.assertFalse (self.c.isdr)
        self.assertEqual (self.c.dr, c)
    
    def test_rhello_dr (self):
        self.assertFalse (self.c.adjacencies)
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x04\x02" \
              b"\x10\x02\x1f\x00\x80\x00\x00" \
              b"\x08\x00\x00\x00\x00\x00\x00\x00\x00"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        self.assertEqual (len (self.c.adjacencies), 1)
        self.assertEqual (self.eventcount (events.adj_up), 0)
        a = self.c.adjacencies[Nodeid (1, 2)]
        self.assertEqual (a.ntype, L1ROUTER)
        self.assertEqual (a.priority, 31)
        self.assertNotEqual (a.state, route_eth.UP)
        self.assertEqual (self.c.minrouterblk, 528)
        # We're going to be DR, but not yet
        self.assertFalse (self.c.isdr)
        # Expire the DR holdoff
        self.c.drtimer.dispatch (Timeout (self.c))
        self.assertTrue (self.c.isdr)
        # The received hello should trigger a new hello at T2 expiration,
        # so deliver that expiration.  More precisely, two of them since
        # we're now DR.
        self.c.dispatch (Timeout (owner = self.c))
        p1 = self.last2sent (3, Macaddr ("AB-00-00-03-00-00"),
                             Macaddr ("AB-00-00-04-00-00"))
        self.assertIsInstance (p1, RouterHello)
        rslist = Elist (p1.elist).rslist
        self.assertTrue (rslist)
        rsent = RSent ()
        rslist = rsent.decode (rslist)
        self.assertFalse (rslist)
        self.assertEqual (rsent.router, Nodeid (1, 2))
        self.assertEqual (rsent.prio, 31)
        self.assertFalse (rsent.twoway)
        # Send the hello with 2-way connectivity
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x04\x02" \
              b"\x10\x02\x1f\x00\x80\x00\x00" \
              b"\x0f\x00\x00\x00\x00\x00\x00\x00" \
              b"\x07\xaa\x00\x04\x00\x05\x04\xa0"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        # Now adjacency should be up
        self.assertEqual (len (self.c.adjacencies), 1)
        self.assertEvent (events.adj_up, adjacent_node = Nodeid (1, 2))
        a = self.c.adjacencies[Nodeid (1, 2)]
        self.assertEqual (a.ntype, L1ROUTER)
        self.assertEqual (a.priority, 31)
        self.assertEqual (a.state, route_eth.UP)
        # The received hello should trigger yet another hello at T2 expiration,
        # so deliver that expiration.
        self.c.dispatch (Timeout (owner = self.c))
        p1 = self.last2sent (5, Macaddr ("AB-00-00-03-00-00"),
                             Macaddr ("AB-00-00-04-00-00"))
        self.assertIsInstance (p1, RouterHello)
        rslist = Elist (p1.elist).rslist
        self.assertTrue (rslist)
        rsent = RSent ()
        rslist = rsent.decode (rslist)
        self.assertFalse (rslist)
        self.assertEqual (rsent.router, Nodeid (1, 2))
        self.assertEqual (rsent.prio, 31)
        self.assertTrue (rsent.twoway)
        # Take away the 2-way connectivity
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x04\x02" \
              b"\x10\x02\x1f\x00\x80\x00\x00" \
              b"\x08\x00\x00\x00\x00\x00\x00\x00\x00"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        self.assertEqual (len (self.c.adjacencies), 1)
        a = self.c.adjacencies[Nodeid (1, 2)]
        self.assertEqual (a.ntype, L1ROUTER)
        self.assertEqual (a.priority, 31)
        self.assertNotEqual (a.state, route_eth.UP)
        self.assertEqual (self.c.minrouterblk, 528)
        self.assertEvent (events.adj_down, adjacent_node = Nodeid (1, 2),
                          reason = "dropped")
        
    def test_shortdata (self):
        # Send endnode hello to create adjacency for neighbor 1.2
        p1 = b"\x0d\x02\x00\x03\xaa\x00\x04\x00\x02\x04\x03\x04\x02" \
             b"\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
             b"\xaa\x00\x04\x00\xff\x0c\x14\x00\x00\x02\252\252"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = p1))
        self.assertEqual (len (self.c.adjacencies), 1)
        a = self.c.adjacencies[Nodeid (1, 2)]
        self.assertEqual (a.state, route_eth.UP)
        self.assertEqual (a.ntype, ENDNODE)
        pkt = b"\x02\x03\x04\x01\x08\x11abcdef payload"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        spkt = self.lastdispatch (1, element = self.r)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (2, 1))
        self.assertEqual (spkt.dstnode, Nodeid (1, 3))
        self.assertEqual (spkt.visit, 17)
        # ditto but with padding
        pkt = b"\x88Testing\x02\x03\x04\x01\x08\x11abcdef payload"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        spkt = self.lastdispatch (2, element = self.r)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (2, 1))
        self.assertEqual (spkt.dstnode, Nodeid (1, 3))
        self.assertEqual (spkt.visit, 17)

    def test_longdata (self):
        # Send endnode hello to create adjacency for neighbor 1.2
        p1 = b"\x0d\x02\x00\x03\xaa\x00\x04\x00\x02\x04\x03\x04\x02" \
             b"\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
             b"\xaa\x00\x04\x00\xff\x0c\x14\x00\x00\x02\252\252"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = p1))
        self.assertEqual (len (self.c.adjacencies), 1)
        a = self.c.adjacencies[Nodeid (1, 2)]
        self.assertEqual (a.state, route_eth.UP)
        self.assertEqual (a.ntype, ENDNODE)
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x03\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        spkt = self.lastdispatch (1, element = self.r)
        self.assertIsInstance (spkt, LongData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (2, 1))
        self.assertEqual (spkt.dstnode, Nodeid (1, 3))
        self.assertEqual (spkt.visit, 17)
        # ditto but with padding
        pkt = b"\x88Testing\x26\x00\x00\xaa\x00\x04\x00\x03\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x02\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        spkt = self.lastdispatch (2, element = self.r)
        self.assertIsInstance (spkt, LongData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (2, 2))
        self.assertEqual (spkt.dstnode, Nodeid (1, 3))
        self.assertEqual (spkt.visit, 17)

    def test_rnd (self):
        for i in range (rcount):
            pkt = randpkt (rmin, rmax)
            self.c.dispatch (Received (owner = self.c,
                                       src = Macaddr ("aa:00:04:00:02:04"),
                                       packet = pkt))

class test_l2routing (test_routing):
    ntype = L2ROUTER
    
    def test_l2hello (self):
        self.assertFalse (self.c.adjacencies)
        # out of area L2 router hello
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x08\x01" \
              b"\x10\x02\x40\x00\x80\x00\x00" \
              b"\x0f\x00\x00\x00\x00\x00\x00\x00" \
              b"\x07\xaa\x00\x04\x00\x07\x08\x9f"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:08"),
                                   packet = pkt))
        self.assertEqual (len (self.c.adjacencies), 1)
        self.assertEqual (self.eventcount (events.adj_up), 0)
        a = self.c.adjacencies[Nodeid (2, 2)]
        self.assertEqual (a.ntype, L2ROUTER)
        self.assertEqual (a.priority, 64)
        self.assertNotEqual (a.state, route_eth.UP)
        self.assertEqual (self.c.minrouterblk, 528)
        # That other router will not be DR (since DR is per area)
        # We will instead, but not yet
        self.assertFalse (self.c.isdr)
        self.assertIsNone (self.c.dr)
        # Expire the DR holdoff
        self.c.drtimer.dispatch (Timeout (self.c))
        self.assertTrue (self.c.isdr)
        # The received hello should trigger a new hello at T2 expiration,
        # so deliver that expiration.
        self.c.dispatch (Timeout (owner = self.c))
        p1 = self.last2sent (3, Macaddr ("AB-00-00-03-00-00"),
                             Macaddr ("AB-00-00-04-00-00"))
        self.assertIsInstance (p1, RouterHello)
        rslist = Elist (p1.elist).rslist
        self.assertTrue (rslist)
        rsent = RSent ()
        rslist = rsent.decode (rslist)
        self.assertFalse (rslist)
        self.assertEqual (rsent.router, Nodeid (2, 2))
        self.assertEqual (rsent.prio, 64)
        self.assertFalse (rsent.twoway)
        # Establish 2 way connectivity
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x08\x01" \
              b"\x10\x02\x40\x00\x80\x00\x00" \
              b"\x16\x00\x00\x00\x00\x00\x00\x00" \
              b"\x0e\xaa\x00\x04\x00\x07\x08\x9f" \
              b"\xaa\x00\x04\x00\x05\x04\xa0"
        self.c.dispatch (Received (owner = self.c,
                                   src = Macaddr ("aa:00:04:00:02:08"),
                                   packet = pkt))
        self.assertEqual (len (self.c.adjacencies), 1)
        self.assertEvent (events.adj_up, adjacent_node = Nodeid (2, 2))
        a = self.c.adjacencies[Nodeid (2, 2)]
        self.assertEqual (a.ntype, L2ROUTER)
        self.assertEqual (a.priority, 64)
        self.assertEqual (a.state, route_eth.UP)
        self.assertEqual (self.c.minrouterblk, 528)
        # The received hello should trigger yet another hello at T2 expiration,
        # so deliver that expiration.
        self.c.dispatch (Timeout (owner = self.c))
        p1 = self.last2sent (5, Macaddr ("AB-00-00-03-00-00"),
                             Macaddr ("AB-00-00-04-00-00"))
        self.assertIsInstance (p1, RouterHello)
        rslist = Elist (p1.elist).rslist
        self.assertTrue (rslist)
        rsent = RSent ()
        rslist = rsent.decode (rslist)
        self.assertFalse (rslist)
        self.assertEqual (rsent.router, Nodeid (2, 2))
        self.assertEqual (rsent.prio, 64)
        self.assertTrue (rsent.twoway)

if __name__ == "__main__":
    unittest.main ()

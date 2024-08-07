#!/usr/bin/env python3

from tests.dntest import *

from decnet.routing_packets import *
from decnet import routing
from decnet import route_ptp
from decnet import datalink
from decnet.node import Nodeinfo
from decnet import logging

rcount = 5000
rmin = 0
rmax = 40
    
class rtest (DnTest):
    phase = 4
    
    def setUp (self):
        super ().setUp ()
        self.node.phase = self.phase
        self.selfinfo = Nodeinfo (None, nodeid = Nodeid (1, 5))
        self.selfinfo.nodename = "testnd"
        self.nodeinfo = unittest.mock.Mock ()
        self.nodeinfo.return_value = self.selfinfo
        self.node.config = self.config = container ()
        self.config.nsp = container ()
        self.config.nsp.max_connections = 1023
        self.config.routing = container ()
        if self.phase == 4:
            self.config.routing.id = Nodeid (1, 5)
        else:
            self.config.routing.id = Nodeid (5)
        self.config.routing.t1 = 50
        self.config.routing.bct1 = 10
        self.config.routing.maxnodes = 100
        self.config.routing.maxarea = 10
        self.config.routing.maxhops = 5
        self.config.routing.amaxhops = 5
        self.config.routing.maxcost = 20
        self.config.routing.amaxcost = 20
        self.config.routing.maxvisits = 30
        # No intercept
        self.config.routing.intercept = 0
        self.config.circuit = dict ()
        self.node.datalink = container ()
        self.node.datalink.circuits = dict ()
        self.node.nsp = unittest.mock.Mock ()
        self.node.nodeid = self.config.routing.id
        p2nodes = ((66, "REMOTE"), (44, "REM44"))
        for i, n in p2nodes:
            if self.phase == 4:
                i += 1024
            rnode = Nodeinfo (None, Nodeid (i))
            rnode.name = n
            self.node.node.nodeinfo_byname[n] = rnode
            self.node.node.nodeinfo_byid[Nodeid (i)] = rnode
        i = 1
        for n, lan in self.circ:
            self.config.circuit[n] = container ()
            self.config.circuit[n].routing = self.config.routing
            self.config.circuit[n].t1 = None
            self.config.circuit[n].t3 = 10
            self.config.circuit[n].cost = 1
            self.config.circuit[n].latency = None
            self.config.circuit[n].priority = 32
            self.config.circuit[n].verify = False
            self.config.circuit[n].nr = 30
            self.config.circuit[n].loop_node = False
            self.node.datalink.circuits[n] = unittest.mock.Mock ()
            if lan:
                self.node.datalink.circuits[n].__class__ = datalink.BcDatalink
        self.config.routing.type = self.ntype
        self.r = self.node.routing = routing.Router (self, self.config)
        self.r.start ()
        i = 1
        for n, lan in self.circ:
            c = self.r.circuits[n]
            setattr (self, "c%d" % i, c)
            setattr (self, "d%d" % i, c.datalink)
            i += 1
        
    def tearDown (self):
        self.r.stop ()
        super ().tearDown ()
    
    def register_api (self, name, sf, ef = None): pass

class test_ethend (rtest):
    ntype = "endnode"
    circ = (( "lan-0", True ),)
    
    def test_dr (self):
        self.assertIsNone (self.c1.dr)
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x04\x02" \
              b"\x10\x02\x40\x00\x80\x00\x00" \
              b"\x0f\x00\x00\x00\x00\x00\x00\x00" \
              b"\x07\xaa\x00\x04\x00\x07\x04\x9f"
        self.node.addwork (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        self.assertEqual (self.c1.dr.macid, Macaddr ("aa:00:04:00:02:04"))
        self.assertEqual (self.c1.dr.nodeid, Nodeid (1, 2))
        # Try sending a packet
        self.r.send (b"payload", Nodeid (1, 17))
        self.assertEqual (self.c1.datalink.counters.orig_sent, 1)
        p, dest = self.lastsent (self.d1, 2)
        self.assertIsInstance (p, LongData)
        self.assertEqual (p.dstnode, Nodeid (1,17))
        self.assertEqual (p.srcnode, Nodeid (1,5))
        self.assertEqual (p.visit, 0)
        self.assertFalse (p.rqr)
        self.assertFalse (p.rts)
        self.assertTrue (p.ie)
        self.assertEqual (p.payload, b"payload")
        self.assertEqual (dest, Macaddr ("aa:00:04:00:02:04"))
        # Try sending a packet.  Note that out of area makes no difference.
        self.r.send (b"payload2", Nodeid (3,17))
        self.assertEqual (self.c1.datalink.counters.orig_sent, 2)
        p, dest = self.lastsent (self.d1, 3)
        self.assertIsInstance (p, LongData)
        self.assertEqual (p.dstnode, Nodeid (3,17))
        self.assertEqual (p.srcnode, Nodeid (1,5))
        self.assertEqual (p.visit, 0)
        self.assertFalse (p.rqr)
        self.assertFalse (p.rts)
        self.assertTrue (p.ie)
        self.assertEqual (p.payload, b"payload2")
        self.assertEqual (dest, Macaddr ("aa:00:04:00:02:04"))
        # Note that change of DR doesn't generate a new endnode hello,
        # so do a hello timer expiration to get one.
        DnTimeout (self.c1)
        p, dest = self.lastsent (self.d1, 4)
        self.assertIsInstance (p, EndnodeHello)
        self.assertEqual (p.neighbor, Macaddr ("aa:00:04:00:02:04"))
        self.assertEqual (dest, Macaddr ("AB-00-00-03-00-00"))
        # Send timeout to DR adjacency object
        DnTimeout (self.c1.dr)
        # Try sending a packet
        self.r.send (b"payload", Nodeid (1,17))
        p, dest = self.lastsent (self.d1, 5)
        self.assertIsInstance (p, LongData)
        self.assertEqual (p.dstnode, Nodeid (1,17))
        self.assertEqual (p.srcnode, Nodeid (1,5))
        self.assertEqual (p.visit, 0)
        self.assertFalse (p.rqr)
        self.assertFalse (p.rts)
        self.assertTrue (p.ie)
        self.assertEqual (p.payload, b"payload")
        self.assertEqual (dest, Macaddr ("aa:00:04:00:11:04"))
        # Check the hello with the DR no longer mentioned
        DnTimeout (self.c1)
        p, dest = self.lastsent (self.d1, 6)
        self.assertIsInstance (p, EndnodeHello)
        self.assertEqual (p.neighbor, NULLID)
        self.assertEqual (dest, Macaddr ("AB-00-00-03-00-00"))
        # Try sending a packet.  Note that out of area makes no difference.
        self.r.send (b"payload2", Nodeid (3,17))
        p, dest = self.lastsent (self.d1, 7)
        self.assertIsInstance (p, LongData)
        self.assertEqual (p.dstnode, Nodeid (3,17))
        self.assertEqual (p.srcnode, Nodeid (1,5))
        self.assertEqual (p.visit, 0)
        self.assertFalse (p.rqr)
        self.assertFalse (p.rts)
        self.assertTrue (p.ie)
        self.assertEqual (p.payload, b"payload2")
        self.assertEqual (dest, Macaddr ("aa:00:04:00:11:0c"))
        
    def test_shortdata (self):
        pkt = b"\x02\x05\x04\x01\x08\x11abcdef payload"
        self.node.addwork (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        self.assertEqual (self.c1.datalink.counters.term_recv, 1)
        w = self.lastdispatch (1, self.node.nsp, itype = Received)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        self.assertEqual (len (self.c1.prevhops), 1)
        self.assertEqual (self.c1.prevhops[Nodeid (2, 1)].prevhop,
                          Macaddr ("aa:00:04:00:02:04"))
        # ditto but with padding
        pkt = b"\x88Testing\x02\x05\x04\x01\x08\x11abcdef payload"
        self.node.addwork (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:07:04"),
                                   packet = pkt))
        self.assertEqual (self.c1.datalink.counters.term_recv, 2)
        w = self.lastdispatch (2, self.node.nsp, itype = Received)
        spkt = w.packet
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # Check that the previous hop cache was updated
        self.assertEqual (len (self.c1.prevhops), 1)
        self.assertEqual (self.c1.prevhops[Nodeid (2, 1)].prevhop,
                          Macaddr ("aa:00:04:00:07:04"))
        # Packet for wrong address is ignored
        pkt = b"\x02\x01\x04\x01\x08\x11abcdef payload"
        self.node.addwork (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        # Check that last received count doesn't change
        self.assertEqual (self.c1.datalink.counters.term_recv, 2)
        self.lastdispatch (2, self.node.nsp, itype = Received)
        
    def test_longdata (self):
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x05\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.node.addwork (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        self.assertEqual (self.c1.datalink.counters.term_recv, 1)
        w = self.lastdispatch (1, self.node.nsp, itype = Received)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        self.assertEqual (len (self.c1.prevhops), 1)
        self.assertEqual (self.c1.prevhops[Nodeid (2, 1)].prevhop,
                          Macaddr ("aa:00:04:00:02:04"))
        # ditto but with padding
        pkt = b"\x88Testing\x26\x00\x00\xaa\x00\x04\x00\x05\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"Other payload"
        self.node.addwork (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:07:04"),
                                   packet = pkt))
        self.assertEqual (self.c1.datalink.counters.term_recv, 2)
        w = self.lastdispatch (2, self.node.nsp, itype = Received)
        spkt = w.packet
        self.assertEqual (w.packet, b"Other payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # Check that the previous hop cache was updated
        self.assertEqual (len (self.c1.prevhops), 1)
        self.assertEqual (self.c1.prevhops[Nodeid (2, 1)].prevhop,
                          Macaddr ("aa:00:04:00:07:04"))
        # Packet for wrong address is ignored
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x01\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.node.addwork (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        # Check that last received count doesn't change
        self.lastdispatch (2, self.node.nsp, itype = Received)
        self.assertEqual (self.c1.datalink.counters.term_recv, 2)

    def test_sendself (self):
        # Send a packet to our own address
        self.r.send (b"payload", Nodeid (1, 5))
        w = self.lastdispatch (1, self.node.nsp, itype = Received)
        self.assertEqual (w.packet, b"payload")
        self.assertEqual (w.src, Nodeid (1, 5))
        self.assertFalse (w.rts)
        
class test_ptpend (rtest):
    ntype = "endnode"
    circ = (( "ptp-0", False ),)

    def setUp (self):
        super ().setUp ()
        self.assertState ("ds")
        self.node.addwork (datalink.DlStatus (owner = self.c1,
                                             status = datalink.DlStatus.UP))
        self.assertState ("ri")        
        
    def assertState (self, name):
        self.assertEqual (self.c1.state.__name__, name, "Circuit state")
    
    def test_send_ph4 (self):
        # Send phase4 init
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru4e")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c1.rphase, 4)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        # Try sending a packet
        self.r.send (b"payload", Nodeid (1,17))
        p, dest = self.lastsent (self.d1, 2)
        self.assertIsInstance (p, ShortData)
        self.assertEqual (p.dstnode, Nodeid (1,17))
        self.assertEqual (p.srcnode, Nodeid (1,5))
        self.assertEqual (p.visit, 0)
        self.assertFalse (p.rqr)
        self.assertFalse (p.rts)
        self.assertEqual (p.payload, b"payload")

    def test_shortdata_ph4 (self):
        # Send phase4 init
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru4e")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c1.rphase, 4)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        pkt = b"\x02\x05\x04\x01\x08\x11abcdef payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.term_recv, 1)
        w = self.lastdispatch (1, self.node.nsp, itype = Received)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # ditto but with padding
        pkt = b"\x88Testing\x02\x05\x04\x01\x08\x11Other payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.term_recv, 2)
        w = self.lastdispatch (2, self.node.nsp, itype = Received)
        spkt = w.packet
        self.assertEqual (w.packet, b"Other payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # Packet for wrong address
        pkt = b"\x02\x01\x04\x01\x08\x11abcdef payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        # Check that last received count doesn't change
        self.assertEqual (self.c1.datalink.counters.term_recv, 2)
        self.lastdispatch (2, self.node.nsp, itype = Received)

    def test_longdata_ph4 (self):
        # Send phase4 init
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru4e")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c1.rphase, 4)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x05\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.term_recv, 1)
        w = self.lastdispatch (1, self.node.nsp, itype = Received)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # ditto but with padding
        pkt = b"\x88Testing\x26\x00\x00\xaa\x00\x04\x00\x05\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"Other payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.term_recv, 2)
        w = self.lastdispatch (2, self.node.nsp, itype = Received)
        spkt = w.packet
        self.assertEqual (w.packet, b"Other payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # Packet for wrong address is ignored
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x01\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        # Check that last received count doesn't change
        self.assertEqual (self.c1.datalink.counters.term_recv, 2)
        self.lastdispatch (2, self.node.nsp, itype = Received)
    
    def test_send_ph3 (self):
        # Send phase3 init
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru3e")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c1.rphase, 3)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        # Try sending a packet
        self.r.send (b"payload", Nodeid (1, 17))
        self.assertEqual (self.c1.datalink.counters.orig_sent, 1)        
        p, dest = self.lastsent (self.d1, 3)
        self.assertIsInstance (p, ShortData)
        self.assertEqual (p.dstnode, Nodeid (17))
        self.assertEqual (p.srcnode, Nodeid (5))
        self.assertEqual (p.visit, 0)
        self.assertFalse (p.rqr)
        self.assertFalse (p.rts)
        self.assertEqual (p.payload, b"payload")

    def test_shortdata_ph3 (self):
        # Send phase3 init
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru3e")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c1.rphase, 3)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        pkt = b"\x02\x05\x00\x01\x08\x11abcdef payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.term_recv, 1)
        w = self.lastdispatch (1, self.node.nsp, itype = Received)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # Packet with padding, should be ignored as invalid
        pkt = b"\x88Testing\x02\x05\x00\x01\x00\x11Other payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.term_recv, 1)
        self.lastdispatch (1, self.node.nsp, itype = Received)
        self.assertEvent (events.fmt_err, 
                          packet_beginning = b"\x88Testi")
        # Packet for wrong address
        pkt = b"\x02\x01\x00\x01\x08\x11abcdef payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        # Check that last received count doesn't change
        self.assertEqual (self.c1.datalink.counters.term_recv, 1)
        self.lastdispatch (1, self.node.nsp, itype = Received)

    def test_longdata_ph3 (self):
        # Send phase3 init
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru3e")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c1.rphase, 3)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        # Long Data header, should be ignored from Phase 3
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x05\x00" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.term_recv, 0)
        # Packet with padding, should be ignored as invalid
        pkt = b"\x88Testing\x26\x00\x00\xaa\x00\x04\x00\x05\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"Other payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.term_recv, 0)
        self.assertEvent (events.fmt_err, 
                          packet_beginning = b"\x88Testi")
        # Packet for wrong address is ignored
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x01\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        # Check that last received count doesn't change
        self.assertEqual (self.c1.datalink.counters.term_recv, 0)
        
    def test_send_ph2 (self):
        # Send phase2 init
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru2")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (1, 66))
        self.assertEqual (self.c1.rphase, 2)
        self.assertEqual (self.c1.id, Nodeid (1, 66))
        # Try sending a packet
        self.r.send (b"payload", Nodeid (1, 66))
        self.assertEqual (self.c1.datalink.counters.orig_sent, 1)
        p, dest = self.lastsent (self.d1, 3, ptype = bytes)
        self.assertEqual (p, b"payload")
        self.r.send (b"payload", Nodeid (1, 44))
        # FIXME: not reachable, check that.
        self.lastsent (self.d1, 3, ptype = bytes)
        # Similar but RQR set
        self.r.send (b"payload", Nodeid (1, 44), rqr = 1)
        self.lastsent (self.d1, 3, ptype = bytes)
        # Verify that it came back to NSP
        w = self.lastdispatch (1, self.node.nsp, itype = Received)
        self.assertEqual (w.packet, b"payload")
        self.assertEqual (w.src, Nodeid (1, 44))
        self.assertTrue (w.rts)
        
    def test_recvdata_ph2 (self):
        # Send phase2 init
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru2")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (1, 66))
        self.assertEqual (self.c1.rphase, 2)
        self.assertEqual (self.c1.id, Nodeid (1, 66))
        # Deliver a packet.  Note that the first byte needs to be a valid
        # NSP header byte (which this is -- 00 means data segment,
        # no BOP, no EOP).
        pkt = b"\x00abcdef payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.term_recv, 1)
        w = self.lastdispatch (1, self.node.nsp, itype = Received)
        self.assertEqual (w.packet, b"\x00abcdef payload")
        self.assertEqual (w.src, Nodeid (1, 66))
        self.assertFalse (w.rts)

    def test_sendself (self):
        # Send a packet to our own address
        self.r.send (b"payload", Nodeid (1, 5))
        w = self.lastdispatch (1, self.node.nsp, itype = Received)
        self.assertEqual (w.packet, b"payload")
        self.assertEqual (w.src, Nodeid (1, 5))
        self.assertFalse (w.rts)
        
class test_ph2 (rtest):
    ntype = "phase2"
    phase = 2
    circ = (( "ptp-0", False ),
            ( "ptp-1", False ))

    def setUp (self):
        super ().setUp ()
        self.assertState (self.c1, "ds")
        self.node.addwork (datalink.DlStatus (owner = self.c1, status = datalink.DlStatus.UP))
        self.assertState (self.c1, "ri")        
        self.node.addwork (datalink.DlStatus (owner = self.c2,
                                             status = datalink.DlStatus.DOWN))
        self.assertState (self.c2, "ds")
        self.node.addwork (datalink.DlStatus (owner = self.c2, status = datalink.DlStatus.UP))
        self.assertState (self.c2, "ri")        
        
    def assertState (self, c, name):
        self.assertEqual (c.state.__name__, name, "Circuit state")
    
    def test_init_ph4 (self):
        # Send phase4 init
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ri")
        self.assertEqual (self.eventcount (events.circ_up), 0)

    def test_init_ph3 (self):
        # Send phase3 init
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ri")
        self.assertEqual (self.eventcount (events.circ_up), 0)

    def test_send_ph2 (self):
        # Send phase2 init to ptp-0
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ru2")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (66))
        self.assertEqual (self.c1.rphase, 2)
        self.assertEqual (self.c1.id, Nodeid (66))
        # Try sending a packet to the neighbor on ptp-0
        self.r.send (b"payload", Nodeid (66))
        self.assertEqual (self.c1.datalink.counters.orig_sent, 1)
        p, dest = self.lastsent (self.d1, 2, ptype = bytes)
        self.assertEqual (p, b"payload")
        # Try sending to some other address (not currently reachable)
        self.r.send (b"payload", Nodeid (44))
        # FIXME self.assertFalse (ok)
        self.lastsent (self.d1, 2, ptype = bytes)
        # Now send phase2 init to ptp-1
        pkt = b"\x58\x01\x2c\x05REM44\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.node.addwork (Received (owner = self.c2, src = self.c2,
                                    packet = pkt))
        self.assertState (self.c2, "ru2")
        self.assertEqual (self.eventcount (events.circ_up), 2)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (44))
        self.assertEqual (self.c2.rphase, 2)
        self.assertEqual (self.c2.id, Nodeid (44))
        # Try sending to the new neighbor on ptp-1
        self.r.send (b"payload2", Nodeid (44))
        self.assertEqual (self.c2.datalink.counters.orig_sent, 1)
        p, dest = self.lastsent (self.d2, 2, ptype = bytes)
        self.assertEqual (p, b"payload2")

    def test_recvdata_ph2 (self):
        # Send phase2 init on ptp-0
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ru2")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (66))
        self.assertEqual (self.c1.rphase, 2)
        self.assertEqual (self.c1.id, Nodeid (66))
        # Deliver a packet.  Note that the first byte needs to be a valid
        # NSP header byte (which this is -- 00 means data segment,
        # no BOP, no EOP).
        pkt = b"\x00abcdef payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.term_recv, 1)
        w = self.lastdispatch (1, self.node.nsp, itype = Received)
        self.assertEqual (w.packet, b"\x00abcdef payload")
        self.assertEqual (w.src, Nodeid (66))
        self.assertFalse (w.rts)
        # Send phase2 init on ptp-1
        pkt = b"\x58\x01\x2c\x05REM44\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.node.addwork (Received (owner = self.c2, src = self.c2,
                                    packet = pkt))
        self.assertState (self.c2, "ru2")
        self.assertEqual (self.eventcount (events.circ_up), 2)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (44))
        self.assertEqual (self.c2.rphase, 2)
        self.assertEqual (self.c2.id, Nodeid (44))
        # Deliver a packet.  Note that the first byte needs to be a valid
        # NSP header byte (which this is -- 00 means data segment,
        # no BOP, no EOP).
        pkt = b"\x00Other payload"
        self.node.addwork (Received (owner = self.c2, packet = pkt))
        self.assertEqual (self.c2.datalink.counters.term_recv, 1)
        w = self.lastdispatch (2, self.node.nsp, itype = Received)
        self.assertEqual (w.packet, b"\x00Other payload")
        self.assertEqual (w.src, Nodeid (44))
        self.assertFalse (w.rts)

class test_ph4l1a (rtest):
    ntype = "l1router"
    phase = 4
    circ = (( "ptp-0", False ),
            ( "ptp-1", False ))
    
    def setUp (self):
        super ().setUp ()
        self.assertState (self.c1, "ds")
        self.node.addwork (datalink.DlStatus (owner = self.c1, status = datalink.DlStatus.UP))
        self.assertState (self.c1, "ri")        
        self.node.addwork (datalink.DlStatus (owner = self.c2,
                                             status = datalink.DlStatus.DOWN))
        self.assertState (self.c2, "ds")
        self.node.addwork (datalink.DlStatus (owner = self.c2, status = datalink.DlStatus.UP))
        self.assertState (self.c2, "ri")        
        
    def assertState (self, c, name):
        self.assertEqual (c.state.__name__, name, "Circuit state")

    def test_init_ph4 (self):
        # Send phase4 init for endnode
        pkt = b"\x01\x02\x04\x03\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ru4e")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEqual (self.eventcount (events.reach_chg), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEvent (events.reach_chg, back = 1,
                          entity = events.NodeEventEntity (Nodeid (1, 2)),
                          status = "reachable")
        self.assertEqual (self.c1.rphase, 4)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        pkt = b"\x01\x03\x04\x03\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.node.addwork (Received (owner = self.c2, src = self.c2,
                                    packet = pkt))
        self.assertState (self.c2, "ru4e")
        self.assertEqual (self.eventcount (events.circ_up), 2)
        self.assertEqual (self.eventcount (events.reach_chg), 2)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 3))
        self.assertEvent (events.reach_chg, back = 1,
                          entity = events.NodeEventEntity (Nodeid (1, 3)),
                          status = "reachable")
        self.assertEqual (self.c2.rphase, 4)
        self.assertEqual (self.c2.id, Nodeid (1, 3))
        # Try some forwarded traffic
        # Forward c1 to c2
        pkt = b"\x88Testing\x02\x03\x04\x02\x04\x11Other payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.trans_recv, 1)
        self.assertEqual (self.c2.datalink.counters.trans_sent, 1)
        p, dest = self.lastsent (self.d2, 2)
        self.assertEqual (p.encode (), b"\x02\x03\x04\x02\x04\x12Other payload")
        # Unreachable destination
        pkt = b"\x02\x42\x04\x02\x04\x11Other payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.trans_recv, 1)
        self.assertEqual (self.r.nodeinfo.counters.unreach_loss, 1)
        self.assertEvent (events.unreach_drop, adjacent_node = Nodeid (1, 2),
                          packet_header = [2, 1090, 1026, 17])
        # Node number out of range
        pkt = b"\x02\xfe\x04\x02\x04\x11Other payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.trans_recv, 1)
        self.assertEqual (self.r.nodeinfo.counters.node_oor_loss, 1)
        self.assertEvent (events.oor_drop, adjacent_node = Nodeid (1, 2),
                          packet_header = [2, 1278, 1026, 17])
        # Too many visits
        pkt = b"\x02\x03\x04\x02\x04\x1eOther payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.trans_recv, 1)
        self.assertEqual (self.r.nodeinfo.counters.aged_loss, 1)
        self.assertEvent (events.aged_drop, adjacent_node = Nodeid (1, 2),
                          packet_header = [2, 1027, 1026, 30])
        # Similar but rqr set.  The packet will bounce back, and the
        # error counters and count of error events is unchanged from above
        # (i.e., still one).
        # Unreachable destination
        pkt = b"\x0a\x42\x04\x02\x04\x11Other payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.trans_recv, 2)
        self.assertEqual (self.c1.datalink.counters.trans_sent, 1)
        self.assertEqual (self.r.nodeinfo.counters.unreach_loss, 1)
        self.assertEqual (self.eventcount (events.unreach_drop), 1)
        p, dest = self.lastsent (self.d1, 2)
        self.assertEqual (p.encode (), b"\x12\x02\x04\x42\x04\x12Other payload")
        # Node number out of range
        pkt = b"\x0a\xfe\x04\x02\x04\x11Other payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.trans_recv, 3)
        self.assertEqual (self.c1.datalink.counters.trans_sent, 2)
        self.assertEqual (self.r.nodeinfo.counters.node_oor_loss, 1)
        self.assertEqual (self.eventcount (events.oor_drop), 1)
        p, dest = self.lastsent (self.d1, 3)
        self.assertEqual (p.encode (), b"\x12\x02\x04\xfe\x04\x12Other payload")
        # Too many visits
        pkt = b"\x0a\x03\x04\x02\x04\x1eOther payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.trans_recv, 4)
        self.assertEqual (self.c1.datalink.counters.trans_sent, 3)
        self.assertEqual (self.r.nodeinfo.counters.aged_loss, 1)
        self.assertEqual (self.eventcount (events.aged_drop), 1)
        p, dest = self.lastsent (self.d1, 4)
        self.assertEqual (p.encode (), b"\x12\x02\x04\x03\x04\x1fOther payload")
        # Terminating packet
        pkt = b"\x02\x05\x04\x02\x04\x1eOther payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.term_recv, 1)
        w = self.lastdispatch (1, self.node.nsp, itype = Received)
        self.assertEqual (w.packet, b"Other payload")
        self.assertEqual (w.src, Nodeid (1, 2))
        self.assertFalse (w.rts)
        # Originating packet
        self.r.send (b"payload2", Nodeid (1, 2))
        self.assertEqual (self.c1.datalink.counters.orig_sent, 1)
        p, dest = self.lastsent (self.d1, 5)
        self.assertEqual (p.encode (), b"\x02\x02\x04\x05\x04\x00payload2")
        # Originating to the other neighbor
        self.r.send (b"payload2", Nodeid (1, 3))
        self.assertEqual (self.c2.datalink.counters.orig_sent, 1)
        p, dest = self.lastsent (self.d2, 3)
        self.assertEqual (p.encode (), b"\x02\x03\x04\x05\x04\x00payload2")
        # Originating to unreachable
        self.r.send (b"foo", Nodeid (1, 7))
        # FIXME self.assertFalse (ok)
        self.assertEqual (self.c1.datalink.counters.orig_sent, 1)
        self.assertEqual (self.c2.datalink.counters.orig_sent, 1)
        # long data, converted to short when forwarded
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x03\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x02\x04\x00\x11\x00\x00" \
              b"abc payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.trans_recv, 5)
        self.assertEqual (self.c2.datalink.counters.trans_sent, 2)
        p, dest = self.lastsent (self.d2, 4)
        self.assertEqual (p.encode (), b"\x02\x03\x04\x02\x04\x12abc payload")
        
    def test_init_ph3 (self):
        # Send phase3 endnode init
        pkt = b"\x01\x02\x00\x03\x10\x02\x01\x03\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ru3e")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c1.rphase, 3)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        # Make the other neighbor phase 4 endnode
        pkt = b"\x01\x03\x04\x03\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.node.addwork (Received (owner = self.c2, src = self.c2,
                                    packet = pkt))
        self.assertState (self.c2, "ru4e")
        self.assertEqual (self.eventcount (events.circ_up), 2)
        #self.assertEqual (self.eventcount (events.reach_chg), 2)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 3))
        self.assertEvent (events.reach_chg, back = 1,
                          entity = events.NodeEventEntity (Nodeid (1, 3)),
                          status = "reachable")
        self.assertEqual (self.c2.rphase, 4)
        self.assertEqual (self.c2.id, Nodeid (1, 3))
        # Try some forwarded traffic
        # Forward c1 to c2
        pkt = b"\x02\x03\x00\x02\x00\x11Other payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.datalink.counters.trans_recv, 1)
        self.assertEqual (self.c2.datalink.counters.trans_sent, 1)
        p, dest = self.lastsent (self.d2, 2)
        self.assertEqual (p.encode (), b"\x02\x03\x04\x02\x04\x12Other payload")
        # Forward c2 to c1
        pkt = b"\x02\x02\x04\x03\x04\x11ph4 payload"
        self.node.addwork (Received (owner = self.c2, packet = pkt))
        self.assertEqual (self.c2.datalink.counters.trans_recv, 1)
        self.assertEqual (self.c1.datalink.counters.trans_sent, 1)
        p, dest = self.lastsent (self.d1, 3)
        self.assertEqual (p.encode (), b"\x02\x02\x00\x03\x00\x12ph4 payload")

    def test_send_ph2 (self):
        # Send phase2 init to ptp-0
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ru2")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (1, 66))
        self.assertEqual (self.c1.rphase, 2)
        self.assertEqual (self.c1.id, Nodeid (1, 66))
        # Try sending a packet to the neighbor on ptp-0
        self.r.send (b"payload", Nodeid (1, 66))
        p, dest = self.lastsent (self.d1, 3, ptype = bytes)
        self.assertEqual (p, b"payload")
        # Try sending to some other address (not currently reachable)
        self.r.send (b"payload", Nodeid (1, 44))
        # FIXME self.assertFalse (ok)
        self.lastsent (self.d1, 3, ptype = bytes)
        # Now send phase2 init to ptp-1
        pkt = b"\x58\x01\x2c\x05REM44\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.node.addwork (Received (owner = self.c2, src = self.c2,
                                    packet = pkt))
        self.assertState (self.c2, "ru2")
        self.assertEqual (self.eventcount (events.circ_up), 2)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (1, 44))
        self.assertEqual (self.c2.rphase, 2)
        self.assertEqual (self.c2.id, Nodeid (1, 44))
        # Try sending to the new neighbor on ptp-1
        self.r.send (b"payload2", Nodeid (1, 44))
        p, dest = self.lastsent (self.d2, 3, ptype = bytes)
        self.assertEqual (p, b"payload2")

    def test_recvdata_ph2 (self):
        # Send phase2 init on ptp-0
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.node.addwork (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ru2")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (1, 66))
        self.assertEqual (self.c1.rphase, 2)
        self.assertEqual (self.c1.id, Nodeid (1, 66))
        # Deliver a packet.  Note that the first byte needs to be a valid
        # NSP header byte (which this is -- 00 means data segment,
        # no BOP, no EOP).
        pkt = b"\x00abcdef payload"
        self.node.addwork (Received (owner = self.c1, packet = pkt))
        w = self.lastdispatch (1, self.node.nsp, itype = Received)
        self.assertEqual (w.packet, b"\x00abcdef payload")
        self.assertEqual (w.src, Nodeid (1, 66))
        self.assertFalse (w.rts)
        # Send phase2 init on ptp-1
        pkt = b"\x58\x01\x2c\x05REM44\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.node.addwork (Received (owner = self.c2, src = self.c2,
                                    packet = pkt))
        self.assertState (self.c2, "ru2")
        self.assertEqual (self.eventcount (events.circ_up), 2)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (1, 44))
        self.assertEqual (self.c2.rphase, 2)
        self.assertEqual (self.c2.id, Nodeid (1, 44))
        # Deliver a packet.  Note that the first byte needs to be a valid
        # NSP header byte (which this is -- 00 means data segment,
        # no BOP, no EOP).
        pkt = b"\x00Other payload"
        self.node.addwork (Received (owner = self.c2, packet = pkt))
        w = self.lastdispatch (2, self.node.nsp, itype = Received)
        self.assertEqual (w.packet, b"\x00Other payload")
        self.assertEqual (w.src, Nodeid (1, 44))
        self.assertFalse (w.rts)

    def test_sendself (self):
        # Send a packet to our own address
        self.r.send (b"payload", Nodeid (1, 5))
        w = self.lastdispatch (1, self.node.nsp, itype = Received)
        self.assertEqual (w.packet, b"payload")
        self.assertEqual (w.src, Nodeid (1, 5))
        self.assertFalse (w.rts)

class test_random (rtest):
    ntype = "endnode"
    circ = (( "lan-0", True ),)

    def test_random (self):
        src = Nodeid (1, 42)
        for i in range (5000):
            pkt = randpkt (8, 64)
            w = Received (owner = self.c1, src = src, packet = pkt)
            self.node.addwork (w)

class test_random_rtr (test_random):
    ntype = "l2router"

class test_random_ptp (test_random_rtr):
    circ = (( "ptp-0", False ),)
    
if __name__ == "__main__":
    unittest.main ()

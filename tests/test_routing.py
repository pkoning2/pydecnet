#!/usr/bin/env python3

from tests.dntest import *

from decnet.routing_packets import *
from decnet import routing
from decnet import route_ptp
from decnet import datalink
from decnet.timers import Timeout
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
        self.config = container ()
        self.config.routing = container ()
        if self.phase == 4:
            self.config.routing.id = Nodeid (1, 5)
        else:
            self.config.routing.id = Nodeid (5)
        self.config.routing.t1 = 50
        self.config.routing.bct1 = 10
        self.config.routing.maxnodes = 100
        self.config.routing.maxhops = 5
        self.config.routing.maxcost = 20
        self.config.routing.maxvisits = 30
        self.config.circuit = dict ()
        self.node.datalink = container ()
        self.node.datalink.circuits = dict ()
        self.node.nsp = unittest.mock.Mock ()
        self.node.nodeid = self.config.routing.id
        i = 1
        for n, lan in self.circ:
            self.config.circuit[n] = container ()
            self.config.circuit[n].t1 = None
            self.config.circuit[n].t3 = 10
            self.config.circuit[n].cost = 1
            self.config.circuit[n].priority = 32
            self.config.circuit[n].verify = False
            self.node.datalink.circuits[n] = unittest.mock.Mock ()
            if lan:
                self.node.datalink.circuits[n].__class__ = datalink.BcDatalink
        self.config.routing.type = self.ntype
        self.r = routing.Router (self, self.config)
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
    
class test_ethend (rtest):
    ntype = "endnode"
    circ = (( "lan-0", True ),)
    
    def test_dr (self):
        self.assertIsNone (self.c1.dr)
        pkt = b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x04\x02" \
              b"\x10\x02\x40\x00\x80\x00\x00" \
              b"\x0f\x00\x00\x00\x00\x00\x00\x00" \
              b"\x07\xaa\x00\x04\x00\x07\x04\x9f"
        self.c1.dispatch (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        self.assertEqual (self.c1.dr.macid, Macaddr ("aa:00:04:00:02:04"))
        self.assertEqual (self.c1.dr.nodeid, Nodeid (1, 2))
        # Try sending a packet
        ok = self.r.send (b"payload", Nodeid (1, 17))
        self.assertTrue (ok)
        self.assertEqual (self.c1.orig_sent, 1)
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
        ok = self.r.send (b"payload2", Nodeid (3,17))
        self.assertTrue (ok)
        self.assertEqual (self.c1.orig_sent, 2)
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
        self.c1.dispatch (Timeout (owner = self.c1))
        p, dest = self.lastsent (self.d1, 4)
        self.assertIsInstance (p, EndnodeHello)
        self.assertEqual (p.neighbor, Macaddr ("aa:00:04:00:02:04"))
        self.assertEqual (dest, Macaddr ("AB-00-00-03-00-00"))
        # Send timeout to DR adjacency object
        self.c1.dr.dispatch (Timeout (owner = self.c1.dr))
        # Try sending a packet
        ok = self.r.send (b"payload", Nodeid (1,17))
        self.assertTrue (ok)
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
        self.c1.dispatch (Timeout (owner = self.c1))
        p, dest = self.lastsent (self.d1, 6)
        self.assertIsInstance (p, EndnodeHello)
        self.assertEqual (p.neighbor, NULLID)
        self.assertEqual (dest, Macaddr ("AB-00-00-03-00-00"))
        # Try sending a packet.  Note that out of area makes no difference.
        ok = self.r.send (b"payload2", Nodeid (3,17))
        self.assertTrue (ok)
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
        self.c1.dispatch (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        self.assertEqual (self.c1.term_recv, 1)
        w = self.lastwork (1)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        self.assertEqual (len (self.c1.prevhops), 1)
        self.assertEqual (self.c1.prevhops[Nodeid (2, 1)].prevhop,
                          Macaddr ("aa:00:04:00:02:04"))
        # ditto but with padding
        pkt = b"\x88Testing\x02\x05\x04\x01\x08\x11abcdef payload"
        self.c1.dispatch (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:07:04"),
                                   packet = pkt))
        self.assertEqual (self.c1.term_recv, 2)
        w = self.lastwork (2)
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
        self.c1.dispatch (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        # Check that last received count doesn't change
        self.assertEqual (self.c1.term_recv, 2)
        self.lastwork (2)
        
    def test_longdata (self):
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x05\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c1.dispatch (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        self.assertEqual (self.c1.term_recv, 1)
        w = self.lastwork (1)
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
        self.c1.dispatch (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:07:04"),
                                   packet = pkt))
        self.assertEqual (self.c1.term_recv, 2)
        w = self.lastwork (2)
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
        self.c1.dispatch (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        # Check that last received count doesn't change
        self.lastwork (2)
        self.assertEqual (self.c1.term_recv, 2)
        
class test_ptpend (rtest):
    ntype = "endnode"
    circ = (( "ptp-0", False ),)

    def setUp (self):
        super ().setUp ()
        self.assertState ("ha")
        w = self.lastwork (1, itype = route_ptp.Start)
        self.c1.dispatch (w)
        self.assertState ("ds")
        self.c1.dispatch (datalink.DlStatus (owner = self.c1, status = True))
        self.assertState ("ri")        
        
    def assertState (self, name):
        self.assertEqual (self.c1.state.__name__, name, "Circuit state")
    
    def test_send_ph4 (self):
        # Send phase4 init
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c1.rphase, 4)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        # Try sending a packet
        ok = self.r.send (b"payload", Nodeid (1,17))
        self.assertTrue (ok)
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
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c1.rphase, 4)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        pkt = b"\x02\x05\x04\x01\x08\x11abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.term_recv, 1)
        w = self.lastwork (2)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # ditto but with padding
        pkt = b"\x88Testing\x02\x05\x04\x01\x08\x11Other payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.term_recv, 2)
        w = self.lastwork (3)
        spkt = w.packet
        self.assertEqual (w.packet, b"Other payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # Packet for wrong address
        pkt = b"\x02\x01\x04\x01\x08\x11abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        # Check that last received count doesn't change
        self.assertEqual (self.c1.term_recv, 2)
        self.lastwork (3)

    def test_longdata_ph4 (self):
        # Send phase4 init
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c1.rphase, 4)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x05\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.term_recv, 1)
        w = self.lastwork (2)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # ditto but with padding
        pkt = b"\x88Testing\x26\x00\x00\xaa\x00\x04\x00\x05\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"Other payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.term_recv, 2)
        w = self.lastwork (3)
        spkt = w.packet
        self.assertEqual (w.packet, b"Other payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # Packet for wrong address is ignored
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x01\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        # Check that last received count doesn't change
        self.assertEqual (self.c1.term_recv, 2)
        self.lastwork (3)
    
    def test_send_ph3 (self):
        # Send phase3 init
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c1.rphase, 3)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        # Try sending a packet
        ok = self.r.send (b"payload", Nodeid (1, 17))
        self.assertTrue (ok)
        self.assertEqual (self.c1.orig_sent, 1)        
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
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c1.rphase, 3)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        pkt = b"\x02\x05\x00\x01\x08\x11abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.term_recv, 1)
        w = self.lastwork (2)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # Packet with padding, should be ignored as invalid
        pkt = b"\x88Testing\x02\x05\x00\x01\x00\x11Other payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.term_recv, 1)
        self.lastwork (2)
        self.assertEvent (events.fmt_err, 
                          packet_beginning = b"\x88Testi")
        # Packet for wrong address
        pkt = b"\x02\x01\x00\x01\x08\x11abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        # Check that last received count doesn't change
        self.assertEqual (self.c1.term_recv, 1)
        self.lastwork (2)

    def test_longdata_ph3 (self):
        # Send phase3 init
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c1.rphase, 3)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x05\x00" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.term_recv, 1)
        w = self.lastwork (2)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # Packet with padding, should be ignored as invalid
        pkt = b"\x88Testing\x26\x00\x00\xaa\x00\x04\x00\x05\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"Other payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.term_recv, 1)
        self.lastwork (2)
        self.assertEvent (events.fmt_err, 
                          packet_beginning = b"\x88Testi")
        # Packet for wrong address is ignored
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x01\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        # Check that last received count doesn't change
        self.assertEqual (self.c1.term_recv, 1)
        self.lastwork (2)
        
    def test_send_ph2 (self):
        # Send phase2 init
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (1, 66))
        self.assertEqual (self.c1.rphase, 2)
        self.assertEqual (self.c1.id, Nodeid (1, 66))
        # Try sending a packet
        ok = self.r.send (b"payload", Nodeid (1, 66))
        self.assertTrue (ok)
        self.assertEqual (self.c1.orig_sent, 1)
        p, dest = self.lastsent (self.d1, 3, ptype = bytes)
        self.assertEqual (p, b"payload")
        ok = self.r.send (b"payload", Nodeid (1, 44))
        self.assertFalse (ok)
        self.lastsent (self.d1, 3, ptype = bytes)

    def test_recvdata_ph2 (self):
        # Send phase2 init
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (1, 66))
        self.assertEqual (self.c1.rphase, 2)
        self.assertEqual (self.c1.id, Nodeid (1, 66))
        # Deliver a packet.  Note that the first byte needs to be a valid
        # NSP header byte (which this is -- 00 means data segment,
        # no BOP, no EOP).
        pkt = b"\x00abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.term_recv, 1)
        w = self.lastwork (2)
        self.assertEqual (w.packet, b"\x00abcdef payload")
        self.assertEqual (w.src, Nodeid (1, 66))
        self.assertFalse (w.rts)
        
class test_ph2 (rtest):
    ntype = "phase2"
    phase = 2
    circ = (( "ptp-0", False ),
            ( "ptp-1", False ))

    def setUp (self):
        super ().setUp ()
        self.assertState (self.c1, "ha")
        self.assertState (self.c2, "ha")
        w1 = self.lastwork (2, back = 1, itype = route_ptp.Start)
        w2 = self.lastwork (2, itype = route_ptp.Start)
        self.c1.dispatch (w1)
        self.assertState (self.c1, "ds")
        self.c1.dispatch (datalink.DlStatus (owner = self.c1, status = True))
        self.assertState (self.c1, "ri")        
        self.c2.dispatch (w2)
        self.assertState (self.c2, "ds")
        self.c2.dispatch (datalink.DlStatus (owner = self.c2, status = True))
        self.assertState (self.c2, "ri")        
        
    def assertState (self, c, name):
        self.assertEqual (c.state.__name__, name, "Circuit state")
    
    def test_init_ph4 (self):
        # Send phase4 init
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ri")
        self.assertEqual (self.eventcount (events.circ_up), 0)

    def test_init_ph3 (self):
        # Send phase3 init
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ri")
        self.assertEqual (self.eventcount (events.circ_up), 0)

    def test_send_ph2 (self):
        # Send phase2 init to ptp-0
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ru")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (66))
        self.assertEqual (self.c1.rphase, 2)
        self.assertEqual (self.c1.id, Nodeid (66))
        # Try sending a packet to the neighbor on ptp-0
        ok = self.r.send (b"payload", Nodeid (66))
        self.assertTrue (ok)
        self.assertEqual (self.c1.orig_sent, 1)
        p, dest = self.lastsent (self.d1, 2, ptype = bytes)
        self.assertEqual (p, b"payload")
        # Try sending to some other address (not currently reachable)
        ok = self.r.send (b"payload", Nodeid (44))
        self.assertFalse (ok)
        self.lastsent (self.d1, 2, ptype = bytes)
        # Now send phase2 init to ptp-1
        pkt = b"\x58\x01\x2c\x05REM44\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c2.dispatch (Received (owner = self.c2, src = self.c2,
                                    packet = pkt))
        self.assertState (self.c2, "ru")
        self.assertEqual (self.eventcount (events.circ_up), 2)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (44))
        self.assertEqual (self.c2.rphase, 2)
        self.assertEqual (self.c2.id, Nodeid (44))
        # Try sending to the new neighbor on ptp-1
        ok = self.r.send (b"payload2", Nodeid (44))
        self.assertTrue (ok)
        self.assertEqual (self.c2.orig_sent, 1)
        p, dest = self.lastsent (self.d2, 2, ptype = bytes)
        self.assertEqual (p, b"payload2")

    def test_recvdata_ph2 (self):
        # Send phase2 init on ptp-0
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ru")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (66))
        self.assertEqual (self.c1.rphase, 2)
        self.assertEqual (self.c1.id, Nodeid (66))
        # Deliver a packet.  Note that the first byte needs to be a valid
        # NSP header byte (which this is -- 00 means data segment,
        # no BOP, no EOP).
        pkt = b"\x00abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.term_recv, 1)
        w = self.lastwork (3)
        self.assertEqual (w.packet, b"\x00abcdef payload")
        self.assertEqual (w.src, Nodeid (66))
        self.assertFalse (w.rts)
        # Send phase2 init on ptp-1
        pkt = b"\x58\x01\x2c\x05REM44\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c2.dispatch (Received (owner = self.c2, src = self.c2,
                                    packet = pkt))
        self.assertState (self.c2, "ru")
        self.assertEqual (self.eventcount (events.circ_up), 2)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (44))
        self.assertEqual (self.c2.rphase, 2)
        self.assertEqual (self.c2.id, Nodeid (44))
        # Deliver a packet.  Note that the first byte needs to be a valid
        # NSP header byte (which this is -- 00 means data segment,
        # no BOP, no EOP).
        pkt = b"\x00Other payload"
        self.c2.dispatch (Received (owner = self.c2, packet = pkt))
        self.assertEqual (self.c2.term_recv, 1)
        w = self.lastwork (4)
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
        self.assertState (self.c1, "ha")
        self.assertState (self.c2, "ha")
        w1 = self.lastwork (2, back = 1, itype = route_ptp.Start)
        w2 = self.lastwork (2, itype = route_ptp.Start)
        self.c1.dispatch (w1)
        self.assertState (self.c1, "ds")
        self.c1.dispatch (datalink.DlStatus (owner = self.c1, status = True))
        self.assertState (self.c1, "ri")        
        self.c2.dispatch (w2)
        self.assertState (self.c2, "ds")
        self.c2.dispatch (datalink.DlStatus (owner = self.c2, status = True))
        self.assertState (self.c2, "ri")        
        
    def assertState (self, c, name):
        self.assertEqual (c.state.__name__, name, "Circuit state")

    def test_init_ph4 (self):
        # Send phase4 init for endnode
        pkt = b"\x01\x02\x04\x03\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ru")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEqual (self.eventcount (events.reach_chg), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEvent (events.reach_chg, back = 1,
                          entity = Nodeid (1, 2), status = "reachable")
        self.assertEqual (self.c1.rphase, 4)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        pkt = b"\x01\x03\x04\x03\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c2.dispatch (Received (owner = self.c2, src = self.c2,
                                    packet = pkt))
        self.assertState (self.c2, "ru")
        self.assertEqual (self.eventcount (events.circ_up), 2)
        self.assertEqual (self.eventcount (events.reach_chg), 2)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 3))
        self.assertEvent (events.reach_chg, back = 1,
                          entity = Nodeid (1, 3), status = "reachable")
        self.assertEqual (self.c2.rphase, 4)
        self.assertEqual (self.c2.id, Nodeid (1, 3))
        # Try some forwarded traffic
        # Forward c1 to c2
        pkt = b"\x88Testing\x02\x03\x04\x02\x04\x11Other payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.trans_recv, 1)
        self.assertEqual (self.c2.trans_sent, 1)
        p, dest = self.lastsent (self.d2, 2)
        self.assertEqual (p.encode (), b"\x02\x03\x04\x02\x04\x12Other payload")
        # Unreachable destination
        pkt = b"\x02\x42\x04\x02\x04\x11Other payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.trans_recv, 1)
        self.assertEqual (self.r.unreach_loss, 1)
        self.assertEvent (events.unreach_drop, adjacent_node = Nodeid (1, 2),
                          packet_header = (2, 1090, 1026, 17))
        # Node number out of range
        pkt = b"\x02\xfe\x04\x02\x04\x11Other payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.trans_recv, 1)
        self.assertEqual (self.r.node_oor_loss, 1)
        self.assertEvent (events.oor_drop, adjacent_node = Nodeid (1, 2),
                          packet_header = (2, 1278, 1026, 17))
        # Too many visits
        pkt = b"\x02\x03\x04\x02\x04\x1eOther payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.trans_recv, 1)
        self.assertEqual (self.r.aged_loss, 1)
        self.assertEvent (events.aged_drop, adjacent_node = Nodeid (1, 2),
                          packet_header = (2, 1027, 1026, 30))
        # Similar but rqr set.  The packet will bounce back, and the
        # error counters and count of error events is unchanged from above
        # (i.e., still one).
        # Unreachable destination
        pkt = b"\x0a\x42\x04\x02\x04\x11Other payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.trans_recv, 2)
        self.assertEqual (self.c1.trans_sent, 1)
        self.assertEqual (self.r.unreach_loss, 1)
        self.assertEqual (self.eventcount (events.unreach_drop), 1)
        p, dest = self.lastsent (self.d1, 2)
        self.assertEqual (p.encode (), b"\x12\x02\x04\x42\x04\x12Other payload")
        # Node number out of range
        pkt = b"\x0a\xfe\x04\x02\x04\x11Other payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.trans_recv, 3)
        self.assertEqual (self.c1.trans_sent, 2)
        self.assertEqual (self.r.node_oor_loss, 1)
        self.assertEqual (self.eventcount (events.oor_drop), 1)
        p, dest = self.lastsent (self.d1, 3)
        self.assertEqual (p.encode (), b"\x12\x02\x04\xfe\x04\x12Other payload")
        # Too many visits
        pkt = b"\x0a\x03\x04\x02\x04\x1eOther payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.trans_recv, 4)
        self.assertEqual (self.c1.trans_sent, 3)
        self.assertEqual (self.r.aged_loss, 1)
        self.assertEqual (self.eventcount (events.aged_drop), 1)
        p, dest = self.lastsent (self.d1, 4)
        self.assertEqual (p.encode (), b"\x12\x02\x04\x03\x04\x1fOther payload")
        # Terminating packet
        pkt = b"\x02\x05\x04\x02\x04\x1eOther payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.term_recv, 1)
        w = self.lastwork (3)
        self.assertEqual (w.packet, b"Other payload")
        self.assertEqual (w.src, Nodeid (1, 2))
        self.assertFalse (w.rts)
        # Originating packet
        ok = self.r.send (b"payload2", Nodeid (1, 2))
        self.assertTrue (ok)
        self.assertEqual (self.c1.orig_sent, 1)
        p, dest = self.lastsent (self.d1, 5)
        self.assertEqual (p.encode (), b"\x02\x02\x04\x05\x04\x00payload2")
        # Originating to the other neighbor
        ok = self.r.send (b"payload2", Nodeid (1, 3))
        self.assertTrue (ok)
        self.assertEqual (self.c2.orig_sent, 1)
        p, dest = self.lastsent (self.d2, 3)
        self.assertEqual (p.encode (), b"\x02\x03\x04\x05\x04\x00payload2")
        # Originating to unreachable
        ok = self.r.send (b"foo", Nodeid (1, 7))
        self.assertFalse (ok)
        self.assertEqual (self.c1.orig_sent, 1)
        self.assertEqual (self.c2.orig_sent, 1)
        # long data, converted to short when forwarded
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x03\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x02\x04\x00\x11\x00\x00" \
              b"abc payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.trans_recv, 5)
        self.assertEqual (self.c2.trans_sent, 2)
        p, dest = self.lastsent (self.d2, 4)
        self.assertEqual (p.encode (), b"\x02\x03\x04\x02\x04\x12abc payload")
        
    def test_init_ph3 (self):
        # Send phase3 endnode init
        pkt = b"\x01\x02\x00\x03\x10\x02\x01\x03\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ru")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c1.rphase, 3)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        # Make the other neighbor phase 4
        pkt = b"\x01\x03\x04\x03\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c2.dispatch (Received (owner = self.c2, src = self.c2,
                                    packet = pkt))
        self.assertState (self.c2, "ru")
        self.assertEqual (self.eventcount (events.circ_up), 2)
        #self.assertEqual (self.eventcount (events.reach_chg), 2)
        self.assertEvent (events.circ_up, adjacent_node = Nodeid (1, 3))
        #self.assertEvent (events.reach_chg, back = 1,
        #                  entity = Nodeid (1, 3), status = "reachable")
        self.assertEqual (self.c2.rphase, 4)
        self.assertEqual (self.c2.id, Nodeid (1, 3))
        # Try some forwarded traffic
        # Forward c1 to c2
        pkt = b"\x02\x03\x00\x02\x00\x11Other payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        self.assertEqual (self.c1.trans_recv, 1)
        self.assertEqual (self.c2.trans_sent, 1)
        p, dest = self.lastsent (self.d2, 2)
        self.assertEqual (p.encode (), b"\x02\x03\x04\x02\x04\x12Other payload")
        # Forward c2 to c1
        pkt = b"\x02\x02\x04\x03\x04\x11ph4 payload"
        self.c2.dispatch (Received (owner = self.c2, packet = pkt))
        self.assertEqual (self.c2.trans_recv, 1)
        self.assertEqual (self.c1.trans_sent, 1)
        p, dest = self.lastsent (self.d1, 3)
        self.assertEqual (p.encode (), b"\x02\x02\x00\x03\x00\x12ph4 payload")

    def test_send_ph2 (self):
        # Send phase2 init to ptp-0
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ru")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (1, 66))
        self.assertEqual (self.c1.rphase, 2)
        self.assertEqual (self.c1.id, Nodeid (1, 66))
        # Try sending a packet to the neighbor on ptp-0
        ok = self.r.send (b"payload", Nodeid (1, 66))
        self.assertTrue (ok)
        p, dest = self.lastsent (self.d1, 3, ptype = bytes)
        self.assertEqual (p, b"payload")
        # Try sending to some other address (not currently reachable)
        ok = self.r.send (b"payload", Nodeid (1, 44))
        self.assertFalse (ok)
        self.lastsent (self.d1, 3, ptype = bytes)
        # Now send phase2 init to ptp-1
        pkt = b"\x58\x01\x2c\x05REM44\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c2.dispatch (Received (owner = self.c2, src = self.c2,
                                    packet = pkt))
        self.assertState (self.c2, "ru")
        self.assertEqual (self.eventcount (events.circ_up), 2)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (1, 44))
        self.assertEqual (self.c2.rphase, 2)
        self.assertEqual (self.c2.id, Nodeid (1, 44))
        # Try sending to the new neighbor on ptp-1
        ok = self.r.send (b"payload2", Nodeid (1, 44))
        self.assertTrue (ok)
        p, dest = self.lastsent (self.d2, 3, ptype = bytes)
        self.assertEqual (p, b"payload2")

    def test_recvdata_ph2 (self):
        # Send phase2 init on ptp-0
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState (self.c1, "ru")
        self.assertEqual (self.eventcount (events.circ_up), 1)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (1, 66))
        self.assertEqual (self.c1.rphase, 2)
        self.assertEqual (self.c1.id, Nodeid (1, 66))
        # Deliver a packet.  Note that the first byte needs to be a valid
        # NSP header byte (which this is -- 00 means data segment,
        # no BOP, no EOP).
        pkt = b"\x00abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        w = self.lastwork (3)
        self.assertEqual (w.packet, b"\x00abcdef payload")
        self.assertEqual (w.src, Nodeid (1, 66))
        self.assertFalse (w.rts)
        # Send phase2 init on ptp-1
        pkt = b"\x58\x01\x2c\x05REM44\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c2.dispatch (Received (owner = self.c2, src = self.c2,
                                    packet = pkt))
        self.assertState (self.c2, "ru")
        self.assertEqual (self.eventcount (events.circ_up), 2)
        self.assertEvent (events.circ_up,
                          adjacent_node = Nodeid (1, 44))
        self.assertEqual (self.c2.rphase, 2)
        self.assertEqual (self.c2.id, Nodeid (1, 44))
        # Deliver a packet.  Note that the first byte needs to be a valid
        # NSP header byte (which this is -- 00 means data segment,
        # no BOP, no EOP).
        pkt = b"\x00Other payload"
        self.c2.dispatch (Received (owner = self.c2, packet = pkt))
        w = self.lastwork (4)
        self.assertEqual (w.packet, b"\x00Other payload")
        self.assertEqual (w.src, Nodeid (1, 44))
        self.assertFalse (w.rts)

if __name__ == "__main__":
    unittest.main ()

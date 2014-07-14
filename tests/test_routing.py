#!/usr/bin/env python3

from tests.dntest import *

import logging

from decnet.routing_packets import *
from decnet import routing
from decnet import route_ptp
from decnet import datalink
from decnet.timers import Timeout
from decnet.node import Nodeinfo

rcount = 5000
rmin = 0
rmax = 40
    
class rtest (DnTest):
    phase = 4
    
    def setUp (self):
        super ().setUp ()
        self.node.phase = self.phase
        self.selfinfo = Nodeinfo (None, id = Nodeid (1, 5))
        self.selfinfo.nodename = "testnd"
        self.nodeinfo = unittest.mock.Mock ()
        self.nodeinfo.return_value = self.selfinfo
        self.config = container ()
        self.config.routing = container ()
        self.config.routing.id = Nodeid (1, 5)
        self.config.routing.t1 = 50
        self.config.routing.bct1 = 10
        self.config.circuit = dict ()
        self.node.datalink.circuits = dict ()
        i = 1
        for n, lan in self.circ:
            self.config.circuit[n] = container ()
            self.config.circuit[n].t3 = 10
            self.config.circuit[n].cost = 1
            self.config.circuit[n].priority = 32
            self.config.circuit[n].verify = False
            self.node.datalink.circuits = dict ()
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
            c.log_up = unittest.mock.Mock ()
            c.log_down = unittest.mock.Mock ()
            c.log_adj_up = unittest.mock.Mock ()
            c.log_adj_down = unittest.mock.Mock ()
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
        # Try sending a packet
        self.r.send (b"payload", Nodeid (1,17))
        p, dest = self.lastsent (self.d1, 2)
        self.assertIsInstance (p, LongData)
        self.assertEqual (p.dstnode, Nodeid (1,17))
        self.assertEqual (p.srcnode, Nodeid (1,5))
        self.assertEqual (p.visit, 0)
        self.assertFalse (p.rqr)
        self.assertFalse (p.rts)
        self.assertTrue (p.ie)
        self.assertEqual (dest, Macaddr ("aa:00:04:00:02:04"))
        # Note that change of DR doesn't generate a new endnode hello,
        # so do a hello timer expiration to get one.
        self.c1.dispatch (Timeout (owner = self.c1))
        p, dest = self.lastsent (self.d1, 3)
        self.assertIsInstance (p, EndnodeHello)
        self.assertEqual (p.neighbor, Macaddr ("aa:00:04:00:02:04"))
        self.assertEqual (dest, Macaddr ("AB-00-00-03-00-00"))
        # Send timeout to DR adjacency object
        self.c1.dr.dispatch (Timeout (owner = self.c1.dr))
        self.c1.dispatch (Timeout (owner = self.c1))
        p, dest = self.lastsent (self.d1, 4)
        self.assertIsInstance (p, EndnodeHello)
        self.assertEqual (p.neighbor, NULLID)
        self.assertEqual (dest, Macaddr ("AB-00-00-03-00-00"))
        # Try sending a packet.  Note that out of area makes no difference.
        self.r.send (b"payload", Nodeid (3,17))
        p, dest = self.lastsent (self.d1, 5)
        self.assertIsInstance (p, LongData)
        self.assertEqual (p.dstnode, Nodeid (3,17))
        self.assertEqual (p.srcnode, Nodeid (1,5))
        self.assertEqual (p.visit, 0)
        self.assertFalse (p.rqr)
        self.assertFalse (p.rts)
        self.assertTrue (p.ie)
        self.assertEqual (dest, Macaddr ("aa:00:04:00:11:0c"))
        
    def test_shortdata (self):
        pkt = b"\x02\x05\x04\x01\x08\x11abcdef payload"
        self.c1.dispatch (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        w = self.lastwork (1)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        self.assertEqual (len (self.c1.prevhops), 1)
        self.assertEqual (self.c1.prevhops[Nodeid (2, 1)].prevhop,
                          Macaddr (Nodeid (1, 2)))
        # ditto but with padding
        pkt = b"\x88Testing\x02\x05\x04\x01\x08\x11abcdef payload"
        self.c1.dispatch (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:07:04"),
                                   packet = pkt))
        w = self.lastwork (2)
        spkt = w.packet
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # Check that the previous hop cache was updated
        self.assertEqual (len (self.c1.prevhops), 1)
        self.assertEqual (self.c1.prevhops[Nodeid (2, 1)].prevhop,
                          Macaddr (Nodeid (1, 7)))
        # Packet for wrong address is ignored
        pkt = b"\x02\x01\x04\x01\x08\x11abcdef payload"
        self.c1.dispatch (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        # Check that last received count doesn't change
        self.lastwork (2)
        
    def test_longdata (self):
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x05\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c1.dispatch (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        w = self.lastwork (1)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        self.assertEqual (len (self.c1.prevhops), 1)
        self.assertEqual (self.c1.prevhops[Nodeid (2, 1)].prevhop,
                          Macaddr (Nodeid (1, 2)))
        # ditto but with padding
        pkt = b"\x88Testing\x26\x00\x00\xaa\x00\x04\x00\x05\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"Other payload"
        self.c1.dispatch (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:07:04"),
                                   packet = pkt))
        w = self.lastwork (2)
        spkt = w.packet
        self.assertEqual (w.packet, b"Other payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # Check that the previous hop cache was updated
        self.assertEqual (len (self.c1.prevhops), 1)
        self.assertEqual (self.c1.prevhops[Nodeid (2, 1)].prevhop,
                          Macaddr (Nodeid (1, 7)))
        # Packet for wrong address is ignored
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x01\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c1.dispatch (Received (owner = self.c1,
                                   src = Macaddr ("aa:00:04:00:02:04"),
                                   packet = pkt))
        # Check that last received count doesn't change
        self.lastwork (2)
        
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
        self.assertEqual (self.c1.log_adj_up.call_count, 1)
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

    def test_shortdata_ph4 (self):
        # Send phase4 init
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c1.log_adj_up.call_count, 1)
        self.assertEqual (self.c1.rphase, 4)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        pkt = b"\x02\x05\x04\x01\x08\x11abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        w = self.lastwork (2)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # ditto but with padding
        pkt = b"\x88Testing\x02\x05\x04\x01\x08\x11Other payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        w = self.lastwork (3)
        spkt = w.packet
        self.assertEqual (w.packet, b"Other payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # Packet for wrong address
        pkt = b"\x02\x01\x04\x01\x08\x11abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        # Check that last received count doesn't change
        self.lastwork (3)

    def test_longdata_ph4 (self):
        # Send phase4 init
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c1.log_adj_up.call_count, 1)
        self.assertEqual (self.c1.rphase, 4)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x05\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        w = self.lastwork (2)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # ditto but with padding
        pkt = b"\x88Testing\x26\x00\x00\xaa\x00\x04\x00\x05\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"Other payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
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
        self.lastwork (3)
    
    def test_send_ph3 (self):
        # Send phase3 init
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c1.log_adj_up.call_count, 1)
        self.assertEqual (self.c1.rphase, 3)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        # Try sending a packet
        self.r.send (b"payload", Nodeid (1, 17))
        p, dest = self.lastsent (self.d1, 3)
        self.assertIsInstance (p, ShortData)
        self.assertEqual (p.dstnode, Nodeid (17))
        self.assertEqual (p.srcnode, Nodeid (5))
        self.assertEqual (p.visit, 0)
        self.assertFalse (p.rqr)
        self.assertFalse (p.rts)

    def test_shortdata_ph3 (self):
        # Send phase3 init
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c1.log_adj_up.call_count, 1)
        self.assertEqual (self.c1.rphase, 3)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        pkt = b"\x02\x05\x00\x01\x08\x11abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        w = self.lastwork (2)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # ditto but with padding
        pkt = b"\x88Testing\x02\x05\x00\x01\x00\x11Other payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        w = self.lastwork (3)
        spkt = w.packet
        self.assertEqual (w.packet, b"Other payload")
        self.assertEqual (w.src, Nodeid (1, 1))
        self.assertFalse (w.rts)
        # Packet for wrong address
        pkt = b"\x02\x01\x00\x01\x08\x11abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        # Check that last received count doesn't change
        self.lastwork (3)

    def test_longdata_ph3 (self):
        # Send phase3 init
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c1.log_adj_up.call_count, 1)
        self.assertEqual (self.c1.rphase, 3)
        self.assertEqual (self.c1.id, Nodeid (1, 2))
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x05\x00" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        w = self.lastwork (2)
        self.assertEqual (w.packet, b"abcdef payload")
        self.assertEqual (w.src, Nodeid (2, 1))
        self.assertFalse (w.rts)
        # ditto but with padding
        pkt = b"\x88Testing\x26\x00\x00\xaa\x00\x04\x00\x05\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"Other payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
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
        self.lastwork (3)
        
    def test_send_ph2 (self):
        # Send phase2 init
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c1.log_adj_up.call_count, 1)
        self.assertEqual (self.c1.rphase, 2)
        self.assertEqual (self.c1.id, Nodeid (1, 66))
        # Try sending a packet
        self.r.send (b"payload", Nodeid (1, 66))
        p, dest = self.lastsent (self.d1, 3, ptype = type (b""))
        self.assertEqual (p, b"payload")

    def test_recvdata_ph2 (self):
        # Send phase2 init
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c1.dispatch (Received (owner = self.c1, src = self.c1,
                                    packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c1.log_adj_up.call_count, 1)
        self.assertEqual (self.c1.rphase, 2)
        self.assertEqual (self.c1.id, Nodeid (1, 66))
        pkt = b"\x00abcdef payload"
        self.c1.dispatch (Received (owner = self.c1, packet = pkt))
        w = self.lastwork (2)
        self.assertEqual (w.packet, b"\x00abcdef payload")
        self.assertEqual (w.src, Nodeid (1, 66))
        self.assertFalse (w.rts)

if __name__ == "__main__":
    unittest.main ()

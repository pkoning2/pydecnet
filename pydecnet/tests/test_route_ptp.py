#!/usr/bin/env python3

from tests.dntest import *

import queue

from decnet.routing_packets import *
from decnet import route_ptp
from decnet import routing
from decnet import datalink
from decnet.timers import Timeout
from decnet.node import Nodeinfo
from decnet.nice import NiceNode

rcount = 5000
rmin = 0
rmax = 30

class rtest (DnTest):

    def setUp (self):
        super ().setUp ()
        self.r = unittest.mock.Mock ()
        self.r.node = self.node
        # Counters:
        self.r.unreach_loss = self.r.aged_loss = self.r.node_oor_loss = 0
        self.r.oversized_loss = self.r.partial_update_loss = 0
        self.r.fmt_errors = self.r.ver_rejects = 0        
        if self.phase == 4:
            self.r.nodeid = Nodeid (1, 5)
        else:
            self.r.nodeid = Nodeid (5)
        self.r.homearea, self.r.tid = self.r.nodeid.split ()
        info = Nodeinfo (None, self.r.nodeid)
        info.nodename = "LOCAL"
        self.node.addnodeinfo (info)
        info = Nodeinfo (None, Nodeid (66))
        info.nodename = "REMOTE"
        info.iverif = b"IVERIF"
        info.overif = b"OVERIF"
        self.node.addnodeinfo (info)
        info = Nodeinfo (None, Nodeid (1, 66))
        info.nodename = "REMOTE"
        info.iverif = b"IVERIF"
        info.overif = b"OVERIF"
        self.node.addnodeinfo (info)
        info = Nodeinfo (None, Nodeid (2))
        info.iverif = b"IVERIF"
        info.overif = b"OVERIF"
        self.node.addnodeinfo (info)
        info = Nodeinfo (None, Nodeid (1, 2))
        info.iverif = b"IVERIF"
        info.overif = b"OVERIF"
        self.node.addnodeinfo (info)
        self.node.addwork.side_effect = self.t_addwork
        self.workqueue = queue.Queue ()
        self.dl = unittest.mock.Mock ()
        self.cp = unittest.mock.Mock ()
        self.cp.start_works = True
        self.dl.create_port.return_value = self.cp
        self.config = container ()
        self.config.t1 = 300
        self.config.t3 = 10
        self.config.cost = 1
        self.config.verify = self.verify
        self.r.phase = self.node.phase = self.phase
        self.r.tiver = self.tiver
        self.r.ntype = self.ntype
        self.r.maxnodes = 200
        self.r.maxarea = 10
        self.r.name = b"TEST"
        self.c = routing.PtpEndnodeCircuit (self.r, "ptp-0",
                                            self.dl, self.config)
        self.c.routing = self.r
        self.c.t3 = 15
        #self.c.term_recv = self.c.orig_sent = 0
        #self.c.trans_recv = self.c.trans_sent = 0
        #self.c.cir_down = self.c.adj_down = self.c.init_fail = 0
        self.c.start ()
        self.assertState ("ha")
        self.dispatch ()
        self.assertState ("ds")
        self.c.dispatch (datalink.DlStatus (owner = self.c, status = True))
        self.assertState ("ri")        

    def tearDown (self):
        self.c.stop ()
        self.dispatch ()
        self.assertState ("ha")
        super ().tearDown ()

    def assertState (self, name):
        self.assertEqual (self.c.state.__name__, name, "Circuit state")
    
    def t_addwork (self, work, handler = None):
        if handler is not None:
            work.owner = handler
        self.workqueue.put (work)

    def dispatch (self):
        try:
            while True:
                work = self.workqueue.get_nowait ()
                work.dispatch ()
        except queue.Empty:
            pass

    def shortpackets (self, pkt):
        for l in range (len (pkt) - 1):
            self.c.dispatch (Received (owner = self.c, src = self.c,
                                       packet = pkt[:l]))
            self.assertIn (self.c.state.__name__, {"ha", "ri"}, "Circuit state")
            if self.c.state == self.c.ha:
                self.dispatch ()
                self.assertState ("ds")
                self.c.dispatch (datalink.DlStatus (owner = self.c,
                                                    status = True))
            self.assertState ("ri")

class test_ph2 (rtest):
    phase = 2
    tiver = tiver_ph2
    ntype = PHASE2
    verify = False

    def startup (self):
        p, x = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, NodeInit)
        self.assertEqual (p.nodename, b"TEST")
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEvent (events.circ_up,
                          adjacent_node = ( 66, "REMOTE" ))
        self.assertEqual (self.c.rphase, 2)
        self.assertEqual (self.c.id, Nodeid (66))

    def test_noverify (self):
        self.startup ()
        pkt = b"\x08\252\252\252"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (1, element = self.r)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, pkt)
        self.assertEqual (spkt.srcnode, Nodeid (66))
        self.assertEqual (spkt.dstnode, self.r.nodeid)
        self.assertEqual (spkt.visit, 1)
        self.c.dispatch (Timeout (owner = self.c))
        p, x = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, NopMsg)
        self.assertRegex (p.payload, b"^\252+$")

    def test_extadr (self):
        # Phase 2 init has address in an EX-2 field, so if it's 128 or above
        # it takes 2 bytes rather than 1.
        pkt = b"\x58\x01\x82\x01\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEvent (events.circ_up, adjacent_node = 130)
        self.assertEqual (self.c.rphase, 2)
        self.assertEqual (self.c.id, Nodeid (130))
        # Deliver an incoming packet
        pkt = b"\x08\252\252\252"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (1, element = self.r)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, pkt)
        self.assertEqual (spkt.srcnode, Nodeid (130))
        self.assertEqual (spkt.dstnode, self.r.nodeid)
        self.assertEqual (spkt.visit, 1)
        # Deliver an incoming packet, with route header
        pkt = b"\x42\x05LOCAL\x06REMOTE\x08\252\252\252"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (2, element = self.r)
        self.assertIsInstance (spkt, ShortData)
        # Payload will be just the part after the route header
        self.assertEqual (spkt.payload, b"\x08\252\252\252")
        self.assertEqual (spkt.srcnode, Nodeid (130))
        self.assertEqual (spkt.dstnode, self.r.nodeid)
        self.assertEqual (spkt.visit, 1)
        # Try a bad route header
        pkt = b"\x42\xf5LOCAL\x06REMOTE\x08\252\252\252"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.lastdispatch (2, element = self.r)
        self.assertEvent (events.fmt_err, 
                          packet_beginning = b"\x42\xf5LOCA")

    def test_send (self):
        self.startup ()
        pkt = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (66),
                         srcnode = Nodeid (5), visit = 1,
                         payload = b"new payload")
        ok = self.c.send (pkt, pkt.dstnode)
        self.assertTrue (ok)
        p, dest = self.lastsent (self.cp, 2, ptype = bytes)
        self.assertEqual (p, pkt.payload)
        # Try long data
        s = LongData (rqr = 1, rts = 0, ie = 1, dstnode = Nodeid (66),
                      srcnode = Nodeid (5), visit = 1,
                      payload = b"new payload")
        ok = self.c.send (s, s.dstnode)
        self.assertTrue (ok)
        p, dest = self.lastsent (self.cp, 3, ptype = bytes)
        self.assertEqual (p, s.payload)
        # Send to non-neighbor should fail (assuming neighbor does not
        # advertise intercept services)
        pkt = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (44),
                         srcnode = Nodeid (5), visit = 1,
                         payload = b"new payload")
        ok = self.c.send (pkt, pkt.dstnode)
        self.assertFalse (ok)
        self.lastsent (self.cp, 3, ptype = bytes)
        
    def test_verify (self):
        p, x = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, NodeInit)
        self.assertEqual (p.nodename, b"TEST")
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x01\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEvent (events.circ_up,
                          adjacent_node = ( 66, "REMOTE" ))
        self.assertEqual (self.c.rphase, 2)
        self.assertEqual (self.c.id, Nodeid (66))
        v, x = self.lastsent (self.cp, 2)
        self.assertIsInstance (v, NodeVerify)
        self.assertEqual (bytes (v), b"\x58\x02\x00OVERIF\x00\x00")
        
    def test_ph3 (self):
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ri")
        self.lastsent (self.cp, 1)
        
    def test_ph4 (self):
        pkt = b"\x01\x02\x00\x02\x10\x02\x02\x00\x00\x20\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ri")
        self.lastsent (self.cp, 1)

    def test_rnd (self):
        self.c.restart = unittest.mock.Mock ()
        self.c.restart.return_value = None
        for i in range (rcount):
            pkt = randpkt (rmin, rmax)
            self.c.dispatch (Received (owner = self.c, src = self.c,
                                       packet = pkt))
        
    def test_rndrun (self):
        self.startup ()
        self.test_rnd ()

    def test_short (self):
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.shortpackets (pkt)
        
class test_ph3 (rtest):
    phase = 3
    tiver = tiver_ph3
    ntype = L1ROUTER
    verify = False
    
    def startup (self):
        p, x = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit3)
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEvent (events.circ_up, adjacent_node = 2)
        self.assertEqual (self.c.rphase, 3)
        self.assertEqual (self.c.id, Nodeid (2))
        self.assertEqual (self.c.ntype, 2)

    def test_noverify (self):
        self.startup ()
        pkt = b"\x02\x03\x00\x01\x00\x11abcdef payload"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (1, element = self.r)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (1))
        self.assertEqual (spkt.dstnode, Nodeid (3))
        self.assertEqual (spkt.visit, 17)
        self.c.dispatch (Timeout (owner = self.c))
        p, x = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, PtpHello)
        self.assertEqual (p.srcnode, Nodeid (5))
        self.assertRegex (p.testdata, b"^\252+$")
        # Send some packets
        pkt = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (2),
                         srcnode = Nodeid (1, 1), visit = 1,
                         payload = b"new payload")
        ok = self.c.send (pkt, pkt.dstnode)
        self.assertTrue (ok)
        p, dest = self.lastsent (self.cp, 3)
        self.assertIs (p, pkt)
        self.assertEqual (p.dstnode, Nodeid (2))
        self.assertEqual (p.srcnode, Nodeid (1, 1))
        # Try long data
        s = LongData (rqr = 1, rts = 0, ie = 1, dstnode = Nodeid (2),
                      srcnode = Nodeid (4, 1), visit = 1,
                      payload = b"new payload")
        ok = self.c.send (s, s.dstnode)
        self.assertTrue (ok)
        p, dest = self.lastsent (self.cp, 4)
        self.assertIsInstance (p, ShortData)
        self.assertEqual (p.rqr, s.rqr)
        self.assertEqual (p.rts, s.rts)
        self.assertEqual (p.dstnode, Nodeid (2))
        self.assertEqual (p.srcnode, Nodeid (4, 1))
        self.assertEqual (p.visit, s.visit)
        self.assertEqual (p.payload, s.payload)
        self.assertFalse (p.ie)
        # Send to non-neighbor should succeed since neighbor is router
        pkt = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (44),
                         srcnode = Nodeid (1), visit = 1,
                         payload = b"new payload")
        ok = self.c.send (pkt, pkt.dstnode)
        self.assertTrue (ok)
        p, dest = self.lastsent (self.cp, 5)
        self.assertIs (p, pkt)
        # test listen timeout
        self.c.adj.dispatch (Timeout (owner = self.c.adj))
        self.assertState ("ha")
        self.assertEqual (self.c.datalink.counters.cir_down, 1)
        self.assertEvent (events.circ_down, reason = "listener_timeout",
                          adjacent_node = 2)
        
    def test_verify (self):
        p, x = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit3)
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)
        pkt = b"\x01\x02\x00\x07\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEvent (events.circ_up, adjacent_node = 2)
        self.assertEqual (self.c.rphase, 3)
        self.assertEqual (self.c.id, Nodeid (2))
        self.assertEqual (self.c.ntype, ENDNODE)  # 3
        v, x = self.lastsent (self.cp, 2)
        self.assertIsInstance (v, PtpVerify)
        self.assertEqual (v.srcnode, Nodeid (5))
        self.assertEqual (v.fcnval, b"OVERIF")
        # Send some packets
        pkt = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (2),
                         srcnode = Nodeid (1, 1), visit = 1,
                         payload = b"new payload")
        ok = self.c.send (pkt, pkt.dstnode)
        self.assertTrue (ok)
        p, dest = self.lastsent (self.cp, 3)
        self.assertIs (p, pkt)
        self.assertEqual (p.dstnode, pkt.dstnode)
        self.assertEqual (p.srcnode, Nodeid (1, 1))
        # Try long data
        s = LongData (rqr = 1, rts = 0, ie = 1, dstnode = Nodeid (2),
                      srcnode = Nodeid (4, 1), visit = 1,
                      payload = b"new payload")
        ok = self.c.send (s, s.dstnode)
        self.assertTrue (ok)
        p, dest = self.lastsent (self.cp, 4)
        self.assertIsInstance (p, ShortData)
        self.assertEqual (p.rqr, s.rqr)
        self.assertEqual (p.rts, s.rts)
        self.assertEqual (p.dstnode, s.dstnode)
        self.assertEqual (p.srcnode, Nodeid (4, 1))
        self.assertEqual (p.visit, s.visit)
        self.assertEqual (p.payload, s.payload)
        self.assertFalse (p.ie)
        # Send to non-neighbor should fail
        pkt = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (44),
                         srcnode = Nodeid (1), visit = 1,
                         payload = b"new payload")
        ok = self.c.send (pkt, pkt.dstnode)
        self.assertFalse (ok)
        self.lastsent (self.cp, 4)

    def test_ph2 (self):
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        p, x = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, NodeInit)
        self.assertEqual (p.nodename, b"TEST")
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)
        self.assertState ("ru")
        self.assertEvent (events.circ_up,
                          adjacent_node = ( 66, "REMOTE" ))
        self.assertEqual (self.c.rphase, 2)
        self.assertEqual (self.c.id, Nodeid (66))
        # Deliver an incoming packet
        pkt = b"\x08\252\252\252"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (1, element = self.r)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, pkt)
        self.assertEqual (spkt.srcnode, Nodeid (66))
        self.assertEqual (spkt.dstnode, self.r.nodeid)
        self.assertEqual (spkt.visit, 1)
        # Deliver an incoming packet, with route header
        pkt = b"\x42\x05LOCAL\x06REMOTE\x08\252\252\252"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (2, element = self.r)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, b"\x08\252\252\252")
        self.assertEqual (spkt.srcnode, Nodeid (66))
        self.assertEqual (spkt.dstnode, self.r.nodeid)
        self.assertEqual (spkt.visit, 1)
        # Hello timer expiration
        self.c.dispatch (Timeout (owner = self.c))
        p, x = self.lastsent (self.cp, 3)
        self.assertIsInstance (p, NopMsg)
        self.assertRegex (p.payload, b"^\252+$")
        # Send some packets
        pkt = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (66),
                         srcnode = Nodeid (5), visit = 1,
                         payload = b"new payload")
        ok = self.c.send (pkt, pkt.dstnode)
        self.assertTrue (ok)
        p, dest = self.lastsent (self.cp, 4, ptype = bytes)
        self.assertEqual (p, pkt.payload)
        # Try long data
        s = LongData (rqr = 1, rts = 0, ie = 1, dstnode = Nodeid (66),
                      srcnode = Nodeid (5), visit = 1,
                      payload = b"new payload")
        ok = self.c.send (s, s.dstnode)
        self.assertTrue (ok)
        p, dest = self.lastsent (self.cp, 5, ptype = bytes)
        self.assertEqual (p, s.payload)
        # Send to non-neighbor should fail (for now)
        pkt = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (44),
                         srcnode = Nodeid (5), visit = 1,
                         payload = b"new payload")
        ok = self.c.send (pkt, pkt.dstnode)
        self.assertFalse (ok)
        self.lastsent (self.cp, 5, ptype = bytes)
        
    def test_ph4 (self):
        pkt = b"\x01\x02\x00\x02\x10\x02\x02\x00\x00\x20\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ri")
        self.lastsent (self.cp, 1)
        
    def test_rnd (self):
        self.c.restart = unittest.mock.Mock ()
        self.c.restart.return_value = None
        for i in range (rcount):
            pkt = randpkt (rmin, rmax)
            self.c.dispatch (Received (owner = self.c, src = self.c,
                                       packet = pkt))

    def test_rndrun (self):
        self.startup ()
        self.test_rnd ()
        
    def test_short (self):
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.shortpackets (pkt)
        
class test_ph4 (rtest):
    phase = 4
    tiver = tiver_ph4
    ntype = L2ROUTER
    verify = False
    
    def startup (self):
        p, x = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 0)
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEvent (events.circ_up, adjacent_node = 1026)
        self.assertEqual (self.c.rphase, 4)
        self.assertEqual (self.c.id, Nodeid (1, 2))

    def test_noverify (self):
        self.startup ()
        pkt = b"\x02\x03\x04\x01\x08\x11abcdef payload"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (1, element = self.r)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (2, 1))
        self.assertEqual (spkt.dstnode, Nodeid (1, 3))
        self.assertEqual (spkt.visit, 17)
        # ditto but with padding
        pkt = b"\x88Testing\x02\x03\x04\x01\x08\x11abcdef payload"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (2, element = self.r)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (2, 1))
        self.assertEqual (spkt.dstnode, Nodeid (1, 3))
        self.assertEqual (spkt.visit, 17)
        # Long data is accepted
        pkt = b"\x26\x00\x00\xaa\x00\x04\x00\x03\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (3, element = self.r)
        self.assertIsInstance (spkt, LongData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (2, 1))
        self.assertEqual (spkt.dstnode, Nodeid (1, 3))
        self.assertEqual (spkt.visit, 17)
        # ditto but with padding
        pkt = b"\x88Testing\x26\x00\x00\xaa\x00\x04\x00\x03\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (4, element = self.r)
        self.assertIsInstance (spkt, LongData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (2, 1))
        self.assertEqual (spkt.dstnode, Nodeid (1, 3))
        self.assertEqual (spkt.visit, 17)
        # test hello transmission
        self.c.dispatch (Timeout (owner = self.c))
        p, x = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, PtpHello)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertRegex (p.testdata, b"^\252+$")
        # Send some packets
        pkt = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (2, 2),
                         srcnode = Nodeid (1, 1), visit = 1,
                         payload = b"new payload")
        ok = self.c.send (pkt, pkt.dstnode)
        self.assertTrue (ok)
        p, dest = self.lastsent (self.cp, 3)
        self.assertIs (p, pkt)
        # Try long data
        s = LongData (rqr = 1, rts = 0, ie = 1, dstnode = Nodeid (2, 2),
                      srcnode = Nodeid (1, 1), visit = 1,
                      payload = b"new payload")
        ok = self.c.send (s, s.dstnode)
        self.assertTrue (ok)
        p, dest = self.lastsent (self.cp, 4)
        self.assertIsInstance (p, ShortData)
        self.assertEqual (p.rqr, s.rqr)
        self.assertEqual (p.rts, s.rts)
        self.assertEqual (p.srcnode, s.srcnode)
        self.assertEqual (p.dstnode, s.dstnode)
        self.assertEqual (p.visit, s.visit)
        self.assertEqual (p.payload, s.payload)
        self.assertFalse (p.ie)
        # Send to non-neighbor should succeed since neighbor is router
        pkt = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (9, 44),
                         srcnode = Nodeid (1, 1), visit = 1,
                         payload = b"new payload")
        ok = self.c.send (pkt, pkt.dstnode)
        self.assertTrue (ok)
        p, dest = self.lastsent (self.cp, 5)
        self.assertIs (p, pkt)
        # test listen timeout
        self.c.adj.dispatch (Timeout (owner = self.c.adj))
        self.assertState ("ha")
        self.assertEqual (self.c.datalink.counters.cir_down, 1)
        self.assertEvent (events.circ_down, reason = "listener_timeout",
                          adjacent_node = 1026)
        # test restart after circuit down
        self.dispatch ()
        self.assertState ("ds")
        
    def test_verify (self):
        p, x = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 0)
        pkt = b"\x01\x02\x04\x07\x10\x02\x02\x00\x00\x10\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEvent (events.circ_up, adjacent_node = 1026)
        self.assertEqual (self.c.rphase, 4)
        self.assertEqual (self.c.id, Nodeid (1, 2))
        self.assertEqual (self.c.ntype, ENDNODE)  # 3
        v, x = self.lastsent (self.cp, 2)
        self.assertIsInstance (v, PtpVerify)
        self.assertEqual (v.srcnode, Nodeid (1, 5))
        self.assertEqual (v.fcnval, b"OVERIF")
        # Send some packets
        pkt = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (1, 2),
                         srcnode = Nodeid (1, 1), visit = 1,
                         payload = b"new payload")
        ok = self.c.send (pkt, pkt.dstnode)
        self.assertTrue (ok)
        p, dest = self.lastsent (self.cp, 3)
        self.assertIs (p, pkt)
        # Try long data
        s = LongData (rqr = 1, rts = 0, ie = 1, dstnode = Nodeid (1, 2),
                      srcnode = Nodeid (1, 1), visit = 1,
                      payload = b"new payload")
        ok = self.c.send (s, s.dstnode)
        self.assertTrue (ok)
        p, dest = self.lastsent (self.cp, 4)
        self.assertIsInstance (p, ShortData)
        self.assertEqual (p.rqr, s.rqr)
        self.assertEqual (p.rts, s.rts)
        self.assertEqual (p.srcnode, s.srcnode)
        self.assertEqual (p.dstnode, s.dstnode)
        self.assertEqual (p.visit, s.visit)
        self.assertEqual (p.payload, s.payload)
        self.assertFalse (p.ie)
        # Send to non-neighbor should fail
        pkt = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (9, 44),
                         srcnode = Nodeid (1, 1), visit = 1,
                         payload = b"new payload")
        ok = self.c.send (pkt, pkt.dstnode)
        self.assertFalse (ok)
        self.lastsent (self.cp, 4)

    def test_ph2 (self):
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        p, x = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, NodeInit)
        self.assertEqual (p.nodename, b"TEST")
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)
        self.assertState ("ru")
        self.assertEvent (events.circ_up,
                          adjacent_node = ( 1090, "REMOTE" ))
        self.assertEqual (self.c.rphase, 2)
        self.assertEqual (self.c.id, Nodeid (1, 66))
        # Deliver an incoming packet
        pkt = b"\x08\252\252\252"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (1, element = self.r)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, pkt)
        self.assertEqual (spkt.srcnode, Nodeid (1, 66))
        self.assertEqual (spkt.dstnode, self.r.nodeid)
        self.assertEqual (spkt.visit, 1)
        # Deliver an incoming packet, with route header
        pkt = b"\x42\x05LOCAL\x06REMOTE\x08\252\252\252"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (2, element = self.r)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, b"\x08\252\252\252")
        self.assertEqual (spkt.srcnode, Nodeid (1, 66))
        self.assertEqual (spkt.dstnode, self.r.nodeid)
        self.assertEqual (spkt.visit, 1)
        # Hello timer expiration
        self.c.dispatch (Timeout (owner = self.c))
        p, x = self.lastsent (self.cp, 3)
        self.assertIsInstance (p, NopMsg)
        self.assertRegex (p.payload, b"^\252+$")
        
    def test_ph3 (self):
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        p, x = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, PtpInit3)
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)
        self.assertState ("ru")
        self.assertEvent (events.circ_up, adjacent_node = 1026)
        self.assertEqual (self.c.rphase, 3)
        self.assertEqual (self.c.id, Nodeid (1, 2))
        pkt = b"\x02\x03\x00\x01\x00\x11abcdef payload"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (1, element = self.r)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (1, 1))
        self.assertEqual (spkt.dstnode, Nodeid (1, 3))
        self.assertEqual (spkt.visit, 17)
        # Hello timer expiration
        self.c.dispatch (Timeout (owner = self.c))
        p, x = self.lastsent (self.cp, 3)
        self.assertIsInstance (p, PtpHello)
        self.assertEqual (p.srcnode, Nodeid (5))
        self.assertRegex (p.testdata, b"^\252+$")
        # Packet with padding should be ignored
        pkt = b"\x88Testing\x02\x03\x04\x01\x08\x11abcdef payload"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.lastdispatch (1, element = self.r)
        self.assertEvent (events.fmt_err, 
                          packet_beginning = b"\x88Testi")
        # Long data with padding
        pkt = b"\x88Testing\x26\x00\x00\xaa\x00\x04\x00\x03\x04" \
              b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00" \
              b"abcdef payload"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (1, element = self.r)
        self.assertEvent (events.fmt_err, 
                          packet_beginning = b"\x88Testi")

    def test_phx (self):
        pkt = b"\x01\x02\x00\x02\x10\x02\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ri")
        self.lastsent (self.cp, 1)
        
    def test_rnd (self):
        self.c.restart = unittest.mock.Mock ()
        self.c.restart.return_value = None
        for i in range (rcount):
            pkt = randpkt (rmin, rmax)
            self.c.dispatch (Received (owner = self.c, src = self.c,
                                       packet = pkt))
        
    def test_rndrun (self):
        self.startup ()
        self.test_rnd ()
        
    def test_short (self):
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.shortpackets (pkt)
        
class test_ph4verify (rtest):
    phase = 4
    tiver = tiver_ph4
    ntype = L2ROUTER
    verify = True
    
    def test_noverify (self):
        p, x = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 1)
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("rv")
        self.assertEqual (self.c.rphase, 4)
        self.assertEqual (self.c.id, Nodeid (1, 2))
        pkt = b"\x03\x02\x04\x06IVERIF"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEvent (events.circ_up, adjacent_node = 1026)
        
    def test_wrongverify (self):
        p, x = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 1)
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("rv")
        self.assertEqual (self.c.rphase, 4)
        self.assertEqual (self.c.id, Nodeid (1, 2))
        pkt = b"\x03\x02\x04\x06ZVERIF"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")
        self.assertEvent (events.ver_rej, reason = "invalid_verification",
                          adjacent_node = 1026)
        self.dispatch ()
        self.assertState ("ds")
        
    def test_verify_timeout (self):
        p, x = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 1)
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("rv")
        self.assertEqual (self.c.rphase, 4)
        self.assertEqual (self.c.id, Nodeid (1, 2))
        self.c.dispatch (Timeout (owner = self.c))
        self.assertState ("ha")
        self.assertEvent (events.init_fault, reason = "verification_timeout",
                          adjacent_node = 1026)
        self.dispatch ()
        self.assertState ("ds")

    def test_verify (self):
        p, x = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 1)
        pkt = b"\x01\x02\x04\x06\x10\x02\x02\x00\x00\x10\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("rv")
        self.assertEqual (self.c.rphase, 4)
        self.assertEqual (self.c.id, Nodeid (1, 2))
        v, x = self.lastsent (self.cp, 2)
        self.assertIsInstance (v, PtpVerify)
        self.assertEqual (v.srcnode, Nodeid (1, 5))
        self.assertEqual (v.fcnval, b"OVERIF")
        pkt = b"\x03\x02\x04\x06IVERIF"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEvent (events.circ_up, adjacent_node = 1026)

    def test_ph2 (self):
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        p, x = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, NodeInit)
        self.assertEqual (p.nodename, b"TEST")
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 1)
        self.assertState ("rv")
        self.assertEqual (self.c.rphase, 2)
        self.assertEqual (self.c.id, Nodeid (1, 66))
        pkt = b"\x58\x02\x00IVERIF\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEvent (events.circ_up,
                          adjacent_node = ( 1090, "REMOTE" ))
        
    def test_ph3 (self):
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        p, x = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, PtpInit3)
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 1)
        self.assertState ("rv")
        self.assertEqual (self.c.rphase, 3)
        self.assertEqual (self.c.id, Nodeid (1, 2))
        pkt = b"\x03\x02\x00\x06IVERIF"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEvent (events.circ_up, adjacent_node = 1026)

    def test_rndrv (self):
        p, x = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 1)
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("rv")
        self.c.restart = unittest.mock.Mock ()
        self.c.restart.return_value = None
        for i in range (rcount):
            pkt = randpkt (rmin, rmax)
            self.c.dispatch (Received (owner = self.c, src = self.c,
                                       packet = pkt))
        
class test_ph4err (rtest):
    phase = 4
    tiver = tiver_ph4
    ntype = L2ROUTER
    verify = False

    def test_zero (self):
        pkt = b"\x01\x00\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

    def test_padinit (self):
        pkt = b"\x88Testing\x01\x00\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertEvent (events.fmt_err, 
                          packet_beginning = b"\x88Testi")
        self.assertState ("ri")

    def test_oor (self):
        if self.ntype != ENDNODE:
            pkt = b"\x01\xc9\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
            self.c.dispatch (Received (owner = self.c,
                                       src = self.c, packet = pkt))
            self.assertState ("ha")

    def test_azero (self):
        pkt = b"\x01\x02\x00\x01\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

    def test_aoor (self):
        pkt = b"\x01\x02\x29\x01\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

    def test_wrongareal1 (self):
        pkt = b"\x01\x02\x08\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

    def test_wrongarea_end (self):
        pkt = b"\x01\x02\x08\x03\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

    def test_ph3zero (self):
        pkt = b"\x01\x00\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

    def test_ph3oor (self):
        if self.ntype != ENDNODE:
            pkt = b"\x01\xc9\x00\x02\x10\x02\x01\x03\x00\x00"
            self.c.dispatch (Received (owner = self.c,
                                       src = self.c, packet = pkt))
            self.assertState ("ha")

    def test_ph3smlblk (self):
        pkt = b"\x01\xc0\x00\x01\x80\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

    def test_ph3area (self):
        pkt = b"\x01\x00\x04\x02\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

    def test_ntype (self):
        pkt = b"\x01\x03\x04\x00\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")
        
    def test_ph3ntype (self):
        pkt = b"\x01\x03\x00\x01\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

# For L1 router, all the above errors are also errors, plus any area mismatch
class test_ph4l1err (test_ph4err):
    phase = 4
    tiver = tiver_ph4
    ntype = L1ROUTER
    verify = False
    
    def test_wrongarea (self):
        pkt = b"\x01\x02\x08\x01\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

# Endnode error cases are the same as L1 router
class test_ph4end_err (test_ph4l1err):
    phase = 4
    tiver = tiver_ph4
    ntype = ENDNODE
    verify = False

class test_ph3err (rtest):
    phase = 3
    tiver = tiver_ph3
    ntype = L1ROUTER
    verify = False

    def test_zero (self):
        pkt = b"\x01\x00\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

    def test_oor (self):
        if self.ntype != ENDNODE:
            pkt = b"\x01\xc9\x00\x02\x10\x02\x01\x03\x00\x00"
            self.c.dispatch (Received (owner = self.c,
                                       src = self.c, packet = pkt))
            self.assertState ("ha")

    def test_ph3smlblk (self):
        pkt = b"\x01\xc0\x00\x01\x80\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

    def test_area (self):
        pkt = b"\x01\x00\x04\x02\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

    def test_ntype (self):
        pkt = b"\x01\x03\x04\x01\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

    def test_padinit (self):
        pkt = b"\x88Testing\x01\x00\x04\x02\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertEvent (events.fmt_err, 
                          packet_beginning = b"\x88Testi")
        self.assertState ("ri")

class test_ph3end_err (test_ph3err):
    phase = 3
    tiver = tiver_ph3
    ntype = ENDNODE
    verify = False

class test_ph2err (rtest):
    phase = 2
    tiver = tiver_ph2
    ntype = PHASE2
    verify = False
    
    def test_zero (self):
        pkt = b"\x58\x01\x00\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

    def test_oor (self):
        pkt = b"\x58\x01\x80\x39\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")

class test_ph4restart (rtest):
    phase = 4
    tiver = tiver_ph4
    ntype = L2ROUTER
    verify = False

    def startup (self):
        p, x = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 0)
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEvent (events.circ_up, adjacent_node = 1026)
        self.assertEqual (self.c.rphase, 4)
        self.assertEqual (self.c.id, Nodeid (1, 2))

    def test_dlrestart (self):
        self.startup ()
        self.c.dispatch (datalink.DlStatus (owner = self.c, status = False))
        self.assertState ("ha")
        self.dispatch ()
        self.assertEvent (events.circ_fault, reason = "sync_lost",
                          adjacent_node = 1026)
        self.assertEqual (self.c.datalink.counters.cir_down, 1)
        self.assertState ("ds")
        
    def test_init (self):
        self.startup ()
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x20\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertEvent (events.init_swerr,
                          reason = "unexpected_packet_type",
                          packet_header = ( 1, 1026 ),
                          adjacent_node = 1026)
        self.assertEqual (self.c.datalink.counters.cir_down, 1)
        self.assertState ("ha")
        
    def test_shortinit (self):
        self.startup ()
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x20\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertEvent (events.fmt_err,
                          packet_beginning = b"\x01\x02\x04\x02\x10\x02")
        self.assertEqual (self.c.datalink.counters.cir_down, 0)
        self.assertState ("ru")
        
    def test_init3 (self):
        self.startup ()
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertEvent (events.init_swerr,
                          reason = "unexpected_packet_type",
                          packet_header = ( 1, 2 ),
                          adjacent_node = 1026)
        self.assertEqual (self.c.datalink.counters.cir_down, 1)
        self.assertState ("ha")
        
    def test_init2 (self):
        self.startup ()
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertEvent (events.init_swerr,
                          reason = "unexpected_packet_type",
                          ni_packet_header = ( 0x58, 1, 66, "REMOTE" ),
                          adjacent_node = 1026)
        self.assertEqual (self.c.datalink.counters.cir_down, 1)
        self.assertState ("ha")
        
    def test_init_workaround (self):
        self.cp.start_works = False
        self.startup ()
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x20\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.dispatch ()
        self.assertState ("ru")
        self.assertEqual (self.c.rphase, 4)
        self.assertEqual (self.c.id, Nodeid (1, 2))

    def test_init3_workaround (self):
        self.cp.start_works = False
        self.startup ()
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.dispatch ()
        self.assertState ("ru")
        self.assertEqual (self.c.rphase, 3)
        self.assertEqual (self.c.id, Nodeid (1, 2))

    def test_init2_workaround (self):
        self.cp.start_works = False
        self.startup ()
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.dispatch ()
        self.assertState ("ru")
        self.assertEqual (self.c.rphase, 2)
        self.assertEqual (self.c.id, Nodeid (1, 66))

    def test_ri_restart (self):
        pkt = b"\x03\x02\x04\x06IVERIF"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertEvent (events.init_swerr, reason = "unexpected_packet_type",
                          packet_header = ( 3, Nodeid (1, 2) ))
        self.assertState ("ha")

    def test_ri_restart_ph2 (self):
        pkt = b"\x58\x02\x00IVERIF\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertEvent (events.init_swerr, reason = "unexpected_packet_type",
                          nv_packet_header = ( 0x58, 2 ))
        self.assertState ("ha")

    def test_badhello (self):
        self.startup ()
        pkt = b"\x05\x02\x04\x05\252\252\252\252\251"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertEvent (events.circ_down, reason = "listener_invalid_data",
                          adjacent_node = 1026,
                          packet_header = ( 5, 1026 ))
        self.assertState ("ha")
        
class test_ph4restart_rv (rtest):
    phase = 4
    tiver = tiver_ph4
    ntype = L2ROUTER
    verify = True

    def startup (self):
        p, x = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 1)
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("rv")
        self.assertEqual (self.c.rphase, 4)
        self.assertEqual (self.c.id, Nodeid (1, 2))

    def test_dlrestart (self):
        self.startup ()
        self.c.dispatch (datalink.DlStatus (owner = self.c, status = False))
        self.assertEvent (events.init_fault, reason = "sync_lost",
                          adjacent_node = Nodeid (1, 2))
        self.assertEqual (self.c.datalink.counters.init_fail, 1)
        self.assertState ("ha")
        self.dispatch ()
        self.assertState ("ds")
        
    def test_init (self):
        self.startup ()
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x20\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")
        self.assertEvent (events.init_swerr, reason = "unexpected_packet_type",
                          packet_header = ( 1, 1026 ),
                          adjacent_node = 1026)
        self.assertEqual (self.c.datalink.counters.init_fail, 1)
        
    def test_init3 (self):
        self.startup ()
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")
        self.assertEvent (events.init_swerr, reason = "unexpected_packet_type",
                          packet_header = ( 1, 2 ),
                          adjacent_node = 1026)
        self.assertEqual (self.c.datalink.counters.init_fail, 1)
        
    def test_init2 (self):
        self.startup ()
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")
        self.assertEvent (events.init_swerr, reason = "unexpected_packet_type",
                          ni_packet_header = ( 0x58, 1, 66, "REMOTE" ),
                          adjacent_node = 1026)
        self.assertEqual (self.c.datalink.counters.init_fail, 1)
        
if __name__ == "__main__":
    unittest.main ()

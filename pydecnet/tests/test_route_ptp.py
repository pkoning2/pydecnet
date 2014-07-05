#!/usr/bin/env python3

from tests.dntest import *

import logging

from decnet.routing_packets import *
from decnet import route_ptp
from decnet import datalink
from decnet import events
from decnet.timers import Timeout
from decnet.node import Nodeinfo

rcount = 5000
rmin = 1
rmax = 30
    
class rtest (DnTest):
    def setUp (self):
        super ().setUp ()
        if self.phase == 4:
            self.node.nodeid = Nodeid (1, 5)
        else:
            self.node.nodeid = Nodeid (5)
        self.node.homearea, self.node.tid = self.node.nodeid.split ()
        self.node.nodename = "testnd"
        self.info = Nodeinfo (None, self.node.nodeid)
        self.info.iverif = b"IVERIF"
        self.info.overif = b"OVERIF"
        self.node.nodeinfo.return_value = self.info
        self.node.addwork.side_effect = self.t_addwork
        self.dl = unittest.mock.Mock ()
        self.cp = unittest.mock.Mock ()
        self.dl.create_port.return_value = self.cp
        self.config = unittest.mock.Mock ()
        self.config.t3 = 10
        self.config.cost = 1
        self.config.verify = self.verify
        self.node.phase = self.phase
        self.node.tiver = self.tiver
        self.node.ntype = self.ntype
        self.node.name = b"TEST"
        self.c = route_ptp.PtpCircuit (self.node, "ptp-0", self.dl, self.config)
        self.c.up = unittest.mock.Mock ()
        self.c.down = unittest.mock.Mock ()
        self.c.parent = self.node
        self.c.t3 = 15
        self.c.init_fail = 0
        self.c.start ()
        self.assertState ("ds")
        self.c.dispatch (datalink.DlStatus (owner = self.c, status = True))
        self.assertState ("ri")        
        
    def tearDown (self):
        self.c.stop ()
        self.assertState ("ha")
        self.assertEqual (self.c.up.call_count, self.c.down.call_count)
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

class test_ph2 (rtest):
    phase = 2
    tiver = tiver_ph2
    ntype = PHASE2
    verify = False
    
    def startup (self):
        p = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, NodeInit)
        self.assertEqual (p.nodename, b"TEST")
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c.up.call_count, 1)
        self.assertEqual (self.c.rphase, 2)
        self.assertEqual (self.c.nodeid, Nodeid (66))

    def test_noverify (self):
        self.startup ()
        pkt = b"0x08\252\252\252"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (1)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, pkt)
        self.assertEqual (spkt.srcnode, Nodeid (66))
        self.assertEqual (spkt.dstnode, self.node.nodeid)
        self.assertEqual (spkt.visit, 1)
        self.c.hellotimer.dispatch (Timeout (owner = self.c.hellotimer))
        p = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, NopMsg)
        self.assertRegex (p.payload, b"^\252+$")

    def test_verify (self):
        p = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, NodeInit)
        self.assertEqual (p.nodename, b"TEST")
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x01\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c.up.call_count, 1)
        self.assertEqual (self.c.rphase, 2)
        self.assertEqual (self.c.nodeid, Nodeid (66))
        v = self.lastsent (self.cp, 2)
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
        
class test_ph3 (rtest):
    phase = 3
    tiver = tiver_ph3
    ntype = L1ROUTER
    verify = False
    
    def startup (self):
        p = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit3)
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c.up.call_count, 1)
        self.assertEqual (self.c.rphase, 3)
        self.assertEqual (self.c.nodeid, Nodeid (2))

    def test_noverify (self):
        self.startup ()
        pkt = b"\x02\x03\x00\x01\x00\x11abcdef payload"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (1)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (1))
        self.assertEqual (spkt.dstnode, Nodeid (3))
        self.assertEqual (spkt.visit, 17)
        self.c.hellotimer.dispatch (Timeout (owner = self.c.hellotimer))
        p = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, PtpHello)
        self.assertEqual (p.srcnode, Nodeid (5))
        self.assertRegex (p.testdata, b"^\252+$")
        self.c.dispatch (Timeout (owner = self.c))
        self.assertState ("ha")
        self.assertEqual (self.c.down.call_count, 1)

    def test_verify (self):
        p = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit3)
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)
        pkt = b"\x01\x02\x00\x06\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c.up.call_count, 1)
        self.assertEqual (self.c.rphase, 3)
        self.assertEqual (self.c.nodeid, Nodeid (2))
        v = self.lastsent (self.cp, 2)
        self.assertIsInstance (v, PtpVerify)
        self.assertEqual (v.srcnode, Nodeid (5))
        self.assertEqual (v.fcnval, b"OVERIF")

    def test_ph2 (self):
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        p = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, NodeInit)
        self.assertEqual (p.nodename, b"TEST")
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)
        self.assertState ("ru")
        self.assertEqual (self.c.up.call_count, 1)
        self.assertEqual (self.c.rphase, 2)
        self.assertEqual (self.c.nodeid, Nodeid (66))
        pkt = b"0x08\252\252\252"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (1)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, pkt)
        self.assertEqual (spkt.srcnode, Nodeid (66))
        self.assertEqual (spkt.dstnode, self.node.nodeid)
        self.assertEqual (spkt.visit, 1)
        self.c.hellotimer.dispatch (Timeout (owner = self.c.hellotimer))
        p = self.lastsent (self.cp, 3)
        self.assertIsInstance (p, NopMsg)
        self.assertRegex (p.payload, b"^\252+$")
        
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
        
class test_ph4 (rtest):
    phase = 4
    tiver = tiver_ph4
    ntype = L2ROUTER
    verify = False
    
    def startup (self):
        p = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 0)
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c.up.call_count, 1)
        self.assertEqual (self.c.rphase, 4)
        self.assertEqual (self.c.nodeid, Nodeid (1, 2))

    def test_noverify (self):
        self.startup ()
        pkt = b"\x02\x03\x04\x01\x08\x11abcdef payload"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (1)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (2, 1))
        self.assertEqual (spkt.dstnode, Nodeid (1, 3))
        self.assertEqual (spkt.visit, 17)
        self.c.hellotimer.dispatch (Timeout (owner = self.c.hellotimer))
        p = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, PtpHello)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertRegex (p.testdata, b"^\252+$")
        self.c.dispatch (Timeout (owner = self.c))
        self.assertState ("ha")
        self.assertEqual (self.c.down.call_count, 1)
        
    def test_verify (self):
        p = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 0)
        pkt = b"\x01\x02\x04\x06\x10\x02\x02\x00\x00\x10\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c.up.call_count, 1)
        self.assertEqual (self.c.rphase, 4)
        self.assertEqual (self.c.nodeid, Nodeid (1, 2))
        v = self.lastsent (self.cp, 2)
        self.assertIsInstance (v, PtpVerify)
        self.assertEqual (v.srcnode, Nodeid (1, 5))
        self.assertEqual (v.fcnval, b"OVERIF")

    def test_ph2 (self):
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        p = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, NodeInit)
        self.assertEqual (p.nodename, b"TEST")
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)
        self.assertState ("ru")
        self.assertEqual (self.c.up.call_count, 1)
        self.assertEqual (self.c.rphase, 2)
        self.assertEqual (self.c.nodeid, Nodeid (1, 66))
        pkt = b"0x08\252\252\252"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (1)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, pkt)
        self.assertEqual (spkt.srcnode, Nodeid (1, 66))
        self.assertEqual (spkt.dstnode, self.node.nodeid)
        self.assertEqual (spkt.visit, 1)
        self.c.hellotimer.dispatch (Timeout (owner = self.c.hellotimer))
        p = self.lastsent (self.cp, 3)
        self.assertIsInstance (p, NopMsg)
        self.assertRegex (p.payload, b"^\252+$")
        
    def test_ph3 (self):
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        p = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, PtpInit3)
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 0)
        self.assertState ("ru")
        self.assertEqual (self.c.up.call_count, 1)
        self.assertEqual (self.c.rphase, 3)
        self.assertEqual (self.c.nodeid, Nodeid (1, 2))
        pkt = b"\x02\x03\x00\x01\x00\x11abcdef payload"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        spkt = self.lastdispatch (1)
        self.assertIsInstance (spkt, ShortData)
        self.assertEqual (spkt.payload, b"abcdef payload")
        self.assertEqual (spkt.srcnode, Nodeid (1, 1))
        self.assertEqual (spkt.dstnode, Nodeid (1, 3))
        self.assertEqual (spkt.visit, 17)
        self.c.hellotimer.dispatch (Timeout (owner = self.c.hellotimer))
        p = self.lastsent (self.cp, 3)
        self.assertIsInstance (p, PtpHello)
        self.assertEqual (p.srcnode, Nodeid (5))
        self.assertRegex (p.testdata, b"^\252+$")

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
        
class test_ph4verify (rtest):
    phase = 4
    tiver = tiver_ph4
    ntype = L2ROUTER
    verify = True
    
    def test_noverify (self):
        p = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 1)
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("rv")
        self.assertEqual (self.c.rphase, 4)
        self.assertEqual (self.c.nodeid, Nodeid (1, 2))
        pkt = b"\x03\x02\x04\x06IVERIF"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c.up.call_count, 1)
        
    def test_wrongverify (self):
        p = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 1)
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("rv")
        self.assertEqual (self.c.rphase, 4)
        self.assertEqual (self.c.nodeid, Nodeid (1, 2))
        pkt = b"\x03\x02\x04\x06ZVERIF"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ha")
        self.assertEqual (self.c.up.call_count, 0)
        e = self.lastevent (events.Event.ver_rej)
        self.assertEqual (e.reason, "invalid_verification")
        
    def test_verify_timeout (self):
        p = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 1)
        pkt = b"\x01\x02\x04\x02\x10\x02\x02\x00\x00\x0a\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("rv")
        self.assertEqual (self.c.rphase, 4)
        self.assertEqual (self.c.nodeid, Nodeid (1, 2))
        self.c.dispatch (Timeout (owner = self.c))
        self.assertState ("ha")
        self.assertEqual (self.c.up.call_count, 0)
        e = self.lastevent (events.Event.ver_rej)
        self.assertEqual (e.reason, "verification_timeout")
        
    def test_verify (self):
        p = self.lastsent (self.cp, 1)
        self.assertIsInstance (p, PtpInit)
        self.assertEqual (p.srcnode, Nodeid (1, 5))
        self.assertEqual (p.verif, 1)
        pkt = b"\x01\x02\x04\x06\x10\x02\x02\x00\x00\x10\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("rv")
        self.assertEqual (self.c.rphase, 4)
        self.assertEqual (self.c.nodeid, Nodeid (1, 2))
        v = self.lastsent (self.cp, 2)
        self.assertIsInstance (v, PtpVerify)
        self.assertEqual (v.srcnode, Nodeid (1, 5))
        self.assertEqual (v.fcnval, b"OVERIF")
        pkt = b"\x03\x02\x04\x06IVERIF"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c.up.call_count, 1)

    def test_ph2 (self):
        pkt = b"\x58\x01\x42\x06REMOTE\x00\x00\x04\x02\x01\x02\x40\x00" \
              b"\x00\x00\x00\x03\x01\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        p = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, NodeInit)
        self.assertEqual (p.nodename, b"TEST")
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 1)
        self.assertState ("rv")
        self.assertEqual (self.c.rphase, 2)
        self.assertEqual (self.c.nodeid, Nodeid (1, 66))
        pkt = b"\x58\x02\x00IVERIF\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c.up.call_count, 1)
        
    def test_ph3 (self):
        pkt = b"\x01\x02\x00\x02\x10\x02\x01\x03\x00\x00"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        p = self.lastsent (self.cp, 2)
        self.assertIsInstance (p, PtpInit3)
        self.assertEqual (p.srcnode, 5)
        self.assertEqual (p.verif, 1)
        self.assertState ("rv")
        self.assertEqual (self.c.rphase, 3)
        self.assertEqual (self.c.nodeid, Nodeid (1, 2))
        pkt = b"\x03\x02\x00\x06IVERIF"
        self.c.dispatch (Received (owner = self.c, src = self.c, packet = pkt))
        self.assertState ("ru")
        self.assertEqual (self.c.up.call_count, 1)

    def test_rndrv (self):
        p = self.lastsent (self.cp, 1)
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
        
if __name__ == "__main__":
    unittest.main ()

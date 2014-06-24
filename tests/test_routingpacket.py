#!/usr/bin/env python3

import unittest, unittest.mock

import sys
import os
import logging

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet.routing_packets import *
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

class rptest (unittest.TestCase):
    def setUp (self):
        logging.exception = unittest.mock.Mock ()

    def tearDown (self):
        self.assertEqual (logging.exception.call_count, 0)
        
class test_shortdata (rptest):
    def test_decode (self):
        s = ShortData ()
        s.decode (b"\x02\x03\x04\x01\x08\x11abcdef payload")
        self.assertEqual (s.rqr, 0)
        self.assertEqual (s.rts, 0)
        self.assertEqual (s.dstnode, Nodeid (1, 3))
        self.assertEqual (s.srcnode, Nodeid (2, 1))
        self.assertEqual (s.visit, 17)
        self.assertEqual (s.payload, b"abcdef payload")

    def test_encode (self):
        s = ShortData (rqr = 1, rts = 0, dstnode = Nodeid (2, 2),
                       srcnode = Nodeid (1, 1), visit = 1,
                       payload = b"new payload")
        b = bytes (s)
        self.assertEqual (b, b"\x0a\x02\x08\x01\x04\x01new payload")
        
class test_longdata (rptest):
    def test_decode (self):
        s = LongData ()
        s.decode (b"\x26\x00\x00\xaa\x00\x04\x00\x03\x04"
                  b"\x00\x00\xaa\x00\x04\x00\x01\x08\x00\x11\x00\x00"
                  b"abcdef payload")
        self.assertEqual (s.rqr, 0)
        self.assertEqual (s.rts, 0)
        self.assertEqual (s.ie, 1)
        self.assertEqual (s.dstnode, Nodeid (1, 3))
        self.assertEqual (s.srcnode, Nodeid (2, 1))
        self.assertEqual (s.visit, 17)
        self.assertEqual (s.payload, b"abcdef payload")

    def test_encode (self):
        s = LongData (rqr = 1, rts = 0, ie = 1, dstnode = Nodeid (2, 2),
                      srcnode = Nodeid (1, 1), visit = 1,
                      payload = b"new payload")
        b = bytes (s)
        self.assertEqual (b, b"\x2e\x00\x00\xaa\x00\x04\x00\x02\x08"
                          b"\x00\x00\xaa\x00\x04\x00\x01\x04\x00\x01"
                          b"\x00\x00new payload")

class test_ptpinit (rptest):
    def test_decode (self):
        s = PtpInit ()
        s.decode (b"\x01\x02\x04\x07\x10\x02\x02\x00\x00\x20\x00\x00")
        self.assertEqual (s.srcnode, Nodeid (1, 2))
        self.assertEqual (s.ntype, 3)
        self.assertEqual (s.verif, 1)
        self.assertEqual (s.blksize, 528)
        self.assertEqual (s.timer, 32)
        self.assertEqual (s.tiver, Version (2, 0, 0))
        self.assertEqual (s.reserved, b"")
        
    def test_decode3 (self):
        s = PtpInit3 ()
        s.decode (b"\x01\x02\x00\x07\x10\x02\x01\x03\x00\x00")
        self.assertEqual (s.srcnode, Nodeid (2))
        self.assertEqual (s.ntype, 3)
        self.assertEqual (s.verif, 1)
        self.assertEqual (s.blksize, 528)
        self.assertEqual (s.tiver, Version (1, 3, 0))
        self.assertEqual (s.reserved, b"")

    def test_encode (self):
        s = PtpInit (srcnode = Nodeid (2, 2), ntype = 2,
                     verif = 0, blksize = 513, timer = 64,
                     tiver = Version (2, 1, 0))
        b = s.encode ()
        self.assertEqual (b, b"\x01\x02\x08\x02\x01\x02\x02\x01\x00"
                          b"\x40\x00\x00")
        
    def test_encode3 (self):
        s = PtpInit3 (srcnode = Nodeid (5), ntype = 2,
                     verif = 0, blksize = 513,
                     tiver = Version (1, 3, 2))
        b = s.encode ()
        self.assertEqual (b, b"\x01\x05\x00\x02\x01\x02\x01\x03\x02\x00")

class test_ptpver (rptest):
    def test_decode (self):
        s = PtpVerify ()
        s.decode (b"\x03\x02\x0c\x04abcd")
        self.assertEqual (s.srcnode, Nodeid (3, 2))
        self.assertEqual (s.fcnval, b"abcd")

    def test_encode (self):
        s = PtpVerify (srcnode = Nodeid (2, 3), fcnval = b"foobar")
        b = bytes (s)
        self.assertEqual (b, b"\x03\x03\x08\x06foobar")
        
class test_ptphello (rptest):
    def test_decode (self):
        s = PtpHello ()
        s.decode (b"\x05\x02\x00\x04abcd")
        self.assertEqual (s.srcnode, Nodeid (2))
        self.assertEqual (s.testdata, b"abcd")

    def test_encode (self):
        s = PtpHello (srcnode = Nodeid (3), testdata = b"foobar")
        b = bytes (s)
        self.assertEqual (b, b"\x05\x03\x00\x06foobar")

class test_rhello (rptest):
    def test_decode (self):
        s = RouterHello ()
        s.decode (b"\x0b\x02\x00\x01\xaa\x00\x04\x00\x02\x04\x02"
                  b"\x10\x02\x40\x00\x80\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00"
                  b"\x07\xaa\x00\x04\x00\x07\x04\x9f")
        self.assertEqual (s.tiver, Version (2, 0, 1))
        self.assertEqual (s.id, Nodeid (1, 2))
        self.assertEqual (s.ntype, 2)
        self.assertEqual (s.blksize, 528)
        self.assertEqual (s.prio, 64)
        self.assertEqual (s.timer, 128)
        e = Elist ()
        e.decode (s.elist)
        r = RSent ()
        r.decode (e.rslist)
        self.assertEqual (r.router, Nodeid (1, 7))
        self.assertEqual (r.prio, 31)
        self.assertEqual (r.twoway, 1)

    def test_encode (self):
        r1 = RSent (router = Nodeid (2, 2), prio = 32)
        r2 = RSent (router = Nodeid (2, 1), prio = 64, twoway = 1)
        e = Elist (rslist = bytes (r1) + bytes (r2))
        s = RouterHello (tiver = Version (2, 0, 0), id = Nodeid (2, 3),
                         ntype = 1, blksize = 513, timer = 80,
                         prio = 16, elist = bytes (e))
        b = s.encode ()
        self.assertEqual (b, b"\x0b\x02\x00\x00\xaa\x00\x04\x00\x03\x08\x01"
                          b"\x01\x02\x10\x00\x50\x00\x00"
                          b"\x16\x00\x00\x00\x00\x00\x00\x00"
                          b"\x0e\xaa\x00\x04\x00\x02\x08\x20"
                          b"\xaa\x00\x04\x00\x01\x08\xc0")
class test_ehello (rptest):
    def test_decode (self):
        s = EndnodeHello ()
        s.decode (b"\x0d\x02\x00\x03\xaa\x00\x04\x00\x01\x0c\x03\x04\x02"
                  b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                  b"\xaa\x00\x04\x00\xff\x0c\x14\x00\x00\x06abcdef")
        self.assertEqual (s.tiver, Version (2, 0, 3))
        self.assertEqual (s.id, Nodeid (3, 1))
        self.assertEqual (s.ntype, 3)
        self.assertEqual (s.blksize, 516),
        self.assertEqual (s.neighbor, Macaddr (Nodeid (3, 255)))
        self.assertEqual (s.timer, 20)
        self.assertEqual (s.testdata, b"abcdef")

    def test_encode (self):
        s = EndnodeHello (tiver = tiver_ph4, id = Nodeid (3, 2),
                          blksize = 513, neighbor = Macaddr (Nodeid (3, 1)),
                          timer = 15, testdata = b"forgetit")
        b = bytes (s)
        self.assertEqual (b, b"\x0d\x02\x00\x00\xaa\x00\x04\x00\x02\x0c"
                          b"\x03\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\xaa\x00\x04\x00\x01\x0c\x0f\x00\x00\x08forgetit")

class routingmsg (rptest):
    def setUp (self):
        super ().setUp ()
        self.circ = unittest.mock.Mock ()
        self.circ.config.cost = 5

class test_p3routing (routingmsg):
    def test_decode (self):
        s = PhaseIIIRouting ()
        s.decode (b"\x07\x03\x00\x00\xff\x7f\x06\x08\x05\x88")
        self.assertEqual (s.srcnode, 3)
        self.assertEqual (s.segments, [ RouteSegEntry (cost = 1023, hops = 31),
                                        RouteSegEntry (cost = 6, hops = 2) ])
        self.assertEqual (list (s.entries (self.circ)), [ (1, (32, 1028)),
                                                          (2, (3, 11)) ])

    def test_decodebad (self):
        s = PhaseIIIRouting ()
        with self.assertRaises (events.Event) as e:
            s.decode (b"\x07\x03\x00\x00\xff\x7f\x06\x08\x06\x88")
        self.assertEqual (e.exception.event, events.Event.adj_down)
        self.assertEqual (e.exception.reason, "checksum_error")

    def test_encode (self):
        s = PhaseIIIRouting (srcnode = Nodeid (4),
                             segments = [ RouteSegEntry (cost = 5, hops = 1),
                                          RouteSegEntry (cost = 99, hops = 5) ])
        b = s.encode ()
        self.assertEqual (b, b"\x07\x04\x00\x00\x05\x04\x63\x14\x68\x18")
        
class test_l1routing (routingmsg):
    def test_decode (self):
        s = L1Routing ()
        s.decode (b"\x07\x03\x00\x00\x02\x00\x05\x00\xff\x7f\x06\x08\x0d\x88")
        self.assertEqual (s.srcnode, 3)
        e = [ L1Segment (count = 2, startid = 5,
                         entries = [ RouteSegEntry (cost = 1023, hops = 31),
                                     RouteSegEntry (cost = 6, hops = 2) ]) ]
        self.assertEqual (s.segments, e)
        self.assertEqual (list (s.entries (self.circ)), [ (5, (32, 1028)),
                                                          (6, (3, 11)) ])

    def test_decodebad (self):
        s = L1Routing ()
        with self.assertRaises (events.Event) as e:
            s.decode (b"\x07\x03\x00\x00\x02\x00\x05\x00\xff\x7f\x06\x08\x0c\x88")
        self.assertEqual (e.exception.event, events.Event.adj_down)
        self.assertEqual (e.exception.reason, "checksum_error")

    def test_decodebadseg (self):
        s = L1Routing ()
        # Segment entry count 0
        with self.assertRaises (events.Event) as e:
            s.decode (b"\x07\x03\x00\x00\x00\x00\x07\x00\xff\x7f\x06\x08\x0d\x88")
        self.assertEqual (e.exception.event, events.Event.fmt_err)
        # Segment start id out of range
        with self.assertRaises (events.Event) as e:
            s.decode (b"\x07\x03\x00\x00\x02\x00\x00\x04\xff\x7f\x06\x08\x08\x8c")
        self.assertEqual (e.exception.event, events.Event.fmt_err)

    def test_encode (self):
        segs = [ L1Segment (count = 2, startid = 3,
                            entries = [ RouteSegEntry (cost = 5, hops = 1),
                                        RouteSegEntry (cost = 99, hops = 5) ]) ]
        s = L1Routing (srcnode = Nodeid (4), segments = segs)
        b = s.encode ()
        self.assertEqual (b, b"\x07\x04\x00\x00\x02\x00\x03\x00"
                          b"\x05\x04\x63\x14\x6e\x18")
        
class test_l2routing (routingmsg):
    def test_decode (self):
        s = L2Routing ()
        s.decode (b"\x09\x03\x00\x00\x02\x00\x05\x00\xff\x7f\x06\x08\x0d\x88")
        self.assertEqual (s.srcnode, 3)
        e = [ L2Segment (count = 2, startid = 5,
                         entries = [ RouteSegEntry (cost = 1023, hops = 31),
                                     RouteSegEntry (cost = 6, hops = 2) ]) ]
        self.assertEqual (s.segments, e)
        self.assertEqual (list (s.entries (self.circ)), [ (5, (32, 1028)),
                                                          (6, (3, 11)) ])

    def test_decodebad (self):
        s = L2Routing ()
        with self.assertRaises (events.Event) as e:
            s.decode (b"\x09\x03\x00\x00\x02\x00\x05\x00\xff\x7f\x06\x08\x0c\x88")
        self.assertEqual (e.exception.event, events.Event.adj_down)
        self.assertEqual (e.exception.reason, "checksum_error")

    def test_decodebadseg (self):
        s = L2Routing ()
        # Segment entry count 0
        with self.assertRaises (events.Event) as e:
            s.decode (b"\x09\x03\x00\x00\x00\x00\x07\x00\xff\x7f\x06\x08\x0d\x88")
        self.assertEqual (e.exception.event, events.Event.fmt_err)
        # Segment start id out of range
        with self.assertRaises (events.Event) as e:
            s.decode (b"\x09\x03\x00\x00\x02\x00\x3f\x00\xff\x7f\x06\x08\x47\x88")
        self.assertEqual (e.exception.event, events.Event.fmt_err)

    def test_encode (self):
        segs = [ L2Segment (count = 2, startid = 3,
                            entries = [ RouteSegEntry (cost = 5, hops = 1),
                                        RouteSegEntry (cost = 99, hops = 5) ]) ]
        s = L2Routing (srcnode = Nodeid (4), segments = segs)
        b = s.encode ()
        self.assertEqual (b, b"\x09\x04\x00\x00\x02\x00\x03\x00"
                          b"\x05\x04\x63\x14\x6e\x18")
        
if __name__ == "__main__":
    unittest.main ()

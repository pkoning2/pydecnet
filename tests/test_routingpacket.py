#!/usr/bin/env python3

import unittest

import sys
import os

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet.routing_packets import *
from decnet import events
from decnet.common import Nodeid

class test_shortdata (unittest.TestCase):
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
        
class test_longdata (unittest.TestCase):
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
        
if __name__ == "__main__":
    unittest.main ()

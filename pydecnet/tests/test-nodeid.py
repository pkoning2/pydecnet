#!/usr/bin/env python3

import unittest

import sys
import os

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet.common import Nodeid, Macaddr

class TestPacket (unittest.TestCase):
    def test_newstr (self):
        n = Nodeid ("1.24")
        self.assertEqual (n.area, 1)
        self.assertEqual (n.tid, 24)
        n = Nodeid ("24")
        self.assertEqual (n.area, 0)
        self.assertEqual (n.tid, 24)
        n = Nodeid ("63.1023")
        self.assertEqual (n.area, 63)
        self.assertEqual (n.tid, 1023)
        with self.assertRaises (ValueError):
            Nodeid ("0")
        with self.assertRaises (ValueError):
            Nodeid ("1024")
        with self.assertRaises (ValueError):
            Nodeid ("0.1")
        with self.assertRaises (ValueError):
            Nodeid ("1.1024")
        with self.assertRaises (ValueError):
            Nodeid ("64.1")

    def test_newint (self):
        n = Nodeid (1, 24)
        self.assertEqual (n.area, 1)
        self.assertEqual (n.tid, 24)
        n = Nodeid (24)
        self.assertEqual (n.area, 0)
        self.assertEqual (n.tid, 24)
        n = Nodeid (63, 1023)
        self.assertEqual (n.area, 63)
        self.assertEqual (n.tid, 1023)
        with self.assertRaises (ValueError):
            Nodeid (0)
        with self.assertRaises (ValueError):
            Nodeid (1024)
        with self.assertRaises (ValueError):
            Nodeid (0, 1)
        with self.assertRaises (ValueError):
            Nodeid (1, 1024)
        with self.assertRaises (ValueError):
            Nodeid (64, 1)

    def test_newmac (self):
        a = Macaddr ("aa-00-04-00-03-04")
        b = Macaddr ("aa-00-04-01-03-04")
        c = Macaddr ("aa-00-04-00-00-04")
        d = Macaddr ("aa-00-04-00-03-00")
        n = Nodeid (a)
        self.assertEqual (n.area, 1)
        self.assertEqual (n.tid, 3)
        with self.assertRaises (ValueError):
            Nodeid (b)
        with self.assertRaises (ValueError):
            Nodeid (c)
        with self.assertRaises (ValueError):
            Nodeid (d)

    def test_newbytes (self):
        n = Nodeid (b"\003\004")
        self.assertEqual (n.area, 1)
        self.assertEqual (n.tid, 3)
        with self.assertRaises (ValueError):
            Nodeid (b"\000\004")
        with self.assertRaises (ValueError):
            Nodeid (b"\003\000")
        
if __name__ == "__main__":
    unittest.main ()

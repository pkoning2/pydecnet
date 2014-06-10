#!/usr/bin/env python3

import unittest

import sys
import os
import time
import logging
import unittest.mock

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet.common import Nodeid, Macaddr, StopThread

logging.trace = unittest.mock.Mock ()

class TestNodeid (unittest.TestCase):
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
        self.assertRaises (ValueError, Nodeid, "0")
        self.assertRaises (ValueError, Nodeid, "1024")
        self.assertRaises (ValueError, Nodeid, "0.1")
        self.assertRaises (ValueError, Nodeid, "1.1024")
        self.assertRaises (ValueError, Nodeid, "64.1")

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

class TestMacaddr (unittest.TestCase):
    def test_newstr (self):
        a = Macaddr ("01-02-03-04-05-06")
        b = Macaddr ("1:2:3:4:5:6")
        c = Macaddr ("1.24")
        self.assertRaises (ValueError, Macaddr, "01-02-03-04-05")
        self.assertRaises (ValueError, Macaddr, "1:2:3:4:5:6:7")
        self.assertRaises (ValueError, Macaddr, "1.1024")
        self.assertRaises (ValueError, Macaddr, "64.1")
        self.assertRaises (ValueError, Macaddr, "0.42")
        self.assertRaises (ValueError, Macaddr, "42")

    def test_newnodeid (self):
        c = Macaddr (Nodeid (1, 24))
        p3 = Nodeid (42)
        self.assertRaises (ValueError, Macaddr, p3)

    def test_newbytes (self):
        a = Macaddr (b"abcdef")
        self.assertRaises (ValueError, Macaddr, b"abcde")
        self.assertRaises (ValueError, Macaddr, b"abcdefg")

class tthread (StopThread):
    hasrun = False
    
    def run (self):
        self.hasrun = True
        while not self.stopnow:
            time.sleep (0.1)

class TestThread (unittest.TestCase):
    def test_stopthread (self):
        t = tthread ()
        t.start ()
        time.sleep (0.1)
        self.assertTrue (t.is_alive ())
        t.stop (wait = True)
        self.assertFalse (t.is_alive ())
        self.assertTrue (t.hasrun)
        
if __name__ == "__main__":
    unittest.main ()

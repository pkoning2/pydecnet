#!/usr/bin/env python3

from tests.dntest import *
from decnet import common

class TestNodeid (DnTest):
    def test_newstr (self):
        n = common.Nodeid ("1.24")
        self.assertEqual (n.area, 1)
        self.assertEqual (n.tid, 24)
        n = common.Nodeid ("24")
        self.assertEqual (n.area, 0)
        self.assertEqual (n.tid, 24)
        n = common.Nodeid ("63.1023")
        self.assertEqual (n.area, 63)
        self.assertEqual (n.tid, 1023)
        self.assertRaises (ValueError, common.Nodeid, "0")
        self.assertRaises (ValueError, common.Nodeid, "1024")
        self.assertRaises (ValueError, common.Nodeid, "0.1")
        self.assertRaises (ValueError, common.Nodeid, "1.1024")
        self.assertRaises (ValueError, common.Nodeid, "64.1")

    def test_newint (self):
        n = common.Nodeid (1, 24)
        self.assertEqual (n.area, 1)
        self.assertEqual (n.tid, 24)
        n = common.Nodeid (24)
        self.assertEqual (n.area, 0)
        self.assertEqual (n.tid, 24)
        n = common.Nodeid (63, 1023)
        self.assertEqual (n.area, 63)
        self.assertEqual (n.tid, 1023)
        with self.assertRaises (ValueError):
            common.Nodeid (0)
        with self.assertRaises (ValueError):
            common.Nodeid (1024)
        with self.assertRaises (ValueError):
            common.Nodeid (0, 1)
        with self.assertRaises (ValueError):
            common.Nodeid (1, 1024)
        with self.assertRaises (ValueError):
            common.Nodeid (64, 1)

    def test_newmac (self):
        a = common.Macaddr ("aa-00-04-00-03-04")
        b = common.Macaddr ("aa-00-04-01-03-04")
        c = common.Macaddr ("aa-00-04-00-00-04")
        d = common.Macaddr ("aa-00-04-00-03-00")
        n = common.Nodeid (a)
        self.assertEqual (n.area, 1)
        self.assertEqual (n.tid, 3)
        with self.assertRaises (ValueError):
            common.Nodeid (b)
        with self.assertRaises (ValueError):
            common.Nodeid (c)
        with self.assertRaises (ValueError):
            common.Nodeid (d)

    def test_newbytes (self):
        n = common.Nodeid (b"\003\004")
        self.assertEqual (n.area, 1)
        self.assertEqual (n.tid, 3)
        n = common.Nodeid (b"\003\000")
        self.assertEqual (n.area, 0)
        self.assertEqual (n.tid, 3)
        with self.assertRaises (ValueError):
            common.Nodeid (b"\000\004")
        n, b = common.Nodeid.decode (b"\003\004abc")
        self.assertEqual (n.area, 1)
        self.assertEqual (n.tid, 3)
        self.assertEqual (b, b"abc")

class TestMacaddr (DnTest):
    def test_newstr (self):
        a = common.Macaddr ("01-02-03-04-05-06")
        b = common.Macaddr ("1:2:3:4:5:6")
        c = common.Macaddr ("1.24")
        self.assertRaises (ValueError, common.Macaddr, "01-02-03-04-05")
        self.assertRaises (ValueError, common.Macaddr, "1:2:3:4:5:6:7")
        self.assertRaises (ValueError, common.Macaddr, "1.1024")
        self.assertRaises (ValueError, common.Macaddr, "64.1")
        self.assertRaises (ValueError, common.Macaddr, "0.42")
        self.assertRaises (ValueError, common.Macaddr, "42")

    def test_newnodeid (self):
        c = common.Macaddr (common.Nodeid (1, 24))
        c = common.Macaddr (common.Nodeid (42))

    def test_newbytes (self):
        a = common.Macaddr (b"abcdef")
        self.assertRaises (ValueError, common.Macaddr, b"abcde")
        self.assertRaises (ValueError, common.Macaddr, b"abcdefg")
        a, b = common.Macaddr.decode (b"abcdefABC")
        self.assertEqual (b, b"ABC")

class tthread (common.StopThread):
    hasrun = False
    
    def run (self):
        self.hasrun = True
        while not self.stopnow:
            time.sleep (0.1)

class TestThread (DnTest):
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

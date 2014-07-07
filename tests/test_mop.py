#!/usr/bin/env python3

"""MOP protocol layer unit tests"""

from tests.dntest import *

import queue

from decnet import mop
from decnet import packet
from decnet import timers
from decnet import datalink
from decnet.apiserver import ApiRequest

tconfig = unittest.mock.Mock ()
tconfig.device = None

class TestMop (DnTest):
    tdata = b"four score and seven years ago"
    
    def setUp (self):
        super ().setUp ()
        self.dl = unittest.mock.Mock ()
        self.dl.use_mop = True
        self.cp = unittest.mock.Mock ()
        self.dl.create_port.return_value = self.cp
        
    def lelen (self, d):
        return len (d).to_bytes (2, "little")

    def test_periodic_sysid (self):
        c = mop.MopCircuit (self.node, "mop-0", self.dl, tconfig)
        c.start ()
        send = self.cp.send
        s = c.sysid
        s.dispatch (timers.Timeout (s))
        sysid, dest = self.lastsent (self.cp, 1)
        self.assertIsInstance (sysid, mop.SysId)
        self.assertEqual (sysid.software, "DECnet/Python")
        self.assertEqual (sysid.receipt, 0)
        self.assertEqual (dest, Macaddr ("AB-00-00-02-00-00"))
    def test_reqid (self):
        c = mop.MopCircuit (self.node, "mop-0", self.dl, tconfig)
        c.start ()
        send = self.cp.send
        w = datalink.Received (owner = c, src = Macaddr (b"foobar"),
                               packet = b"\x05\x00\x02\x00")
        c.dispatch (w)
        sysid, dest = self.lastsent (self.cp, 1)
        self.assertIsInstance (sysid, mop.SysId)
        self.assertEqual (sysid.software, "DECnet/Python")
        self.assertEqual (sysid.receipt, 2)
        self.assertEqual (dest, Macaddr (b"foobar"))
        
    def test_recsysid (self):
        c = mop.MopCircuit (self.node, "mop-0", self.dl, tconfig)
        c.start ()
        send = self.cp.send
        macid = Macaddr (b"Foobar")
        w = datalink.Received (owner = c, src = macid,
                               packet = b"\x07\x00\x00\x00"
                               b"\x01\x00\x03\x03\x00\x00"
                               b"\x02\x00\x01\x0d"
                               b"\x64\x00\x01\x07"
                               b"\xc8\x00\x09\x08Unittest")
        c.dispatch (w)
        w2 = unittest.mock.Mock ()
        w2.__class__ = ApiRequest
        w2.circuit = "mop-0"
        w2.command = "sysid"
        s = c.sysid
        s.dispatch (w2)
        a, k = w2.done.call_args
        reply = a[0]
        self.assertRegex (reply, str (macid))
        self.assertRegex (reply, "Computer Interconnect interface")
        h = s.html (None)
        self.assertRegex (h, str (macid))
        self.assertRegex (h, "Computer Interconnect interface")
        self.assertRegex (h, "Unittest")
        # Now update the entry
        w = datalink.Received (owner = c, src = macid,
                               packet = b"\x07\x00\x00\x00"
                               b"\x01\x00\x03\x03\x00\x00"
                               b"\x02\x00\x01\x0d"
                               b"\x64\x00\x01\x07"
                               b"\xc8\x00\x09\x08New text")
        c.dispatch (w)
        h = s.html (None)
        self.assertRegex (h, str (macid))
        self.assertRegex (h, "Computer Interconnect interface")
        self.assertNotRegex (h, "Unittest")
        self.assertRegex (h, "New text")
        
if __name__ == "__main__":
    unittest.main ()

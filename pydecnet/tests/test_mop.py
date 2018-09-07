#!/usr/bin/env python3

"""MOP protocol layer unit tests"""

from tests.dntest import *

import queue

from decnet import mop
from decnet import packet
from decnet import timers
from decnet import datalink
from decnet import http

tconfig = container ()
tconfig.device = None
tconfig.console = False

class TestMop (DnTest):
    tdata = b"four score and seven years ago"
    
    def setUp (self):
        super ().setUp ()
        self.dl = unittest.mock.Mock ()
        self.dl.use_mop = True
        self.cp = unittest.mock.Mock ()
        self.dl.create_port.return_value = self.cp
        self.httpthread = None
        
    def tearDown (self):
        if self.httpthread:
            self.httpthread.stop ()
        super ().tearDown ()
    
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
        self.node.mopcircuit = c
        c.start ()
        send = self.cp.send
        macid = Macaddr (b"Foobar")
        w = datalink.Received (owner = c, src = macid,
                               packet = b"\x07\x00\x00\x00"
                               b"\x01\x00\x03\x03\x00\x00"
                               b"\x02\x00\x02\x0d\x00"
                               b"\x64\x00\x01\x07"
                               b"\xc8\x00\x09\x08Unittest")
        c.dispatch (w)
        # Use the api, but called directly (don't go through the
        # trouble of bringing up the http server)
        ret = c.sysid.get_api ()
        self.assertEqual (len (ret), 1)
        reply = ret[0]
        self.assertEqual (reply["srcaddr"], macid)
        self.assertEqual (reply["device"], "Computer Interconnect interface")
        self.assertEqual (reply["software"], "Unittest")
        # Now update the entry.  Include an unknown (software dependent)
        # field to validate open ended TLV parsing
        w = datalink.Received (owner = c, src = macid,
                               packet = b"\x07\x00\x00\x00"
                               b"\x01\x00\x03\x03\x00\x00"
                               b"\x02\x00\x02\x0d\x00"
                               b"\x64\x00\x01\x07"
                               b"\xc8\x00\x09\x08New text"
                               b"\xca\x00\x0cSW dependent")
        c.dispatch (w)
        ret = c.sysid.get_api ()
        self.assertEqual (len (ret), 1)
        reply = ret[0]
        self.assertEqual (reply["srcaddr"], macid)
        self.assertEqual (reply["device"], "Computer Interconnect interface")
        self.assertEqual (reply["software"], "New text")
        # Locate the sysid entry
        entry = c.sysid.heard[macid]
        self.assertEqual (entry.field202, b"SW dependent")
        
if __name__ == "__main__":
    unittest.main ()

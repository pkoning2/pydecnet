#!/usr/bin/env python3

"""MOP protocol layer unit tests"""

from tests.dntest import *

import queue

from decnet import mop
from decnet import packet
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
        s = c.sysid
        DnTimeout (s)
        sysid, dest = self.lastsent (self.cp, 1)
        self.assertIsInstance (sysid, mop.SysId)
        self.assertEqual (sysid.software, "DECnet/Python")
        self.assertEqual (sysid.receipt, 0)
        self.assertEqual (dest, Macaddr ("AB-00-00-02-00-00"))

    def test_reqid (self):
        c = mop.MopCircuit (self.node, "mop-0", self.dl, tconfig)
        c.start ()
        w = datalink.Received (owner = c, src = Macaddr (b"foobar"),
                               packet = b"\x05\x00\x02\x00")
        self.node.addwork (w)
        sysid, dest = self.lastsent (self.cp, 1)
        self.assertIsInstance (sysid, mop.SysId)
        self.assertEqual (sysid.software, "DECnet/Python")
        self.assertEqual (sysid.receipt, 2)
        self.assertEqual (dest, Macaddr (b"foobar"))
        
    def test_recsysid (self):
        c = mop.MopCircuit (self.node, "mop-0", self.dl, tconfig)
        self.node.mopcircuit = c
        c.start ()
        macid = Macaddr (b"Foobar")
        w = datalink.Received (owner = c, src = macid,
                               packet = b"\x07\x00\x00\x00"
                               b"\x01\x00\x03\x03\x00\x00"
                               b"\x02\x00\x02\x0d\x00"
                               b"\x64\x00\x01\x07"
                               b"\xc8\x00\x09\x08Unittest")
        self.node.addwork (w)
        # Use the api, but called directly (don't go through the
        # trouble of bringing up the API server)
        ret = c.sysid.api ()["sysid"]
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
        self.node.addwork (w)
        ret = c.sysid.api ()["sysid"]
        self.assertEqual (len (ret), 1)
        reply = ret[0]
        self.assertEqual (reply["srcaddr"], macid)
        self.assertEqual (reply["device"], "Computer Interconnect interface")
        self.assertEqual (reply["software"], "New text")
        # Locate the sysid entry
        entry = c.sysid.heard[macid]
        self.assertEqual (entry.field202, b"SW dependent")
        # An unusually complex one taken from an actual trace:
        w = datalink.Received (owner = c, src = macid,
                              packet = b"\x07\x00\x00\x00"
                                       b"\x01\x00\x03\x04\x00\x00"
                                       b"\x02\x00\x02A\x00"
                                       b"\x07\x00\x06\xaa\x00\x04\x00\x12|"
                                       b"d\x00\x01\xcb"
                                       b"\x90\x01\x01\x01"
                                       b"\xc8\x00\x01\xff"
                                       b"\xc9\x00\x04AVMS"
                                       b"\xca\x00\x08V8.3    "
                                       b"\xcb\x00\x08RAPTOR  "
                                       b"\xcc\x00\x04\xc0\x07\x00\x00"
                                       b"\xcd\x00\x08\x17\x010\x08\x01\x00\x00\x00"
                                       b"\xce\x00\x08\x86\x010\x08\x02\x00\x00\x00"
                                       b"\xcf\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"
                                       b"\xd0\x00\x04 \x00\x00\x02"
                                       b"\xd1\x00\x14\xa2z\xa2\x1b\x00\x00\x00\x00\x03\x00\x00\x00\x80\x00\x86\x00\x02\x02\x01\x00")
        self.node.addwork (w)
        ret = c.sysid.api ()["sysid"]
        self.assertEqual (len (ret), 1)
        reply = ret[0]
        self.assertEqual (reply["srcaddr"], macid)
        self.assertEqual (reply["device"], 203)
        self.assertEqual (reply["hwaddr"], Macaddr ("aa-00-04-00-12-7c"))
        self.assertEqual (reply["software"], -1)
        # Locate the sysid entry
        entry = c.sysid.heard[macid]
        self.assertEqual (entry.field201, b"AVMS")
        self.assertEqual (entry.field202, b"V8.3    ")

    def test_tolerance (self):
        """Test the handling of non-conforming packets"""
        c = mop.MopCircuit (self.node, "mop-0", self.dl, tconfig)
        self.node.mopcircuit = c
        c.start ()
        macid = Macaddr (b"Foobar")
        # "Software" field with ASCII string without preceding length
        # field, and oversized.
        w = datalink.Received (owner = c, src = macid,
                               packet = b"\x07\x00\x00\x00"
                                        b"\x01\x00\x03\x03\x00\x00"
                                        b"\x02\x00\x02A\x00"
                                        b"\x07\x00\x06\xaa\x00\x04\x00\x1d|"
                                        b"\x08\x00\n\x14\x13\x04\x19\x109-\x00\x00\x00"
                                        b"d\x00\x01\x0f"
                                        b"\xc8\x002SANYALnet Labs, PANDA TOPS-20 Monitor 7.1(21733)-4"
                                        b"\x90\x01\x01\x01"
                                        b"\x91\x01\x02\x06\x01")
        self.node.addwork (w)
        ret = c.sysid.api ()["sysid"]
        self.assertEqual (len (ret), 1)
        reply = ret[0]
        self.assertEqual (reply["srcaddr"], macid)
        self.assertEqual (reply["software"],
                          "SANYALnet Labs, PANDA TOPS-20 Monitor 7.1(21733)-4")
        # Packet with incomplete TLV ("Software" field has T but not LV)
        del c.sysid.heard[macid]
        w = datalink.Received (owner = c, src = macid,
                               packet = b"\x07\x00\x00\x00"
                                        b"\x01\x00\x03\x03\x00\x00"
                                        b"\x02\x00\x02A\x00"
                                        b"\x07\x00\x06\xaa\x00\x04\x00\x1c|"
                                        b"d\x00\x01%"
                                        b"\xc8\x00")
        self.node.addwork (w)
        ret = c.sysid.api ()["sysid"]
        self.assertEqual (len (ret), 1)
        reply = ret[0]
        self.assertEqual (reply["srcaddr"], macid)
        self.assertEqual (reply["device"], "DELQA CSMA/CD communication link")
        self.assertEqual (reply["software"], "")
        
if __name__ == "__main__":
    unittest.main ()

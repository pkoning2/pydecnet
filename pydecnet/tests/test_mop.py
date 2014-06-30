#!/usr/bin/env python3

"""MOP protocol layer unit tests"""

import unittest

import sys
import os
import time
import random
import queue

import unittest.mock

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet import mop
from decnet import packet
from decnet import timers
from decnet import datalink
from decnet.common import *
from decnet.apiserver import ApiRequest

def trace (fmt, *args):
    print ("trace:", fmt % args)

def debug (fmt, *args):
    print ("debug:", fmt % args)

tconfig = unittest.mock.Mock ()
tconfig.device = None

random.seed (999)
def randpkt (minlen, maxlen):
    plen = random.randrange (minlen, maxlen + 1)
    i = random.getrandbits (plen * 8)
    return i.to_bytes (plen, "little")

class TestMop (unittest.TestCase):
    tdata = b"four score and seven years ago"
    
    def setUp (self):
        self.lpatch = unittest.mock.patch ("decnet.mop.logging")
        self.spatch = unittest.mock.patch ("decnet.mop.statemachine.logging")
        self.lpatch.start ()
        self.spatch.start ()
        #mop.logging.trace.side_effect = trace
        #mop.statemachine.logging.trace.side_effect = trace
        #mop.logging.debug.side_effect = debug
        self.tnode = unittest.mock.Mock ()
        self.tnode.node = self.tnode
        self.dl = unittest.mock.Mock ()
        self.dl.use_mop = True
        self.cp = unittest.mock.Mock ()
        self.dl.create_port.return_value = self.cp
        
    def tearDown (self):
        self.lpatch.stop ()
        self.spatch.stop ()

    def lastsent (self, calls):
        self.assertEqual (self.cp.send.call_count, calls)
        a, k = self.cp.send.call_args
        w = a[0]
        self.assertIsInstance (w, packet.Packet)
        return w

    def lelen (self, d):
        return len (d).to_bytes (2, "little")

    def pad (self, d):
        if len (d) < 46:
            d += bytes (46 - len (d))
        return d
    
    def test_periodic_sysid (self):
        c = mop.MopCircuit (self.tnode, "mop-0", self.dl, tconfig)
        c.start ()
        send = self.cp.send
        s = c.sysid
        s.dispatch (timers.Timeout (s))
        sysid = self.lastsent (1)
        self.assertIsInstance (sysid, mop.SysId)
        self.assertEqual (sysid.software, "DECnet/Python")
        self.assertEqual (sysid.receipt, 0)
        
    def test_reqid (self):
        c = mop.MopCircuit (self.tnode, "mop-0", self.dl, tconfig)
        c.start ()
        send = self.cp.send
        w = datalink.Received (owner = c, src = Macaddr (b"foobar"),
                               packet = b"\x05\x00\x02\x00")
        c.dispatch (w)
        sysid = self.lastsent (1)
        self.assertIsInstance (sysid, mop.SysId)
        self.assertEqual (sysid.software, "DECnet/Python")
        self.assertEqual (sysid.receipt, 2)

    def test_recsysid (self):
        c = mop.MopCircuit (self.tnode, "mop-0", self.dl, tconfig)
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

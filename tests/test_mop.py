#!/usr/bin/env python3

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
        self.lpatch.start ()
        #mop.logging.trace.side_effect = trace
        #mop.logging.debug.side_effect = debug
        self.tnode = unittest.mock.Mock ()
        self.tnode.node = self.tnode
        self.dl = unittest.mock.Mock ()
        self.dl.__class__ = datalink.BcDatalink
        self.cp = unittest.mock.Mock ()
        self.dl.create_port.return_value = self.cp
        
    def tearDown (self):
        self.lpatch.stop ()

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
        
if __name__ == "__main__":
    unittest.main ()

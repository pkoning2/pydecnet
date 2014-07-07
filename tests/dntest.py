#!/usr/bin/env python3

import sys
import os
import time
import random

import unittest
import unittest.mock

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet.common import *
from decnet import packet
from decnet import events

def testcases (tests):
    for t in tests:
        if isinstance (t, unittest.TestCase):
            yield t
        else:
            yield from testcases (t)
            
# Custom testcase loader to load only Test* classes, not base classes
# that are not in themselves a complete test.
def load_tests (loader, tests, pattern):
    suite = unittest.TestSuite ()
    for t in testcases (tests):
        if type (t).__name__.lower ().startswith ("test"):
            suite.addTest (t)
    return suite

random.seed (999)
def randpkt (minlen, maxlen):
    plen = random.randrange (minlen, maxlen + 1)
    i = random.getrandbits (plen * 8)
    return i.to_bytes (plen, "little")

class DnTest (unittest.TestCase):
    debug = False
    trace = False

    def setUp (self):
        """Common setup for DECnet/Python test cases.

        If "debug" and/or "trace" attributes are set True in the derived
        class or object, debug and/or trace logging will be printed.
        """
        self.node = unittest.mock.Mock ()
        self.node.node = self.node
        self.lpatches = list ()
        for n, m in sys.modules.items ():
            if n.startswith ("decnet.") and hasattr (m, "logging"):
                ln = "%s.logging" % n
                p = unittest.mock.patch (ln)
                self.lpatches.append (p)
                l = p.start ()
                if self.debug:
                    l.debug.side_effect = self.mockdebug
                if self.trace:
                    l.trace.side_effect = self.mocktrace
                    
    def tearDown (self):
        for p in self.lpatches:
            p.stop ()
            
    def mockdebug (self, fmt, *args):
        print (self, "debug:", fmt % args)

    def mocktrace (self, fmt, *args):
        print (self, "trace:", fmt % args)

    def lastsent (self, port, calls):
        self.assertEqual (port.send.call_count, calls)
        a, k = port.send.call_args
        w = a[0]
        self.assertIsInstance (w, packet.Packet)
        return w

    def lastreceived (self, calls):
        self.assertEqual (self.node.addwork.call_count, calls)
        a, k = self.node.addwork.call_args
        w = a[0]
        self.assertIsInstance (w, Received)
        return w

    def lastevent (self, code):
        self.assertTrue (self.node.logevent.call_count)
        a, k = self.node.logevent.call_args
        try:
            e = k["event"]
        except KeyError:
            e = a[0]
        if code:
            self.assertEqual (e, code)
        e = events.Event (*a, **k)
        e._local_node = self.node
        e._timestamp = time.time ()
        return e
        
    def lastdispatch (self, calls):
        self.assertEqual (self.node.dispatch.call_count, calls)
        a, k = self.node.dispatch.call_args
        w = a[0]
        self.assertIsInstance (w, packet.Packet)
        return w


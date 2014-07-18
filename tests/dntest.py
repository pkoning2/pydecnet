#!/usr/bin/env python3

import sys
import os
import time
import random
import collections

import unittest
import unittest.mock

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet.common import *
from decnet import packet
from decnet import events
from decnet import logging
from decnet import node

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
    if not plen:
        return b""
    i = random.getrandbits (plen * 8)
    return i.to_bytes (plen, "little")

class container (object):
    """An empty object, but you can assign attributes to it."""

class t_node (node.Node):
    nodeid = Nodeid (42, 1023)
    nodename = "NEMO"
    
    def __init__ (self):
        self.node = self
        self.nodeinfo_byname = dict()
        self.nodeinfo_byid = dict()
        self.addwork = unittest.mock.Mock ()
        self.timers = unittest.mock.Mock ()
        self.dispatch = unittest.mock.Mock ()
        self.ecounts = collections.Counter ()
        node.Node.initfilter (self)
        self.elist = list ()
        
    def start (self, mainthread = False): pass
    def mainloop (self): raise Exception
    def stop (self): pass
    def register_api (self, command, handler, help = None): pass

    def logevent (self, event, entity = None, **kwds):
        if isinstance (event, events.Event):
            event.setsource (self.nodeid)
        else:
            event = event (entity, source = self.nodeid, **kwds)
        self.ecounts[event.__class__] += 1
        self.elist.append (event)
        super ().logevent (event, entity, **kwds)
        
class DnTest (unittest.TestCase):
    loglevel = logging.WARNING

    def setUp (self):
        """Common setup for DECnet/Python test cases.
        """
        self.node = t_node ()
        self.node.logevent = unittest.mock.Mock (wraps = self.node.logevent)
        self.lpatches = list ()
        for n in ("critical", "error", "warning", "info", "debug",
                  "trace", "log", "exception"):
            m = getattr (logging, n)
            p = unittest.mock.patch ("decnet.logging.%s" % n, wraps = m)
            p.start ()
            self.lpatches.append (p)                                     
        h = logging.StreamHandler (sys.stdout)
        logging.basicConfig (handler = h, level = self.loglevel)
        self.setloglevel (self.loglevel)
        
    def setloglevel (self, level):
        logging.getLogger ().setLevel (level)
        
    def tearDown (self):
        logging.shutdown ()
        for p in self.lpatches:
            p.stop ()
            
    def lastsent (self, port, calls, back = 0, ptype = packet.Packet):
        self.assertEqual (port.send.call_count, calls)
        if back:
            a, k = port.send.call_args_list[-1 - back]
        else:
            a, k = port.send.call_args
        if len (a) > 1:
            w, dest = a
        else:
            w = a[0]
            dest = None
        self.assertIsInstance (w, ptype)
        return w, dest

    def lastwork (self, calls, itype = Received):
        self.assertEqual (self.node.addwork.call_count, calls)
        a, k = self.node.addwork.call_args
        w = a[0]
        self.assertIsInstance (w, itype)
        return w

    def assertEvent (self, evt = None, **kwds):
        self.assertTrue (self.node.elist)
        e = self.node.elist[-1]
        if evt:
            self.assertEqual (type (e), evt)
        for k, v in kwds.items ():
            p = getattr (e, k)
            try:
                v = p.values[v]
            except (AttributeError, KeyError):
                pass
            pval = p.val
            if isinstance (pval, collections.abc.Sequence):
                # Multiple.  Keep just the values
                pval = [ v for v, f in pval ]
                if len (pval) == 1:
                    pval = pval[0]
            self.assertEqual (pval, v)
            
    def assertParam (self, p, value):
        if not isinstance (value, int):
            value = p.values[value]
        self.assertEqual (p.val, value)

    def lastdispatch (self, calls, element = None):
        element = element or self.node
        self.assertEqual (element.dispatch.call_count, calls)
        a, k = element.dispatch.call_args
        w = a[0]
        self.assertIsInstance (w, packet.Packet)
        return w

    def eventcount (self, ec):
        return self.node.ecounts[ec]
    

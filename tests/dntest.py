#!/usr/bin/env python3

import sys
import os
import time
import random
import collections
from collections.abc import Sequence
import re

import unittest
import unittest.mock

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet.common import *
from decnet import logging
from decnet import packet
from decnet import events
from decnet import node
from decnet import event_logger
from decnet import timers

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

def start_timer (item, timeout):
    #print ("starting timeout {} on {}", timeout, item)
    item.next = False
    
def stop_timer (item):
    #print ("stopping timer on {}", item)
    item.next = item
    
class t_node (node.Node):
    nodeid = Nodeid (1, 5)
    nodename = "NEMO"
    
    def __init__ (self):
        self.node = self
        self.nodeinfo_byname = dict()
        self.nodeinfo_byid = dict()
        self.addwork = unittest.mock.Mock ()
        self.timers = unittest.mock.Mock ()
        self.timers.start.side_effect = start_timer
        self.timers.stop.side_effect = stop_timer
        self.dispatch = unittest.mock.Mock ()
        self.ecounts = collections.Counter ()
        self.event_logger = event_logger.EventLogger (self, None)
        self.elist = list ()
        self.nicenode = NiceNode (self.nodeid, self.nodename)
        
    def start (self, mainthread = False): pass
    def mainloop (self): raise Exception
    def stop (self): pass

    def logevent (self, event, entity = None, **kwds):
        if isinstance (event, events.Event):
            event.setsource (self.nodeid)
        else:
            event = event (entity, source = self.nodeid, **kwds)
        self.ecounts[event.__class__] += 1
        self.elist.append (event)
        super ().logevent (event, entity, **kwds)

    def addwork_dispatcher (self, work, handler = None):
        # This method is used as the side effect of "addwork" if a
        # particular test actually needs to dispatch work items to
        # their handler.
        work.dispatch ()

    def enable_dispatcher (self):
        self.addwork.side_effect = self.addwork_dispatcher
        
class DnTest (unittest.TestCase):
    loglevel = logging.CRITICAL

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
        # logging.logging is the Python standard logging module
        h = logging.logging.StreamHandler (sys.stdout)
        logging.logging.basicConfig (handlers = [ h ], level = self.loglevel)
        self.setloglevel (self.loglevel)
        self.lasttrace = 0
        self.lastdebug = 0
        
    def setloglevel (self, level):
        logging.logging.getLogger ().setLevel (level)
        logging.tracing = True
        
    def tearDown (self):
        logging.logging.shutdown ()
        for p in self.lpatches:
            p.stop ()
            
    def lastsent (self, port, calls, back = 0, ptype = packet.Packet):
        self.assertEqual (port.send.call_count, calls)
        if back:
            a, k = port.send.call_args_list[-1 - back]
        else:
            a, k = port.send.call_args
        if len (a) > 1:
            w, dest, *extra = a
        else:
            w = a[0]
            # If there wasn't a second positional argument,
            # destination address might be given as a keyword argument
            # instead.
            dest = k.get ("dest", None)
        self.assertIsInstance (w, ptype)
        return w, dest

    def lastwork (self, calls, back = 0, itype = Received):
        # The work we expect to be posted comes from a separate
        # thread, which means it might not be here quite yet.  Allow
        # for that.
        if self.node.addwork.call_count != calls:
            time.sleep (0.1)
        self.assertEqual (self.node.addwork.call_count, calls)
        if back:
            a, k = self.node.addwork.call_args_list[-1 - back]
        else:
            a, k = self.node.addwork.call_args
        w = a[0]
        self.assertIsInstance (w, itype)
        return w

    def assertEvent (self, evt = None, back = 0, entity = None, **kwds):
        self.assertTrue (self.node.elist)
        e = self.node.elist[-1 - back]
        # Encode it to force all the NiceType classes to be set
        e.encode ()
        if evt:
            self.assertEqual (type (e), evt)
        if entity:
            self.assertEqual (e.entity_type, entity)
        for k, v in kwds.items ():
            p = getattr (e, k)
            try:
                vdict = e._values[k]
                v = vdict[v]
            except (AttributeError, KeyError):
                pass
            except AttributeError:
                pass
            self.assertEqual (p, v)
        eparams = [ k for k, v in e.__dict__.items () if
                    isinstance (v, packet.Field) and k not in kwds ]
        if eparams:
            eparams = " ".join (sorted (eparams))
            msg = "Missing event parameter checks: {}".format (eparams)
            self.fail (msg)
            
    def assertParam (self, p, value):
        if not isinstance (value, int):
            value = p.values[value]
        self.assertEqual (p, value)

    def lastdispatch (self, calls, element = None):
        element = element or self.node
        self.assertEqual (element.dispatch.call_count, calls)
        a, k = element.dispatch.call_args
        w = a[0]
        self.assertIsInstance (w, packet.Packet)
        return w

    def eventcount (self, ec):
        return self.node.ecounts[ec]
    
    def short (self, b, cls, maxlen = None):
        if not maxlen:
            maxlen = len (b) - 1
        for l in range (1, maxlen):
            try:
                ret = cls (b[:l])
                self.fail ("Accepted truncated data: length %d result %s" % (l, ret))
            except packet.DecodeError:
                pass
            except AssertionError:
                raise
            except Exception as e:
                self.fail ("Unexpected exception %s for input %s (len %d)"
                           % (e, b[:l], l))
        ret = cls (b)
        return ret

    def shortfield (self, b, cls, maxlen = None):
        if not maxlen:
            maxlen = len (b) - 1
        for l in range (1, maxlen):
            try:
                ret, x = cls.decode (b[:l])
                self.fail ("Accepted truncated data: length %d result %s" % (l, ret))
            except packet.DecodeError:
                pass
            except AssertionError:
                raise
            except Exception as e:
                self.fail ("Unexpected exception %s for input %s (len %d)"
                           % (e, b[:l], l))
        ret, b = cls.decode (b)
        self.assertEqual (b, b"")
        return ret

    def assertTrace (self, pat, msg = None):
        if not msg:
            msg = "No new trace message matching '{}' found".format (pat)
        lt = self.lasttrace
        self.lasttrace = logging.trace.call_count
        self.assertGreater (self.lasttrace, lt, msg)
        pat_re = re.compile (pat, re.I)
        for c in logging.trace.call_args_list[lt:]:
            args, kwargs = c
            if pat_re.search (args[0]):
                return args
        self.fail (msg)
        
    def assertDebug (self, pat, msg = None):
        if not msg:
            msg = "No new debug message matching '{}' found".format (pat)
        lt = self.lastdebug
        self.lastdebug = logging.debug.call_count
        self.assertGreater (self.lastdebug, lt, msg)
        pat_re = re.compile (pat, re.I)
        for c in logging.debug.call_args_list[lt:]:
            args, kwargs = c
            if pat_re.search (args[0]):
                return args
        self.fail (msg)
        
_port = 6665

def nextport ():
    global _port
    _port += 1
    return _port

# Wrapper to deliver a timeout to the specified Element
def DnTimeout (dest):
    assert (dest.islinked ())
    stop_timer (dest)
    t = timers.Timeout (dest, dest.revcount)
    t.dispatch ()
    

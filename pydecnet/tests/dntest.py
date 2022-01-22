#!/usr/bin/env python3

import sys
import os
import time
import random
import collections
from collections.abc import Sequence
import re
import queue

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
from decnet import datalink
from decnet import config

# The log level defaults to "CRITICAL" meaning nothing really, but can
# be overridden by environment variable "LOGLEVEL".  Or it can be
# overridden in individual testcases by calling "setloglevel" or
# "trace" methods of the test suite base class.
loglevel = os.environ.get ("LOGLEVEL", logging.CRITICAL)

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

def testsdu (num = 0):
    "Generate test payload (SDU)"
    # If the argument is omitted or zero, a standard string is
    # returned.  Otherwise the payload is the supplied number encoded
    # as a 4 byte integer.
    if num:
        return num.to_bytes (4, "little")
    return b"four score and seven years ago"

class container (object):
    """An empty object, but you can assign attributes to it."""

def start_timer (item, timeout):
    logging.trace ("starting timeout {} on {}", timeout, item)
    item.next = False
    
def stop_timer (item):
    logging.trace ("stopping timer on {}", item)
    item.next = item

class Dispatcher:
    def __init__ (self):
        self.workqueue = queue.Queue ()
        # Initially dispatching is enabled.  It may be that some test
        # cases will want to turn it off for specific reasons.
        self.do_dispatch = True
        self.working = False
        
    def addwork (self, work, handler = None):
        """Add a work item (instance of a Work subclass) to the node's
        work queue.  This can be called from any thread.  If "handler"
        is specified, set the owner of the work item to that value,
        overriding the handler specified when the Work object was created.
        """
        # This method adapted from decnet.node
        if handler is not None:
            work.owner = handler
        logging.trace ("Add work {} of {}", work, work.owner)
        self.workqueue.put (work)
        if self.do_dispatch:
            self.dispatch ()

    def dispatch (self):
        # If we're not currently in a work item, dispatch any queued
        # work items, one by one.  This is called from addwork if
        # dispatching is enabled, and can also be called at any time
        # (useful if dispatching is disabled) to cause queued but not
        # dispatched work items to be dispatched at that time.
        if not self.working:
            self.working = True
            while True:
                try:
                    item = self.workqueue.get (0)
                    logging.trace ("dispatch work {} of {}", item, item.owner)
                    item.dispatch ()
                    logging.trace ("finished work {} of {}", item, item.owner)
                except queue.Empty:
                    break
            self.working = False

class t_node (node.Node):
    nodeid = Nodeid (1, 5)
    nodename = "NEMO"
    
    def __init__ (self):
        self.node = self
        self.intercept = self
        self.nodeinfo_byname = dict()
        self.nodeinfo_byid = dict()
        self.addwork = unittest.mock.Mock ()
        self.dispatcher = Dispatcher ()
        self.addwork.side_effect = self.dispatcher.addwork
        self.timers = unittest.mock.Mock ()
        self.timers.start.side_effect = start_timer
        # Don't model the jitter, just make this like regular start
        self.timers.jstart.side_effect = start_timer
        self.timers.stop.side_effect = stop_timer
        self.dispatch = unittest.mock.Mock ()
        self.ecounts = collections.Counter ()
        self.event_logger = event_logger.EventLogger (self, None)
        self.elist = list ()
        self.apis = dict ()
        self.nicenode = NiceNode (self.nodeid, self.nodename)
        
    def start (self, mainthread = False): pass
    def stop (self): pass
    def register_api (self, name, sf, ef = None): pass

    def logevent (self, event, entity = None, **kwds):
        if isinstance (event, events.Event):
            event.setsource (self.nodeid)
        else:
            event = event (entity, source = self.nodeid, **kwds)
        self.ecounts[event.__class__] += 1
        self.elist.append (event)
        super ().logevent (event, entity, **kwds)

    def enable_dispatcher (self, enable = True):
        self.dispatcher.do_dispatch = enable

    def intfun (self): return 7
        
    def intreq (self): return 0

class DnTest (unittest.TestCase):
    def setUp (self):
        """Common setup for DECnet/Python test cases.
        """
        global node
        node = self.node = t_node ()
        self.node.logevent = unittest.mock.Mock (wraps = self.node.logevent)
        # Start the pydecnet logging machinery.  This used to just
        # start the Python standard logger with a "basic" config, but
        # that isn't really good enough because we don't get the nice
        # timestamps and other helpful information.
        lc = container ()
        lc.log_config = lc.log_file = lc.syslog = lc.chroot = None
        lc.keep = lc.uid = lc.gid = 0
        lc.daemon = False
        lc.log_level = loglevel
        logging.start (lc)
        # Make sure the level is set properly.
        self.setloglevel (loglevel)
        self.lpatches = list ()
        for n in ("critical", "error", "warning", "info", "debug",
                  "trace", "log", "exception"):
            m = getattr (logging, n)
            p = unittest.mock.patch ("decnet.logging.%s" % n, wraps = m)
            p.start ()
            self.lpatches.append (p)
        self.lasttrace = 0
        self.lastdebug = 0
        
    def setloglevel (self, level):
        logging.logging.getLogger ().setLevel (level)
        logging.tracing = True

    def trace (self):
        # A shortcut for something we use during debug
        self.setloglevel (logging.TRACE)

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

    def lastdispatch (self, calls, element = None, back = 0,
                      itype = packet.Packet):
        # Check the count of work items that have been delivered to
        # the element (by default the node) and return the most recent
        # item, or n items back from most recent if back is given.
        # Verify that the item is of type itype.
        #
        # In earlier code, a similar check was done that looked at the
        # node.addwork calls.  That is more problematic because a
        # number of layers use work items internally, and all work
        # items go through that call.  We are interested not so much
        # in the internals but rather in work items delivered to the
        # next layer, which is what checking for dispatched items will
        # do.
        element = element or self.node
        if element.dispatch.call_count != calls:
            time.sleep (0.1)
        self.assertEqual (element.dispatch.call_count, calls)
        if not calls:
            return None
        if back:
            a, k = element.dispatch.call_args_list[-1 - back]
        else:
            a, k = element.dispatch.call_args
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

    def assertUp (self, count = 1):
        w = self.lastdispatch (count, itype = datalink.DlStatus)
        self.assertEqual (w.status, w.UP)
        
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

    def config (self, s):
        ret, msg = config.configparser.parse_args (s.split ())
        if msg:
            self.fail ("config error: {}".format (msg))
        return ret
    
_port = 6665

def nextport ():
    global _port
    _port += 1
    return _port

# Wrapper to deliver a timeout to the specified Element
def DnTimeout (dest):
    assert (dest.islinked ())
    stop_timer (dest)
    # Timeouts are delivered through the work queue in the real
    # system, and we need to do that here as well to make sure proper
    # sequentiality is maintained.
    logging.trace ("Queueing Timeout")
    node.addwork (timers.Timeout (dest, dest.revcount))

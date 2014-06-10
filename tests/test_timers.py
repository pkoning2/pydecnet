#!/usr/bin/env python3

import unittest

import sys
import os
import time
import logging
import unittest.mock

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet import timers

logging.trace = unittest.mock.Mock ()

class TNode (object):
    def addwork (self, work):
        work.dispatch ()

tnode = TNode ()
tnode.node = tnode

class TTimer (timers.Timer):
    fired = None
    def dispatch (self, item):
        self.fired = time.time ()
        
class TestTimer (unittest.TestCase):
    def test_wheel1 (self):
        wheel = timers.TimerWheel (tnode, 0.1, 400)
        t = TTimer ()
        self.assertIsNone (t.fired)
        now = time.time ()
        wheel.start (t, 1.0)
        time.sleep (2)
        # Supplied delay is rounded up to the next multiple of a timer tick,
        # and then the expiration can happen up to one tick sooner.
        self.assertTrue (0 <= t.fired - now <= 1.1)
        timers.StopThread.stop (wheel)

    def test_wheel2 (self):
        wheel1 = timers.TimerWheel (tnode, 0.1, 400)
        wheel2 = timers.TimerWheel (tnode, 2, 400)
        t1 = TTimer ()
        t2 = TTimer ()
        # Offset the timer start a bit from the wheel start
        time.sleep (0.75)
        self.assertIsNone (t1.fired)
        self.assertIsNone (t2.fired)
        now = time.time ()
        wheel1.start (t1, 1.0)
        wheel2.start (t2, 1.0)
        time.sleep (3)
        d1 = t1.fired - now
        d2 = t2.fired - now
        # Supplied delay is rounded up to the next multiple of a timer tick,
        # and then the expiration can happen up to one tick sooner.
        self.assertTrue (0 <= d1 <= 1.1)
        self.assertTrue (0 <= d2 <= 2.1)
        # Do it once more with feeling
        now = time.time ()
        wheel1.start (t1, 1.0)
        wheel2.start (t2, 1.0)
        time.sleep (3)
        d1 = t1.fired - now
        d2 = t2.fired - now
        # Supplied delay is rounded up to the next multiple of a timer tick,
        # and then the expiration can happen up to one tick sooner.
        self.assertTrue (0 <= d1 <= 1.1)
        self.assertTrue (0 <= d2 <= 2.1)
        timers.StopThread.stop (wheel1)
        timers.StopThread.stop (wheel2)
    
if __name__ == "__main__":
    unittest.main ()

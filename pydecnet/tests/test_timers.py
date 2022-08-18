#!/usr/bin/env python3

import queue

from tests.dntest import *

from decnet import timers

class TNode (object):
    def __init__ (self):
        self.workqueue = queue.Queue ()
        
    def addwork (self, work, handler = None):
        work.owner.fired = time.time ()
        self.workqueue.put (work)
        
    def dowork (self):
        while True:
            try:
                work = self.workqueue.get_nowait ()
            except queue.Empty:
                break
            work.dispatch ()

tnode = TNode ()
tnode.node = tnode

class TTimer (timers.Timer):
    def __init__ (self, name = "t"):
        self.fired = None
        self.delivered = False
        self.name = name
        super ().__init__ ()
        
    def dispatch (self, item):
        self.delivered = True
        
class TestTimer (DnTest):
    def test_wheel1 (self):
        wheel = timers.TimerWheel (tnode, 0.1, 400)
        wheel.startup ()
        t = TTimer ()
        self.assertIsNone (t.fired)
        now = time.time ()
        wheel.start (t, 1.0)
        time.sleep (2)
        tnode.dowork ()
        # Supplied delay is rounded up to the next multiple of a timer tick,
        # and then the expiration can happen up to one tick sooner.
        self.assertTrue (0 <= t.fired - now <= 1.1)
        self.assertTrue (t.delivered)
        timers.StopThread.stop (wheel)

    def test_wheel2 (self):
        wheel1 = timers.TimerWheel (tnode, 0.1, 400)
        wheel2 = timers.TimerWheel (tnode, 2, 400)
        wheel1.startup ()
        wheel2.startup ()
        t1 = TTimer ("t1")
        t2 = TTimer ("t2")
        # Offset the timer start a bit from the wheel start
        time.sleep (0.75)
        self.assertIsNone (t1.fired)
        self.assertIsNone (t2.fired)
        now = time.time ()
        wheel1.start (t1, 1.0)
        wheel2.start (t2, 1.0)
        time.sleep (3)
        tnode.dowork ()
        d1 = t1.fired - now
        d2 = t2.fired - now
        # Supplied delay is rounded up to the next multiple of a timer tick,
        # and then the expiration can happen up to one tick sooner.
        self.assertTrue (0 <= d1 <= 1.1)
        self.assertTrue (0 <= d2 <= 2.1)
        self.assertTrue (t1.delivered)
        self.assertTrue (t2.delivered)
        # Do it once more with feeling
        now = time.time ()
        t1.delivered = t2.delivered = False
        wheel1.start (t1, 1.0)
        wheel2.start (t2, 1.0)
        time.sleep (3)
        tnode.dowork ()
        d1 = t1.fired - now
        d2 = t2.fired - now
        # Supplied delay is rounded up to the next multiple of a timer tick,
        # and then the expiration can happen up to one tick sooner.
        self.assertTrue (0 <= d1 <= 1.1)
        self.assertTrue (0 <= d2 <= 2.1)
        self.assertTrue (t1.delivered)
        self.assertTrue (t2.delivered)
        timers.StopThread.stop (wheel1)
        timers.StopThread.stop (wheel2)
    
    def test_canceled (self):
        """Verify that canceling a timer before the timeout is actually
        delivered prevents the delivery.
        """
        wheel = timers.TimerWheel (tnode, 0.1, 400)
        wheel.startup ()
        t2 = TTimer ("t2")
        class T2Timer (TTimer):
            def dispatch (self, item):
                wheel.stop (t2)
                super ().dispatch (item)
        t1 = T2Timer ("t1")
        self.assertIsNone (t1.fired)
        self.assertIsNone (t2.fired)
        now = time.time ()
        wheel.start (t1, 1.0)
        wheel.start (t2, 1.0)
        time.sleep (2)
        tnode.dowork ()
        # Both timers expired, but only one was delivered because its
        # delivery canceled the other.
        self.assertTrue (0 <= t1.fired - now <= 1.1)
        self.assertTrue (0 <= t2.fired - now <= 1.1)
        self.assertTrue (t1.delivered)
        self.assertFalse (t2.delivered)
        timers.StopThread.stop (wheel)

if __name__ == "__main__":
    unittest.main ()

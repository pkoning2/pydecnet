#!/usr/bin/env python3

"""Timer support for DECnet

This implements the timer wheel mechanism, with callbacks on expiration.
"""

from abc import abstractmethod, ABCMeta
import time

from .common import *
from . import logging
from . import html

class Cque (object):
    """Base class for objects that can be put on a circular queue.
    Instances of this class will also serve as list heads.
    """
    __slots__ = ("prev", "next", "revcount")
    
    def reset (self):
        self.next = self.prev = self
        
    def __init__ (self):
        self.reset ()
        self.revcount = 0
    
    def add_after (self, item):
        """Insert "item" as the successor of this object, i.e., first
        on the list if this is the list head.
        """
        self.revcount += 1
        item.prev = self
        item.next = self.next
        self.next.prev = item
        self.next = item

    def add_before (self, item):
        """Insert "item" as the predecessor of this object, i.e., last
        on the list if this is the list head.
        """
        self.revcount += 1
        item.next = self
        item.prev = self.prev
        self.prev.next = item
        self.prev = item

    def remove (self):
        """Remove this item from whatever circular queue it is on.
        To avoid trouble, we also link this item to itself, so accidental
        repeat calls to remove won't corrupt the queue.
        """
        self.revcount += 1
        self.next.prev = self.prev
        self.prev.next = self.next
        self.reset ()

    def islinked (self):
        """Return True if the queue is not empty (for list heads) or
        the queue element is linked into a queue (for elements).
        """
        return self.next != self
    
class Timer (Cque, metaclass = ABCMeta):
    """Abstract base class for an object that can be put on the
    TimerWheel, i.e., acts as a timer.
    """
    __slots__ = ()
    
    @abstractmethod
    def dispatch (self, item):
        """This method is called if the timer expires.
        """
        pass

class CallbackTimer (Timer):
    """A simple timer that does a call to a given function with
    a given argument on expiration.
    """
    __slots__ = ("fun", "arg")
    
    def __init__ (self, fun, arg = None):
        super ().__init__ ()
        self.fun = fun
        self.arg = arg

    def dispatch (self, item):
        self.fun (self.arg)

class Timeout (Work):
    """A timer has timed out.
    """
    # There is some extra processing here beyond what is done for the
    # usual case of dispatching work items.  This is done to close a
    # timing window.
    #
    # Timer expiration happens in a separate thread (the timer wheel
    # thread), so Timeout work items may be posted to the node work
    # queue at any time, while the node thread is doing work in some
    # layer.  That work might include making state changes that cancel
    # and/or restart timers.  This concurrency may result in a timeout
    # being delivered for some element after that timer was supposedly
    # canceled.  Rather than force ever timer user to cope with this,
    # we put the check here.  Every Timer (the base class of any
    # element that can have timeouts delivered to it) has a "revcount"
    # field, which is incremented for every start and stop operation.
    # When a timeout is seen in the timer thread, the value of the
    # revcount field at that instant is saved here.  When it comes
    # time to dispatch this Timeout work item to its owner (the Timer
    # subclass object) this is done only if the saved revcount still
    # matches the value currently in the Timer.  If they differ, then
    # the owner has done additional timer operations, such as stop,
    # between the recognition of the timeout and now.  If so, we
    # discard the work item rather than deliver it.
    def __init__ (self, owner, revcount):
        self.revcount = revcount
        super ().__init__ (owner)

    def dispatch (self):
        if self.revcount == self.owner.revcount:
            super ().dispatch ()
            
class TimerWheel (Element, StopThread):
    """A timer wheel.
    """
    # We want to reuse these names for the timer API.
    __start = StopThread.start
    __stop = StopThread.stop
    
    def __init__ (self, parent, tick, maxtime):
        """Define a wheel that ticks every "tick" seconds and has
        a max timeout of "maxtime" seconds.
        """
        Element.__init__ (self, parent)
        StopThread.__init__ (self)
        maxtime = int ((maxtime + 1) / tick)
        self.wheel = [ Cque () for i in range (maxtime) ]
        self.pos = 0
        self.maxtime = maxtime
        self.tick = tick
        self.lock = threading.Lock ()
        self.stats = Histogram ()

    def startup (self):
        logging.debug ("Starting timer subsystem")
        self.__start ()

    def start (self, item, timeout):
        """Start timer running for "item", it will time out in "timeout"
        seconds.  The minimum timeout is one tick.

        If the timer times out, send a Timeout work item to "item".
        """
        ticks = int (timeout / self.tick) or 1
        if ticks >= self.maxtime:
            raise OverflowError ("Timeout {} too large".format (timeout))
        if not isinstance (item, Timer):
            raise TypeError ("Timer item is not of Timer type")
        with self.lock:
            pos = (self.pos + ticks) % self.maxtime
            item.remove ()
            # Add this new item to the end of the list.  This is
            # important to insure that items with the same expiration
            # time expire in the order they were added.  NSP needs
            # that to avoid retransmitting packets out of order.
            self.wheel[pos].add_before (item)
        logging.trace ("Started {:.2f} second timeout for {}", timeout, item)

    def jstart (self, item, timeout):
        "Start a timer, with -10%/+0% jitter applied"
        # This is standard practice in DECnet Phase V, but older
        # versions also benefit from doing this in many cases.
        if timeout > 2.0:
            timeout *= random.uniform (0.9, 1.0)
        self.start (item, timeout)
        
    def run (self):
        """Tick handler.
        """
        maxdt = self.tick * 2
        prev = time.time ()
        while not self.stopnow:
            time.sleep (self.tick)
            cur = time.time ()
            dt = cur - prev
            self.stats.count (dt)
            if dt > maxdt:
                logging.trace ("timer thread excessive tick latency {}", dt)
            prev = cur
            self.pos = (self.pos + 1) % self.maxtime
            self.expirations ()
            
    def expirations (self):
        count = 0
        qh = self.wheel[self.pos]
        # We'll remove timed out items from the list one at a time,
        # to ensure things work correctly even if they are being removed
        # concurrent with this expiration handler.  That's why the
        # items are removed one at a time under protection of the
        # timer wheel lock, rather than making a copy of the list
        # and walking that copy.
        while qh.islinked ():
            with self.lock:
                item = qh.next
                item.remove ()
                revcount = item.revcount
            if item is not qh:
                logging.trace ("Timeout for {}", item)
                self.node.addwork (Timeout (item, revcount))
                count += 1
        return count
    
    def shutdown (self):
        self.__stop (True)
        logging.debug ("Timer subsystem shut down")

    def stop (self, item):
        """Stop the timer for "item".
        """
        if not isinstance (item, Timer):
            raise TypeError ("Timer item is not of Timer type")
        logging.trace ("Stopped timeout for {}", item)
        with self.lock:
            item.remove ()

    def html (self):
        """Return an HTML section with timer statistics.
        """
        self.stats.calc_stats ()
        return html.tbsection ("Timer statistics", self.stats.header,
                               [ self.stats.stats () ])

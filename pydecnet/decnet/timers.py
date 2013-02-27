#!/usr/bin/env python3

"""Timer support for DECnet

This implements the timer wheel mechanism, with callbacks on expiration.
"""

from abc import abstractmethod, ABCMeta
import time
import logging

from .common import *

class Cque (object):
    """Base class for objects that can be put on a circular queue.
    Instances of this class will also serve as list heads.
    """
    __slots__ = ("prev", "next")
    
    def __init__ (self):
        self.next = self.prev = self

    reset = __init__
    
    def add (self, item):
        """Insert "item" as the successor of this object, i.e., first
        on the list if this is the list head.
        """
        item.prev = self
        item.next = self.next
        self.next.prev = item
        self.next = item

    def remove (self):
        """Remove this item from whatever circular queue it is on.
        To avoid trouble, we also link this item to itself, so accidental
        repeat calls to remove won't corrupt the queue.
        """
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
    
    def __init__ (self, fun, arg):
        super ().__init__ ()
        self.fun = fun
        self.arg = arg

    def dispatch (self, item):
        self.fun (self.arg)

class Timeout (Work):
    """A timer has timed out.
    """
    
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
        self.__start ()

    def start (self, item, timeout):
        """Start timer running for "item", it will time out in "timeout"
        seconds.  The minimum timeout is one tick.

        If the timer times out, send a Timeout work item to "item".
        """
        ticks = int (timeout / self.tick) or 1
        if ticks >= self.maxtime:
            raise OverflowError ("Timeout %d too large" % timeout)
        if not isinstance (item, Timer):
            raise TypeError ("Timer item is not of Timer type")
        self.lock.acquire ()
        pos = (self.pos + ticks) % self.maxtime
        item.remove ()
        self.wheel[pos].add (item)
        self.lock.release ()
        #logging.debug ("Started %d second timeout for %s", timeout, item)
        
    def run (self):
        """Tick handler.
        """
        while not self.stopnow:
            time.sleep (self.tick)
            pos = self.pos = (self.pos + 1) % self.maxtime
            qh = self.wheel[pos]
            # We'll remove timed out items from the list one at a time,
            # to ensure things work correctly even if they are being removed
            # concurrent with this expiration handler.  That's why the
            # items are removed one at a time under protection of the
            # timer wheel lock, rather than making a copy of the list
            # and walking that copy.
            while qh.islinked ():
                self.lock.acquire ()
                item = qh.next
                item.remove ()
                self.lock.release ()
                if item is not qh:
                    self.node.addwork (Timeout (item))

    def shutdown (self):
        self.__stop (True)

    def stop (self, item):
        """Stop the timer for "item".
        """
        if not isinstance (item, Timer):
            raise TypeError ("Timer item is not of Timer type")
        self.lock.acquire ()
        item.remove ()
        self.lock.release ()


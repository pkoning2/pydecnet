#!/usr/bin/env python3

"""Timer support for DECnet

This implements the timer wheel mechanism, with callbacks on expiration.
"""

from abc import abstractmethod
import threading
import time

class StopThread (threading.Thread):
    """A thread with stop method.
    """
    def __init__ (self):
        super ().__init__ ()
        self.stopnow = False
        
    def stop (self, wait = False):
        """Stop the thread associated with this connection.  The actual
        handling of "stopnow" needs to go into the class that uses this.

        If "wait" is True, wait for the thread to exit.
        """
        if not self.stopnow and self.isAlive ():
            self.stopnow = True
            if wait:
                self.join (10)
                if self.is_alive ():
                    print ("Thread failed to stop after 10 seconds")

class Cque (object):
    """Base class for objects that can be put on a circular queue.
    Instances of this class will also serve as list heads.
    """
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

    def __bool__ (self):
        """Return True if the queue is not empty (for list heads) or
        the queue element is linked into a queue (for elements).
        """
        return self.next != self
    
class Timer (Cque):
    """Abstract base class for an object that can be put on the
    TimerWheel, i.e., acts as a timer.
    """
    @abstractmethod
    def timeout (self):
        """This method is called if the timer expires.
        """
        pass

class CallbackTimer (Timer):
    """A simple timer that does a call to a given function with
    a given argument on expiration.
    """
    def __init__ (self, fun, arg):
        super ().__init__ ()
        self.fun = fun
        self.arg = arg

    def timeout (self):
        self.fun (self.arg)
        
class TimerWheel (StopThread):
    """A timer wheel.
    """
    # We want to reuse these names for the timer API.
    __start = StopThread.start
    __stop = StopThread.stop
    
    def __init__ (self, tick, maxtime):
        """Define a wheel that ticks every "tick" seconds and has
        a max tick count of "maxtime".
        """
        super ().__init__ ()
        maxtime += 1
        self.wheel = [ Cque () for i in range (maxtime) ]
        self.pos = 0
        self.maxtime = maxtime
        self.tick = tick
        self.lock = threading.Lock ()
        self.__start ()

    def start (self, item, timeout):
        """Start timer running for "item", it will time out in "timeout"
        timer ticks.  The minimum timeout is one tick.
        """
        ticks = timeout // self.tick or 1
        if ticks >= self.maxtime:
            raise OverflowError ("Timeout %d too large" % timeout)
        if not isinstance (item, Timer):
            raise TypeError ("Timer item is not of Timer type")
        self.lock.acquire ()
        pos = (self.pos + ticks) % self.maxtime
        self.wheel[pos].add (item)
        self.lock.release ()
        
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
            while qh:
                self.lock.acquire ()
                item = qh.next
                item.remove ()
                self.lock.release ()
                item.timeout ()

    def shutdown (self):
        self.__stop (True)

    def stop (self, item):
        """Stop the timer for "item".
        """
        self.lock.acquire ()
        item.remove ()
        self.lock.release ()

try:
    timers
except (AttributeError, NameError):
    # timers will be a singleton timer wheel, one second ticks, timeouts
    # up to one hour.
    timers = TimerWheel (1, 3600)

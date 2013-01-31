#!

"""DECnet/Python Node object -- the container for all the parts of DECNET

"""

import queue

class Node (object):
    """A Node object is the outermost container for all the other objects
    that make up a DECnet node.  Typically there is one Node object, but
    it's certainly possible to create multiple ones (to emulate an
    entire network within a single process).
    """
    def __init__ (self):
        from decnet import timers    # Done here to avoid import loop
        self.node = self
        self.timers = timers.TimerWheel (self, 1, 3600)
        self.workqueue = queue.Queue ()

    def addwork (self, work):
        """Add a work item (instance of a Work subclass) to the node's
        work queue.  This can be called from any thread.
        """
        self.workqueue.put (work)
        
    def run (self):
        q = self.workqueue
        try:
            while True:
                work = q.get ()
                work.dispatch ()
        finally:
            self.timers.shutdown ()
            
class Element (object):
    """Element is the base class for most classes that define DECnet
    components.  The elements of a node form a tree, whose root is
    the Node object.
    """
    def __init__ (self, parent):
        self.parent = parent
        self.node = parent.node

# Classes used to send work to DECnet components.  We need these because
# we want the main processing to be done in the main thread, to avoid
# lots of locks and thread safety bugs.  Other threads, such as the timer
# thread, datalinks, etc., create Work objects and queue these onto the
# node work queue.  The node then calls the dispatch method, which sends
# the work to the dispatch method of the component (called the "owner").
# For example, the datalink receive thread will send received packets
# to the routing initialization layer instance for that circuit.
#
# Derived classes can override __init__ to add more attributes, but
# in many cases derived classes need nothing else.  Any keyword arguments
# on the constructor will produce attributes by those names, so overriding
# __init__ is only useful if you need something more complicated.

class Work (object):
    """Base class for work object
    """
    def __init__ (self, owner, **kwarg):
        self.owner = owner
        self.__dict__.update (kwarg)

    def dispatch (self):
        self.owner.dispatch (self)
        

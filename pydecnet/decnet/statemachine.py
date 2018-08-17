#!

"""State machine base class.

"""

from abc import abstractmethod

from . import timers
from . import logging

class Timeout (object): pass

class StateMachine (timers.Timer):
    """Abstract base class for a state machine.

    The state machine is defined by a set of methods, each of which
    is a function of one argument, which specifies the action to be
    taken in that state given the input passed as argument.  The
    action method returns the desired new state or None to leave it
    alone.

    There is one required action method, "s0" which is the initial
    state.

    Method "validate" may be overridden to define common checks or
    actions to be done before the state action is invoked.  It returns
    True to perform the state action, or False to skip it.
    
    State machines are derived from Timer, because as a rule every
    state machine needs to have timeouts.  If a timeout occurs, the
    action method is called with a Timeout object for argument.
    """
    def __init__ (self):
        super ().__init__ ()
        self.state = self.s0

    @abstractmethod
    def s0 (self, data):
        """The initial state of the state machine.
        """
        pass

    def validate (self, data):
        """Override this to define common checks or actions done
        before the state action.  Return False to skip the state
        action, True to perform it, some other value that tests
        as True to use that data instead.
        """
        return True
    
    def dispatch (self, data):
        """Process the state machine input "data" for the current state.
        Returns the output defined by the action for that state, if any.
        The current state is updated as appropriate.
        """
        v = self.validate (data)
        if v:
            if v is not True:
                logging.trace ("{} {} substituting {}", self.statename (),
                               data, v)
                data = v
            newstate = self.state (data)
            if newstate:
                logging.trace ("{} finished with {}, new state {}",
                               self.statename (), data, newstate.__name__)
                self.state = newstate
            else:
                logging.trace ("{} finished with {}, no state change",
                               self.statename (), data)
        else:
            logging.trace ("{} {} rejected by validate",
                           self.statename (), data)
            
    def statename (self):
        """Return a string giving the object's name, if it has one
        (otherwise the state machine class name), and the current state name.
        """
        try:
            return "{}<state: {}>".format (self.name, self.state.__name__)
        except Exception:
            return "{}<state: {}>".format (self.__class__.__name__, self.state.__name__)

    __str__ = statename

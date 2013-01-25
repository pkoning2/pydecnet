#!

"""State machine base class.

"""

from abc import abstractmethod
from .timers import Timer

class Timeout (object): pass

class StateMachine (Timer):
    """Abstract base class for a state machine.

    The state machine is defined by a set of methods, each of which
    is a function of one argument, which specifies the action to be
    taken in that state given the input passed as argument.  The
    action method returns the output for that input, and updates
    the current state of the state machine as needed.

    There is one required action method, "s0" which is the initial
    state.

    State machines are derived from Timer, because as a rule every
    state machine needs to have timeouts.  If a timeout occurs, the
    action method is called with a Timeout object for argument.
    """
    def __init__ (self):
        self.state = self.s0

    @abstractmethod
    def s0 (self, data):
        """The initial state of the state machine.
        """
        pass

    def action (self, data):
        """Process the state machine input "data" for the current state.
        Returns the output defined by the action for that state, if any.
        The current state is updated as appropriate.
        """
        return self.state (data)

    def __str__ (self):
        """Return a string giving the state machine class name and the
        current state name.
        """
        return "%s<state: %s>" % (self.__class__.__name__, self.state.__name__)

    def timeout (self):
        """Timeout of the state machine's timer.  Call the current state
        method with a Timeout object as argument.
        """
        t = Timeout ()
        self.action (t)
        

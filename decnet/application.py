#!

"""Application interface to Session Control. 

This contains the machinery used to communicate with an external
object server process (via pipes) or an external client (via HTTP API
requests).  It also supplies the base class for module objects, i.e.,
DECnet application code that runs in the pydecnet process.
"""

import subprocess
import os

from .common import *
from . import logging
from . import pktlogging
from . import http
from .nsp import WrongState

class ApplicationWork (Work):
    name = "Outgoing request"

class BaseConnector (Element):
    """Base class for the interface between Session Control and an
    application.  It defines a small object which mainly is used to
    track the connections owned by a particular application.  Subclasses
    take care of the different types: module, process, and HTTP API
    client.
    """
    def __init__ (self, parent, obj):
        """Initialize an application.  

        "parent" is the Session object.  "obj" is the object definition
        (the DECnet object attributes) which are saved but not otherwise
        used.  Individual applications may need to refer to this, in
        particular obj.argument (the --argument value from the object
        definition in the config file).
        """
        super ().__init__ (parent)
        self.conns = dict ()
        self.object = obj

    def dispatch (self, item):
        try:
            conn = item.connection
            handle = id (conn)
            if item.closes:
                # This is a closing work item (disconnect or reject), so
                # forget the connection.
                del self.conns[handle]
            else:
                # Add the connection if not known yet, otherwise check
                # that it still matches.
                assert self.conns.setdefault (handle, conn) == conn
        except AttributeError:
            pass
        try:
            self.dispatch2 (item)
        except Exception:
            logging.exception ("Unhandled exception in {}".format (self.object))
            for conn in self.conns.values ():
                try:
                    conn.abort ()
                except WrongState:
                    conn.reject ()
            del self.conns

    # The methods below are called by the file based (JSON encoded)
    # applications, so they refer to connections via handles, and data
    # arrives at latin-1 encoded strings (which are basically bytes, but
    # not the same type).
    def accept (self, handle, data = ""):
        conn = self.conns[handle]
        return conn.accept (bytes (data, "latin1"))

    def reject (self, handle, data = ""):
        conn = self.conns[handle]
        conn.reject (bytes (data, "latin1"))
        del self.conns[handle]
    
    def disconnect (self, handle, data = ""):
        conn = self.conns[handle]
        conn.disconnect (bytes (data, "latin1"))
        del self.conns[handle]

    def abort (self, handle, data = ""):
        conn = self.conns[handle]
        conn.abort (bytes (data, "latin1"))
        del self.conns[handle]

    def interrupt (self, handle, data):
        conn = self.conns[handle]
        return conn.interrupt (bytes (data, "latin1"))

    def data (self, handle, data):
        conn = self.conns[handle]
        return conn.send_data (bytes (data, "latin1"))

    def setsockopt (self, handle, **kwds):
        conn = self.conns[handle]
        return conn.setsockopt (**kwds)

    def connect (self, dest, remuser, conndata = b"",
                 username = b"", password = b"", account = b""):
        conn = self.parent.connect (self, dest, remuser, conndata,
                                    username, password, account)
        self.conns[id (conn)] = conn
        return conn

# The application API into Session Control consists of all the callable
# items in the ApplicationConnector class, except for the internal ones
# (the ones starting with _).
BaseConnector.api = frozenset (k for (k, v) in BaseConnector.__dict__.items ()
                               if k[0] != '_' and k != "dispatch"
                               and callable (v))

class ModuleConnector (BaseConnector):
    """A connector applications implemented as Python modules and
    run within the pydecnet process ("module" type DECnet objects).  The
    actual application modules derive from this class.
    """
    def __init__ (self, parent, obj, appcls):
        super ().__init__ (parent, obj)
        self.app = appcls (self, obj)

    def dispatch2 (self, item):
        self.app.dispatch (item)
            
class ProcessConnector (BaseConnector):
    """This class has an interface like that of a "module" type
    application object, but instead of implementing an application
    itself, it converts that interface to a full duplex JSON stream, via
    pipes to a process.  This is the mechanism used to run "file"
    (separate process) applications.

    The JSON streams are connected via pipes to the process stdin
    (messages from session control) and stdout (requests to session
    control).  In addition, there is a pipe to the process stderr, which
    takes error messages and other logging information to the PyDECnet
    logging facility.
    """
    def __init__ (self, parent, obj):
        self.conns = dict ()
        super ().__init__ (parent,obj)
        self.sp = None
        self.othread = self.ethread = None
        self.enc = http.DNJsonEncoder ().encode
        self.dec = http.DNJsonDecoder ().decode
        # Build the minimal environment we want to pass down
        env = dict ()
        for k in "HOME", "PATH", "USER", "LOGNAME", "PYTHONPATH":
            try:
                env[k] = os.environ[k]
            except KeyError:
                pass
        args = [ obj.file ] + obj.argument
        logging.trace ("Starting file, args {}, environment {}", args, env)
        # Start the requested program file in a new process
        self.sp = subprocess.Popen (args,
                                    bufsize = 1,
                                    stdin = subprocess.PIPE,
                                    stdout = subprocess.PIPE,
                                    stderr = subprocess.PIPE,
                                    universal_newlines = True,
                                    start_new_session = True,
                                    env = env,
                                    restore_signals = True,
                                    shell = False)
        tname = str (obj)
        self.othread = StopThread (target = self.ohandler,
                                   name = tname,
                                   args = (self, self.sp.stdout))
        self.ethread = StopThread (target = self.ehandler,
                                   name = tname + " log",
                                   args = (self, self.sp.stderr))
        self.othread.start ()
        self.ethread.start ()

    def dispatch2 (self, item):
        if isinstance (item, ApplicationWork):
            # Process work from the process, a request to Session
            # Control.
            args = item.args
            action = args["mtype"]
            if action not in self.api:
                raise AttributeError ("Invalid API request")
            del args["mtype"]
            logging.trace ("Application SC {} request:\n{}",
                           action, repr (args))
            action = getattr (self, action)
            action (**args)
        else:
            # Process work sent up from the Session Control layer. 
            handle = id (item.connection)
            msg = bytes (item.message)
            mtype = item.name
            jdict = dict (handle = handle, data = msg, type = mtype)
            try:
                jdict["reason"] = item.reason
            except AttributeError:
                pass
            jdict = self.enc (jdict)
            print (jdict, file = self.sp.stdin)
        
    def ohandler (self, parent, opipe):
        """Read JSON requests from stdout and turn them into
        ApplicationWork items.
        """
        while not self.othread.stopnow:
            req = opipe.readline ().rstrip ("\n")
            if not req:
                continue
            req = self.dec (req)
            work = ApplicationWork (parent, args = req)
            parent.node.addwork (work)
            
    def ehandler (self, parent, epipe):
        """Read input from stderr.  If it looks like a JSON encoded
        object, use that to invoke logging.log.  If not, log it as a
        plain text DEBUG message.
        """
        while not self.ethread.stopnow:
            req = epipe.readline ().rstrip ("\n")
            if not req:
                continue
            try:
                reqd = self.dec (req)
                logging.log (reqd["level"], reqd["message"], *reqd["args"])
            except Exception:
                logging.debug ("Application {} debug message: {}",
                               parent.object, req)

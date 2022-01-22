#!

"""Connectors for the various APIs

This defines SimpleApiConnector and SimplePipeConnector classes.  Both
provide a basic procedural wrapper around the raw JSON based PyDECnet
API, suitable for single operation at a time request/response
exchanges.  For a more powerful connector that uses asyncio services
to handle concurrent operations and bidirectional data flows, see
module async_connectors.  """

import os
import sys
import socket
import functools
from logging import CRITICAL, ERROR, WARNING, INFO, DEBUG

defsockname = os.getenv ("DECNETAPI", "/tmp/decnetapi.sock")

from decnet.common import *
from decnet.logging import TRACE
from decnet.packet import IndexedField

enc = DNJsonEncoder ().encode
dec = DNJsonDecoder ().decode

class ApiError (Exception): "Error reported by API server"
class ConnClosed (ApiError): "Operation on closed socket"
class SequenceError (ApiError): "Unexpected message for new connection"
    
def makestr (v):
    if not isinstance (v, (str, int)):
        if isinstance (v, bytetypes):
            v = str (v, "latin1")
        else:
            v = str (v)
    return v

class ConnMessage (bytes):
    data = b""
    
    @classmethod
    def decode (cls, d):
        try:
            data = d["data"]
            if isinstance (data, str):
                d["data"] = data.encode ("latin1")
        except KeyError:
            pass
        data = d.pop ("data", b"")
        if isinstance (data, bytetypes):
            ret = cls (data)
        else:
            ret = cls ()
            ret.data = data
        ret.__dict__.update (d)
        return ret

    def encode (self):
        return dict (data = makestr (self), type = self.type)

class Connection:
    def __init__ (self, owner, system, api, handle):
        self.owner = owner
        self.system = system
        self.api = api
        self.handle = handle
        self.closed = False
        owner.connections[handle] = self

    def __str__ (self):
        return "Connection {}".format (self.handle)
    
    def recv (self):
        if self.closed:
            raise ConnClosed
        rc, resp = self.owner.recv ()
        # Check that it is expected
        assert rc == self
        resptype = resp.type
        if resptype in ("reject", "disconnect", "abort", "close"):
            self.close ()
        return resp

    def send (self, **req):
        if self.closed:
            raise ConnClosed
        req["handle"] = self.handle
        self.owner.send (system = self.system, api = self.api, **req)

    def close (self):
        if not self.closed:
            self.closed = True
            del self.owner.connections[self.handle]
        
    # Session control layer requests; for each of those, the "type"
    # field in the JSON request matches the method name.
    def accept (self, data = ""):
        self.send (type = "accept", data = makestr (data))

    def reject (self, data = ""):
        self.send (type = "reject", data = makestr (data))
        # This leaves the connection closed
        self.close ()
    
    def disconnect (self, data = ""):
        self.send (type = "disconnect", data = makestr (data))
        # This leaves the connection closed
        self.close ()

    def abort (self, data = ""):
        self.send (type = "abort", data = makestr (data))
        # This leaves the connection closed
        self.close ()

    def interrupt (self, data):
        self.send (type = "interrupt", data = makestr (data))

    def data (self, data):
        self.send (type = "data", data = makestr (data))

    def setsockopt (self, **kwds):
        self.send (type = "setsockopt", **kwds)

class SimpleConnector:
    "Base class for a simple one request/response connector"
    def __init__ (self):
        self.connections = dict ()
        self.tag = 1

    def connect (self, api = "session", system = None, **kwds):
        rc, resp = self.exch (api = api, system = system,
                              type = "connect", **kwds)
        # rc is the new connection, resp is the "connecting" message
        # that doesn't tell us anything except for the connection
        # handle.  Next, receive the accept or reject reply from the
        # destination.
        if not rc:
            if isinstance (resp, dict):
                resp = ConnMessage.decode (resp)
        if resp.type == "connecting":
            resp = rc.recv ()
        if resp.type == "reject":
            rc = None
        return rc, resp
    
    def recv (self):
        resp = self.readline ()
        rc, resp = self.parse (resp)
        if isinstance (resp, Exception):
            raise resp
        return rc, resp
    
    def parse (self, resp):
        if not resp:
            raise EOFError
        resp = dec (resp)
        h = resp.get ("handle", None)
        if h:
            rc = self.connections.get (h, None)
            if not rc:
                # New connection
                if resp["type"] not in ("connect", "connecting", "bind"):
                    raise SequenceError (resp)
                rc = self.makeconn (resp, h)
        else:
            # No connection reference
            rc = None
        err = resp.get ("error", None)
        resp = ConnMessage.decode (resp)
        if err:
            resp = ApiError (err, resp)
        return rc, resp

    def exch (self, **req):
        req["tag"] = self.tag = self.tag + 1
        self.send (**req)
        rc, resp = self.recv ()
        assert resp.tag == self.tag
        return rc, resp
    
    def close (self):
        for c in list (self.connections.values ()):
            c.close ()

class SimpleApiConnector (SimpleConnector):
    """Simple connector using API (Unix socket) transport

    This wraps the "general API" for PyDECnet, using a Unix domain
    socket.  The default socket used is /tmp/decnetapi.sock, a different
    name can be supplied using environment variable DECNETAPI.
    """
    def log (self, *args, **kwargs): pass
        
    def __init__ (self, name = defsockname):
        super ().__init__ ()
        self.sockname = name
        self.sock = socket.socket (socket.AF_UNIX)
        self.sock.connect (name)
        self.pending = b""

    def readline (self):
        "Read a line from the API socket"
        while b"\n" not in self.pending:
            r = self.sock.recv (65536)
            if not r:
                return None
            self.pending += r
        ret, self.pending = self.pending.split (b"\n", 1)
        return ret.decode ("latin1")
    
    def send (self, *, api = None, system = None, **req):
        # Empty request means "get system list", otherwise fill in
        # standard arguments.
        if api:
            if system:
                req["system"] = system
            req["api"] = api
        req = enc (req)
        req = (req + "\n").encode ("latin1")
        self.sock.send (req)

    def makeconn (self, resp, h):
        return Connection (self, resp["system"], resp["api"], h)

    def close (self):
        super ().close ()
        self.sock.close ()
        
class SimplePipeConnector (SimpleConnector):
    'Simple connector using pipes (for use in "file" type objects)'
    def __init__ (self):
        super ().__init__ ()

    def readline (self):
        return sys.stdin.readline ()

    def send (self, **req):
        # Make sure unneeded keys are not in the request
        req.pop ("system", None)
        req.pop ("api", None)
        req = enc (req)
        print (req, flush = True)

    def makeconn (self, resp, h):
        return Connection (self, "", "session", h)
        
    def log (self, level, msg, *args, **kwargs):
        logreq = dict (level = level, message = msg, args = args,
                       kwargs = kwargs)
        logreq = enc (logreq)
        print (logreq, file = sys.stderr, flush = True)

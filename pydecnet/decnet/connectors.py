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
import re
from logging import CRITICAL, ERROR, WARNING, INFO, DEBUG

defsockname = os.getenv ("DECNETAPI", "/tmp/decnetapi.sock")

from decnet.common import *
from decnet.logging import TRACE
from decnet.packet import Packet, IndexedField
from decnet.session import reject_text

enc = DNJsonEncoder ().encode
dec = DNJsonDecoder ().decode

class ApiError (Exception): "Error reported by API server"
class ConnClosed (ApiError): "Operation on closed socket"
class SequenceError (ApiError): "Unexpected message for new connection"

_pmr_re = re.compile (r"""([a-z0-9.]+)((?:::[a-z0-9.]+)*?)(?:::['"]?(?:(?:(\d+)=)|(?:task=(\S+)))?['"]?)?$""", re.I)

def makestr (v):
    if isinstance (v, dict):
        v = { k : makestr (vv) for (k, vv) in v.items () }
    elif not isinstance (v, (str, int)):
        if isinstance (v, Packet):
            v = v.encode ()
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
        try:
            # If there's a reject/disconnect reason and the code is
            # known, remember the associated message text.
            ret.text = reject_text[d["reason"]]
        except KeyError:
            pass
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
        # Wait for a reply, which must be a "runstate" report.
        resp = self.recv ()
        if resp.type != "runstate":
            self.close ()

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

    def log (self, *args, **kwargs):
        pass
        
    def logpacket (self, pkt, *args, **kwargs):
        pkt = makestr (makebytes (pkt))
        kwargs["extra"] = { "packetdata" : pkt }
        self.log (*args, **kwargs)

    def checkpmr (self, kwds, api):
        # Returns:
        # If PMR is needed: PMR request string
        # If not PMR: None
        remuser = kwds.get ("remuser", None)
        hopcount = int (kwds.pop ("hopcount", 0))
        if api == "session":
            # DECnet connection.  See if it involves PMR, or if the
            # request specified the destination object as part of the
            # dest argument string.
            m = _pmr_re.match (kwds["dest"])
            if m:
                kwds["dest"] = m.group (1)
            if m and (m.group (3) or m.group (4)):
                # Dest in the string, extract it
                if m.group (4):
                    remuser = m.group (4)
                else:
                    remuser = int (m.group (3))
                # Fill in the remote user argument
                kwds["remuser"] = remuser
            if m and m.group (2):
                # Multiple nodes were specified, use PMR
                path = m.group (2)[2:]
                finaluser = remuser
                kwds["remuser"] = 123
                h = chr (hopcount)
                # Construct the PMR request string
                if isinstance (finaluser, int):
                    spec = "{}{}::{}=".format (h, path, finaluser)
                else:
                    spec = "{}{}::TASK={}".format (h, path, finaluser)
                return spec
        # Not PMR, do the normal connect
        return None

    def parsepmrresponse (self, rc, pmrresp):
        if not pmrresp:
            text = "Empty PMR response"
        else:
            code = pmrresp[0]
            if code == 1:
                # Success.  PyDECnet extension: the destination
                # object accept data is at the end of the reply
                # string.
                adata = pmrresp.rsplit (b":", 1)[1]
                resp = ConnMessage (adata)
                resp.type = "accept"
                resp.pmrresponse = pmrresp
                return rc, resp
            elif code == 2:
                # Reject.  Build a connect reject message, with
                # the response string content as message text.
                text = makestr (pmrresp[1:])
            else:
                text = "Unknown PMR response code {}".format (code)
        resp = ConnMessage (b"")
        resp.type = "reject"
        resp.reason = 0
        resp.text = text
        return None, resp
        
    def connect (self, api = "session", system = None, **kwds):
        kwds = makestr (kwds)
        pmrspec = self.checkpmr (kwds, api)
        # Do the connect
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
            resp.text = reject_text.get (resp.reason, resp.reason)
            rc = None
        elif pmrspec:
            # Other option is accept.  If we're using PMR, talk to it
            rc.data (pmrspec)
            # Get the reply
            pmrresp = rc.recv ()
            rc, resp = self.parsepmrresponse (rc, pmrresp)
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

#!

"""An asynchronous (using coroutines) version of the API adapters

These are written for Python 3.7 or later.
"""

import asyncio
import traceback

from .connectors import *

# A sentinel sent to a component to tell it to close down.
SHUTDOWN = object ()

# These two functions wrap a file object in an asyncio stream.  You'd
# think that would be a standard high level API, but it isn't, and the
# low level API isn't nearly as friendly.  The code here is adapted
# from asyncio/streams.py.
async def make_read_stream (f):
    loop = asyncio.get_running_loop ()
    reader = asyncio.StreamReader (loop = loop)
    protocol = asyncio.StreamReaderProtocol (reader, loop = loop)
    t, p = await loop.connect_read_pipe (lambda: protocol, f)
    return reader

async def make_write_stream (f):
    # It sure isn't clear why Reader objects are needed here, but it
    # seems they are.
    loop = asyncio.get_running_loop ()
    reader = asyncio.StreamReader (loop = loop)
    protocol = asyncio.StreamReaderProtocol (reader, loop = loop)
    t, p = await loop.connect_write_pipe (lambda: protocol, f)
    writer = asyncio.StreamWriter (t, protocol, reader, loop)
    return writer

class AsyncConnection (Connection):
    def __init__ (self, owner, system, api, handle):
        super ().__init__ (owner, system, api, handle)
        self.recvq = asyncio.Queue ()
        self.listenq = asyncio.Queue ()

    async def recv (self):
        if self.closed:
            raise ConnClosed
        resp = await self.recvq.get ()
        if isinstance (resp, Exception):
            raise resp
        resptype = resp.type
        if resptype in ("reject", "disconnect", "abort", "close"):
            self.close ()
        return resp
    
    async def listen (self):
        ret = await self.listenq.get ()
        return ret

class AsyncConnector (SimpleConnector):
    def __init__ (self):
        super ().__init__ ()
        # This queue is for messages not related to a connection
        self.listenq = None
        self.exchanges = dict ()
        self.sendtask = self.recvtask = None
        
    async def recv (self):
        resp = await self.recvq ()
        if isinstance (resp, Exception):
            raise resp
        return resp

    async def sender (self):
        try:
            while True:
                msg = await self.sendq.get ()
                if msg is SHUTDOWN:
                    break
                self.writer.write (msg)
                await self.writer.drain ()
        finally:
            self.writer.close ()
            
    async def receiver (self):
        try:
            while True:
                req = await self.reader.readline ()
                if not req:
                    break
                self.dispatch (req)
        finally:
            await self.close ()
            
    async def start (self):
        # In some Python versions this has to be done after the event
        # loop is started, i.e., after the asyncio.run.  So do it at
        # start time rather than at object creation time.
        self.recvq = asyncio.Queue ()
        self.sendq = asyncio.Queue ()
        # Now start the two background tasks
        self.sendtask = asyncio.create_task (self.sender ())
        self.recvtask = asyncio.create_task (self.receiver ())

    async def logged_task (self, aw):
        try:
            return await aw
        except CancelledError:
            raise
        except Exception as e:
            traceback.print_exc ()
            
    async def serve_forever (self, boundconn, connhandler):
        """Helper to look for inbound connections and serve them as they
        arrive, until canceled.  "boundconn" is the bound connection
        returned by a previous "bind" call.  "connhandler" is a
        coroutine function that will be started as a new task, with the
        new connection as argument, each time an incoming connection is
        delivered.

        This method would not normally be used with the
        AsyncPipeConnector since that is for DECnet objects (which are
        started by PyDECnet handle a single inbound connection).
        """
        while True:
            conn = await boundconn.listen ()
            if conn is SHUTDOWN:
                break
            asyncio.create_task (connhandler (conn))
            
    async def close (self):
        if self.recvtask:
            self.recvtask.cancel ()
        if self.sendtask:
            self.sendq.put_nowait (SHUTDOWN)
            await asyncio.wait_for (self.sendtask, 5)
        
    def send (self, req):
        req = enc (req)
        req = (req + "\n").encode ("latin1")
        self.sendq.put_nowait (req)
        
    def dispatch (self, resp):
        rc, resp = self.parse (resp)
        if isinstance (resp, ApiError):
            tag = getattr (resp.args[1], "tag", None)
        else:
            tag = getattr (resp, "tag", None)
        if tag is not None:
            try:
                exch = self.exchanges.pop (tag)
            except KeyError:
                # Unexpected tag, ignore message entirely.  This can
                # happen if the exchange was canceled by the caller
                # (perhaps it timed out).
                return
            # Give the completed exchange response to whoever is
            # waiting for it.
            exch.set_result ((rc, resp))
        elif rc:
            rc.recvq.put_nowait (resp)
        else:
            self.recvq.put_nowait (resp)

    async def exch (self, **req):
        tag = self.tag = self.tag + 1
        req["tag"] = tag
        f = asyncio.get_running_loop ()
        f = f.create_future ()
        self.exchanges[tag] = f
        self.send (**req)
        try:
            rc, resp = await f
            if isinstance (resp, Exception):
                raise resp
            return rc, resp
        except Exception:
            # Exception, probably a cancel.  Make sure the tag is no
            # longer shown as pending.
            self.exchanges.pop (tag, None)
            raise

    async def connect (self, *, api = "session", system = None, **kwds):
        """This method returns a pair of values: normally rc which is
        the new connection, and resp which is the "connecting" message
        that doesn't tell us anything except for the connection handle.
        But if there was an error in argument validation, rc is None and
        resp is a "reject" message.
        
        Unlike the "connect" method in the simple connectors
        classes, here we do not wait for the accept or reject.
        Instead, it is up to the caller to look for that, as the
        first message received by the newly created connection.  The
        case of "reject" being returned here applies only to connect
        requests that are refused by PyDECnet, typically because of
        invalid parameters.
        """
        rc, resp = await self.exch (api = api, system = system,
                                    type = "connect", **kwds)
        if not rc:
            if isinstance (resp, dict):
                resp = ConnMessage.decode (resp)
        if resp.type == "reject":
            rc = None
        return rc, resp

    async def bind (self, num = 0, name = "", auth = "off", *, system = None):
        """Bind to an object number and/or name, to receive inbound
        connection requests addressed to that object.  The return
        value is a connection object associated with the bind; it
        will receive new connections that can be seen by the
        "listen" method, but has no data service.
        """
        rc, resp = await self.exch (api = "session", system = system,
                                    type = "bind",
                                    num = num, name = name, auth = auth)
        return rc
    
    def makeconn (self, resp, h, *, system = None, api = None):
        conn = AsyncConnection (self, system, api, h)
        resp["newconnection"] = conn
        if resp["type"] == "connect":
            # Inbound connection, find the listen connection ("bind"
            # state) that it goes with
            bh = resp.get ("listenhandle", None)
            if bh is None:
                # It's not related to a bind, that means it is the
                # connect sent to the Pipe based connector for a "file"
                # (subprocess) object.
                if self.listenq:
                    self.listenq.put_nowait (conn)
                return conn
            # Find the listen connection
            bc = self.connections.get (bh, None)
            if bc:
                bc.listenq.put_nowait (conn)
            else:
                # No listener, that probably means this message crossed
                # the wire with a close (unbind).
                conn.reject ()
                return None
        return conn
        
class AsyncApiConnector (AsyncConnector):
    "Asynchronous connector using API (Unix socket) transport"
    def __init__ (self, name = defsockname):
        super ().__init__ ()
        self.sockname = name

    async def start (self):
        self.reader, self.writer = await asyncio.open_unix_connection (self.sockname)
        await super ().start ()
            
    def send (self, *, tag = None, api = None, system = None, **req):
        # Empty request means "get system list", otherwise fill in
        # standard arguments.  But "tag" is not considered in this test.
        if req:
            assert api
            if system:
                req["system"] = system
            req["api"] = api
        elif api:
            req["api"] = api
        if tag is not None:
            req["tag"] = tag
        super ().send (req)

    def makeconn (self, resp, h):
        return super ().makeconn (resp, h, system = resp["system"],
                                  api = resp["api"])

class AsyncPipeConnector (AsyncConnector):
    'Asynchronous connector using pipes (for use in "file" type objects)'
    def __init__ (self):
        super ().__init__ ()
        self.logq = asyncio.Queue ()
        # This will receive the (one) "connect" message, the one that
        # started this subprocess.
        self.listenq = asyncio.Queue ()

    async def start (self):
        self.reader = await make_read_stream (sys.stdin)
        self.writer = await make_write_stream (sys.stdout)
        self.logstream = await make_write_stream (sys.stderr)
        self.logtask = asyncio.create_task (self.logger ())
        await super ().start ()

    async def listen (self):
        """Get the inbound connection for the object that caused the
        creation of this pipe API subprocess.
        """
        ret = await self.listenq.get ()
        return ret

    def send (self, **req):
        # Make sure unneeded keys are not in the request
        req.pop ("system", None)
        req.pop ("api", None)
        super ().send (req)

    async def close (self):
        await super ().close ()
        self.logq.put_nowait (SHUTDOWN)
        await asyncq.wait_for (self.logtask, 5)
        
    def log (self, level, msg, *args, **kwargs):
        logreq = dict (level = level, message = msg, args = args,
                       kwargs = kwargs)
        logreq = enc (logreq)
        logreq = (logreq + "\n").encode ("latin1")
        self.logq.put_nowait (logreq)

    async def logger (self):
        try:
            while True:
                logreq = await self.logq.get ()
                if logreq == SHUTDOWN:
                    break
                self.logstream.write (logreq)
                await self.logstream.drain ()
        finally:
            self.logstream.close ()
            await self.logstream.wait_closed ()
            

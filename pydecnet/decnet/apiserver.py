#!

"""DECnet/Python API machinery
"""

import os
import sys
import io
import socket

from .common import *
from . import logging

SvnFileRev = "$LastChangedRevision$"

enc = DNJsonEncoder ().encode
dec = DNJsonDecoder ().decode

class ApiHandler:
    def __init__ (self, owner, sock):
        logging.trace ("API connection start")
        self.sock = sock
        self.owner = owner
        self.pending = b""
        self.dthread = StopThread (target = self.handle)
        self.dthread.start ()

    def readline (self):
        "Read a line from the socket"
        while b"\n" not in self.pending:
            r = self.sock.recv (4096)
            if not r:
                return None
            self.pending += r
        ret, self.pending = self.pending.split (b"\n", 1)
        return ret.decode ("latin1")
    
    def error (self, text, **kwargs):
        ret = dict (kwargs)
        ret["error"] = text
        return ret
    
    def handle (self):
        try:
            while not self.dthread.stopnow:
                req = self.readline ()
                if not req:
                    break
                logging.trace ("API request: {}", req)
                tag = None
                try:
                    req = dec (req)
                except Exception as e:
                    logging.trace ("Parse error {}", e)
                    req = "bad"
                    ret = self.error ("Parse error", exception = e)
                if req != "bad":
                    tag = req.pop ("tag", None)
                    if not req:
                        # Empty request, that's a request for list of
                        # systems
                        ret = dict ()
                        for n in self.owner.nodes.values ():
                            d = n.json_description ()
                            ret.update (d)
                    else:
                        # Note that we extract AND remove the standard
                        # keys from the request, so that the lower level
                        # methods don't need to deal with those extra
                        # items.  This helps when the request is passed
                        # as a **req argument to some action method.
                        system = req.pop ("system", self.owner.defnode).upper ()
                        node = self.owner.nodes.get (system, None)
                        subsys = req.pop ("api", None)
                        # "type" is the request, or operation; default to "get"
                        reqtype = req.pop ("type", "get")
                        if not system:
                            ret = self.error ("required argument 'system' missing")
                        elif not subsys:
                            ret = self.error ("required argument 'api' missing")
                        elif not node:
                            ret = self.error ("Unknown system name", system = system)
                        else:
                            # Call the api method of the specified (or
                            # defaulted) node, with ApiHandler object,
                            # subsystem ("api") name, request type, tag if
                            # any, and the request dictionary.  Return value
                            # is a reply dictionary from the addressed
                            # subsystem, or None not to send a reply at this
                            # time.
                            ret = node.api (self, subsys, reqtype, tag, req)
                            if ret:
                                # Add the standard request keys "system"
                                # and "api" back into the reply.  Don't
                                # touch "type" because a different value
                                # might be supplied by the subsystem.
                                ret["system"] = system
                                ret["api"] = subsys
                    if ret and tag is not None:
                        # If the request was tagged, tag the
                        # reply also.  The subsystem is
                        # reponsible for tagging any
                        # asynchronous replies for this request.
                        ret["tag"] = tag
                if ret:
                    self.send_dict (ret)
        finally:
            for n in self.owner.nodes.values ():
                n.end_api (self)
            try:
                self.sock.close ()
            except Exception:
                pass
            try:
                del self.owner.clients[self]
            except Exception:
                pass

    def send_dict (self, ret):
        ret = enc (ret)
        logging.trace ("message to API client: {}", ret)
        try:
            ret += "\n"
            ret = ret.encode ("latin1")
            self.sock.send (ret)
        except Exception as e:
            logging.debug ("send failure {}", e)
        
    def stop (self):
        self.dthread.stop ()
        
class ApiServer:
    """The DECnet API server, using a Unix socket
    """
    def __init__ (self, config, nodelist):
        logging.debug ("Initializing API server on {}", config.name)
        self.config = config
        self.nodes = { n.nodename : n for n in nodelist }
        if len (nodelist) == 1:
            self.defnode = nodelist[0].nodename
        else:
            self.defnode = None
        if os.path.exists (config.name):
            raise RuntimeError ("Another socket server is already running")
        self.socketname = config.name
        self.clients = dict ()
        
    def start (self):
        """Start a thread for the server -- that thread will then start
        two more threads for each API client connection.
        """
        # For some reason, if this is done in the constructor rather
        # than here, bad things happen on Linux.  Somehow an IP
        # address gets associated with the socket as "laddr", causing
        # the bind to fail.  Moving it here makes things work.  Don't
        # know why...
        self.socket = socket.socket (socket.AF_UNIX)
        try:
            self.socket.bind (self.socketname)
            os.chmod (self.socketname, self.config.mode)
            self.socket.listen (3)
        except Exception:
            logging.exception ("Error binding to API socket")
            return
        self.server_thread = StopThread (target = self.apilisten,
                                         name = "decnet-api")
        # Exit the server thread when the main thread terminates
        self.server_thread.start ()
        logging.debug ("API server started")

    def apilisten (self):
        try:
            while not self.server_thread.stopnow:
                dsock, addr = self.socket.accept ()
                # Create and start a handler instance for the new
                # connection.
                h = ApiHandler (self, dsock)
                self.clients[h] = h
            logging.trace ("Dropped out of loop due to stopnow")
        except Exception as e:
            logging.trace ("Exiting due to {}", e)
        finally:
            self.cleanup ()

    def stop (self, wait = True):
        for h in list (self.clients.values ()):
            try:
                h.stop ()
            except Exception:
                pass
        try:
            self.socket.close ()
        except Exception:
            pass
        self.server_thread.stop ()

    def cleanup (self):
        try:
            self.socket.close ()
        except Exception:
            pass
        try:
            os.remove (self.socketname)
        except Exception:
            logging.exception ("Error removing API socket {}", self.socketname)
        logging.debug ("API shut down")

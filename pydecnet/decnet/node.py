#!

"""DECnet/Python Node object -- the container for all the parts of DECNET

"""

import os
import sys
import io
import argparse
import queue
import threading
import socketserver
import shlex
import socket
import logging
import select
from fcntl import *

from .common import *
from . import timers

class dnparser_message (Exception): pass
class dnparser_error (Exception): pass

class dnparser (argparse.ArgumentParser):
    """A subclass of argparse.ArgumentParser that overrides the
    error handling and program exits in the standard parser so
    control always comes back to the caller.
    """
    def _print_message (self, message, file = None):
        raise dnparser_message (message)

    def error (self, message):
        raise dnparser_error (message)

    def parse_args (self, args, namespace = None):
        """Parse an argument list.  Return value is a tuple consisting
        of the parse output (a Namespace object, or the object supplied
        in the namespace argument if any) and the message generated by
        the parse.  One of these will be None or False: for a successful parse,
        there is no message, and for a failed one or a help request,
        there is no result.  More precisely, the result is None for
        a help message, False for an error message.
        """
        try:
            return super ().parse_args (args, namespace), None
        except dnparser_message as e:
            return None, e.args[0]
        except dnparser_error as e:
            return False, e.args[0]

api = dnparser (prog = "")
dncommands = api.add_subparsers (help = "Commands")

class Node (object):
    """A Node object is the outermost container for all the other objects
    that make up a DECnet node.  Typically there is one Node object, but
    it's certainly possible to create multiple ones (to emulate an
    entire network within a single process).
    """
    def __init__ (self, config):
        #super ().__init__ ()
        self.node = self
        self.config = config
        self.timers = timers.TimerWheel (self, 0.1, 3600)
        try:
            sock = config.node.api_socket
        except AttributeError:
            sock = DEFAPISOCKET
        self.api = DnApiServer (self, sock)
        self.workqueue = queue.Queue ()
        #self.start ()
        
    def addwork (self, work, handler = None):
        """Add a work item (instance of a Work subclass) to the node's
        work queue.  This can be called from any thread.  If "handler"
        is specified, set the owner of the work item to that value,
        overriding the handler specified when the Work object was created.
        """
        if handler is not None:
            work.owner = handler
        self.workqueue.put (work)
        
    def start (self):
        """Node main loop.  This is intended to be the main loop of
        the whole DECnet process, so it loops here and does not return
        until told to shut down.
        """
        logging.debug ("Starting node main loop")
        self.api.start ()
        q = self.workqueue
        try:
            while True:
                try:
                    work = q.get ()
                except KeyboardInterrupt:
                    break
                if isinstance (work, Shutdown):
                    break
                try:
                    work.dispatch ()
                except Exception:
                    logging.exception ("Exception processing work item %r", work)
        finally:
            logging.debug ("Stopping node")
            self.api.stop ()
            self.timers.shutdown ()
            logging.debug ("DECnet/Python shut down")
            logging.shutdown ()
            
    def register_api (self, command, handler, help = None):
        """Register a command under the DECnet/Python API.  Arguments
        are the command name, the handler element (where requests for this
        command will be dispatched to) and optional help text.  The
        function returns an argparse subparser object, which the caller
        should populate with any command arguments desired.

        When requests matching this command are subsequently dispatched,
        they will come to the owner in the form of ApiRequest work items.
        """
        sp = dncommands.add_parser (command, help = help)
        sp.set_defaults (command = command, handler = handler)
        return sp


class ApiWork (Work):
    """Work requests carrying continuation data in the "data" attribute.
    """
        
ACCEPT_TEXT = "100 Continue text"
ACCEPT_BINARY = "101 Continue binary"
DONE = "200 OK"
REJECT = "300 Error"

class ApiRequest (Work, socketserver.StreamRequestHandler):
    """A work request generated by the Node API machinery.  Generally
    these arrive from outside this process on Unix stream sockets, but
    they can also be generated internally provided the requester follows
    the same interface.

    An ApiRequest work item contains the following information:
    1. Any command arguments, set by argparse when parsing the API request.
       These correspond to the command arguments set in the command
       parser obtained from the register_api function.
    2. "node", the parent node object.
    3. "rfile", the file from which the request and any data can be read
    4. "wfile", the file to which responses can be written.

    The handler for this work item should use this information to process
    the request.  If the request can be completed synchronously, it should
    do so and call the "done" method of the handler object.  Otherwise,
    it should call the "accepted" method, indicating whether the data stream
    for the remaining processing should be text or binary.  If the request
    cannot be accepted, it should call the "reject" method.

    If the request is accepted, subsequent work is sent using ApiWork
    work requests, which are sent to the work handler identified in the
    call to the "accepted" method.
    """
    wbufsize = -1
    
    def __init__(self, request, client_address, server):
        Work.__init__ (self, None)
        try:
            socketserver.StreamRequestHandler.__init__ (self, request,
                                                        client_address, server)
        except (OSError, socket.error):
            logging.debug ("Socket connection closed")
            
    def setup (self):
        super ().setup ()
        self.binary = False
        self.rfile = io.TextIOWrapper(self.rfile, encoding = "latin-1",
                                      errors = "ignore", newline = None,
                                      line_buffering = True)
        self.wfile = io.TextIOWrapper(self.wfile, encoding = "latin-1",
                                      errors = "ignore", newline = None,
                                      line_buffering = True)
        self.node = self.server.parent
        self.phore = threading.Semaphore (0)
        self._done = False

    def send (self, msg):
        msg += '\n'
        if isinstance (msg, str) and self.binary:
            msg = msg.encode ("latin-1", "ignore")
        logging.debug ("Sending reply %r", msg)
        try:
            self.wfile.write (msg)
        except (OSError, ValueError, socket.error):
            pass
        
    def accepted (self, worker, binary = False):
        """Indicate the request is accepted and processing continues
        using this connection.  If "binary" is True, the connection files
        are switched to unbuffered binary mode.  "worker" is the element
        that wants to receive followup ApiWork work items carrying subsequent
        input data for the request.  If set to None, that means no input
        is expected or wanted.
        """
        if binary:
            self.send (ACCEPT_BINARY)
            if not self.binary:
                # Unwrap twice to get the raw (unbuffered) file
                self.rfile = self.rfile.detach ().detach ()
                self.wfile = self.wfile.detach ().detach ()
                self.binary = True
        else:
            self.send (ACCEPT_TEXT)
        self.worker = worker
        if worker:
            # Release the handler thread so it can send additional
            # input to the worker.
            self.phore.release ()

    def finished (self, status, text = None):
        """Finished with this operation.  The status line is sent followed
        by any text; then the connection is closed.
        """
        if status:
            self.send (status)
        if text:
            self.send (text)
        try:
            self.wfile.flush ()
            self.wfile.close ()
            self.rfile.close ()
        except (OSError, ValueError, socket.error):
            pass
        # Tell the handle method that we're done
        self._done = True
        self.phore.release ()
        
    def done (self, text = None):
        """Indicate the operation was successful.  There may be additional
        text following the status line.  The requester should keep reading
        until it sees the socket close.
        """
        self.finished (DONE, text)

    def reject (self, text = None):
        """Indicate that the operation request was rejected.  There may
        be additional text explaining the error following the status line.
        The requester should keep reading until it sees the socket close.
        """
        self.finished (REJECT, text)
        
    def handle (self):
        logging.debug ("Starting Handler object for API")
        try:
            req = self.rfile.readline ().rstrip ('\n')
            if not req:
                logging.debug ("No API request received")
                return
            logging.debug ("API request: %s", req)
        except Exception:
            logging.exception ("Exception reading API request")
            return
        req = shlex.split (req)
        if not req:
            return
        req, msg = api.parse_args (req, self)
        if not req:
            if req is None:
                self.done (msg)
            else:
                self.reject (msg)
            return
        # Parse was successful.  This has updated the attributes of
        # self.  "handler" is the element that should receive this work
        # item, so copy that to "owner".
        self.owner = self.handler
        self.node.addwork (self)
        # Wait for the element handler to deal with it
        self.phore.acquire ()
        if self._done:
            # If the request is finished now, exit
            logging.debug ("Request is finished")
            return
        logging.debug ("Starting request data loop")
        infd = self.rfile.fileno ()
        oldflags = fcntl (infd, F_GETFL, 0)
        p = select.poll ()
        p.register (infd, select.POLLIN)
        try:
            fcntl (infd, F_SETFL, oldflags | os.O_NONBLOCK)
            while not self._done:
                p.poll ()
                while True:
                    req = self.rfile.read (256)
                    if req is None:
                        break
                    #logging.debug ("API data: %r", req)
                    w = ApiWork (self.worker, data = req)
                    self.node.addwork (w)
                    if not req:
                        # end of file, i.e., disconnect
                        logging.debug ("Request done due to closed connection")
                        return
        except (OSError, socket.error, ValueError):
            logging.debug ("Request done due to closed connection")
            return
        self.rfile.close ()
        logging.debug ("Request is finished")
        
class DnApiServer (Element, socketserver.ThreadingUnixStreamServer):
    """A class for the Unix socket server for the DECnet API.
    """
    def __init__ (self, parent, name):
        if os.path.exists (name):
            raise RuntimeError ("Another socket server is already running")
        Element.__init__ (self, parent)
        self.daemon_threads = True
        socketserver.ThreadingUnixStreamServer.__init__ (self, name, ApiRequest,
                                                         bind_and_activate = False)
        self.socketname = name
        
    def start (self):
        """Start a thread with the server -- that thread will then start one
        more thread for each request.
        """
        try:
            self.server_bind ()
            self.server_activate ()
        except Exception:
            logging.exception ("Error binding to API socket")
            return
        self.server_thread = threading.Thread (target = self.serve_forever)
        # Exit the server thread when the main thread terminates
        self.server_thread.daemon = True
        self.server_thread.start ()
        logging.debug ("API server started")

    def stop (self, wait = True):
        try:
            os.remove (self.socketname)
            logging.debug ("API shut down")
        except Exception:
            logging.exception ("Error removing API socket %s", self.socketname)

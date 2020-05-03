#!

"""DECnet/Python access via HTTP

"""

import http.server
import socketserver
import traceback
import sys
import io
import os.path
from urllib.parse import urlparse, parse_qs
import re
import mimetypes
import time
import subprocess

try:
    import ssl
except ImportError:
    ssl = None
    
from .common import *
from . import logging
from . import html
from . import mapper

packagedir = os.path.dirname (__file__)

SvnFileRev = "$LastChangedRevision$"

def revno (s):
    return int (s.split ()[1])

DNREV = None

def setdnrev ():
    # This has to be in a function called during program startup,
    # rather than top level code.  Otherwise it runs whenever this
    # module happens to be imported in the order in which the various
    # sources are read.  By delaying until we start execution, all our
    # modules have been imported.
    global DNREV, DNFULLVERSION, bottom
    if DNREV is None:
        DNREV = 0
        for m in sys.modules.values ():
            fn = getattr (m, "__file__", None)
            if isinstance (fn, str) and fn.startswith (packagedir):
                # It's a DECnet module, get its rev
                r = getattr (m, "SvnFileRev", None)
                if r:
                    r = revno (r)
                    DNREV = max (DNREV, r)
        DNFULLVERSION = "{}-{} © 2013-{} by {}".format (DNVERSION, DNREV,
                                                        CYEAR, AUTHORS)
        htmlversion = DNFULLVERSION.replace ("©", "&copy;")
        bottom = html.footer ("{}<br>{}".format (htmlversion, PYTHONVERSION))
        
PYTHONVERSION = "Python {}.{}.{} ({}) on {}".format (sys.version_info.major,
                                                     sys.version_info.minor,
                                                     sys.version_info.micro,
                                                     sys.version_info.releaselevel,
                                                     sys.platform)

class Monitor:
    def __init__ (self, config, nodelist):
        self.config = config
        self.nodelist = nodelist
        httproot = config.http_root or packagedir
        self.resources = os.path.join (httproot, "resources")
        if config.mapper:
            self.mapserver = mapper.Mapper (config, nodelist)
        else:
            self.mapserver = None

    def start (self):
        html.setstarttime ()
        setdnrev ()
        ports = list ()
        mapserver = self.mapserver
        if mapserver:
            mapserver.start ()
        if self.config.http_port:
            if self.config.https_port:
                # Both are defined, start https server in a thread
                t = StopThread (target = self.serverstart, name = "https",
                                args = (True,))
                t.start ()
            self.serverstart (False)
        else:
            self.serverstart (True)

    def serverstart (self, secure):
        config = self.config
        if secure:
            server_address = (config.source, config.https_port)
            logging.debug ("Starting https server on port {}",
                           config.https_port)
        else:
            server_address = (config.source, config.http_port)
            logging.debug ("Starting http server on port {}", config.http_port)
        httpd = DECnetMonitor (server_address, DECnetMonitorRequest,
                               self.nodelist, config, self.resources,
                               self.mapserver, secure)
        if secure:
            httpd.socket = ssl.wrap_socket (httpd.socket,
                                            certfile = config.certificate,
                                            server_side = True)
        httpd.serve_forever ()
        
class DECnetMonitor (socketserver.ThreadingMixIn, http.server.HTTPServer):
    def __init__ (self, addr, rclass, nodelist, config, resources,
                  mapserver, secure):
        self.nodelist = nodelist
        self.api = config.api
        self.mapserver = mapserver
        if mapserver:
            self.addlinks = (("/map", "Network map"),)
        else:
            self.addlinks = ()
        self.resources = resources
        self.secure = secure or config.insecure_api
        super ().__init__ (addr, rclass)

#psplit_re = re.compile (r"/([^/\s]*)(?:/(\S*))?")
class DECnetMonitorRequest (http.server.BaseHTTPRequestHandler):
    def setup (self):
        super ().setup ()
        self.wtfile = io.TextIOWrapper (self.wfile)
        
    def log_message (self, fmt, *args):
        logging.trace (fmt % (args))

    def findnode (self):
        # Identify the node addressed by the request's query argument,
        # required if there is more than one.  Return the node index,
        # node object, and the split-apart path string.
        p = urlparse (self.path)
        if p.scheme or p.netloc or p.params or p.fragment:
            logging.trace ("Invalid path: {}", self.path)
            self.send_error (400, "Invalid request")
            return None, None, None
        logging.trace ("http from {} get {}", self.client_address, p.path)
        parts = os.path.realpath (p.path).split ("/")
        if not parts or parts[0]:
            self.send_error (400, "Invalid request")
            logging.trace ("Invalid path: {}", self.path)
            return None, None, None
        parts = parts[1:]
        nodelist = self.server.nodelist
        mapserver = self.server.mapserver
        if len (nodelist) > 1:
            if not p.query:
                return 0, None, parts
            q = parse_qs (p.query)
            node = q["system"][0].upper ()
            for i, n in enumerate (nodelist):
                if n.nodename and n.nodename.upper () == node:
                    return i, n, parts
            self.send_error (404, "System not found")
            return 0, None, None
        return 0, nodelist[0], parts

    msg_500 = "Exception during server processing.<p><pre>{}</pre>"
    def handle_exception (self, op):
        logging.exception ("Exception handling http {} of {}", op, self.path)
        # Replace the "explanation" part of the message for code 500
        self.responses[500] = [self.responses[500][0],
                               self.msg_500.format (traceback.format_exc ())]
        self.send_error (500)

    def do_GET (self):
        try:
            nodeidx, tnode, parts = self.findnode ()
            if parts is None:
                return
            mapserver = self.server.mapserver
            if parts[0] == "robots.txt":
                parts = [ "resources", "robots.txt" ]
            if parts[0] == "api" and self.server.api:
                if not self.server.secure:
                    self.send_error (401, "API access requires HTTPS")
                    return
                ret = self.json_get (parts[1:], tnode)
                if not ret:
                    return
                ctype = "application/json"
                ret = str (ret).encode ("utf-8", "ignore")
            elif parts[0] == "resources":
                # Fetching a resource (a constant file)
                fn = os.path.join (self.server.resources, *parts[1:])
                ctype = mimetypes.guess_type (fn, False)[0]
                try:
                    with open (fn, "rb") as f:
                        ret = f.read ()
                except OSError:
                    self.send_error (404, "File not found")
                    return
            else:
                mobile = False
                if parts[0] == "m":
                    # Mobile format page requested
                    mobile = True
                    parts = parts[1:]
                if not parts:
                    parts = ['']
                ctype = "text/html"
                if mapserver and parts[0] == "map":
                    ctype = "text/html"
                    title, top, body = mapserver.html (mobile, parts[1:])
                    if not title:
                        self.send_error (404, "File not found")
                        return
                    ret = html.mapdoc (mobile, title, top,
                                       body, bottom)
                elif not tnode:
                    if parts != ['']:
                        logging.trace ("Missing system parameter")
                        self.send_error (400, "Missing system parameter")
                        return
                    ret = self.node_list (mobile)
                else:
                    ret = tnode.http_get (mobile, parts)
                    if not ret:
                        self.send_error (404, "File not found")
                        return
                    title, sb, body = ret
                    if len (self.server.nodelist) > 1:
                        sb.insert (0, self.node_sidebar (mobile, nodeidx))
                    sb = html.sidebar (*sb)
                    top = html.page_title (title, links = self.server.addlinks)
                    ret = html.doc (mobile, title, top,
                                    html.middle (sb, body), bottom)
                ret = str (ret).encode ("utf-8", "ignore")
            self.send_response (200)
            self.send_header ("Content-type", ctype)
            self.send_header ("Content-Length", str (len (ret)))
            self.end_headers ()
            self.wfile.write (ret)
        except Exception:
            self.handle_exception ("GET")

    def do_POST (self):
        try:
            nodeidx, tnode, parts = self.findnode ()
            if parts is None:
                return
            if not tnode:
                logging.trace ("Missing system parameter")
                self.send_error (400, "Missing system parameter")
                return
            if parts[0] == "api" and self.server.api:
                if not self.server.secure:
                    self.send_error (401, "API access requires HTTPS")
                    return
                ret = self.json_post (parts[1:], tnode)
                if not ret:
                    return
                ctype = "application/json"
            else:
                self.send_error (405, "No such object or not supported with POST")
                return
            if isinstance (ret, str):
                ret = ret.encode ("utf-8", "ignore")                
            self.send_response (200)
            self.send_header ("Content-type", ctype)
            self.send_header ("Content-Length", str(len (ret)))
            self.end_headers ()
            self.wfile.write (ret)
        except Exception:
            self.handle_exception ("POST")

    def node_sidebar (self, mobile, idx = -1):
        ret = [ (html.sbbutton_active
                 if idx == i else html.sbbutton) (mobile,
                                                  n.description (mobile))
                 for i, n in enumerate (self.server.nodelist) ]
        return html.sbelement (html.sblabel ("Systems"), *ret)
    
    def node_list (self, mobile):
        title = "DECnet/Python monitoring"
        top = html.page_title (title, links = self.server.addlinks)
        return html.doc (mobile, title, top,
                         html.sidebar (self.node_sidebar (mobile)), bottom)
    
    def getapientity (self, what, tnode):
        logging.trace ("getentity node {} path {}", tnode, what)
        for ent in what:
            if ent:
                # Ignore empty entries in the path
                logging.trace ("current entity {} looking for {}", tnode, ent)
                tnode = tnode.getentity (ent)
        logging.trace ("getentity: found {}", tnode)
        return tnode
    
    def json_get (self, what, tnode):
        logging.trace ("API GET request for {}, node {}", what, tnode)
        data = dict ()
        if not what or what == ['']:
            for n in self.server.nodelist:
                data.update (n.json_description ())
            return dnEncoder.encode (data)
        elif not tnode:
            self.send_error (404, "No such API object")
            return
        try:
            ent = self.getapientity (what, tnode)
            handler = ent.get_api
        except (KeyError, AttributeError):
            logging.trace ("API GET handler lookup error", exc_info = True)
            self.send_error (404, "No such API object")
            return None
        try:
            handler = ent.get_api
        except AttributeError:
            self.send_error (405, "No such object or not supported with GET")
            return None
        try:
            data = handler ()
        except Exception:
            logging.debug ("API GET handler error", exc_info = True)
            data = { "status" : "exception", "exception" : traceback.format_exc () }
        return dnEncoder.encode (data)

    def json_post (self, what, tnode):
        logging.trace ("API POST request for {}, node {}", what, tnode)
        nbytes = 0
        length = self.headers.get ("content-length")
        if length:
            nbytes = int (length)
        data = None
        if nbytes:
            data = dnDecoder.decode (self.rfile.read (nbytes))
        logging.trace ("POST input data: {}", str (data))
        try:
            ent = self.getapientity (what, tnode)
        except (KeyError, AttributeError):
            logging.trace ("API POST handler lookup error", exc_info = True)
            self.send_error (404, "No such API object")
            return None
        try:
            handler = ent.post_api
        except AttributeError:
            self.send_error (405, "No such object or not supported with POST")
            return None
        try:
            ret = handler (data)
        except Exception:
            logging.debug ("API POST handler error", exc_info = True)
            ret = { "status" : "exception", "exception" : traceback.format_exc () }
        return dnEncoder.encode (ret)

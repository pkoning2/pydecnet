#!

"""DECnet/Python access via HTTP

"""

import http.server
import json
import cgitb
import io
from urllib.parse import urlparse, parse_qs
import re
import ssl

from .common import *
from . import logging

# Robots.txt response: we want to disallow all web walkers because
# everything here is dynamic content; it doesn't make any sense to try
# to index it.
robots_txt = b"""User-agent: *
Disallow: /
"""

class DNJsonDecoder (json.JSONDecoder):
    def __init__ (self):
        super ().__init__ (strict = False)

    def decode (self, s):
        if isinstance (s, (bytes, bytearray)):
            s = str (s, encoding = "latin1")
        return super ().decode (s)
    
class DNJsonEncoder (json.JSONEncoder):
    def __init__ (self):
        super ().__init__ (allow_nan = False, separators = (',', ':'))
        
    def default (self, o):
        # Encode bytes and bytearray as latin-1 strings -- but not
        # their subclasses which are expected to supply their own
        # formatting mechanisms.  Macaddr is an example.
        if type (o) in { bytes, bytearray }:
            return str (o, encoding = "latin1")
        try:
            return str (o)
        except Exception:
            pass
        return super ().default (o)

    def encode (self, o):
        return bytes (super ().encode (o), encoding = "latin1")
    
dnDecoder = DNJsonDecoder ()
dnEncoder = DNJsonEncoder ()

class Monitor:
    def __init__ (self, config):
        self.config = config

    def start (self, nodelist):
        ports = list ()
        config = self.config.http
        if config.http_port:
            if config.https_port:
                # Both are defined, start https server in a thread
                t = StopThread (target = self.serverstart, name = "https",
                                args = (nodelist, config, True))
                t.start ()
            self.serverstart (nodelist, config, False)
        else:
            self.serverstart (nodelist, config, True)

    def serverstart (self, nodelist, config, secure):
        if secure:
            server_address = ("", config.https_port)
            logging.debug ("Starting https server on port {}", config.https_port)
        else:
            server_address = ("", config.http_port)
            logging.debug ("Starting http server on port {}", config.http_port)
        httpd = DECnetMonitor (server_address, DECnetMonitorRequest, nodelist, config, secure)
        if secure:
            httpd.socket = ssl.wrap_socket (httpd.socket,
                                            certfile = config.certificate,
                                            server_side = True)
        httpd.serve_forever ()
        
class DECnetMonitor (http.server.HTTPServer):
    def __init__ (self, addr, rclass, nodelist, config, secure):
        self.nodelist = nodelist
        self.api = config.api
        self.secure = secure
        super ().__init__ (addr, rclass)
        dont_close (self.socket)

#psplit_re = re.compile (r"/([^/\s]*)(?:/(\S*))?")
class DECnetMonitorRequest (http.server.BaseHTTPRequestHandler):
    def setup (self):
        super ().setup ()
        self.wtfile = io.TextIOWrapper (self.wfile)
        self.excepthook = cgitb.Hook (file = self.wtfile)
        
    def log_message (self, fmt, *args):
        logging.trace (fmt % (args))

    def findnode (self):
        # Identify the node addressed by the request's query argument,
        # required if there is more than one.  Return the node object
        # and the split-apart path string.
        p = urlparse (self.path)
        if p.scheme or p.netloc or p.params or p.fragment:
            logging.trace ("Invalid path: {}", self.path)
            self.send_error (400, "Invalid request")
            return None, None
        logging.trace ("http from {} get {}", self.client_address, p.path)
        parts = p.path.split ("/")
        if not parts or parts[0]:
            self.send_error (400, "Invalid request")
            logging.trace ("Invalid path: {}", self.path)
            return None, None
        parts = parts[1:]
        nodelist = self.server.nodelist
        if len (nodelist) > 1:
            if not p.query:
                return None, parts
            q = parse_qs (p.query)
            node = q["system"][0].upper ()
            for n in nodelist:
                if n.nodename.upper () == node:
                    return n, parts
            self.send_error (400, "System not found")
            return None, None
        return nodelist[0], parts
        
    def do_GET (self):
        try:
            tnode, parts = self.findnode ()
            if parts is None:
                return
            if parts[0] == "robots.txt":
                ret = robots_txt
                ctype = "text/plain"
            else:
                if parts[0] == "api" and self.server.api:
                    if not self.server.secure:
                        self.send_error (401, "API access requires HTTPS")
                        return
                    ret = self.json_get (parts[1:], tnode)
                    if not ret:
                        return
                    ctype = "application/json"
                else:
                    ctype = "text/html"
                    if not tnode:
                        if parts != ['']:
                            logging.trace ("Missing system parameter")
                            self.send_error (400, "Missing system parameter")
                            return
                        ret = self.node_list ()
                    else:
                        ret = tnode.http_get (parts, len (self.server.nodelist) > 1)
                        if not ret:
                            self.send_error (404, "File not found")
                            return
            if isinstance (ret, str):
                ret = ret.encode ("utf-8", "ignore")                
            self.send_response (200)
            self.send_header ("Content-type", ctype)
            self.send_header ("Content-Length", str (len (ret)))
            self.end_headers ()
            self.wfile.write (ret)
        except Exception:
            logging.exception ("Exception handling http get of {}", self.path)
            self.excepthook.handle ()

    def do_POST (self):
        try:
            tnode, parts = self.findnode ()
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
            logging.exception ("Exception handling http get of {}", self.path)
            self.excepthook.handle ()
            
    def node_list (self):
        ret = [ """<html><head>
                <title>DECnet/Python monitoring</title></head>
                <body>
                <h2>DECnet/Python monitoring</h2>
                <p>There are multiple nodes, click on one of the entries
                below to see that one.</p>
                <table border=1 cellspacing=0 cellpadding=4>""" ]
        for n in self.server.nodelist:
            ret.append ("<tr><td>{}</td></tr>".format (n.description ()))
        ret.append ("</body></html>\n")
        return '\n'.join (ret)

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
        elif not tnode:
            self.send_error (404, "No such API object")
            return
        else:
            try:
                ent = self.getapientity (what, tnode)
                data = ent.get_api ()
            except (KeyError, AttributeError):
                logging.trace ("API GET error", exc_info = True)
                data = None
        if data is None:
            self.send_error (404, "No such API object")
            return None
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
            ret = ent.post_api (data)
        except (KeyError, AttributeError):
            logging.trace ("API POST error", exc_info = True)
            ret = None
        if ret is None:
            self.send_error (404, "No such API object")
            return None
        return dnEncoder.encode (ret)

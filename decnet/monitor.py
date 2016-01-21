#!

"""DECnet/Python monitoring via HTTP

"""

import http.server
import cgitb
import io
from urllib.parse import urlparse
import re

from .common import *

def Monitor (node, config):
    if config.system.http_port: # or config.system.https_port:
        tname = "{}.httpd".format (node.nodename)
        ports = list ()
        if config.system.http_port:
            ports.append ("{}".format (config.system.http_port))
        #if config.system.https_port:
        #    ports.append ("{}".format (config.system.https_port))
        logging.debug ("Initializing HTTP server on %s", ", ".join (ports))
        t = StopThread (target = http_thread, name = tname,
                        args = (node, config))
    else:
        logging.debug ("HTTP disabled")
        t = None
    return t

def http_thread (node, config):
    port = config.system.http_port
    server_address = ("", port)
    httpd = DECnetMonitor (node, server_address, DECnetMonitorRequest)
    httpd.serve_forever ()

class DECnetMonitor (http.server.HTTPServer):
    def __init__ (self, node, addr, rclass):
        self.node = node
        super ().__init__ (addr, rclass)
        dont_close (self.socket)

psplit_re = re.compile (r"/([^/\s]*)(?:/(\S*))?")
class DECnetMonitorRequest (http.server.BaseHTTPRequestHandler):
    def setup (self):
        super ().setup ()
        self.wtfile = io.TextIOWrapper (self.wfile)
        self.excepthook = cgitb.Hook (file = self.wtfile)
        
    def log_message (self, fmt, *args):
        logging.trace (fmt, *args)
        
    def do_GET (self):
        try:
            self.node = self.server.node
            p = urlparse (self.path)
            if p.scheme or p.netloc or p.params or p.query or p.fragment:
                logging.trace ("Invalid path: %s", self.path)
                return
            p = p.path
            logging.trace ("http from %s get %s", self.client_address, p)
            ret = [ self.common_start () ]
            m = psplit_re.match (p)
            if not m:
                logging.trace ("Invalid path: %s", self.path)
                return
            if p == "/":
                ret.append (self.summary ())
            elif m.group (1) == "routing":
                ret.append (self.routing (m.group (2)))
            elif m.group (1) == "bridge":
                ret.append (self.bridge (m.group (2)))
            elif m.group (1) == "mop":
                ret.append (self.mop (m.group (2)))
            else:
                self.send_error(404, "File not found")
                return
            ret.append (self.common_end ())
            ret = '\n'.join (ret).encode ("utf-8", "ignore")
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.send_header("Content-Length", str(len (ret)))
            self.end_headers ()
            self.wfile.write (ret)
        except Exception:
            logging.exception ("Exception handling http get of %s", self.path)
            self.excepthook.handle ()
            
    def common_start (self):
        if self.node.routing:
            return """<html><head>
            <title>DECnet/Python monitoring on node {0.node.nodeid} ({0.node.nodename})</title></head>
            <body>
            <table border=1 cellspacing=0 cellpadding=4 rules=none><tr>
            <td width=180 align=center><a href="/">Overall summary</td>
            <td width=180 align=center><a href="/routing">Routing layer</td>
            <td width=180 align=center><a href="/mop">MOP</td></table>
            """.format (self)
        else:
            return """<html><head>
            <title>DECnet/Python monitoring on bridge {0.node.nodename}</title></head>
            <body>
            <table border=1 cellspacing=0 cellpadding=4 rules=none><tr>
            <td width=180 align=center><a href="/">Overall summary</td>
            <td width=180 align=center><a href="/bridge">Bridge layer</td>
            """.format (self)

    def common_end (self):
        return "</body></html>\n"
    
    def summary (self):
        ret = list ()
        if self.node.routing:
            ret.append (self.node.routing.html ("overall"))
        else:
            ret.append (self.node.bridge.html ("overall"))
        # more...
        return "\n".join (ret)

    def routing (self, what):
        if self.node.routing:
            return self.node.routing.html (what)
        return ""
        
    def bridge (self, what):
        if self.node.bridge:
            return self.node.bridge.html (what)
        return ""
        
    def mop (self, what):
        if self.node.mop:
            return self.node.mop.html (what)
        return ""

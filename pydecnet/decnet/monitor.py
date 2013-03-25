#!

"""DECnet/Python monitoring via HTTP

"""

import http.server

from .common import *

def Monitor (node, config):
    tname = "{}.httpd".format (node.nodename)
    logging.debug ("Initializing HTTP")
    t = StopThread (target = http_thread, name = tname, args = (node, config))
    return t

def start ():
    logging.debug ("Starting HTTP")
    t.daemon = True
    t.start ()

def http_thread (node, config):
    server_address = ("", 8000)
    httpd = DECnetMonitor (node, server_address, DECnetMonitorRequest)
    httpd.serve_forever ()

class DECnetMonitor (http.server.HTTPServer):
    def __init__ (self, node, addr, rclass):
        self.node = node
        super ().__init__ (addr, rclass)

class DECnetMonitorRequest (http.server.BaseHTTPRequestHandler):
    def log_message (self, fmt, *args):
        logging.trace (fmt, *args)
        
    def print (self, s):
        """Workaround for a bug in socket, or socketserver: "wfile"
        is a binary file so the standard print function does not work.
        """
        s += '\n'
        s = s.encode ("utf-8", "ignore")
        self.wfile.write (s)
        
    def do_GET (self):
        self.node = self.server.node
        logging.trace ("http from %s get %s", self.client_address, self.path)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers ()
        self.print ("""<html><title>hello decnet</title>
<body><h1>Section header</h1>
<p>Hello world, in particular {0.client_address}, from the HTTP monitor server for {0.node.nodename}</p>
</body>
</html>""".format (self))
    

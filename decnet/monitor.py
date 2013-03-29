#!

"""DECnet/Python monitoring via HTTP

"""

import http.server
import cgitb
import io

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
    def setup (self):
        super ().setup ()
        self.wtfile = io.TextIOWrapper (self.wfile)
        self.excepthook = cgitb.Hook (file = self.wtfile)
        
    def log_message (self, fmt, *args):
        logging.trace (fmt, *args)
        
    def do_GET (self):
        try:
            self.node = self.server.node
            p = self.path
            logging.trace ("http from %s get %s", self.client_address, p)
            ret = [ self.common_start () ]
            if p == "/":
                ret.append (self.summary ())
            elif p == "/routing":
                ret.append (self.routing ())
            elif p == "/mop":
                ret.append (self.mop ())
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
        return """<html><head>
<title>DECnet/Python monitoring on {0.node.nodename}</title></head>
<body>
""".format (self)

    def common_end (self):
        return "</body></html>\n"
    

    def summary (self):
        ret = list ()
        ret.append (self.node.routing.html ("summary"))
        # more...
        return "\n".join (ret)

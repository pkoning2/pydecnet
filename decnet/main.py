#!

"""Main entry point for DECnet/Python

"""

import sys
if sys.version_info[0] < 3:
    print ("PyDECnet requires Python 3.2 or later")
    sys.exit (1)

try:
    import argparse
except ImportError:
    print ("PyDECnet requires Python 3.2 or later")
    sys.exit (1)
    
import time
import threading
import os
try:
    from daemon import DaemonContext
except ImportError:
    DaemonContext = None
    
from . import common
from . import config
from . import node
from . import events
from . import logging
from . import http

SvnFileRev = "$LastChangedRevision$"

DEFPIDFILE = "/var/run/pydecnet.pid"

dnparser = argparse.ArgumentParser ()
dnparser.add_argument ("configfile", type = argparse.FileType ("r"),
                       metavar = "CFN", nargs = "*",
                       help = "Configuration file")
if DaemonContext:
    dnparser.add_argument ("-d", "--daemon", action = "store_true",
                           default = False,
                           help = "Run as daemon.  Requires a log file name to be specified.")
dnparser.add_argument ("--pid-file", metavar = "FN",
                       default = DEFPIDFILE,
                       help = "PID file (default: {})".format (DEFPIDFILE))
dnparser.add_argument ("-L", "--log-file", metavar = "FN",
                       help = "Log file (default: log to stderr)")
# Note that we set the default level to INFO rather than the conventional
# WARNING, so that events will get logged by default.
dnparser.add_argument ("-e", "--log-level", default = "INFO",
                       metavar = "LV",
                       choices = ("TRACE", "DEBUG", "INFO",
                                  "WARNING", "ERROR"),
                       help = "Log level (default: INFO)")
dnparser.add_argument ("-S", action = "store_const", 
                       dest = "syslog", const = "local",
                       help = "Log to local syslog")
dnparser.add_argument ("--syslog", metavar = "S",
                       help = """Log to syslog at the indicated address,
                                 "local" means the appropriate local UDP
                                 or named socket""")
dnparser.add_argument ("--log-config", metavar = "LC",
                       help = "Logging configuration file")
dnparser.add_argument ("-k", "--keep", type = int, default = 0,
                       help = """Number of log files to keep with nightly
                              rotation.  Requires a log file name
                              to be specified.""")
dnparser.add_argument ("-H", "--config-help", metavar = "CMD",
                       nargs = "?", const = "",
                       help = "Show configuration file help (for CMD if given)")

class pidfile:
    def __init__ (self, fn):
        self.fn = fn

    def __enter__ (self):
        try:
            f = open (self.fn, "wt")
        except Exception as exc:
            logging.exception ("failure creating pidfile {}", self.fn)
            return
        f.write ("{}\n".format (os.getpid ()))
        f.close ()

    def __exit__ (self, exc_type, exc_value, traceback):
        try:
            os.remove (self.fn)
        except Exception as exc:
            logging.exception ("error removing pidfile {}", self.fn)
            return
        
def main ():
    """Main program.  Parses command arguments and instantiates the
    parts of DECnet.
    """
    global nodes
    # Initialize DNFULLVERSION
    http.setdnrev ()
    dnparser.add_argument ("-V", "--version", action = "version",
                           version = http.DNFULLVERSION)
    p = dnparser.parse_args ()
    if not DaemonContext:
        p.daemon = False
    if p.config_help is not None:
        if p.config_help:
            args = p.config_help, "-h"
        else:
            args = ( "-h", )
        p, msg = config.configparser.parse_args (args)
        print (msg)
        return
    if not p.configfile:
        print ("At least one config file argument must be specified")
        sys.exit (1)
    # First start up the logging machinery
    logging.start (p)
    # Read all the configs
    logging.info ("Starting DECnet/Python")
    configs = [ config.Config (c) for c in p.configfile ]
    
    # Initialize all the nodes
    nodes = [ ]
    httpserver = None
    for c in configs:
        if hasattr (c, "routing") or hasattr (c, "bridge"):
            nodes.append (node.Node (c))
        else:
            if httpserver:
                print ("Duplicate http interface definition")
                sys.exit (1)
            if c.http.http_port:
                httpserver = http.Monitor (c)

    # Start all the nodes, each in a thread of its own.
    for n in nodes:
        n.start ()
    try:
        if p.daemon:
            daemoncontext = DaemonContext (files_preserve = common.files_preserve,
                                           pidfile = pidfile (p.pid_file))
            logging.info ("Becoming daemon just before starting main thread")
            daemoncontext.open ()
        if httpserver:
            httpserver.start (nodes)
        else:
            logging.trace ("idling without http")
            while True:
                time.sleep (100)
    except SystemExit as exc:
        logging.info ("Exiting: {}", exc)
    except Exception:
        logging.exception ("Exception caught in main")
    except KeyboardInterrupt:
        logging.info ("Exiting due to Ctrl-C")
    finally:
        # Stop nodes in reverse of the order in which they were started.
        # Note that the last node (the one that owns the main thread)
        # was already stopped by the time we get here.
        for n in reversed (nodes):
            n.stop ()
        # For symmetry with the startup messages:
        threading.current_thread ().name = "MainThread"
        logging.stop ()
        if p.daemon:
            daemoncontext.close ()

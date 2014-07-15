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
import logging
import logging.handlers
import threading
import os
from daemon import DaemonContext

from . import common
from . import config
from . import node
from . import events

TRACE = 2
DEFPIDFILE = "/var/run/pydecnet.pid"

dnparser = argparse.ArgumentParser ()
dnparser.add_argument ("configfile", type = argparse.FileType ("r"),
                       metavar = "CFN", nargs = "*",
                       help = "Configuration file")
dnparser.add_argument ("-d", "--daemon", action = "store_true",
                       default = False,
                       help = "Run as daemon.  Requires a log file name to be specified.")
dnparser.add_argument ("--pid-file", metavar = "FN",
                       default = DEFPIDFILE,
                       help = "PID file (default: %s)" % DEFPIDFILE)
dnparser.add_argument ("-L", "--log-file", metavar = "FN",
                       help = "Log file (default: log to stderr)")
# Note that we set the default level to INFO rather than the conventional
# WARNING, so that events will get logged by default.
dnparser.add_argument ("-e", "--log-level", default = "INFO",
                       metavar = "LV",
                       choices = ("TRACE", "DEBUG", "INFO",
                                  "WARNING", "ERROR"),
                       help = "Log level (default: INFO)")
dnparser.add_argument ("-k", "--keep", type = int, default = 0,
                       help = """Number of log files to keep with nightly
rotation.  Requires a log file name to be specified.""")
dnparser.add_argument ("-V", "--version", action = "version",
                       version = common.DNVERSION)
dnparser.add_argument ("-H", "--config-help", metavar = "CMD",
                       nargs = "?", const = "",
                       help = "Show configuration file help (for CMD if given)")

# This one is like the one in the "logging" module but with the
# decimal comma corrected to a decimal point.
def formatTime(self, record, datefmt=None):
    """
    Return the creation time of the specified LogRecord as formatted text.
    """
    ct = self.converter (record.created)
    if datefmt:
        s = time.strftime (datefmt, ct)
    else:
        t = time.strftime ("%Y-%m-%d %H:%M:%S", ct)
        s = "%s.%03d" % (t, record.msecs) # the use of % here is internal
    return s
logging.Formatter.formatTime = formatTime

def trace (msg, *args, **kwargs):
    logging.log (TRACE, msg, *args, **kwargs)
    
class pidfile:
    def __init__ (self, fn):
        self.fn = fn

    def __enter__ (self):
        try:
            f = open (self.fn, "wt")
        except Exception as exc:
            logging.exception ("failure creating pidfile %s", self.fn)
            return
        f.write ("%d\n" % os.getpid ())
        f.close ()

    def __exit__ (self, exc_type, exc_value, traceback):
        try:
            os.remove (self.fn)
        except Exception as exc:
            logging.exception ("error removing pidfile %s", self.fn)
            return
        
def main ():
    """Main program.  Parses command arguments and instantiates the
    parts of DECnet.
    """
    p = dnparser.parse_args ()
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
    logging.addLevelName (TRACE, "TRACE")
    logging.trace = trace
    if p.log_file:
        if p.keep:
            h = logging.handlers.TimedRotatingFileHandler (filename = p.log_file,
                                                           when = "midnight",
                                                           backupCount = p.keep)
        else:
            h = logging.FileHandler (filename = p.log_file, mode = "w")
        # If we run as daemon, we want to keep the handler's stream open
        common.dont_close (h.stream)
    else:
        if p.keep:
            print ("--keep requires --log-file")
            sys.exit (1)
        if p.daemon:
            print ("--daemon requires --log-file")
            sys.exit (1)
        h = logging.StreamHandler (sys.stderr)
    logging.basicConfig (handler = h, level = p.log_level,
                         format = "%(asctime)s: %(threadName)s: %(message)s")
    # Read all the configs
    logging.info ("Starting DECnet/Python")
    configs = [ config.Config (c) for c in p.configfile ]
    
    # Initialize all the nodes
    nodes = [ node.Node (c) for c in configs ]

    # Start all the nodes.  The last one will run in the main thread,
    # the others get a thread of their own
    for n in nodes[:-1]:
        n.start ()
    try:
        if p.daemon:
            daemoncontext = DaemonContext (files_preserve = common.files_preserve,
                                           pidfile = pidfile (p.pid_file))
            logging.info ("Becoming daemon just before starting main thread")
            daemoncontext.open ()
        nodes[-1].start (mainthread = True)
    except SystemExit as exc:
        logging.info ("Exiting: %s", exc)
    except Exception:
        logging.exception ("Exception caught in main")
    finally:
        # Stop nodes in reverse of the order in which they were started.
        # Note that the last node (the one that owns the main thread)
        # was already stopped by the time we get here.
        for n in reversed (nodes[:-1]):
            n.stop ()
        # For symmetry with the startup messages:
        threading.current_thread ().name = "MainThread"
        logging.info ("DECnet/Python shut down")
        logging.shutdown ()
        if p.daemon:
            daemoncontext.close ()

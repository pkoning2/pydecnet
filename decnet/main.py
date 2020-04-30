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
import signal
try:
    from daemon import DaemonContext
except ImportError:
    DaemonContext = None
try:
    import pwd
except ImportError:
    pwd = None
    
from .common import *
from . import config
from . import node
from . import events
from . import logging
from . import http

SvnFileRev = "$LastChangedRevision$"

DEFPIDFILE = "/var/run/pydecnet.pid"

signalled = False

dnparser = argparse.ArgumentParser ()
# Note: at least one config file is required, but use "*" for nargs,
# not "+".  The reason is that no config files are specified if -h or
# -H are used.
dnparser.add_argument ("configfile", type = argparse.FileType ("r"),
                       metavar = "CFN", nargs = "*",
                       help = "Configuration file")
if DaemonContext:
    dnparser.add_argument ("-d", "--daemon", action = "store_true",
                           default = False,
                           help = "Run as daemon.  Requires a log file name to be specified.")
else:
    dnparser.set_defaults (daemon = False)
if hasattr (os, "setuid") and hasattr (os, "chroot"):
    dnparser.add_argument ("--chroot", default = "", metavar = "P",
                           help = "Root to change to, see documentation for details")
    dnparser.add_argument ("--uid", default = None,
                           help = "User ID or user name to set")
    dnparser.add_argument ("--gid", default = 0, type = int,
                           help = "Group ID to set")
else:
    dnparser.set_defaults (chroot = None, uid = None, gid = 0)
    
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
    def __init__ (self, args):
        self.args = args
        self.fn = abspath (args.pid_file)

    def __enter__ (self):
        fn = self.args.chroot + self.fn
        try:
            f = open (fn, "wt")
        except Exception as exc:
            logging.exception ("failure creating pidfile {}", fn)
            return
        f.write ("{}\n".format (os.getpid ()))
        f.close ()
        os.chown (fn, self.args.uid or -1, self.args.gid or -1)

    def __exit__ (self, exc_type, exc_value, traceback):
        try:
            os.remove (self.fn)
        except Exception as exc:
            logging.exception ("error removing pidfile {}", self.fn)
            return
        
def sighandler (signum, frame):
    global signalled
    signalled = True
    raise KeyboardInterrupt

def main ():
    """Main program.  Parses command arguments and instantiates the
    parts of DECnet.
    """
    global nodes
    # Handle SIGTERM as a sign to quit
    signal.signal (signal.SIGTERM, sighandler)
    # Initialize DNFULLVERSION
    http.setdnrev ()
    dnparser.add_argument ("-V", "--version", action = "version",
                           version = http.DNFULLVERSION)
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

    # Handle the chroot and uid/gid arguments
    if p.chroot:
        p.chroot = abspath (p.chroot)
        assert os.path.isdir (p.chroot)
    if p.uid:
        try:
            p.uid = int (p.uid)
        except ValueError:
            if pwd:
                rec = pwd.getpwnam (p.uid)
                p.uid = rec.pw_uid
                if not p.gid:
                    p.gid = rec.pw_gid
    else:
        p.uid = 0

    # First start up the logging machinery
    logging.start (p)

    # Read all the configs
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
            if c.http.http_port or c.http.https_port:
                httpserver = c.http
    if not nodes:
        print ("At least one routing or bridge instance must be configured")
        sys.exit (1)
    if httpserver:
        httpserver = http.Monitor (httpserver, nodes)
        
    logging.info ("Starting DECnet/Python {}-{}", http.DNVERSION, http.DNREV)

    # Before starting the various layers and elements, become daemon
    # if requested.  This means we don't have to worry about file
    #  descriptors used by DECnet -- none are open yet.  The exception
    #  is logging, which we handle by stopping it just before the
    #  daemon call and restarting it right after.
    #
    # Apart from the file descriptors issue, daemon transition must be
    # done before we start any threads (at least on Linux) because the
    # fork() machinery used by daemon entry doesn't carry the threads
    # along with it.
    try:
        if p.daemon:
            logging.trace ("About to transition to daemon mode")
            logging.stop (exiting = False)
            daemoncontext = DaemonContext (pidfile = pidfile (p))
            daemoncontext.open ()
            logging.restart (chrootdone = False)
            logging.info ("Now running as daemon")
        if p.chroot or p.gid or p.uid:
            if p.chroot:
                logging.trace ("About to change root to {}", p.chroot)
                logging.stop (exiting = False)
                os.chroot (p.chroot)
                os.chdir ("/")
                logging.restart ()
            if p.gid:
                os.setgid (p.gid)
            if p.uid:
                os.setuid (p.uid)
            logging.info ("Running in {} as uid {}, gid {}", p.chroot,
                          p.uid, p.gid)
    except Exception:
        logging.exception ("Exception in daemon or chroot or uid/gid actions")
        raise
    
    # Start all the nodes, each in a thread of its own.
    for n in nodes:
        n.start ()
    try:
        if httpserver:
            httpserver.start ()
        else:
            logging.trace ("idling without http")
            while True:
                time.sleep (100)
    except SystemExit as exc:
        logging.info ("Exiting: {}", exc)
    except Exception:
        logging.exception ("Exception caught in main")
    except KeyboardInterrupt:
        if signalled:
            logging.info ("Exiting due to SIGTERM")
        else:
            logging.info ("Exiting due to Ctrl/C")
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

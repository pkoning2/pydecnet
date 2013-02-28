#!

"""Main entry point for DECnet/Python

"""

import argparse
import time
import logging
import threading

from . import common
from . import config
from . import node
from . import datalink
from . import mop
from . import routing

dnparser = argparse.ArgumentParser ()
dnparser.add_argument ("configfile", type = argparse.FileType ("r"),
                       metavar = "FN", nargs = "*",
                       help = "Configuration file, default '%s'" % config.DEFCONFIG)
dnparser.add_argument ("-L", "--log-file", metavar = "FN",
                       help = "Log file (default: stderr)")
# Note that we set the default level to INFO rather than the conventional WARNING,
# so that events will get logged by default.
dnparser.add_argument ("-e", "--log-level", default = "INFO",
                       metavar = "LV",
                       choices = ("DEBUG", "INFO", "WARNING", "ERROR"),
                       help = "Log level (default: WARNING)")
dnparser.add_argument ("-V", "--version", action = "version",
                       version = common.DNVERSION)
dnparser.add_argument ("-H", "--config-help", metavar = "CMD",
                       nargs = "?", const = "",
                       help = "Show config file help (for CMD if given)")

# This one is like the one in the "logging" module but with the
# decimal comma corrected to a decimal point.
def formatTime(self, record, datefmt=None):
    """
    Return the creation time of the specified LogRecord as formatted text.
    """
    ct = self.converter(record.created)
    if datefmt:
        s = time.strftime(datefmt, ct)
    else:
        t = time.strftime("%Y-%m-%d %H:%M:%S", ct)
        s = "%s.%03d" % (t, record.msecs) # the use of % here is internal
    return s
logging.Formatter.formatTime = formatTime

class system (object):
    """A wrapper for a single system (i.e., an instance of a configuration,
    as defined by a config file).
    """
    def __init__ (self, cf, last = False):
        self.cf = cf.name
        logging.info ("Initializing DECnet/Python for %s", self.cf)
        c = config.Config (cf)

        # Now create the major entities in the appropriate order.  They will
        # create subsidiary ones based on the config settings.
        self.last = last
        self.n = node.Node (c)
        self.dl = datalink.DatalinkLayer (self.n, c)
        self.m = mop.Mop (self.n, c)
        self.r = routing.Routing (self.n, c)

    def start (self):
        logging.info ("Starting DECnet/Python for %s", self.cf)
        
        # Things have been created.  Now start them.  We'll start the Node
        # last because its loop will be the main thread.
        self.dl.start ()
        self.m.start ()
        self.r.start ()
        if self.last:
            self.n.start ()
        else:
            threading.Thread (target = self.n.start)

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
        config.configparser.parse_args (args)
    logging.basicConfig (filename = p.log_file, level = p.log_level,
                         format = "%(asctime)s: %(levelname)s: %(message)s")
    cflist = p.configfile
    if not cflist:
        cflist = [ config.DEFCONFIG ]

    # Initialize all the systems
    systems = [ system (cf) for cf in cflist[:-1] ]
    systems.append (system (cflist[-1], True))

    # Now start them all
    for s in systems:
        s.start ()

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

dnparser = argparse.ArgumentParser ()
dnparser.add_argument ("configfile", type = argparse.FileType ("r"),
                       metavar = "FN", nargs = "+",
                       help = "Configuration file")
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
        return
    logging.basicConfig (filename = p.log_file, level = p.log_level,
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
    nodes[-1].start (mainthread = True)

#!

"""Main entry point for DECnet/Python

"""

import argparse
import time
import logging

from . import common
from . import config
from . import node
from . import datalink
from . import mop
from . import routing

dnparser = argparse.ArgumentParser ()
dnparser.add_argument ("-f", "--config-file", type = argparse.FileType ("r"),
                       metavar = "FN",
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
    logging.info ("DECnet/Python starting")
    c = config.Config (p.config_file)

    # Now create the major entities in the appropriate order.  They will
    # create subsidiary ones based on the config settings.
    n = node.Node (c)
    dl = datalink.DatalinkLayer (n, c)
    m = mop.Mop (n, c)
    r = routing.Routing (n, c)

    # Things have been created.  Now start them.  We'll start the Node
    # last because its loop will be the main thread.
    dl.start ()
    m.start ()
    r.start ()
    n.start ()
    

#!

"""Logging extensions for DECnet/Python.

"""

import logging
import logging.config
import logging.handlers
from .common import *
import os
import stat
import sys
import json
import time
import functools

try:
    from yaml import load, Loader
except ImportError:
    load = None
    
SvnFileRev = "$LastChangedRevision$"

# Additional level
TRACE = 2

# Inherit some names from the standard logging module
CRITICAL = logging.CRITICAL
ERROR = logging.ERROR
WARNING = logging.WARNING
INFO = logging.INFO
DEBUG = logging.DEBUG

# Some more names which will be replaced later, but are used when the
# log machinery isn't actually started -- in the test suite.
critical = logging.critical
error = logging.error
warning = logging.warning
info = logging.info
debug = logging.debug
exception = logging.exception
trace = functools.partial (logging.log, TRACE)
log = logging.log

stdlog =  {
    "version": 1,
    "formatters": {
        "dnformatter": {
            "()": "decnet.logging.DnFormatter",
            "format": "{asctime}: {threadName}: {message}",
            "style": "{"
            }
        },
    "handlers": {
        "dnhandler": {
            "class": "logging.StreamHandler",
            "formatter": "dnformatter"
            }
        },
    "root": {
        "handlers": [ "dnhandler" ],
        "level": "INFO"
        }
    }

class DnFormatter (logging.Formatter):
    default_msec_format = "%s.%03d"

class DnSysLogHandler (logging.handlers.SysLogHandler):
    def mapPriority (self, levelname):
        if levelname == "TRACE":
            levelname = "DEBUG"
        return super ().mapPriority (levelname)

# We want not just overall log record formatting, but also message
# string formatting to be done with "format".  The "style" argument of
# Formatter doesn't do that, instead we have to override getMessage in
# the LogRecord class to make that work.
class DecnetLogRecord (logging.LogRecord):
    def getMessage (self):
        return str (self.msg).format (*self.args)

logging.setLogRecordFactory (DecnetLogRecord)

logging.addLevelName (TRACE, "TRACE")

def start (p):
    if p.log_config:
        fn = p.log_config
        with open (fn, "rt") as f:
            lc = f.read ()
        if fn.endswith (".yaml"):
            if not load:
                print ("YAML config file but no YAML support",
                       file = sys.stderr)
                sys.exit (1)
            lc = load (lc, Loader = Loader)
        else:
            lc = json.loads (lc)
    else:
        lc = stdlog
        h = lc["handlers"]["dnhandler"]
        rl = lc["root"]
        if p.log_file:
            h["filename"] = p.log_file
            if p.keep:
                h["class"] = "logging.handlers.TimedRotatingFileHandler"
                h["when"] = "midnight"
                h["backupCount"] = p.keep
            else:
                h["class"] = "logging.FileHandler"
                h["mode"] = "w"
        elif p.syslog:
            if p.syslog == "local":
                # Pseudo-destination meaning whatever appears to be the
                # correct way to talk to the local syslog daemon.
                for dest in ("/dev/log", "/var/run/syslog"):
                    try:
                        s = os.stat (dest)
                        if stat.S_ISSOCK (s.st_mode):
                            break
                    except OSError:
                        pass
                else:
                    dest = ("localhost", logging.handlers.SYSLOG_UDP_PORT)
            else:
                hp = p.syslog.split (":")
                if len (hp) > 2:
                    print ("Invalid syslog argument", p.syslog, file = sys.stderr)
                    sys.exit (1)
                if len (hp) == 2:
                    dest = [ hp[0], int (hp[1]) ]
                else:
                    dest = [ hp[0], logging.handlers.SYSLOG_UDP_PORT ]
            h["class"] = "decnet.logging.DnSysLogHandler"
            h["address"] = dest
        else:
            if p.keep:
                print ("--keep requires --log-file", file = sys.stderr)
                sys.exit (1)
            if p.daemon:
                print ("--daemon requires --log-file", file = sys.stderr)
                sys.exit (1)
        rl["level"] = p.log_level
    #print ("Logging config is:\n", lc)
    # Create a formatter using {} formatting, and set the message
    # format we want
    logging.config.dictConfig (lc)

    # We're going to make a child logger "decnet" for everything we
    # do.  By default that will simply delegate to the root logger,
    # but a custom log config could set up something special for it if
    # desired.
    global decnetLogger, tracing
    global critical, error, warning, info, debug, trace, exception
    decnetLogger = logging.getLogger ("decnet")
    # For optimizing trace actions when tracing isn't requested.
    # Typically, logging.trace calls from the fastpath (as opposed to
    # error or slow cases) should be conditional under "tracing".
    tracing = decnetLogger.isEnabledFor (TRACE)
    critical = decnetLogger.critical
    error = decnetLogger.error
    warning = decnetLogger.warning
    info = decnetLogger.info
    debug = decnetLogger.debug
    # Handle TRACE as a call to the "log" method with the level
    # supplied ahead of time.  Doing it this way, rather than via a
    # simple "trace" function in this module, results in the correct
    # caller info in the message (the place where the "trace" call is
    # made, rather than a trace function here calling "log").
    trace = functools.partial (decnetLogger.log, TRACE)
    exception = decnetLogger.exception
    return

def stop ():
    info ("DECnet/Python shut down")
    logging.shutdown ()
    

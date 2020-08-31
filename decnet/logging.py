#!

"""Logging extensions for DECnet/Python.

"""

import logging
import logging.config
import logging.handlers
import os
import stat
import sys
import json
import time
import functools
import copy
import collections

try:
    from yaml import load, Loader
except ImportError:
    load = None
    
from .common import *

SvnFileRev = "$LastChangedRevision$"

# Additional level
TRACE = 2

# Inherit some names from the standard logging module
CRITICAL = logging.CRITICAL
ERROR = logging.ERROR
WARNING = logging.WARNING
INFO = logging.INFO
DEBUG = logging.DEBUG

# All the code refers to "logging" which doesn't go to the standard
# logging module methods, but rather to methods of the "decnet"
# logger.  Initially we'll use the module methods, though; they are
# replaced by references to the decnet logger at startup.
critical = logging.critical
error = logging.error
warning = logging.warning
info = logging.info
debug = logging.debug
exception = logging.exception
trace = functools.partial (logging.log, TRACE)
log = logging.log

# Like the standard getLogger but it also adds a trace method
def getLogger (name):
    ret = logging.getLogger (name)
    if not hasattr (ret, "trace"):
        ret.trace = functools.partial (ret.log, TRACE)
    return ret

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
        },
    "loggers" : {
        "decnet": {
            "propagate" : True
            },
        "decnet.mapper": {
            "propagate" : True
            }
        }
    }

class DnFormatter (logging.Formatter):
    default_msec_format = "%s.%03d"

class DnSysLogHandler (logging.handlers.SysLogHandler):
    def mapPriority (self, levelname):
        if levelname == "TRACE":
            levelname = "DEBUG"
        return super ().mapPriority (levelname)


def flush ():
    "Flush all handlers"
    for h in logging._handlers.values ():
        h.flush ()

def bypass (bypass = True):
    "Configure the bypass setting of all handlers"
    for h in logging._handlers.values ():
        try:
            h.set_bypass (bypass)
        except AttributeError:
            pass

def check_handlers ():
    "Tell all the handlers to check if they are set up right"
    for h in logging._handlers.values ():
        try:
            h._check ()
        except AttributeError:
            pass
        
class DnMemoryHandler (logging.Handler):
    """A buffering handler somewhat like the standard
    handlers.MemoryHandler.  But instead of flushing the buffered
    entries when the limit is reached, discard the oldest.  

    Entries are flushed to the attached destination handler when flush()
    is called, when a message with level >= flushLevel is logged, or
    when a message with exception information attached is logged.  The
    defaut flush level is WARNING, which is the level used for logging
    DECnet circuit down events.

    This handler is intended for efficient capture of trace
    level log items without the cost of formatting all of them and
    writing them to a file.  The assumption is that other components
    will call flush() when "something sufficiently interesting" happened
    (after logging that); the output log will then reflect that
    occurrence as well as some amount of history leading up to it.
    """
    def __init__ (self, capacity = 100, target = None,
                  flushLevel = logging.WARNING):
        super ().__init__ ()
        self.buffer = collections.deque (maxlen = capacity)
        self.target = target
        self.bypassing = False
        if isinstance (flushLevel, str):
            # This can be done (counterintuitively) with getLevelName,
            # except in Python 3.4.  So do it the not so elegant way.
            flushLevel = logging._nameToLevel[flushLevel]
        self.flushLevel = flushLevel
        
    def _check (self):
        "Check the target handler for this handler."
        if isinstance (self.target, str):
            # It's a string, convert to a handler
            self.target = logging._handlers[self.target]

    def set_bypass (self, bypass):
        if bypass:
            self.buffer.clear ()
        self.bypassing = bypass
        
    def emit (self, record):
        if self.bypassing:
            if self.target:
                self.target.handle (record)
        else:
            self.buffer.append (record)
            # Now flush if it's time to do that
            if self.flush_needed (record):
                self.flush ()

    def flush_needed (self, record):
        return record.levelno >= self.flushLevel or \
               getattr (record, "exc_info", None)
        
    def flush (self):
        if self.target:
            try:
                while True:
                    self.target.handle (self.buffer.popleft ())
            except IndexError:
                pass
            self.target.flush ()
            
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
    # Start logging using the supplied config.  If a chroot argument
    # is specified in the program arguments in "p", prefix each file
    # name with the supplied chroot value.  This is done since the
    # logger is started before the chroot() call is made.  Then
    # afterwards, the "restart" function is called to reload the same
    # config but without the chroot prefixed onto the file paths.
    global logconfig, chrootlogconfig
    if p.log_config:
        fn = p.log_config
        with open (fn, "rt") as f:
            lc = f.read ()
        if fn.endswith (".yaml"):
            if not load:
                print ("YAML config file but no YAML support",
                       file = sys.stderr)
                sys.exit (1)
            logconfig = load (lc, Loader = Loader)
        else:
            logconfig = json.loads (lc)
        if "loggers" not in logconfig:
            logconfig["loggers"] = stdlog["loggers"]
        if "decnet" not in logconfig["loggers"]:
            logconfig["loggers"]["decnet"] = stdlog["loggers"]["decnet"]
    else:
        logconfig = stdlog
        h = logconfig["handlers"]["dnhandler"]
        rl = logconfig["root"]
        if p.log_file:
            h["filename"] = abspath (p.log_file)
            if p.keep:
                h["class"] = "logging.handlers.TimedRotatingFileHandler"
                h["when"] = "midnight"
                h["backupCount"] = p.keep
            else:
                h["class"] = "logging.FileHandler"
                h["mode"] = "a"
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
    # Make a copy of the config and put the root in front of each file
    # name string.  Also collect the file names, then after starting
    # the logger, set uid/gid of each file.
    chroot = p.chroot
    fns = list ()
    chrootlogconfig = copy.deepcopy (logconfig)
    for h in chrootlogconfig["handlers"].values ():
        try:
            h["filename"] = chroot + h["filename"]
            fns.append (h["filename"])
        except KeyError:
            pass
        try:
            h["address"] = chroot + h["address"]
        except (KeyError, TypeError):
            pass
    # Create a formatter using {} formatting, and set the message
    # format we want
    logging.config.dictConfig (chrootlogconfig)
    if p.uid or p.gid:
        for fn in fns:
            os.chown (fn, p.uid or -1, p.gid or -1)
    setdecnetlogger ()

def restart (chrootdone = True):
    # Simply reload the appropriate saved config
    if chrootdone:
        lc = logconfig
    else:
        lc = chrootlogconfig
    logging.config.dictConfig (lc)
    setdecnetlogger ()
    info ("Logging configuration reloaded")
    
def setdecnetlogger ():
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
    exception = decnetLogger.exception
    # Handle "trace" as a call to the "log" method with the level
    # supplied ahead of time.  Doing it this way, rather than via a
    # simple "trace" function in this module, results in the correct
    # caller info in the message (the place where the "trace" call is
    # made, rather than a trace function here calling "log").
    trace = functools.partial (decnetLogger.log, TRACE)
    # Make sure the handlers are set up properly
    check_handlers ()

def stop (exiting = True):
    if exiting:
        bypass ()
        log (99, "DECnet/Python shut down")
    else:
        debug ("DECnet/Python logging stopped")
    logging.shutdown ()
    

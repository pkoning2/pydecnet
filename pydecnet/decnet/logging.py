#!

"""Logging extensions for DECnet/Python.

"""

import logging
import logging.config
import logging.handlers
from .common import *
import traceback
import os
import stat

# Expose part of the standard logging objects

handlers = logging.handlers
exception = logging.exception
critical = logging.critical
error = logging.error
warning = logging.warning
info = logging.info
debug = logging.debug
log = logging.log
getLogger = logging.getLogger
FileHandler = logging.FileHandler
StreamHandler = logging.StreamHandler
basicConfig = logging.basicConfig
shutdown = logging.shutdown
CRITICAL = logging.CRITICAL
ERROR = logging.ERROR
WARNING = logging.WARNING
INFO = logging.INFO
DEBUG = logging.DEBUG
Formatter = logging.Formatter

class DnSysLogHandler (logging.handlers.SysLogHandler):
    def mapPriority (self, levelname):
        if levelname == "TRACE":
            levelname = "DEBUG"
        return super ().mapPriority (levelname)
    
# Additional level
TRACE = 2

# We want not just overall log record formatting, but also message
# string formatting to be done with "format".  The "style" argument of
# Formatter doesn't do that, instead we have to override getMessage in
# the LogRecord class to make that work.
class DecnetLogRecord (logging.LogRecord):
    def getMessage (self):
        return str (self.msg).format (*self.args)

logging.setLogRecordFactory (DecnetLogRecord)

def trace (msg, *args, **kwargs):
    caller = traceback.extract_stack (limit = 2)[0]
    try:
        fn = caller.filename
        ln = caller.lineno
    except AttributeError:
        # Python 3.3 has a tuple
        fn = caller[0]
        ln = caller[1]
    logging.log (TRACE, "{}:{}: {}".format (os.path.basename (fn), ln, msg),
                 *args, **kwargs)
    
logging.addLevelName (TRACE, "TRACE")

def start (p):
    if p.log_file:
        if p.keep:
            h = logging.handlers.TimedRotatingFileHandler (filename = p.log_file,
                                                           when = "midnight",
                                                           backupCount = p.keep)
        else:
            h = logging.FileHandler (filename = p.log_file, mode = "w")
        # If we run as daemon, we want to keep the handler's stream open
        common.dont_close (h.stream)
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
                print ("Invalid syslog argument", p.syslog)
                sys.exit (1)
            if len (hp) == 2:
                dest = (hp[0], int (hp[1]))
            else:
                dest = (hp[0], logging.handlers.SYSLOG_UDP_PORT)
        h = DnSysLogHandler (dest)
    else:
        if p.keep:
            print ("--keep requires --log-file")
            sys.exit (1)
        if p.daemon:
            print ("--daemon requires --log-file")
            sys.exit (1)
        h = logging.StreamHandler (sys.stderr)
    # Create a formatter using {} formatting, and set the message format we want
    fmt = logging.Formatter (fmt = "{asctime}: {threadName}: {message}",
                             style = '{')
    fmt.default_msec_format = "%s.%03d"
    h.setFormatter (fmt)
    logging.basicConfig (handlers = [ h ], level = p.log_level)
    info ("DECnet/Python started")

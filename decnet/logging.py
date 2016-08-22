#!

"""Logging extensions for DECnet/Python.

"""

import time
import logging
import logging.handlers
from .common import *
import traceback
import os

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

# Additional level
TRACE = 2

# This one is like the one in the "logging" module but with the
# decimal comma corrected to a decimal point.
def formatTime(self, record, datefmt = None):
    """Return the creation time of the specified LogRecord as formatted text.
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
    caller = traceback.extract_stack (limit = 2)[0]
    logging.log (TRACE, "{}:{}: {}".format (os.path.basename (caller.filename),
                                            caller.lineno, msg),
                 *args, **kwargs)
    
logging.addLevelName (TRACE, "TRACE")


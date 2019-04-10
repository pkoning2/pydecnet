#!

"""Logging extensions for DECnet/Python.

"""

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
Formatter = logging.Formatter

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


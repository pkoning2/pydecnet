#!

""" Test application for session layer unit test

This application is referenced by test_session.py to exercise the
various session layer APIs.
"""

from decnet.common import Element
from decnet import session
from decnet import logging

class Application (Element):
    def __init__ (self, parent, obj):
        super ().__init__ (parent)
        # Save the object --argument value
        self.argument = obj.argument

    def dispatch (self, item):
        # Process work sent up from the Session Control layer.
        conn = item.connection
        msg = item.message
        if isinstance (item, session.ConnectInit):
            if msg == b"reject":
                conn.reject (b"rejected")
            elif msg == b"crash":
                raise Exception ("Crash at startup")
            else:
                conn.accept (b"accepted")
        elif isinstance (item, session.Data):
            if msg == b"argument":
                reply = bytes (self.argument, encoding = "latin1")
            elif msg == b"disconnect":
                conn.disconnect (b"as requested")
                return
            elif msg == b"abort":
                conn.abort (b"aborted")
                return
            elif msg == b"crash":
                raise Exception ("Crash while running")
            else:
                reply = b"echo: " + msg
            conn.send_data (reply)
        elif isinstance (item, session.Interrupt):
            conn.interrupt (b"echo: " + item.message)
        elif isinstance (item, session.Disconnect):
            # Nothing to do
            logging.info ("Disconnected")
            
        

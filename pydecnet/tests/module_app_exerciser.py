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
        self.conn = self.conn2 = None
        # Save the object --argument value (which is a list)
        self.argument = obj.argument

    def dispatch (self, item):
        # Process work sent up from the Session Control layer.
        conn = item.connection
        assert conn == self.conn or conn == self.conn2 or self.conn is None
        msg = item.message
        if isinstance (item, session.ConnectInit):
            if msg == b"reject":
                conn.reject (b"rejected")
            elif msg == b"crash":
                raise Exception ("Crash at startup")
            else:
                conn.accept (b"accepted")
            self.conn = conn
        elif isinstance (item, session.Data):
            if msg == b"argument":
                reply = bytes (repr (self.argument), encoding = "latin1")
            elif msg == b"disconnect":
                conn.disconnect (b"as requested")
                return
            elif msg == b"abort":
                conn.abort (b"aborted")
                return
            elif msg == b"crash":
                raise Exception ("Crash while running")
            elif msg == b"connect":
                self.conn2 = self.parent.connect (0, 73, b"test")
                reply = id (self.conn2).to_bytes (8, "little")
            else:
                reply = b"echo: " + msg
            conn.send_data (reply)
        elif isinstance (item, session.Accept):
            assert conn == self.conn2
            conn.send_data (b"accepted")
        elif isinstance (item, session.Reject):
            assert conn == self.conn2
            self.conn2 = None
            self.conn.send_data (b"rejected")
        elif isinstance (item, session.Interrupt):
            conn.interrupt (b"echo interrupt")
        elif isinstance (item, session.Disconnect):
            # No reply, but log it
            logging.log (20, "Disconnected")
        else:
            assert 0, "Unexpected request type {}".format (item.name)
            
        

#!

"""DAP protocol common code

This is the DAP protocol machinery common to client and server.
"""

import sys

from .common import *
from .dap_packets import *
from .logging import dump_packet

# Not quite unlimited but large...
BUFSIZ = 65535

class DapError (DNAException): "DAP base error"
class NotData (DapError): "Unexpected non-data message"

class DapSession:
    """Wrapper class for a DAP protocol connection, either the client or
    the server end.
    """
    def __init__ (self, conn, client, debug = False,
                  dest = "", auth = ""):
        """Initialize the object and run the config handshake.  "client"
        is True for the client side (NFT).  If there is an error, closes
        the connection and raises a DapError exception
        """
        self.dest = dest
        self.auth = auth
        self.debug = debug
        self.conn = conn
        self.client = client
        # Construct our Configuration message.  This describes a
        # rather basic implementation, similar to the Ultrix one.
        # Note that for the moment we have a read-only implementation,
        # file transfer and sequential record access.  Record access
        # is required by VMS, which blindly uses that for file
        # transfer even if we say we don't support it.
        self.myconfig = Config (bufsiz = BUFSIZ, ostype = MYOSTYPE,
                                filesys = MYFILESYS, version = DAPVERSION,
                                prealloc = 0, fo_seq = 1, seq_xfer = 1,
                                append = 0, blocking = 1, len2 = 1, dir = 1,
                                dattim_xa = 1, fprot_xa = 1, delete = 0,
                                seq_ra = 1, rename = 0, glob = 1, name = 1)
        if client:
            conn.data (self.myconfig)
            remconfig = conn.recv ()
        else:
            # Server side, send config in response to the received
            # one.  This isn't required but it is an easy way to avoid
            # trying to send before the NSP connection enters the RUN
            # state (completion of the third leg of the 3-way
            # handshake).
            remconfig = conn.recv ()
            conn.data (self.myconfig)
        if remconfig.type != "data":
            if not conn.closed:
                conn.close ()
                raise NotData
        self.remconfig = DapBase (remconfig)
        if self.debug:
            print ("Received DAP message:", file = sys.stderr)
            print (dump_packet (remconfig), file = sys.stderr)
            print (self.remconfig, file = sys.stderr)
        self.bufsiz = min (self.remconfig.bufsiz, BUFSIZ)
        # Remember if we're running protocol V7 or an earlier version
        self.v7 = self.remconfig.version[0] >= 7 and DAPVERSION[0] >= 7
        self.txdata = list ()
        self.txlen = 0
        self.rxdata = None

    def recv (self):
        "Receive another DAP packet"
        if not self.rxdata:
            try:
                self.rxdata = self.conn.recv ()
            except Exception:
                self.rxdata = None
                return None
            if self.rxdata.type != "data":
                if not self.conn.closed:
                    self.conn.close ()
                return None
        # Parse a message out of the received data
        msg, self.rxdata = DapBase.decode (self.rxdata)
        if self.debug:
            print ("Received DAP message:", file = sys.stderr)
            print (dump_packet (msg.decoded_from), file = sys.stderr)
            print (msg, file = sys.stderr)
        if isinstance (msg, Config):
            # VMS seems to have a bizarre habit of sending another
            # Config after a file has been transferred.  Certainly DAP
            # 5.6.0 doesn't authorize that, so I doubt V7 does.  If we
            # see this, respond with our config and look for another
            # message.
            self.flush ()
            self.conn.data (self.myconfig)
            return self.recv ()
        return msg

    def flush (self):
        """Flush pending transmit data.
        """
        if self.txdata:
            self.conn.data (b"".join (self.txdata))
            self.txdata = list ()
            self.txlen = 0
            
    def send (self, msg):
        """Send a DAP message.  Use blocking if permitted and possible
        given the negotiated parameters.  Note that we don't use this
        method for sending Configuration messages; those are sent
        directly to the connection since blocking is not allowed for
        those.
        """
        msg.m_length = msg.m_len256 = 0
        msgb = msg.encode ()
        if self.debug:
            print ("Sending DAP message:", file = sys.stderr)
            print (msg, file = sys.stderr)
            print (dump_packet (msgb), file = sys.stderr)
        mlen = len (msgb)
        assert mlen <= self.bufsiz, "DAP message too large for peer"
        if not self.remconfig.blocking:
            # Blocking not supported by peer
            self.conn.data (msgb)
            return
        if self.txlen + mlen > self.bufsiz:
            # This message doesn't fit with what was already buffered.
            # Send what we had buffered before.
            self.flush ()
        if mlen > 254 and not self.remconfig.len2:
            # Long message but 2 byte length not supported.  We can
            # still block this message with earlier ones but we can't
            # put another after it since we can't encode its length.
            self.txdata.append (msgb)
            self.flush ()
            return
        # We can block with encoded length.  Do so, which involves
        # repeating the encode.  (We could take shortcuts but it isn't
        # worth the trouble.)  Note that the length field(s) encoded in
        # the header give the length of what follows, hence the
        # adjustments by -3 or -4.
        if mlen < 255:
            # One byte length
            mlen += 1
            msg.length = mlen - 3
            msg.m_length = 1
        else:
            # Two byte length
            mlen += 2
            lenf = mlen - 4
            msg.length = lenf & 0xff
            msg.len256 = lenf >> 8
            # Set both length field flags
            msg.m_length = msg.m_len256 = 1
        # Encode the message and append it to the waiting transmit data.
        self.txdata.append (msg.encode ())
        self.txlen += mlen

    @property
    def closed (self):
        return self.conn.closed
    
    def close (self):
        if not self.conn.closed:
            self.conn.close ()

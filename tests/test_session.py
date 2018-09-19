#!/usr/bin/env/python3

"""Unit test for the Session Control layer.

This also tests the mirror application (in a basic way) as part of
verifying successful connection to an application.  
"""

from tests.dntest import *
from decnet import nsp
from decnet import session
from decnet import logging

class stest (DnTest):
    phase = 4
    
    def setUp (self):
        super ().setUp ()
        self.node.phase = 4
        self.config = container ()
        self.config.session = container ()
        self.config.object = [ ]
        self.node.nsp = unittest.mock.Mock ()
        self.s = session.Session (self.node, self.config)
        #self.setloglevel (logging.TRACE)
        
class test_inbound (stest):
    def test_mirror (self):
        p = b"\x00\x19\x01\x00\x04PAUL\x00"
        ci = nsp.ConnInit (payload = p)
        m = unittest.mock.Mock ()
        w = Received (owner = self.s, connection = m,
                      packet = ci, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.accept.call_count, 1)
        self.assertEqual (m.accept.call_args, unittest.mock.call (b"\xff\xff"))
        self.assertTrue (m in self.s.conns)
        # Send a data packet
        p = b"\x00test data"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.send_data.call_count, 1)
        self.assertEqual (m.send_data.call_args, unittest.mock.call (b"\x01" + p[1:]))
        # Close the connection
        disc = nsp.DiscInit (data_ctl = b"", reason = 0)
        w = Received (owner = self.s, connection = m,
                      packet = disc, reject = False)
        self.s.dispatch (w)
        self.assertEqual (len (self.s.conns), 0)
        
class test_inbound_err (stest):
    def test_noobj (self):
        p = b"\x00\x15\x01\x00\x04PAUL\x00"
        ci = nsp.ConnInit (payload = p)
        m = unittest.mock.Mock ()
        w = Received (owner = self.s, connection = m,
                      packet = ci, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.reject.call_count, 1)
        self.assertEqual (m.reject.call_args, unittest.mock.call (session.NO_OBJ, b""))
        self.assertEqual (len (self.s.conns), 0)
        
class test_outbound (stest):
    def test_outbound (self):
        conn = unittest.mock.Mock ()
        nsp = self.node.nsp
        nsp.connect.return_value = conn

class test_random (stest):
    def test_random (self):
        m = unittest.mock.Mock ()
        for i in range (5000):
            pkt = nsp.ConnInit (payload = randpkt (8, 64))
            w = Received (owner = self.s, connection = m,
                          packet = pkt, reject = False)
            self.s.dispatch (w)
        
if __name__ == "__main__":
    unittest.main ()

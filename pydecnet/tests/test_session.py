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
        self.config.object = [ container () ]
        self.config.object[0].number = 0
        self.config.object[0].file = None
        self.config.object[0].disable = False
        self.config.object[0].name = "TESTER"
        self.config.object[0].module = "tests.module_app_exerciser"
        self.config.object[0].argument = "myargument"
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
        self.assertEqual (m.send_data.call_args,
                          unittest.mock.call (b"\x01" + p[1:]))
        # Close the connection
        disc = nsp.DiscInit (data_ctl = b"", reason = 0)
        w = Received (owner = self.s, connection = m,
                      packet = disc, reject = False)
        self.s.dispatch (w)
        self.assertEqual (len (self.s.conns), 0)

    def test_reject (self):
        p = b"\x01\x00\x06TESTER\x01\x00\x04PAUL\x02\x06reject"
        ci = nsp.ConnInit (payload = p)
        m = unittest.mock.Mock ()
        w = Received (owner = self.s, connection = m,
                      packet = ci, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.reject.call_count, 1)
        self.assertEqual (m.reject.call_args,
                          unittest.mock.call (0, b"rejected"))
        self.assertEqual (len (self.s.conns), 0)
        
    def test_inbound_disc (self):
        p = b"\x01\x00\x06TESTER\x01\x00\x04PAUL\x02\x06accept"
        ci = nsp.ConnInit (payload = p)
        m = unittest.mock.Mock ()
        w = Received (owner = self.s, connection = m,
                      packet = ci, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.accept.call_count, 1)
        self.assertEqual (m.accept.call_args, unittest.mock.call (b"accepted"))
        self.assertTrue (m in self.s.conns)
        # Send a data packet
        p = b"test data"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.send_data.call_count, 1)
        self.assertEqual (m.send_data.call_args,
                          unittest.mock.call (b"echo: test data"))
        # Close the connection
        disc = nsp.DiscInit (data_ctl = b"", reason = 0)
        w = Received (owner = self.s, connection = m,
                      packet = disc, reject = False)
        self.s.dispatch (w)
        self.assertEqual (len (self.s.conns), 0)
        self.assertEqual (logging.info.call_count, 1)
        self.assertEqual (logging.info.call_args,
                          unittest.mock.call ("Disconnected"))
        
    def test_app_disc (self):
        p = b"\x01\x00\x06TESTER\x01\x00\x04PAUL\x02\x06accept"
        ci = nsp.ConnInit (payload = p)
        m = unittest.mock.Mock ()
        w = Received (owner = self.s, connection = m,
                      packet = ci, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.accept.call_count, 1)
        self.assertEqual (m.accept.call_args, unittest.mock.call (b"accepted"))
        self.assertTrue (m in self.s.conns)
        # Send a data packet
        p = b"disconnect"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.disconnect.call_count, 1)
        self.assertEqual (m.disconnect.call_args,
                          unittest.mock.call (session.APPLICATION, b"as requested"))
        self.assertEqual (len (self.s.conns), 0)
        
    def test_app_abort (self):
        p = b"\x01\x00\x06TESTER\x01\x00\x04PAUL\x02\x06accept"
        ci = nsp.ConnInit (payload = p)
        m = unittest.mock.Mock ()
        w = Received (owner = self.s, connection = m,
                      packet = ci, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.accept.call_count, 1)
        self.assertEqual (m.accept.call_args, unittest.mock.call (b"accepted"))
        self.assertTrue (m in self.s.conns)
        # Send a data packet
        p = b"abort"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.abort.call_count, 1)
        self.assertEqual (m.abort.call_args,
                          unittest.mock.call (session.ABORT, b"aborted"))
        self.assertEqual (len (self.s.conns), 0)

    def test_bigdata (self):
        p = b"\x01\x00\x06TESTER\x01\x00\x04PAUL\x02\x06accept"
        ci = nsp.ConnInit (payload = p)
        m = unittest.mock.Mock ()
        w = Received (owner = self.s, connection = m,
                      packet = ci, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.accept.call_count, 1)
        self.assertEqual (m.accept.call_args, unittest.mock.call (b"accepted"))
        self.assertTrue (m in self.s.conns)
        # Send a data packet
        p = bytes (range (256)) * 32    # 8k bytes
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.send_data.call_count, 1)
        self.assertEqual (m.send_data.call_args,
                          unittest.mock.call (b"echo: " + p))
        # Close the connection
        disc = nsp.DiscInit (data_ctl = b"", reason = 0)
        w = Received (owner = self.s, connection = m,
                      packet = disc, reject = False)
        self.s.dispatch (w)
        self.assertEqual (len (self.s.conns), 0)
        
    def test_interrupt (self):
        p = b"\x01\x00\x06TESTER\x01\x00\x04PAUL\x02\x06accept"
        ci = nsp.ConnInit (payload = p)
        m = unittest.mock.Mock ()
        w = Received (owner = self.s, connection = m,
                      packet = ci, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.accept.call_count, 1)
        self.assertEqual (m.accept.call_args, unittest.mock.call (b"accepted"))
        self.assertTrue (m in self.s.conns)
        p = b"interrupt test"
        d = nsp.IntMsg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.interrupt.call_count, 1)
        self.assertEqual (m.interrupt.call_args,
                          unittest.mock.call (b"echo interrupt"))
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
        self.assertEqual (m.reject.call_args,
                          unittest.mock.call (session.NO_OBJ))
        self.assertEqual (len (self.s.conns), 0)
        
    def test_conncrash (self):
        p = b"\x01\x00\x06TESTER\x01\x00\x04PAUL\x02\x05crash"
        ci = nsp.ConnInit (payload = p)
        m = unittest.mock.Mock ()
        w = Received (owner = self.s, connection = m,
                      packet = ci, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.reject.call_count, 1)
        self.assertEqual (m.reject.call_args,
                          unittest.mock.call (session.OBJ_FAIL))
        self.assertEqual (len (self.s.conns), 0)
        
    def test_runcrash (self):
        p = b"\x01\x00\x06TESTER\x01\x00\x04PAUL\x02\x06accept"
        ci = nsp.ConnInit (payload = p)
        m = unittest.mock.Mock ()
        w = Received (owner = self.s, connection = m,
                      packet = ci, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.accept.call_count, 1)
        self.assertEqual (m.accept.call_args, unittest.mock.call (b"accepted"))
        self.assertTrue (m in self.s.conns)
        # Send a data packet
        p = b"crash"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.s.dispatch (w)
        self.assertEqual (m.abort.call_count, 1)
        self.assertEqual (m.abort.call_args,
                          unittest.mock.call (session.OBJ_FAIL))
        
class test_outbound (stest):
    def test_outbound (self):
        conn = unittest.mock.Mock ()
        nspmock = self.node.nsp
        nspmock.connect.return_value = conn
        dest = Nodeid (42, 1)
        payload = b"good morning"
        sc = self.s.connect (dest, payload)
        self.assertIs (sc.nspconn, conn)
        self.assertEqual (len (self.s.conns), 1)
        self.assertEqual (self.s.conns[conn], sc)
        self.assertEqual (nspmock.connect.call_count, 1)
        self.assertEqual (nspmock.connect.call_args,
                          unittest.mock.call (dest, payload))
        sc.disconnect ()
        self.assertEqual (len (self.s.conns), 0)

    def test_outbound_nores (self):
        conn = unittest.mock.Mock ()
        nspmock = self.node.nsp
        nspmock.connect.return_value = conn
        dest = Nodeid (42, 1)
        payload = b"good morning"
        sc = self.s.connect (dest, payload)
        self.assertIs (sc.nspconn, conn)
        self.assertEqual (len (self.s.conns), 1)
        self.assertEqual (self.s.conns[conn], sc)
        self.assertEqual (nspmock.connect.call_count, 1)
        self.assertEqual (nspmock.connect.call_args,
                          unittest.mock.call (dest, payload))
        sc.client = unittest.mock.Mock ()
        pkt = nsp.NoRes ()
        w = Received (owner = self.s, connection = conn,
                      packet = pkt, reject = True)
        self.s.dispatch (w)
        self.assertEqual (len (self.s.conns), 0)
        self.assertEqual (sc.client.dispatch.call_count, 1)
        w2 = sc.client.dispatch.call_args[0][0]
        self.assertIsInstance (w2, session.Reject)
        self.assertEqual (w2.reason, 1)
        self.assertEqual (w2.message, b"")
        self.assertEqual (w2.connection, sc)
        
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

#!/usr/bin/env/python3

"""Unit test for the Session Control layer.

This includes testing the application interface via the use of a
tester module (or process), which invokes all the SC interfaces on
request.
"""
import time
import signal

from tests.dntest import *
from decnet import nsp
from decnet import session
from decnet import logging

class stest (DnTest):
    phase = 4
    process = False
    
    def setUp (self):
        super ().setUp ()
        self.node.phase = 4
        self.config = container ()
        self.config.session = container ()
        self.config.object = [ container () ]
        self.config.object[0].number = 0
        self.config.object[0].disable = False
        self.config.object[0].name = "TESTER"
        if self.process:
            self.config.object[0].module = None
            self.config.object[0].file = "tests/file_app_exerciser.py"
        else:
            self.config.object[0].file = None
            self.config.object[0].module = "tests.module_app_exerciser"
        self.config.object[0].argument = [ "myargument", "arg2" ]
        self.config.object[0].authentication = "off"
        self.node.nsp = unittest.mock.Mock ()
        self.s = session.Session (self.node, self.config)
        #self.setloglevel (logging.TRACE)
        
    def pp (self):
        # Pause if using external subprocess
        if self.process:
            time.sleep (0.2)
            
class test_inbound_noconn (stest):
    "Tests inbound where no data connection results"
    
    def test_reject (self):
        p = b"\x01\x00\x06TESTER\x01\x00\x04PAUL\x02\x06reject"
        ci = nsp.ConnInit (payload = p)
        m = unittest.mock.Mock ()
        w = Received (owner = self.s, connection = m,
                      packet = ci, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (m.reject.call_count, 1)
        self.assertEqual (m.reject.call_args,
                          unittest.mock.call (0, b"rejected"))
        self.assertEqual (len (self.s.conns), 0)

    def test_noobj (self):
        p = b"\x00\x15\x01\x00\x04PAUL\x00"
        ci = nsp.ConnInit (payload = p)
        m = unittest.mock.Mock ()
        w = Received (owner = self.s, connection = m,
                      packet = ci, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (m.reject.call_count, 1)
        self.assertEqual (m.reject.call_args,
                          unittest.mock.call (session.NO_OBJ))
        self.assertEqual (len (self.s.conns), 0)
        
    def test_conncrash (self):
        p = b"\x01\x00\x06TESTER\x01\x00\x04PAUL\x02\x05crash"
        ci = nsp.ConnInit (payload = p)
        m = unittest.mock.Mock ()
        # Force an exception in "abort" because that's what will
        # happen if you try this when the connection is in CR state.
        m.abort.side_effect = nsp.WrongState
        w = Received (owner = self.s, connection = m,
                      packet = ci, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (m.reject.call_count, 1)
        self.assertEqual (m.reject.call_args,
                          unittest.mock.call (session.OBJ_FAIL))
        self.assertEqual (len (self.s.conns), 0)

class test_inbound (stest):
    "Tests inbound that begin with a running connection"

    def setUp (self):
        super ().setUp ()
        p = b"\x01\x00\x06TESTER\x01\x00\x04PAUL\x02\x06accept"
        ci = nsp.ConnInit (payload = p)
        m = unittest.mock.Mock ()
        w = Received (owner = self.s, connection = m,
                      packet = ci, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (m.accept.call_count, 1)
        self.assertEqual (m.accept.call_args, unittest.mock.call (b"accepted"))
        self.assertTrue (m in self.s.conns)
        self.assertEqual (len (self.s.conns), 1)
        self.m = m
        
    def test_inbound_disc (self):
        m = self.m
        p = b"test data"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (m.send_data.call_count, 1)
        self.assertEqual (m.send_data.call_args,
                          unittest.mock.call (b"echo: test data"))
        # Close the connection
        disc = nsp.DiscInit (data_ctl = b"", reason = 0)
        w = Received (owner = self.s, connection = m,
                      packet = disc, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (len (self.s.conns), 0)
        self.assertEqual (logging.log.call_count, 1)
        self.assertEqual (logging.log.call_args,
                          unittest.mock.call (20, "Disconnected"))
        
    def test_app_disc (self):
        m = self.m
        p = b"disconnect"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (m.disconnect.call_count, 1)
        self.assertEqual (m.disconnect.call_args,
                          unittest.mock.call (session.APPLICATION, b"as requested"))
        self.assertEqual (len (self.s.conns), 0)
        
    def test_app_abort (self):
        m = self.m
        p = b"abort"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (m.abort.call_count, 1)
        self.assertEqual (m.abort.call_args,
                          unittest.mock.call (session.ABORT, b"aborted"))
        self.assertEqual (len (self.s.conns), 0)

    def test_bigdata (self):
        m = self.m
        p = bytes (range (256)) * 32    # 8k bytes
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (m.send_data.call_count, 1)
        self.assertEqual (m.send_data.call_args,
                          unittest.mock.call (b"echo: " + p))
        # Close the connection
        disc = nsp.DiscInit (data_ctl = b"", reason = 0)
        w = Received (owner = self.s, connection = m,
                      packet = disc, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (len (self.s.conns), 0)
        
    def test_interrupt (self):
        m = self.m
        p = b"interrupt test"
        d = nsp.IntMsg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (m.interrupt.call_count, 1)
        self.assertEqual (m.interrupt.call_args,
                          unittest.mock.call (b"echo interrupt"))
        # Close the connection
        disc = nsp.DiscInit (data_ctl = b"", reason = 0)
        w = Received (owner = self.s, connection = m,
                      packet = disc, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (len (self.s.conns), 0)
        
    def test_arguments (self):
        m = self.m
        p = b"argument"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (m.send_data.call_count, 1)
        self.assertEqual (m.send_data.call_args,
                          unittest.mock.call (b"['myargument', 'arg2']"))
        # Close the connection
        disc = nsp.DiscInit (data_ctl = b"", reason = 0)
        w = Received (owner = self.s, connection = m,
                      packet = disc, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (len (self.s.conns), 0)
        
    def test_connect1 (self):
        "Connect request, process dies before accept"
        m = self.m
        p = b"connect"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.node.addwork (w)
        self.pp ()
        # Confirm the second (outbound) connection exists in the
        # session state
        self.assertEqual (len (self.s.conns), 2)
        # Get the tester's reply
        self.assertEqual (m.send_data.call_count, 1)
        if self.process:
            # Verify that session control reported the opened
            # connection to the process
            self.assertEqual (m.send_data.call_args,
                              unittest.mock.call (b"connection created"))
        else:
            # Get the new connection's handle
            h = int.from_bytes (m.send_data.call_args[0][0], "little")
        # Find the new connection
        c2 = [ k for k in self.s.conns if k is not m ][0]
        # Send a "go crash" message on the first connection, note that
        # the second connection is still in CI state.
        p = b"crash"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (m.abort.call_count, 1)
        self.assertEqual (m.abort.call_args,
                          unittest.mock.call (session.OBJ_FAIL))
        self.assertEqual (c2.abort.call_count, 1)
        self.assertEqual (c2.abort.call_args,
                          unittest.mock.call (session.OBJ_FAIL))
        # That should kill both connections
        self.assertEqual (len (self.s.conns), 0)
        
    def test_connect2 (self):
        "Connect request accepted"
        m = self.m
        p = b"connect"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.node.addwork (w)
        self.pp ()
        # Confirm the second (outbound) connection exists in the
        # session state
        self.assertEqual (len (self.s.conns), 2)
        # Find the new connection
        c2 = [ k for k in self.s.conns if k is not m ][0]
        # Accept the connection
        conf = nsp.ConnConf (data_ctl = b"")
        w = Received (owner = self.s, connection = c2,
                      packet = conf, reject = False)
        self.node.addwork (w)
        self.pp ()
        # Check the reply from the tester
        self.assertEqual (c2.send_data.call_count, 1)
        self.assertEqual (c2.send_data.call_args,
                          unittest.mock.call (b"accepted"))
        # Send some regular data on the first connection
        p = b"test data"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (m.send_data.call_count, 2)
        self.assertEqual (m.send_data.call_args,
                          unittest.mock.call (b"echo: test data"))
        # Send some regular data on the second connection
        p = b"test data 2"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = c2,
                      packet = d, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (c2.send_data.call_count, 2)
        self.assertEqual (c2.send_data.call_args,
                          unittest.mock.call (b"echo: test data 2"))
        # Close the first connection from this end
        disc = nsp.DiscInit (data_ctl = b"", reason = 0)
        w = Received (owner = self.s, connection = m,
                      packet = disc, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (len (self.s.conns), 1)
        self.assertEqual (logging.log.call_count, 1)
        self.assertEqual (logging.log.call_args,
                          unittest.mock.call (20, "Disconnected"))
        # Close the other from the other end
        p = b"disconnect"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = c2,
                      packet = d, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (c2.disconnect.call_count, 1)
        self.assertEqual (c2.disconnect.call_args,
                          unittest.mock.call (session.APPLICATION, b"as requested"))
        self.assertEqual (len (self.s.conns), 0)

    def test_connect3 (self):
        "Connect request rejected"
        m = self.m
        p = b"connect"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.node.addwork (w)
        self.pp ()
        # Confirm the second (outbound) connection exists in the
        # session state
        self.assertEqual (len (self.s.conns), 2)
        # Find the new connection
        c2 = [ k for k in self.s.conns if k is not m ][0]
        # Accept the connection
        disc = nsp.DiscInit (data_ctl = b"", reason = 0)
        w = Received (owner = self.s, connection = c2,
                      packet = disc, reject = True)
        self.node.addwork (w)
        self.pp ()
        # Check the reply from the tester
        self.assertEqual (m.send_data.call_count, 2)
        self.assertEqual (m.send_data.call_args,
                          unittest.mock.call (b"rejected"))
        # Close the first connection
        disc = nsp.DiscInit (data_ctl = b"", reason = 0)
        w = Received (owner = self.s, connection = m,
                      packet = disc, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (len (self.s.conns), 0)

    def test_runcrash (self):
        m = self.m
        p = b"crash"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (m.abort.call_count, 1)
        self.assertEqual (m.abort.call_args,
                          unittest.mock.call (session.OBJ_FAIL))
        
class test_file_noconn (test_inbound_noconn):
    process = True

class test_file (test_inbound):
    process = True

    def test_signal (self):
        m = self.m
        p = b"signal"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.node.addwork (w)
        self.pp ()
        self.assertEqual (m.abort.call_count, 1)
        self.assertEqual (m.abort.call_args,
                          unittest.mock.call (session.OBJ_FAIL))
        if hasattr (signal, "Signals"):
            self.assertEqual (logging.debug.call_args,
                              unittest.mock.call ("Subprocess for {} exited with signal {} ({})", "object TESTER", 15, "SIGTERM"))
        else:
            # Python 3.3 doesn't have the signal.Signals feature
            self.assertEqual (logging.debug.call_args,
                              unittest.mock.call ("Subprocess for {} exited with signal {} ({})", "object TESTER", 15, "unknown signal"))
    
class test_outbound (stest):
    def test_outbound (self):
        conn = unittest.mock.Mock ()
        nspmock = self.node.nsp
        nspmock.connect.return_value = conn
        dest = Nodeid (42, 1)
        payload = b"hello"
        sc = self.s.connect (self, dest, 25, payload)
        self.assertIs (sc.nspconn, conn)
        self.assertEqual (len (self.s.conns), 1)
        self.assertEqual (self.s.conns[conn], sc)
        self.assertEqual (nspmock.connect.call_count, 1)
        cidest, cidata = nspmock.connect.call_args[0]
        self.assertEqual (cidest, dest)
        cidata = bytes (cidata)
        self.assertEqual (cidata, b"\x00\x19\x01\x00\x08PyDECnet\x02\x05hello")
        sc.disconnect ()
        self.assertEqual (len (self.s.conns), 0)

    def test_outbound_nores (self):
        conn = unittest.mock.Mock ()
        nspmock = self.node.nsp
        nspmock.connect.return_value = conn
        dest = Nodeid (42, 1)
        payload = b"hi"
        sc = self.s.connect (self, dest, 25, payload, "100,1", "DEMO", "Plugh")
        self.assertIs (sc.nspconn, conn)
        self.assertEqual (len (self.s.conns), 1)
        self.assertEqual (self.s.conns[conn], sc)
        self.assertEqual (nspmock.connect.call_count, 1)
        cidest, cidata = nspmock.connect.call_args[0]
        self.assertEqual (cidest, dest)
        cidata = bytes (cidata)
        self.assertEqual (cidata, b"\x00\x19\x01\x00\x08PyDECnet\x03\x05100,1\x04DEMO\x05Plugh\x02hi")
        sc.client = unittest.mock.Mock ()
        pkt = nsp.NoRes ()
        w = Received (owner = self.s, connection = conn,
                      packet = pkt, reject = True)
        self.node.addwork (w)
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
            self.node.addwork (w)
        
if __name__ == "__main__":
    unittest.main ()

#!/usr/bin/env python3

"""Unit test for the NSP layer.
"""

from tests.dntest import *
from decnet import nsp
from decnet import routing
from decnet import logging

class ntest (DnTest):
    phase = 4
    
    def setUp (self):
        super ().setUp ()
        self.node.phase = 4
        self.config = container ()
        self.config.nsp = container ()
        self.config.nsp.max_connections = 511
        self.config.nsp.nsp_delay = 3
        self.node.routing = unittest.mock.Mock ()
        self.node.session = unittest.mock.Mock ()
        self.nsp = nsp.NSP (self.node, self.config)
        #self.setloglevel (logging.TRACE)
        self.nsp.start ()

class test_inbound (ntest):
    def test_accept (self):
        r = self.node.routing
        s = self.node.session
        # Connect Init, no flow control
        p = b"\x18\x00\x00\x03\x00\x01\x02\x04\x02payload"
        rla = 3
        src = Nodeid (1, 42)
        w = Received (owner = self.nsp, src = src, packet = p, rts = False)
        self.nsp.dispatch (w)
        # Check reply
        self.assertEqual (r.send.call_count, 1)
        args, kwargs = r.send.call_args
        ack, dest = args
        self.assertEqual (dest, src)
        self.assertEqual (ack.dstaddr, rla)
        # Check data to Session Control
        self.assertEqual (self.node.addwork.call_count, 1)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.ConnInit)
        self.assertEqual (pkt.payload, b"payload")
        # Check connection state
        nc = w.connection
        self.assertIs (self.nsp.rconnections[(src, rla)], nc)
        self.assertEqual (nc.dstaddr, rla)
        lla = nc.srcaddr
        self.assertIs (self.nsp.connections[lla], nc)
        # SC send accept
        nc.accept (b"excellent")
        # Verify confirm went out
        self.assertEqual (r.send.call_count, 2)
        args, kwargs = r.send.call_args
        cc, dest = args
        self.assertIsInstance (cc, nsp.ConnConf)
        self.assertEqual (dest, src)
        self.assertEqual (cc.srcaddr, lla)
        self.assertEqual (cc.dstaddr, rla)
        self.assertEqual (cc.data_ctl, b"excellent")
        # Check new connection state
        self.assertEqual (nc.state, nc.cc)
        # Send a data segment
        d = b"\x60" + lla.to_bytes (2, "little") + b"\x03\x00\x01\x00data payload"
        w = Received (owner = self.nsp, src = src, packet = d, rts = False)
        self.nsp.dispatch (w)
        # Check data to Session Control
        self.assertEqual (self.node.addwork.call_count, 2)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.DataSeg)
        self.assertEqual (pkt.payload, b"data payload")
        # Check new connection state
        self.assertEqual (nc.state, nc.run)
        # No reply yet
        self.assertEqual (r.send.call_count, 2)
        # Send a data message
        nc.send_data (b"hello world")
        # Verify data was sent, with piggyback ack
        self.assertEqual (r.send.call_count, 3)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.DataSeg)
        self.assertEqual (dest, src)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertTrue (ds.bom)
        self.assertTrue (ds.eom)
        self.assertEqual (ds.acknum, nsp.AckNum (1))
        self.assertFalse (hasattr (ds, "acknum2"))
        self.assertEqual (ds.payload, b"hello world")

if __name__ == "__main__":
    unittest.main ()

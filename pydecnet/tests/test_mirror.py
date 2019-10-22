#!/usr/bin/env/python3

"""Unit test for the MIRROR object.

This uses session control as the interface to mirror, so the stimulus
is handed up as simulated operations from/to NSP.
"""
import time

from tests.dntest import *
from decnet import nsp
from decnet import session
from decnet import logging

class test_mirror (DnTest):
    phase = 4
    process = False
    
    def setUp (self):
        super ().setUp ()
        self.node.phase = 4
        self.config = container ()
        self.config.session = container ()
        if self.process:
            self.config.object = [ container () ]
            self.config.object[0].number = 25
            self.config.object[0].file = "decnet/applications/mirror.py"
            self.config.object[0].disable = False
            self.config.object[0].name = "MIRROR"
            self.config.object[0].module = None
            self.config.object[0].argument = [ ]
            self.config.object[0].authentication = "off"
            self.node.enable_dispatcher ()
        else:
            self.config.object = [ ]
        self.node.nsp = unittest.mock.Mock ()
        self.s = session.Session (self.node, self.config)
        #self.setloglevel (logging.TRACE)

    def test_mirror (self):
        p = b"\x00\x19\x01\x00\x04PAUL\x00"
        ci = nsp.ConnInit (payload = p)
        m = unittest.mock.Mock ()
        w = Received (owner = self.s, connection = m,
                      packet = ci, reject = False)
        self.s.dispatch (w)
        if self.process:
            time.sleep (0.2)
        self.assertEqual (m.accept.call_count, 1)
        self.assertEqual (m.accept.call_args, unittest.mock.call (b"\xff\xff"))
        self.assertTrue (m in self.s.conns)
        # Send a data packet
        p = b"\x00test data"
        d = nsp.DataSeg (payload = p)
        w = Received (owner = self.s, connection = m,
                      packet = d, reject = False)
        self.s.dispatch (w)
        if self.process:
            time.sleep (0.2)
        self.assertEqual (m.send_data.call_count, 1)
        self.assertEqual (m.send_data.call_args,
                          unittest.mock.call (b"\x01" + p[1:]))
        # Close the connection
        disc = nsp.DiscInit (data_ctl = b"", reason = 0)
        w = Received (owner = self.s, connection = m,
                      packet = disc, reject = False)
        self.s.dispatch (w)
        if self.process:
            time.sleep (0.2)
        self.assertEqual (len (self.s.conns), 0)

class test_mirror_file (test_mirror):
    process = True
    

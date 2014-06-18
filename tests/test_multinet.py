#!/usr/bin/env python3

import unittest

import sys
import os
import time
import socket
import select

import unittest.mock

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet import datalink
from decnet import multinet
from decnet.common import *

# Custom testcase loader to load only Test* classes, not base classes
# that are not in themselves a complete test.
def load_tests (loader, tests, pattern):
    suite = unittest.TestSuite ()
    for k, v in globals().items():
        if type (v) is type and k.startswith ("Test"):
            tests = loader.loadTestsFromTestCase (v)
            suite.addTests (tests)
    return suite

def trace (fmt, *args):
    print ("trace:", fmt % args)

class MultinetBase (unittest.TestCase):
    testsdu = b"four score and seven years ago"
    
    def setUp (self):
        self.lpatch = unittest.mock.patch ("decnet.multinet.logging")
        self.lpatch.start ()
        #multinet.logging.trace.side_effect = trace
        self.tnode = unittest.mock.Mock ()
        self.tnode.node = self.tnode
        self.mult = multinet.Multinet (self.tnode, "multinet-0", self.tconfig)
        self.rport = self.mult.create_port (self.tnode)
        
    def tearDown (self):
        thread = self.mult.rthread
        self.rport.close ()
        for i in range (15):
            time.sleep (0.1)
            if not thread.is_alive ():
                break
        self.assertFalse (thread.is_alive ())
        self.mult.close ()
        self.lpatch.stop ()

    def receivedata (self):
        sellist = [ self.socket.fileno () ]
        r, w, e = select.select (sellist, [ ], sellist, 1)
        self.assertFalse (e, "Socket error")
        self.assertTrue (r, "Nothing received in send test")
        b = self.receivepdu ()
        return b

    def test_xmit (self):
        expected = self.pdu (0, self.testsdu)
        self.rport.send (self.testsdu, None)
        b = self.receivedata ()
        self.assertEqual (b, expected)
        self.assertEqual (self.mult.bytes_sent, len (self.testsdu))
        # and another
        expected = self.pdu (1, self.testsdu)
        self.rport.send (self.testsdu, None)
        b = self.receivedata ()
        self.assertEqual (b, expected)
        self.assertEqual (self.mult.bytes_sent, 2 * len (self.testsdu))

    def lastwork (self, calls):
        self.assertEqual (self.tnode.addwork.call_count, calls)
        a, k = self.tnode.addwork.call_args
        w = a[0]
        self.assertIsInstance (w, Work)
        return w

    def assertUp (self):
        w = self.lastwork (1)
        self.assertIsInstance (w, datalink.DlStatus)
        self.assertTrue (w.status)
        
    def test_rcv1 (self):
        pdu = self.pdu (0, self.testsdu)
        self.sendpdu (pdu)
        time.sleep (0.1)
        w = self.lastwork (2)
        b = w.packet
        self.assertEqual (b, self.testsdu)
        self.assertEqual (self.mult.bytes_recv, 30)        

class TestMultinetUDP (MultinetBase):
    def setUp (self):
        self.tconfig = unittest.mock.Mock ()
        self.tconfig.device = "127.0.0.1:6666:6667"  # UDP mode
        super ().setUp ()
        self.socket = socket.socket (socket.AF_INET, socket.SOCK_DGRAM,
                                     socket.IPPROTO_UDP)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind (("", 6666))
        self.rport.open ()
        time.sleep (0.1)
        self.assertUp ()

    def tearDown (self):
        self.socket.close ()
        super ().tearDown ()

    def pdu (self, n, sdu):
        return n.to_bytes (2, "little") + b"\000\000" + sdu
    
    def receivepdu (self):
        b, addr = self.socket.recvfrom (1500)
        self.assertEqual (addr, ("127.0.0.1", 6667))
        return b
    
    def sendpdu (self, pdu):
        self.socket.sendto (pdu, ("127.0.0.1", 6667))

class MultinetTCPbase (MultinetBase):
    def tearDown (self):
        self.socket.close ()
        super ().tearDown ()

    def pdu (self, n, sdu):
        return len (sdu).to_bytes (2, "little") + b"\000\000" + sdu
    
    def sendpdu (self, pdu):
        self.socket.send (pdu)

    def receivepdu (self):
        hdr = self.socket.recv (4)
        self.assertEqual (len (hdr), 4)
        plen = int.from_bytes (hdr[:2], "little")
        b = self.socket.recv (plen)
        return hdr + b

    def test_disconnect (self):
        self.socket.close ()
        time.sleep (0.1)
        w = self.lastwork (2)
        self.assertIsInstance (w, datalink.DlStatus)
        self.assertFalse (w.status)
        
class TestMultinetTCPconnect (MultinetTCPbase):
    def setUp (self):
        self.tconfig = unittest.mock.Mock ()
        self.tconfig.device = "127.0.0.1:6666:connect"  # active TCP
        super ().setUp ()
        self.socket = socket.socket (socket.AF_INET)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind (("", 6666))
        self.socket.listen (1)
        self.rport.open ()
        sock, ainfo = self.socket.accept ()
        self.assertEqual (ainfo[0], "127.0.0.1")
        self.socket.close ()
        self.socket = sock
        time.sleep (0.1)
        self.assertUp ()        

class TestMultinetTCPlisten (MultinetTCPbase):
    def setUp (self):
        self.tconfig = unittest.mock.Mock ()
        self.tconfig.device = "127.0.0.1:6666:listen"  # passive TCP
        super ().setUp ()
        self.rport.open ()
        time.sleep (0.1)
        self.socket = socket.socket (socket.AF_INET)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect (("127.0.0.1", 6666))
        time.sleep (0.1)
        self.assertUp ()

if __name__ == "__main__":
    unittest.main ()

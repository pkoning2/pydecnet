#!/usr/bin/env python3

from tests.dntest import *

import socket
import select

from decnet import datalink
from decnet import simdmc

class SimhDMCBase (DnTest):
    testsdu = b"four score and seven years ago"

    def setUp (self):
        super ().setUp ()
        with self.assertWarns (DeprecationWarning):
            self.dmc = simdmc.SimhDMC (self.node, "dmc-0", self.tconfig)
        self.rport = self.dmc.create_port (self.node)
        
    def tearDown (self):
        thread = self.dmc.rthread
        self.rport.close ()
        for i in range (15):
            time.sleep (0.1)
            if not thread.is_alive ():
                break
        self.assertFalse (thread.is_alive ())
        self.socket.close ()
        self.dmc.close ()
        super ().tearDown ()

    def receivedata (self):
        sellist = [ self.socket.fileno () ]
        r, w, e = select.select (sellist, [ ], sellist, 1)
        self.assertFalse (e, "Socket error")
        self.assertTrue (r, "Nothing received in send test")
        b = self.receivepdu ()
        return b

    def pdu (self, n, sdu):
        return len (sdu).to_bytes (2, "big") + sdu
    
    def sendpdu (self, pdu):
        self.socket.send (pdu)

    def receivepdu (self):
        hdr = self.socket.recv (2)
        self.assertEqual (len (hdr), 2)
        plen = int.from_bytes (hdr, "big")
        b = self.socket.recv (plen)
        return hdr + b

    def test_xmit (self):
        expected = self.pdu (0, self.testsdu)
        self.rport.send (self.testsdu, None)
        b = self.receivedata ()
        self.assertEqual (b, expected)
        self.assertEqual (self.dmc.counters.bytes_sent, len (self.testsdu))
        # and another
        expected = self.pdu (1, self.testsdu)
        self.rport.send (self.testsdu, None)
        b = self.receivedata ()
        self.assertEqual (b, expected)
        self.assertEqual (self.dmc.counters.bytes_sent, 2 * len (self.testsdu))

    def lastwork (self, calls):
        self.assertEqual (self.node.addwork.call_count, calls)
        a, k = self.node.addwork.call_args
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
        self.assertEqual (self.dmc.counters.bytes_recv, 30)        

    def test_disconnect (self):
        self.socket.close ()
        time.sleep (0.1)
        w = self.lastwork (2)
        self.assertIsInstance (w, datalink.DlStatus)
        self.assertFalse (w.status)
        
class TestSimhDMCconnect (SimhDMCBase):
    def setUp (self):
        self.tconfig = container ()
        self.lport = nextport ()
        self.tconfig.device = "127.0.0.1:{}".format (self.lport)  # active TCP
        super ().setUp ()
        self.socket = socket.socket (socket.AF_INET)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind (("", self.lport))
        self.socket.listen (1)
        self.rport.open ()
        sock, ainfo = self.socket.accept ()
        self.assertEqual (ainfo[0], "127.0.0.1")
        self.socket.close ()
        self.socket = sock
        time.sleep (0.1)
        self.assertUp ()
        
class TestSimhDMClisten (SimhDMCBase):
    def setUp (self):
        self.tconfig = container ()
        self.cport = nextport ()
        self.tconfig.device = "127.0.0.1:{}:secondary".format (self.cport)  # passive TCP
        super ().setUp ()
        self.rport.open ()
        time.sleep (0.1)
        self.socket = socket.socket (socket.AF_INET)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect (("127.0.0.1", self.cport))
        time.sleep (0.1)
        self.assertUp ()

if __name__ == "__main__":
    unittest.main ()

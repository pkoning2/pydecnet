#!/usr/bin/env python3

from tests.dntest import *

import queue

from decnet import gre

tconfig = unittest.mock.Mock ()
tconfig.device = "127.0.0.1"

dest = ("127.0.0.1", 47)

class TestGre (DnTest):
    tdata = b"four score and seven years ago"
    
    def setUp (self):
        super ().setUp ()
        # It's not possible to run two ends of a GRE tunnel on localhost
        # because there's only one protocol number, not source and dest
        # as there is for UDP.  So we have to mock up the socket and
        # select calls to do the sending and receiving of data.
        self.spatch = unittest.mock.patch ("decnet.gre.socket")
        self.selpatch = unittest.mock.patch ("decnet.gre.select.select")
        self.spatch.start ()
        self.selpatch.start ()
        self.pq = queue.Queue ()
        gre.select.select.side_effect = self.mselect
        self.sock = gre.socket.socket.return_value
        self.sock.fileno.return_value = 42
        self.sock.recvfrom.side_effect = self.deliver
        self.gre = gre.GRE (self.node, "gre-0", tconfig)
        self.gre.open ()

    def tearDown (self):
        self.gre.close ()
        for i in range (15):
            time.sleep (0.1)
            if not self.gre.is_alive ():
                break
        self.assertFalse (self.gre.is_alive ())
        self.spatch.stop ()
        self.selpatch.stop ()
        super ().tearDown ()
        
    def circ (self):
        c = unittest.mock.Mock ()
        c.parent = self.node
        c.node = self.node
        return c
    
    def mselect (self, *args):
        try:
            self.pkt = self.pq.get (timeout = 1)
            return (True, False, False)
        except queue.Empty:
            return (False, False, False)
            
    def deliver (self, len):
        p = self.pkt
        self.pkt = None
        self.pq.task_done ()
        return b'\x45' + bytes (19) + p, dest

    def postPacket (self, pkt):
        self.pq.put (pkt)
        self.pq.join ()
        
    def lelen (self, d):
        return len (d).to_bytes (2, "little")
    
    def test_rcv1 (self):
        rcirc = self.circ ()
        self.rport = self.gre.create_port (rcirc, ROUTINGPROTO)
        self.postPacket (b"\x00\x00\x60\x03" +
                         self.lelen (self.tdata) + self.tdata)
        w = self.lastreceived (1)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (w.packet, self.tdata)
        self.assertEqual (self.gre.unk_dest, 0)
        self.assertEqual (self.gre.bytes_recv, 32)
        self.assertEqual (self.rport.bytes_recv, 32)
        
    def test_rcvdemux (self):
        rcirc = self.circ ()
        lcirc = self.circ ()
        self.rport = self.gre.create_port (rcirc, ROUTINGPROTO)
        self.lport = self.gre.create_port (lcirc, LOOPPROTO, False)
        self.postPacket (b"\x00\x00\x60\x03" +
                         self.lelen (self.tdata) + self.tdata)
        w = self.lastreceived (1)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (w.packet, self.tdata)
        self.assertEqual (self.gre.unk_dest, 0)
        self.assertEqual (self.gre.bytes_recv, 32)
        self.assertEqual (self.lport.bytes_recv, 0)
        self.assertEqual (self.rport.bytes_recv, 32)
        self.postPacket (b"\x00\x00\x90\x00" + self.tdata)
        w = self.lastreceived (2)
        self.assertEqual (w.owner, lcirc)
        self.assertEqual (w.packet, self.tdata)
        self.assertEqual (self.gre.unk_dest, 0)
        self.assertEqual (self.gre.bytes_recv, 62)
        self.assertEqual (self.lport.bytes_recv, 30)
        self.assertEqual (self.rport.bytes_recv, 32)
        self.postPacket (b"\x00\x00\x91\x00" + self.tdata)
        self.lastreceived (2)   # Check that nothing new is posted
        self.assertEqual (self.gre.unk_dest, 1)
        self.assertEqual (self.gre.bytes_recv, 62)
        self.assertEqual (self.lport.bytes_recv, 30)
        self.assertEqual (self.rport.bytes_recv, 32)

    def test_xmit (self):
        self.rport = self.gre.create_port (self.node, ROUTINGPROTO)
        self.lport = self.gre.create_port (self.node, LOOPPROTO, False)
        self.rport.send (b"four score and seven years ago", None)
        data = self.sock.sendto.call_args
        self.assertIsNotNone (data)
        a, k = data
        b, addr = a
        b = bytes (b)
        expected = b"\x00\x00\x60\x03\x1e\x00four score and seven years ago"
        self.assertEqual (addr, dest)
        self.assertEqual (b[:len (expected)], expected)
        self.assertEqual (self.gre.bytes_sent, 36)
        self.assertEqual (self.lport.bytes_sent, 0)
        self.assertEqual (self.rport.bytes_sent, 36)
        self.lport.send (b"four score and seven years ago", None)
        data = self.sock.sendto.call_args
        a, k = data
        b, addr = a
        b = bytes (b)
        expected = b"\x00\x00\x90\x00four score and seven years ago"
        self.assertEqual (addr, dest)
        self.assertEqual (b[:len (expected)], expected)
        self.assertEqual (self.gre.bytes_sent, 70)
        self.assertEqual (self.lport.bytes_sent, 34)
        self.assertEqual (self.rport.bytes_sent, 36)

    def test_randpdu (self):
        rcirc = self.circ ()
        self.rport = self.gre.create_port (rcirc, ROUTINGPROTO)
        for i in range (100):
            pkt = randpkt (10, 1500)
            self.postPacket (pkt)

    def test_randproto (self):
        rcirc = self.circ ()
        self.rport = self.gre.create_port (rcirc, ROUTINGPROTO)
        for i in range (100):
            pkt = randpkt (10, 1500)
            self.postPacket (gre.greflags + pkt)

    def test_randpkt (self):
        hdr = b"\x00\x00\x60\x03"
        rcirc = self.circ ()
        self.rport = self.gre.create_port (rcirc, ROUTINGPROTO)
        for i in range (100):
            pkt = randpkt (10, 1500)
            self.postPacket (hdr + pkt)

    def test_randpayload (self):
        hdr = b"\x00\x00\x60\x03"
        rcirc = self.circ ()
        self.rport = self.gre.create_port (rcirc, ROUTINGPROTO)
        for i in range (100):
            pkt = randpkt (10, 1500)
            self.postPacket (hdr + self.lelen (pkt) + pkt)
        
if __name__ == "__main__":
    unittest.main ()

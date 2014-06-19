#!/usr/bin/env python3

import unittest

import sys
import os
import time
import random
import queue

import unittest.mock

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet import gre
from decnet.common import *

random.seed (999)

tconfig = unittest.mock.Mock ()
tconfig.device = "127.0.0.1"

def debug (fmt, *args):
    print ("debug:", fmt % args)

def trace (fmt, *args):
    print ("trace:", fmt % args)

dest = ("127.0.0.1", 47)

def randpkt (minlen, maxlen):
    plen = random.randrange (minlen, maxlen + 1)
    i = random.getrandbits (plen * 8)
    return i.to_bytes (plen, "little")

class TestGre (unittest.TestCase):
    tdata = b"four score and seven years ago"
    
    def setUp (self):
        self.lpatch = unittest.mock.patch ("decnet.gre.logging")
        # It's not possible to run two ends of a GRE tunnel on localhost
        # because there's only one protocol number, not source and dest
        # as there is for UDP.  So we have to mock up the socket and
        # select calls to do the sending and receiving of data.
        self.spatch = unittest.mock.patch ("decnet.gre.socket")
        self.selpatch = unittest.mock.patch ("decnet.gre.select.select")
        self.lpatch.start ()
        self.spatch.start ()
        self.selpatch.start ()
        self.pq = queue.Queue ()
        #gre.logging.debug.side_effect = debug
        #gre.logging.trace.side_effect = trace
        gre.select.select.side_effect = self.mselect
        self.tnode = unittest.mock.Mock ()
        self.tnode.node = self.tnode
        self.sock = gre.socket.socket.return_value
        self.sock.fileno.return_value = 42
        self.sock.recvfrom.side_effect = self.deliver
        self.gre = gre.GRE (self.tnode, "gre-0", tconfig)
        self.gre.open ()

    def tearDown (self):
        self.gre.close ()
        for i in range (15):
            time.sleep (0.1)
            if not self.gre.is_alive ():
                break
        self.assertFalse (self.gre.is_alive ())
        self.lpatch.stop ()
        self.spatch.stop ()
        self.selpatch.stop ()

    def circ (self):
        c = unittest.mock.Mock ()
        c.parent = self.tnode
        c.node = self.tnode
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

    def lastwork (self, calls):
        self.assertEqual (self.tnode.addwork.call_count, calls)
        a, k = self.tnode.addwork.call_args
        w = a[0]
        self.assertIsInstance (w, Received)
        return w

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
        w = self.lastwork (1)
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
        w = self.lastwork (1)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (w.packet, self.tdata)
        self.assertEqual (self.gre.unk_dest, 0)
        self.assertEqual (self.gre.bytes_recv, 32)
        self.assertEqual (self.lport.bytes_recv, 0)
        self.assertEqual (self.rport.bytes_recv, 32)
        self.postPacket (b"\x00\x00\x90\x00" + self.tdata)
        w = self.lastwork (2)
        self.assertEqual (w.owner, lcirc)
        self.assertEqual (w.packet, self.tdata)
        self.assertEqual (self.gre.unk_dest, 0)
        self.assertEqual (self.gre.bytes_recv, 62)
        self.assertEqual (self.lport.bytes_recv, 30)
        self.assertEqual (self.rport.bytes_recv, 32)
        self.postPacket (b"\x00\x00\x91\x00" + self.tdata)
        self.lastwork (2)   # Check that nothing new is posted
        self.assertEqual (self.gre.unk_dest, 1)
        self.assertEqual (self.gre.bytes_recv, 62)
        self.assertEqual (self.lport.bytes_recv, 30)
        self.assertEqual (self.rport.bytes_recv, 32)

    def test_xmit (self):
        self.rport = self.gre.create_port (self.tnode, ROUTINGPROTO)
        self.lport = self.gre.create_port (self.tnode, LOOPPROTO, False)
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

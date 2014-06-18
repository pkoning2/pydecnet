#!/usr/bin/env python3

import unittest

import sys
import os
import time
import unittest.mock

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet import gre
from decnet.common import *

tnode = unittest.mock.Mock ()
tnode.node = tnode

tconfig = unittest.mock.Mock ()
tconfig.device = "127.0.0.1"

def trace (fmt, *args):
    print ("trace:", fmt % args)

dest = ("127.0.0.1", 47)

packet = None
def wait1 (*args):
    time.sleep (0.1)
    return (bool (packet), False, False)
    
def deliver (len):
    global packet
    p = packet
    packet = None
    return b'\x45' + bytes (19) + p, dest

class TestGre (unittest.TestCase):
    def setUp (self):
        self.lpatch = unittest.mock.patch ("decnet.gre.logging")
        self.spatch = unittest.mock.patch ("decnet.gre.socket")
        self.selpatch = unittest.mock.patch ("decnet.gre.select.select")
        self.lpatch.start ()
        self.spatch.start ()
        self.selpatch.start ()
        #gre.logging.trace.side_effect = trace
        gre.select.select.side_effect = wait1
        self.sock = gre.socket.socket.return_value
        self.sock.fileno.return_value = 42
        self.sock.recvfrom.side_effect = deliver
        self.gre = gre.GRE (tnode, "gre-0", tconfig)
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

    def postPacket (self, pkt):
        global packet
        packet = pkt
        for i in range (10):
            time.sleep (0.1)
            if not packet:
                break
        self.assertIsNone (packet, "Packet was not picked up")
        
    def test_rcv1 (self):
        self.rport = self.gre.create_port (tnode, ROUTINGPROTO)
        self.postPacket (b"\x00\x00\x60\x03\036\000four score and seven years ago")
        self.assertEqual (self.gre.unk_dest, 0)
        self.assertEqual (self.gre.bytes_recv, 32)
        self.assertEqual (self.rport.bytes_recv, 32)
        
    def test_rcvdemux (self):
        self.rport = self.gre.create_port (tnode, ROUTINGPROTO)
        self.lport = self.gre.create_port (tnode, LOOPPROTO, False)
        self.postPacket (b"\x00\x00\x60\x03\036\000four score and seven years ago")
        self.assertEqual (self.gre.unk_dest, 0)
        self.assertEqual (self.gre.bytes_recv, 32)
        self.assertEqual (self.lport.bytes_recv, 0)
        self.assertEqual (self.rport.bytes_recv, 32)
        self.postPacket (b"\x00\x00\x90\x00four score and seven years ago")
        self.assertEqual (self.gre.unk_dest, 0)
        self.assertEqual (self.gre.bytes_recv, 62)
        self.assertEqual (self.lport.bytes_recv, 30)
        self.assertEqual (self.rport.bytes_recv, 32)
        self.postPacket (b"\x00\x00\x91\x00four score and seven years ago")
        self.assertEqual (self.gre.unk_dest, 1)
        self.assertEqual (self.gre.bytes_recv, 62)
        self.assertEqual (self.lport.bytes_recv, 30)
        self.assertEqual (self.rport.bytes_recv, 32)

    def test_xmit (self):
        self.rport = self.gre.create_port (tnode, ROUTINGPROTO)
        self.lport = self.gre.create_port (tnode, LOOPPROTO, False)
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
        
if __name__ == "__main__":
    unittest.main ()

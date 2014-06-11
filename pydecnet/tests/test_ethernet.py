#!/usr/bin/env python3

import unittest

import sys
import os
import time
import logging
import unittest.mock

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet import ethernet
from decnet.common import *

logging.trace = unittest.mock.Mock ()
tnode = unittest.mock.Mock ()
tnode.node = tnode

tconfig = unittest.mock.Mock ()
tconfig.device = None
tconfig.random_address = False

packet = None
def wait1 (x, fun):
    time.sleep (0.1)
    global packet
    if packet:
        fun (len (packet), packet, 0)
        packet = None
        
class TestEth (unittest.TestCase):
    def setUp (self):
        self.lpatch = unittest.mock.patch ("decnet.ethernet.logging")
        self.ppatch = unittest.mock.patch ("decnet.ethernet.pcap")
        self.lpatch.start ()
        self.ppatch.start ()
        ethernet.pcap._pcap.error = Exception ("Pcap test error")
        self.pd = ethernet.pcap.pcapObject.return_value.dispatch
        self.pd.return_value = 0
        self.pd.side_effect = wait1
        self.eth = ethernet.Ethernet (tnode, "eth-0", tconfig)
        self.eth.hwaddr = Macaddr ("02-03-04-05-06-07")
        self.eth.open ()
        
    def tearDown (self):
        self.eth.stop (wait = True)
        self.lpatch.stop ()
        self.ppatch.stop ()

    def postPacket (self, pkt):
        global packet
        if len (pkt) < 64:
            pkt += bytes (64 - len (pkt))
        packet = pkt
        for i in range (10):
            time.sleep (0.1)
            if not packet:
                break
        self.assertIsNone (packet, "Packet was not picked up")
        
    def test_rcv1 (self):
        self.rport = self.eth.create_port (tnode, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        self.postPacket (b"\xaa\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03\040\000four score and seven years ago")
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 64)
        self.assertEqual (self.rport.bytes_recv, 64)
        
    def test_rcvdemux (self):
        self.rport = self.eth.create_port (tnode, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        self.lport = self.eth.create_port (tnode, LOOPPROTO, False)
        self.postPacket (b"\xaa\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03\040\000four score and seven years ago")
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 64)
        self.assertEqual (self.lport.bytes_recv, 0)
        self.assertEqual (self.rport.bytes_recv, 64)
        self.postPacket (b"\xaa\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04" \
                         b"\x90\x00\040\000four score and seven years ago")
        self.assertEqual (self.eth.unk_dest, 1)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 64)
        self.assertEqual (self.lport.bytes_recv, 0)
        self.assertEqual (self.rport.bytes_recv, 64)
        self.postPacket (b"\x02\x03\x04\x05\x06\x07\xaa\x00\x04\x00\x2a\x04" \
                         b"\x90\x00\040\000four score and seven years ago")
        self.assertEqual (self.eth.unk_dest, 1)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 128)
        self.assertEqual (self.lport.bytes_recv, 64)
        self.assertEqual (self.rport.bytes_recv, 64)
        
    def test_rcvmc (self):
        self.rport = self.eth.create_port (tnode, ROUTINGPROTO)
        self.rport.add_multicast (Macaddr ("AB-00-00-03-00-00"))
        self.lport = self.eth.create_port (tnode, LOOPPROTO, False)
        self.lport.add_multicast (Macaddr ("CF-00-00-00-00-00"))
        self.postPacket (b"\xab\x00\x00\x03\x00\x00\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03\040\000four score and seven years ago")
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 64)
        self.assertEqual (self.eth.bytes_recv, 64)
        self.assertEqual (self.lport.bytes_recv, 0)
        self.assertEqual (self.rport.bytes_recv, 64)
        self.postPacket (b"\xab\x00\x00\x00\x00\x00\xaa\x00\x04\x00\x2a\x04" \
                         b"\x90\x00\040\000four score and seven years ago")
        self.assertEqual (self.eth.unk_dest, 1)
        self.assertEqual (self.eth.mcbytes_recv, 64)
        self.assertEqual (self.eth.bytes_recv, 64)
        self.assertEqual (self.lport.bytes_recv, 0)
        self.assertEqual (self.rport.bytes_recv, 64)
        self.postPacket (b"\xcf\x00\x00\x00\x00\x00\xaa\x00\x04\x00\x2a\x04" \
                         b"\x90\x00\040\000four score and seven years ago")
        self.assertEqual (self.eth.unk_dest, 1)
        self.assertEqual (self.eth.mcbytes_recv, 128)
        self.assertEqual (self.eth.bytes_recv, 128)
        self.assertEqual (self.lport.bytes_recv, 64)
        self.assertEqual (self.rport.bytes_recv, 64)
        
if __name__ == "__main__":
    unittest.main ()

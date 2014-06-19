#!/usr/bin/env python3

import unittest

import sys
import os
import time
import unittest.mock

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet import ethernet
from decnet.common import *

def trace (fmt, *args):
    print ("trace:", fmt % args)

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
    tdata = b"four score and seven years ago"
    
    def setUp (self):
        self.lpatch = unittest.mock.patch ("decnet.ethernet.logging")
        self.ppatch = unittest.mock.patch ("decnet.ethernet.pcap")
        self.lpatch.start ()
        self.ppatch.start ()
        #ethernet.logging.trace.side_effect = trace
        ethernet.pcap._pcap.error = Exception ("Pcap test error")
        self.pcap = ethernet.pcap.pcapObject.return_value
        self.pd = self.pcap.dispatch
        self.pd.return_value = 0
        self.pd.side_effect = wait1
        self.tnode = unittest.mock.Mock ()
        self.tnode.node = self.tnode
        self.eth = ethernet.Ethernet (self.tnode, "eth-0", tconfig)
        self.eth.hwaddr = Macaddr ("02-03-04-05-06-07")
        self.eth.open ()
        
    def tearDown (self):
        self.eth.close ()
        for i in range (15):
            time.sleep (0.1)
            if not self.eth.is_alive ():
                break
        self.assertFalse (self.eth.is_alive ())
        self.lpatch.stop ()
        self.ppatch.stop ()

    def postPacket (self, pkt):
        global packet
        if len (pkt) < 60:
            pkt += bytes (60 - len (pkt))
        packet = pkt
        for i in range (10):
            time.sleep (0.1)
            if not packet:
                break
        self.assertIsNone (packet, "Packet was not picked up")
        
    def lastwork (self, calls):
        self.assertEqual (self.tnode.addwork.call_count, calls)
        a, k = self.tnode.addwork.call_args
        w = a[0]
        self.assertIsInstance (w, Received)
        return w

    def circ (self):
        c = unittest.mock.Mock ()
        c.parent = self.tnode
        c.node = self.tnode
        return c
    
    def lelen (self, d):
        return len (d).to_bytes (2, "little")

    def pad (self, d):
        if len (d) < 46:
            d += bytes (46 - len (d))
        return d
    
    def test_rcv1 (self):
        rcirc = self.circ ()
        self.rport = self.eth.create_port (rcirc, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        self.postPacket (b"\xaa\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03" + self.lelen (self.tdata) + self.tdata)
        w = self.lastwork (1)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (bytes (w.packet), self.tdata)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 60)
        self.assertEqual (self.rport.bytes_recv, 60)
        
    def test_rcvdemux (self):
        rcirc = self.circ ()
        lcirc = self.circ ()
        self.rport = self.eth.create_port (rcirc, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        self.lport = self.eth.create_port (lcirc, LOOPPROTO, False)
        self.postPacket (b"\xaa\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03" + self.lelen (self.tdata) + self.tdata)
        w = self.lastwork (1)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (bytes (w.packet), self.tdata)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 60)
        self.assertEqual (self.lport.bytes_recv, 0)
        self.assertEqual (self.rport.bytes_recv, 60)
        self.postPacket (b"\xaa\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04" \
                         b"\x90\x00" + self.tdata)
        self.lastwork (1)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 60)
        self.assertEqual (self.lport.bytes_recv, 0)
        self.assertEqual (self.rport.bytes_recv, 60)
        self.postPacket (b"\x02\x03\x04\x05\x06\x07\xaa\x00\x04\x00\x2a\x04" \
                         b"\x90\x00" + self.tdata)
        w = self.lastwork (2)
        self.assertEqual (w.owner, lcirc)
        self.assertEqual (bytes (w.packet), self.pad (self.tdata))
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 120)
        self.assertEqual (self.lport.bytes_recv, 60)
        self.assertEqual (self.rport.bytes_recv, 60)
        
    def test_addrfilter (self):
        rcirc = self.circ ()
        self.rport = self.eth.create_port (rcirc, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        self.postPacket (b"\xaa\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03" + self.lelen (self.tdata) + self.tdata)
        w = self.lastwork (1)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (bytes (w.packet), self.tdata)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 60)
        self.assertEqual (self.rport.bytes_recv, 60)
        # Multicast and mismatch
        self.postPacket (b"\xab\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03" + self.lelen (self.tdata) + self.tdata)
        self.lastwork (1)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 60)
        self.assertEqual (self.rport.bytes_recv, 60)
        # Unicast mismatch (hardware address, but not this port address
        self.postPacket (b"\x02\x03\x04\x05\x06\x07\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03" + self.lelen (self.tdata) + self.tdata)
        self.lastwork (1)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 60)
        self.assertEqual (self.rport.bytes_recv, 60)
        
    def test_promisc (self):
        rcirc = self.circ ()
        self.rport = self.eth.create_port (rcirc, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        self.rport.set_promiscuous (True)
        self.postPacket (b"\xaa\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03" + self.lelen (self.tdata) + self.tdata)
        w = self.lastwork (1)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (bytes (w.packet), self.tdata)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 60)
        self.assertEqual (self.rport.bytes_recv, 60)
        # Multicast and mistmatch
        self.postPacket (b"\xab\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03" + self.lelen (self.tdata) + self.tdata)
        w = self.lastwork (2)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (bytes (w.packet), self.tdata)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv,60)
        self.assertEqual (self.eth.bytes_recv, 120)
        self.assertEqual (self.rport.bytes_recv, 120)
        # Unicast mismatch (hardware address, but not this port address
        self.postPacket (b"\x02\x03\x04\x05\x06\x07\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03" + self.lelen (self.tdata) + self.tdata)
        w = self.lastwork (3)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (bytes (w.packet), self.tdata)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 60)
        self.assertEqual (self.eth.bytes_recv, 180)
        self.assertEqual (self.rport.bytes_recv, 180)
        
    def test_rcvmc (self):
        rcirc = self.circ ()
        lcirc = self.circ ()
        self.rport = self.eth.create_port (rcirc, ROUTINGPROTO)
        self.rport.add_multicast (Macaddr ("AB-00-00-03-00-00"))
        self.lport = self.eth.create_port (lcirc, LOOPPROTO, False)
        self.lport.add_multicast (Macaddr ("CF-00-00-00-00-00"))
        self.postPacket (b"\xab\x00\x00\x03\x00\x00\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03" + self.lelen (self.tdata) + self.tdata)
        w = self.lastwork (1)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (bytes (w.packet), self.tdata)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 60)
        self.assertEqual (self.eth.bytes_recv, 60)
        self.assertEqual (self.lport.bytes_recv, 0)
        self.assertEqual (self.rport.bytes_recv, 60)
        self.postPacket (b"\xab\x00\x00\x00\x00\x00\xaa\x00\x04\x00\x2a\x04" \
                         b"\x90\x00" + self.tdata)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 60)
        self.assertEqual (self.eth.bytes_recv, 60)
        self.assertEqual (self.lport.bytes_recv, 0)
        self.assertEqual (self.rport.bytes_recv, 60)
        self.postPacket (b"\xcf\x00\x00\x00\x00\x00\xaa\x00\x04\x00\x2a\x04" \
                         b"\x90\x00" + self.tdata)
        w = self.lastwork (2)
        self.assertEqual (w.owner, lcirc)
        self.assertEqual (bytes (w.packet), self.pad (self.tdata))
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 120)
        self.assertEqual (self.eth.bytes_recv, 120)
        self.assertEqual (self.lport.bytes_recv, 60)
        self.assertEqual (self.rport.bytes_recv, 60)

    def test_xmit (self):
        self.rport = self.eth.create_port (self.tnode, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        self.lport = self.eth.create_port (self.tnode, LOOPPROTO, False)
        self.rport.send (self.tdata, Macaddr (Nodeid (1, 42)))
        inject = self.pcap.inject.call_args
        self.assertIsNotNone (inject)
        b = bytes (inject[0][0])
        expected = b"\xaa\x00\x04\x00\x2a\x04\xaa\x00\x04\x00\x03\x04" \
                   b"\x60\x03" + self.lelen (self.tdata) + self.tdata
        self.assertEqual (b[:len (expected)], expected)
        self.assertEqual (self.eth.bytes_sent, 46)
        self.assertEqual (self.lport.bytes_sent, 0)
        self.assertEqual (self.rport.bytes_sent, 46)
        self.lport.send (self.tdata, Macaddr (Nodeid (1, 43)))
        inject = self.pcap.inject.call_args
        b = bytes (inject[0][0])
        expected = b"\xaa\x00\x04\x00\x2b\x04\x02\x03\x04\x05\x06\x07" \
                   b"\x90\x00" + self.tdata
        self.assertEqual (b[:len (expected)], expected)
        self.assertEqual (self.eth.bytes_sent, 90)
        self.assertEqual (self.lport.bytes_sent, 44)
        self.assertEqual (self.rport.bytes_sent, 46)
        
if __name__ == "__main__":
    unittest.main ()

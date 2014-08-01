#!/usr/bin/env python3

from tests.dntest import *

from fcntl import *
import queue
import os
import select
import socket
import sys
import struct

from decnet import ethernet

class EthTest (DnTest):
    tdata = b"four score and seven years ago"

    def setUp (self):
        super ().setUp ()
        self.config = container ()
        self.config.device = self.dev
        self.config.random_address = False
        self.eth = ethernet.Ethernet (self.node, "eth-0", self.config)
        self.eth.hwaddr = Macaddr ("02-03-04-05-06-07")
        self.eth.open ()
        
    def tearDown (self):
        self.eth.close ()
        for i in range (15):
            time.sleep (0.1)
            if not self.eth.is_alive ():
                break
        self.assertFalse (self.eth.is_alive ())
        super ().tearDown ()
        
    def circ (self):
        c = unittest.mock.Mock ()
        c.parent = self.node
        c.node = self.node
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
        self.rport = self.eth.create_port (self.node, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        self.lport = self.eth.create_port (self.node, LOOPPROTO, False)
        self.rport.send (self.tdata, Macaddr (Nodeid (1, 42)))
        b = self.lastSent ()
        expected = b"\xaa\x00\x04\x00\x2a\x04\xaa\x00\x04\x00\x03\x04" \
                   b"\x60\x03" + self.lelen (self.tdata) + self.tdata
        self.assertEqual (b[:len (expected)], expected)
        self.assertEqual (self.eth.bytes_sent, 46)
        self.assertEqual (self.lport.bytes_sent, 0)
        self.assertEqual (self.rport.bytes_sent, 46)
        self.lport.send (self.tdata, Macaddr (Nodeid (1, 43)))
        b = self.lastSent ()
        expected = b"\xaa\x00\x04\x00\x2b\x04\x02\x03\x04\x05\x06\x07" \
                   b"\x90\x00" + self.tdata
        self.assertEqual (b[:len (expected)], expected)
        self.assertEqual (self.eth.bytes_sent, 90)
        self.assertEqual (self.lport.bytes_sent, 44)
        self.assertEqual (self.rport.bytes_sent, 46)
        
    def test_randpdu (self):
        rcirc = self.circ ()
        self.rport = self.eth.create_port (rcirc, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        for i in range (100):
            pkt = randpkt (10, 1500)
            self.postPacket (pkt, False)

    def test_randproto (self):
        rcirc = self.circ ()
        self.rport = self.eth.create_port (rcirc, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        hdr = b"\xaa\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04"
        for i in range (100):
            pkt = randpkt (10, 1500)
            self.postPacket (hdr + pkt, False)

    def test_randpkt (self):
        hdr = b"\xaa\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04\x60\x03"
        rcirc = self.circ ()
        self.rport = self.eth.create_port (rcirc, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        for i in range (100):
            pkt = randpkt (10, 1500)
            self.postPacket (hdr + pkt, False)

    def test_randpayload (self):
        hdr = b"\xaa\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04\x60\x03"
        rcirc = self.circ ()
        self.rport = self.eth.create_port (rcirc, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        for i in range (100):
            pkt = randpkt (10, 1498)
            self.postPacket (hdr + self.lelen (pkt) + pkt, False)
        
class TestEthPcap (EthTest):
    dev = "pcap:eth-0"
    
    def setUp (self):
        ethernet.pcap._pcap.error = Exception ("Pcap test error")
        self.ppatch = unittest.mock.patch ("decnet.ethernet.pcap")
        self.ppatch.start ()
        self.pcap = ethernet.pcap.pcapObject.return_value
        self.pd = self.pcap.dispatch
        self.pd.return_value = 0
        self.pd.side_effect = self.pdispatch
        self.pq = queue.Queue ()
        # All is ready, open the Ethernet
        super ().setUp ()
        
    def tearDown (self):
        super ().tearDown ()
        self.ppatch.stop ()
        
    def pdispatch (self, n, fun):
        try:
            pkt = self.pq.get (timeout = 0.1)
            fun (len (pkt), pkt, 0)
            self.pq.task_done ()
            return 1
        except queue.Empty:
            return 0
        
    def postPacket (self, pkt, wait = True):
        if len (pkt) < 60:
            pkt += bytes (60 - len (pkt))
        self.pq.put (pkt)
        self.pq.join ()

    def lastSent (self):
        inject = self.pcap.inject.call_args
        self.assertIsNotNone (inject)
        return bytes (inject[0][0])
        
# It would be nice just to read/write another /dev/tapN interface to do
# these tests, but for that to work there has to be a bridge between
# the two, and we can't count on that.  So instead mock out the relevant
# API calls.
class TestEthTap (EthTest):
    dev = "tap:/dev/tap0"
    
    def setUp (self):
        self.ospatch = unittest.mock.patch ("decnet.ethernet.os")
        self.selpatch = unittest.mock.patch ("decnet.ethernet.select.select")
        self.fpatch = unittest.mock.patch ("decnet.ethernet.fcntl")
        self.syspatch = unittest.mock.patch ("decnet.ethernet.sys")
        self.os = self.ospatch.start ()
        self.selpatch.start ()
        self.fpatch.start ()
        self.sys = self.syspatch.start ()
        self.sys.platform = "testsystem"
        self.pq = queue.Queue ()
        ethernet.select.select.side_effect = self.mselect
        self.os.open.return_value = 42
        self.os.read.side_effect = self.deliver
        # All set, open the interface
        super ().setUp ()

    def tearDown (self):
        super ().tearDown ()
        self.ospatch.stop ()
        self.fpatch.stop ()
        self.selpatch.stop ()
        self.syspatch.stop ()

    def mselect (self, *args):
        try:
            self.pkt = self.pq.get (timeout = 0.1)
            return (True, False, False)
        except queue.Empty:
            return (False, False, False)
            
    def deliver (self, fd, len):
        p = self.pkt
        self.pkt = None
        self.pq.task_done ()
        return p

    def postPacket (self, pkt, wait = True):
        if len (pkt) < 60:
            pkt += bytes (60 - len (pkt))
        self.pq.put (pkt)
        self.pq.join ()
        
    def lastSent (self):
        write = self.os.write.call_args
        self.assertIsNotNone (write)
        return bytes (write[0][1])

class TestEthUdp (EthTest):
    dev = "udp:9999:127.0.0.1:9998"
    
    def setUp (self):
        # First open the Ethernet
        super ().setUp ()
        self.socket = socket.socket (socket.AF_INET, socket.SOCK_DGRAM,
                                     socket.IPPROTO_UDP)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind (("", 9998))
        
    def tearDown (self):
        self.socket.close ()
        super ().tearDown ()
        
    def postPacket (self, pkt, wait = True):
        if len (pkt) < 60:
            pkt += bytes (60 - len (pkt))
        self.socket.sendto (pkt, ("127.0.0.1", 9999))
        if wait:
            time.sleep (0.1)
            
    def lastSent (self):
        b, addr = self.socket.recvfrom (1500)
        self.assertEqual (addr, ("127.0.0.1", 9999))
        return b
    
if __name__ == "__main__":
    unittest.main ()

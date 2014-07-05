#!/usr/bin/env python3

from tests.dntest import *

import queue

from decnet import ethernet

tconfig = unittest.mock.Mock ()
tconfig.device = None
tconfig.random_address = False

class TestEth (DnTest):
    tdata = b"four score and seven years ago"
    
    def setUp (self):
        super ().setUp ()
        self.ppatch = unittest.mock.patch ("decnet.ethernet.pcap")
        self.ppatch.start ()
        ethernet.pcap._pcap.error = Exception ("Pcap test error")
        self.pcap = ethernet.pcap.pcapObject.return_value
        self.pd = self.pcap.dispatch
        self.pd.return_value = 0
        self.pd.side_effect = self.pdispatch
        self.pq = queue.Queue ()
        self.eth = ethernet.Ethernet (self.node, "eth-0", tconfig)
        self.eth.hwaddr = Macaddr ("02-03-04-05-06-07")
        self.eth.open ()
        
    def tearDown (self):
        self.eth.close ()
        for i in range (15):
            time.sleep (0.1)
            if not self.eth.is_alive ():
                break
        self.assertFalse (self.eth.is_alive ())
        self.ppatch.stop ()
        super ().tearDown ()
        
    def pdispatch (self, n, fun):
        try:
            pkt = self.pq.get (timeout = 1)
            fun (len (pkt), pkt, 0)
            self.pq.task_done ()
            return 1
        except queue.Empty:
            return 0
        
    def postPacket (self, pkt):
        if len (pkt) < 60:
            pkt += bytes (60 - len (pkt))
        self.pq.put (pkt)
        self.pq.join ()
        
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
        w = self.lastreceived (1)
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
        w = self.lastreceived (1)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (bytes (w.packet), self.tdata)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 60)
        self.assertEqual (self.lport.bytes_recv, 0)
        self.assertEqual (self.rport.bytes_recv, 60)
        self.postPacket (b"\xaa\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04" \
                         b"\x90\x00" + self.tdata)
        self.lastreceived (1)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 60)
        self.assertEqual (self.lport.bytes_recv, 0)
        self.assertEqual (self.rport.bytes_recv, 60)
        self.postPacket (b"\x02\x03\x04\x05\x06\x07\xaa\x00\x04\x00\x2a\x04" \
                         b"\x90\x00" + self.tdata)
        w = self.lastreceived (2)
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
        w = self.lastreceived (1)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (bytes (w.packet), self.tdata)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 60)
        self.assertEqual (self.rport.bytes_recv, 60)
        # Multicast and mismatch
        self.postPacket (b"\xab\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03" + self.lelen (self.tdata) + self.tdata)
        self.lastreceived (1)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 60)
        self.assertEqual (self.rport.bytes_recv, 60)
        # Unicast mismatch (hardware address, but not this port address
        self.postPacket (b"\x02\x03\x04\x05\x06\x07\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03" + self.lelen (self.tdata) + self.tdata)
        self.lastreceived (1)
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
        w = self.lastreceived (1)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (bytes (w.packet), self.tdata)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv, 0)
        self.assertEqual (self.eth.bytes_recv, 60)
        self.assertEqual (self.rport.bytes_recv, 60)
        # Multicast and mistmatch
        self.postPacket (b"\xab\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03" + self.lelen (self.tdata) + self.tdata)
        w = self.lastreceived (2)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (bytes (w.packet), self.tdata)
        self.assertEqual (self.eth.unk_dest, 0)
        self.assertEqual (self.eth.mcbytes_recv,60)
        self.assertEqual (self.eth.bytes_recv, 120)
        self.assertEqual (self.rport.bytes_recv, 120)
        # Unicast mismatch (hardware address, but not this port address
        self.postPacket (b"\x02\x03\x04\x05\x06\x07\xaa\x00\x04\x00\x2a\x04" \
                         b"\x60\x03" + self.lelen (self.tdata) + self.tdata)
        w = self.lastreceived (3)
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
        w = self.lastreceived (1)
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
        w = self.lastreceived (2)
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
        
    def test_randpdu (self):
        rcirc = self.circ ()
        self.rport = self.eth.create_port (rcirc, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        for i in range (100):
            pkt = randpkt (10, 1500)
            self.postPacket (pkt)

    def test_randproto (self):
        rcirc = self.circ ()
        self.rport = self.eth.create_port (rcirc, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        hdr = b"\xaa\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04"
        for i in range (100):
            pkt = randpkt (10, 1500)
            self.postPacket (hdr + pkt)

    def test_randpkt (self):
        hdr = b"\xaa\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04\x60\x03"
        rcirc = self.circ ()
        self.rport = self.eth.create_port (rcirc, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        for i in range (100):
            pkt = randpkt (10, 1500)
            self.postPacket (hdr + pkt)

    def test_randpayload (self):
        hdr = b"\xaa\x00\x04\x00\x03\x04\xaa\x00\x04\x00\x2a\x04\x60\x03"
        rcirc = self.circ ()
        self.rport = self.eth.create_port (rcirc, ROUTINGPROTO)
        self.rport.set_macaddr (Macaddr (Nodeid (1, 3)))
        for i in range (100):
            pkt = randpkt (10, 1498)
            self.postPacket (hdr + self.lelen (pkt) + pkt)
        
if __name__ == "__main__":
    unittest.main ()

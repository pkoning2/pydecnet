#!/usr/bin/env python3

from tests.dntest import *

import os

from decnet import gre
from decnet import config
from decnet.host import LocalAddresses

local4 = [ a for a in LocalAddresses if "." in a ]
local6 = [ a for a in LocalAddresses if ":" in a and
                                        not a.startswith ("fe80") ]

def setUpModule ():
    if os.getuid () != 0:
        raise unittest.SkipTest ("GRE tests must be run as root")
    if len (local4) < 2:
        raise unittest.SkipTest ("GRE tests require two local IPv4 addresses")
    
class GreTest (DnTest):
    # Base class for GRE tests.
    tdata = b"four score and seven years ago"
    
    def tearDown (self):
        self.gre.close ()
        self.tsock.close ()
        for i in range (15):
            time.sleep (0.1)
            if not self.gre.is_alive ():
                break
        self.assertFalse (self.gre.is_alive ())
        super ().tearDown ()
        
    def circ (self):
        c = unittest.mock.Mock ()
        c.parent = self.node
        c.node = self.node
        return c
    
    def postPacket (self, pkt):
        self.tsock.sendto (pkt, self.uaddr)

    def expect (self):
        msg, addr = self.tsock.recvfrom (1504)
        # Skip past the IP header, if IP4. 
        if self.skipIpHdr:
            ver, hlen = divmod (msg[0], 16)
            if ver == 4:
                pos = 4 * hlen
            else:
                self.fail ("Unknown header version {}".format (ver))
        else:
            pos = 0
        msg = msg[pos:]
        return msg, addr

    def lelen (self, d):
        return len (d).to_bytes (2, "little")

    def test_rcv1 (self):
        rcirc = self.circ ()
        self.rport = self.gre.create_port (rcirc, ROUTINGPROTO)
        self.postPacket (b"\x00\x00\x60\x03" +
                         self.lelen (self.tdata) + self.tdata)
        time.sleep (0.1)
        w = self.lastdispatch (1, rcirc, itype = Received)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (w.packet, self.tdata)
        self.assertEqual (self.gre.counters.unk_dest, 0)
        self.assertEqual (self.gre.counters.bytes_recv, 32)
        self.assertEqual (self.rport.counters.bytes_recv, 32)
        
    def test_rcvdemux (self):
        rcirc = self.circ ()
        lcirc = self.circ ()
        self.rport = self.gre.create_port (rcirc, ROUTINGPROTO)
        self.lport = self.gre.create_port (lcirc, LOOPPROTO, False)
        self.postPacket (b"\x00\x00\x60\x03" +
                         self.lelen (self.tdata) + self.tdata)
        time.sleep (0.1)
        w = self.lastdispatch (1, rcirc, itype = Received)
        self.assertEqual (w.owner, rcirc)
        self.assertEqual (w.packet, self.tdata)
        self.assertEqual (self.gre.counters.unk_dest, 0)
        self.assertEqual (self.gre.counters.bytes_recv, 32)
        self.assertEqual (self.lport.counters.bytes_recv, 0)
        self.assertEqual (self.rport.counters.bytes_recv, 32)
        self.postPacket (b"\x00\x00\x90\x00" + self.tdata)
        time.sleep (0.1)
        w = self.lastdispatch (1, lcirc, itype = Received)
        self.assertEqual (w.owner, lcirc)
        self.assertEqual (w.packet, self.tdata)
        self.assertEqual (self.gre.counters.unk_dest, 0)
        self.assertEqual (self.gre.counters.bytes_recv, 62)
        self.assertEqual (self.lport.counters.bytes_recv, 30)
        self.assertEqual (self.rport.counters.bytes_recv, 32)
        self.postPacket (b"\x00\x00\x91\x00" + self.tdata)
        time.sleep (0.1)
        self.lastdispatch (1, lcirc, itype = Received)   # Check that nothing new is posted
        if self.gre.counters.unk_dest != 1:
            time.sleep (0.1)
        self.assertEqual (self.gre.counters.unk_dest, 1)
        self.assertEqual (self.gre.counters.bytes_recv, 62)
        self.assertEqual (self.lport.counters.bytes_recv, 30)
        self.assertEqual (self.rport.counters.bytes_recv, 32)

    def test_xmit (self):
        self.rport = self.gre.create_port (self.node, ROUTINGPROTO)
        self.lport = self.gre.create_port (self.node, LOOPPROTO, False)
        self.rport.send (b"four score and seven years ago", None)
        data = self.expect ()
        self.assertIsNotNone (data)
        b, addr = data
        b = bytes (b)
        expected = b"\x00\x00\x60\x03\x1e\x00four score and seven years ago"
        self.assertEqual (addr, self.raddr)
        self.assertEqual (b[:len (expected)], expected)
        self.assertEqual (self.gre.counters.bytes_sent, 36)
        self.assertEqual (self.lport.counters.bytes_sent, 0)
        self.assertEqual (self.rport.counters.bytes_sent, 36)
        self.lport.send (b"four score and seven years ago", None)
        data = self.expect ()
        b, addr = data
        b = bytes (b)
        expected = b"\x00\x00\x90\x00four score and seven years ago"
        self.assertEqual (addr, self.raddr)
        self.assertEqual (b[:len (expected)], expected)
        self.assertEqual (self.gre.counters.bytes_sent, 70)
        self.assertEqual (self.lport.counters.bytes_sent, 34)
        self.assertEqual (self.rport.counters.bytes_sent, 36)

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

class TestGre4 (GreTest):
    skipIpHdr = True
    
    def setUp (self):
        super ().setUp ()
        # We can't simply use 127.0.0.1 as the address of both ends,
        # because there is only a single protocol number, not source
        # and destination side as for UDP or TCP.  But if the host has
        # more than one local address, as is normal, then we can use
        # two of them.  This works because IP knows that any
        # communication between its local addresses is local; it isn't
        # necessary to use the address of the loopback interface for
        # both end points.
        self.uaddr = (local4[1], gre.GREPROTO)
        # For some reason it arrives in recvfrom with 0 in the second
        # element.
        self.raddr = (local4[1], 0)
        self.tsock = socket.socket (socket.AF_INET, socket.SOCK_RAW,
                                    gre.GREPROTO)
        self.tsock.bind ((local4[0], 0))
        spec = "circuit gre-0 GRE --destination {} --source {}".format (local4[0], local4[1])
        tconfig = self.config (spec)
        self.gre = gre.GRE (self.node, "gre-0", tconfig)
        self.gre.open ()
        
@unittest.skipIf (len (local6) < 2,
                  "GRE IPv6 test requires two local IPv6 addresses")
class TestGre6 (GreTest):
    skipIpHdr = False
    
    def setUp (self):
        super ().setUp ()
        self.uaddr = (local6[1], gre.GREPROTO)
        # For some reason it arrives in recvfrom with 0 in the second
        # element.
        self.raddr = (local6[1], 0, 0, 0)
        self.tsock = socket.socket (socket.AF_INET6, socket.SOCK_RAW,
                                    gre.GREPROTO)
        self.tsock.bind ((local6[0], 0))
        spec = "circuit gre-0 GRE --destination {} --source {}".format (local6[0], local6[1])
        tconfig = self.config (spec)
        self.gre = gre.GRE (self.node, "gre-0", tconfig)
        self.gre.open ()
    
if __name__ == "__main__":
    unittest.main ()

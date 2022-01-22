#!/usr/bin/env python3

"DDCMP tests"

import socket
import select
import os

from tests.dntest import *
from decnet import datalink
from decnet import ddcmp

SYN4 = bytes ([ ddcmp.SYN ] * 4)

class TestPackets (DnTest):
    def test_start (self):
        "DDCMP Start packet"
        b = b"\x05\x06\xc0\x00\x00\x01\x75\x95"
        start, b1 = ddcmp.DMHdr.decode (b)
        self.assertEqual (b1, b"")
        self.assertIsInstance (start, ddcmp.StartMsg)
        b2 = start.encode ()
        self.assertEqual (b, b2)

    def test_start2 (self):
        "Start packet with address 2 (should be accepted)"
        b = b"\x05\x06\xc0\x00\x00\x02\x35\x94"
        start, b1 = ddcmp.DMHdr.decode (b)
        self.assertEqual (b1, b"")
        self.assertIsInstance (start, ddcmp.StartMsg)
        # When encoding the address is forced to 1
        b1 = b"\x05\x06\xc0\x00\x00\x01\x75\x95"
        b2 = start.encode ()
        self.assertEqual (b1, b2)

    def test_stack (self):
        "DDCMP Start Ack packet"
        b = b"\x05\x07\xc0\x00\x00\x01\x48\x55"
        stack, b1 = ddcmp.DMHdr.decode (b)
        self.assertEqual (b1, b"")
        self.assertIsInstance (stack, ddcmp.StackMsg)
        b2 = stack.encode ()
        self.assertEqual (b, b2)
        
    def test_ack (self):
        "DDCMP Ack packet"
        b = b"\x05\x01\x00\x00\x00\x01\xfc\x55"
        ack, b1 = ddcmp.DMHdr.decode (b)
        self.assertEqual (b1, b"")
        self.assertIsInstance (ack, ddcmp.AckMsg)
        self.assertEqual (ack.resp, 0)
        self.assertEqual (ack.addr, 1)
        b2 = ack.encode ()
        self.assertEqual (b, b2)

    def test_nak (self):
        "DDCMP NAK packet"
        b = b"\x05\x02\x03\x01\x00\x01\xe9\xd1"
        nak, b1 = ddcmp.DMHdr.decode (b)
        self.assertEqual (b1, b"")
        self.assertIsInstance (nak, ddcmp.NakMsg)
        self.assertEqual (nak.subtype, 3)
        self.assertEqual (nak.resp, 1)
        self.assertEqual (nak.addr, 1)
        b2 = nak.encode ()
        self.assertEqual (b, b2)

    def test_rep (self):
        "DDCMP Rep packet"
        b = b"\x05\x03\x00\x00\x01\x01\x84\x05"
        rep, b1 = ddcmp.DMHdr.decode (b)
        self.assertEqual (b1, b"")
        self.assertIsInstance (rep, ddcmp.RepMsg)
        self.assertEqual (rep.num, 1)
        self.assertEqual (rep.addr, 1)
        b2 = rep.encode ()
        self.assertEqual (b, b2)

    def test_data (self):
        "DDCMP normal data packet"
        b = b"\x81\x0c\x00\x00\x01\x01\xce\x40\x01\x01\xa4\x01" \
            b"\x40\x02\x02\x00\x00\x3c\x00\x00\x55\xe6"
        data, b1 = ddcmp.DMHdr.decode (b)
        self.assertEqual (b1, b"")
        self.assertIsInstance (data, ddcmp.DataMsg)
        self.assertEqual (data.resp, 0)
        self.assertEqual (data.num, 1)
        self.assertEqual (data.payload, b"\x01\x01\xa4\x01\x40\x02\x02\x00\x00\x3c\x00\x00")
        b2 = data.encode ()
        self.assertEqual (b, b2)
            
class DDCMPbase (DnTest):
    # Default DDCMP QMax is 7, but we use 2 for most tests
    qmax = 2
    
    def setUp (self):
        super ().setUp ()
        self.tconfig.qmax = self.qmax
        self.dmc = ddcmp.DDCMP (self.node, "dmc-0", self.tconfig)
        self.rport = self.dmc.create_port (self.node)
        self.node.enable_dispatcher ()

    def start1 (self, count = 1):
        "DDCMP startup where we do the reply (STACK message)"
        # Await first message, it should be DDCMP START
        b = self.receivedata ()
        start = b"\x05\x06\xc0\x00\x00\x01\x75\x95"
        self.assertEqual (b, start)
        # Pretend we didn't hear it; timeout should produce another.
        DnTimeout (self.rport.parent)
        b = self.receivedata ()
        self.assertEqual (b, start)
        # Now reply with STACK
        self.sendpdu (b"\x05\x07\xc0\x00\x00\x01\x48\x55")
        # Next should be ACK (or DATA, but we don't do that)
        b = self.receivedata ()
        ack = b"\x05\x01\x00\x00\x00\x01\xfc\x55"
        self.assertEqual (b, ack)
        self.assertUp (count)
        # No timer running now
        self.assertFalse (self.rport.parent.islinked ())
        
    def start2 (self, ack = True):
        "DDCMP startup where we send a START"
        # Await first message, it should be DDCMP START
        b = self.receivedata ()
        start = b"\x05\x06\xc0\x00\x00\x01\x75\x95"
        self.assertEqual (b, start)
        # We send a start
        self.sendpdu (start)
        # Reply should be STACK
        stack = b"\x05\x07\xc0\x00\x00\x01\x48\x55"
        b = self.receivedata ()
        self.assertEqual (b, stack)
        # Pretend we didn't hear it; timeout should produce another.
        DnTimeout (self.rport.parent)
        b = self.receivedata ()
        self.assertEqual (b, stack)
        if ack:
            # Now reply with Ack (Resp=0)
            self.sendpdu (b"\x05\x01\x00\x00\x00\x01\xfc\x55")
            time.sleep (0.1)
            self.assertUp ()
            # No timer running now
            self.assertFalse (self.rport.parent.islinked ())
        else:
            self.assertTrue (self.rport.parent.islinked ())

    def start3 (self):
        "DDCMP startup where both sides run the handshake (cross over)"
        # Await first message, it should be DDCMP START
        b = self.receivedata ()
        start = b"\x05\x06\xc0\x00\x00\x01\x75\x95"
        self.assertEqual (b, start)
        # We send a START
        self.sendpdu (start)
        # ... immediately followed by a STACK
        stack = b"\x05\x07\xc0\x00\x00\x01\x48\x55"
        self.sendpdu (stack)
        # Next we should receive a STACK
        b = self.receivedata ()
        self.assertEqual (b, stack)
        # Now reply with Ack (Resp=0)
        ack = b"\x05\x01\x00\x00\x00\x01\xfc\x55"
        self.sendpdu (ack)
        # We should receive an Ack to the STACK we sent
        b = self.receivedata ()
        self.assertEqual (b, ack)
        # After all that the state should be UP
        self.assertUp ()
        # No timer running now
        self.assertFalse (self.rport.parent.islinked ())
        
    def tearDown (self):
        thread = self.dmc.rthread
        self.rport.close ()
        if thread:
            for i in range (15):
                time.sleep (0.1)
                if not thread.is_alive ():
                    break
            self.assertFalse (thread.is_alive (), "Thread failed to exit")
        self.dmc.close ()
        super ().tearDown ()

    def pdu (self, num, sdu, resp = 0):
        return bytes (ddcmp.DataMsg (num = num, resp = resp, payload = sdu))
                          
    def data_ready (self, t = 1):
        sellist = [ self.socket.fileno () ]
        r, w, e = select.select (sellist, [ ], sellist, t)
        return bool (r) and not e
    
    def receivedata (self):
        self.assertTrue (self.data_ready (), "Data ready timeout")
        b = self.receivepdu ()
        return b

class CommonTests:
    def test_xmit (self):
        self.start1 ()
        # Note that data sequence numbers start with 1.
        expected = self.pdu (1, testsdu ())
        self.rport.send (testsdu (), None)
        b = self.receivedata ()
        self.assertEqual (b, expected)
        self.assertEqual (self.dmc.counters.bytes_sent, len (testsdu ()))
        self.assertEqual (self.dmc.counters.pkts_sent, 1)
        # Reply with a data packet that ACKs this one
        b = self.pdu (1, testsdu (), resp = 1)
        self.sendpdu (b)
        # Response should be an ACK for that
        b = self.receivedata ()
        expected = bytes (ddcmp.AckMsg (resp = 1))
        self.assertEqual (b, expected)
        # SDU should be sent up
        w = self.lastdispatch (2, itype = Received)
        b = w.packet
        self.assertEqual (b, testsdu ())
        self.assertEqual (self.dmc.counters.bytes_recv, 30)
        self.assertEqual (self.dmc.counters.pkts_recv, 1)
        # Send another
        expected = self.pdu (2, testsdu (), resp = 1)
        self.rport.send (testsdu (), None)
        b = self.receivedata ()
        self.assertEqual (b, expected)
        self.assertEqual (self.dmc.counters.bytes_sent, 2 * len (testsdu ()))
        self.assertEqual (self.dmc.counters.pkts_sent, 2)
        # Generate an ACK timeout
        DnTimeout (self.rport.parent)
        b = self.receivedata ()
        # We're expecting Rep 2
        expected_rep = b"\x05\x03\x00\x00\x02\x01\x84\xf5"
        self.assertEqual (b, expected_rep)
        # Send a NAK 1, Rep response
        self.sendpdu (b"\x05\x02\x03\x01\x00\x01\xe9\xd1")
        # The second packet should be retransmitted
        b = self.receivedata ()
        self.assertEqual (b, expected)
        self.assertEqual (self.dmc.counters.bytes_sent, 2 * len (testsdu ()))
        self.assertEqual (self.dmc.counters.pkts_sent, 2)
        # Ack it
        self.sendpdu (bytes (ddcmp.AckMsg (resp = 2)))
        time.sleep (0.1)
        # No timer running now
        self.assertFalse (self.rport.parent.islinked ())
        
    def test_rcv1 (self, ack = True):
        "Receive inbound message"
        self.start2 (ack)
        pdu = self.pdu (1, testsdu ())
        self.sendpdu (pdu)
        time.sleep (0.1)
        if not ack:
            # There should be two dispatches as a result of the data
            # message, the first of which is the Up
            w = self.lastdispatch (2, itype = datalink.DlStatus, back = 1)
            self.assertEqual (w.status, w.UP)
        w = self.lastdispatch (2, itype = Received)
        b = w.packet
        self.assertEqual (b, testsdu ())
        self.assertEqual (self.dmc.counters.bytes_recv, 30)
        self.assertEqual (self.dmc.counters.pkts_recv, 1)
        # We should get an Ack back
        expected_ack = b"\x05\x01\x00\x01\x00\x01\xad\x95"
        b = self.receivedata ()
        self.assertEqual (b, expected_ack)
        # Pretend we didn't hear it
        rep = b"\x05\x03\x00\x00\x01\x01\x84\x05"
        self.sendpdu (rep)
        # That should resend the Ack
        b = self.receivedata ()
        self.assertEqual (b, expected_ack)
        # No timer running now
        self.assertFalse (self.rport.parent.islinked ())

    def test_rcv2 (self):
        "Receive inbound message that also Acks the STACK"
        self.test_rcv1 (False)

    def test_restart_remote (self):
        "Test handling of remote protocol restart"
        self.start3 ()
        # DDCMP is up, now take it down with a START in run state
        start = b"\x05\x06\xc0\x00\x00\x01\x75\x95"
        self.sendpdu (start)
        time.sleep (0.1)
        # Datalink should report DOWN
        w = self.lastdispatch (2, itype = datalink.DlStatus)
        self.assertEqual (w.status, w.DOWN)
        # Await first message, it should be DDCMP START
        b = self.receivedata ()
        self.assertEqual (b, start)
        # Now reply with STACK
        self.sendpdu (b"\x05\x07\xc0\x00\x00\x01\x48\x55")
        # Next should be ACK (or DATA, but we don't do that)
        b = self.receivedata ()
        ack = b"\x05\x01\x00\x00\x00\x01\xfc\x55"
        self.assertEqual (b, ack)
        self.assertUp (3)
        # No timer running now
        self.assertFalse (self.rport.parent.islinked ())

    def test_restart_local (self):
        "Test handling of local protocol restart"
        self.start1 ()
        # DDCMP is up, send a data message
        pdu = self.pdu (1, testsdu ())
        self.sendpdu (pdu)
        time.sleep (0.1)
        w = self.lastdispatch (2, itype = Received)
        b = w.packet
        self.assertEqual (b, testsdu ())
        self.assertEqual (self.dmc.counters.bytes_recv, 30)
        self.assertEqual (self.dmc.counters.pkts_recv, 1)
        # We should get an Ack back
        expected_ack = b"\x05\x01\x00\x01\x00\x01\xad\x95"
        b = self.receivedata ()
        self.assertEqual (b, expected_ack)
        # Now take it down with a restart request
        self.rport.restart ()
        # Await first message, it should be DDCMP START
        b = self.receivedata ()
        start = b"\x05\x06\xc0\x00\x00\x01\x75\x95"
        self.assertEqual (b, start)
        # Now reply with STACK
        self.sendpdu (b"\x05\x07\xc0\x00\x00\x01\x48\x55")
        # Next should be ACK (or DATA, but we don't do that)
        b = self.receivedata ()
        ack = b"\x05\x01\x00\x00\x00\x01\xfc\x55"
        self.assertEqual (b, ack)
        self.assertUp (4)
        # No timer running now
        self.assertFalse (self.rport.parent.islinked ())

    def test_maint1 (self):
        "Enter maintenance mode from starting state"
        # Await first message, it should be DDCMP START
        b = self.receivedata ()
        start = b"\x05\x06\xc0\x00\x00\x01\x75\x95"
        self.assertEqual (b, start)
        # Send a Maintenance message
        maint = bytes (ddcmp.MaintMsg (payload = testsdu ()))
        self.sendpdu (maint)
        time.sleep (0.1)
        # No timer running now
        self.assertFalse (self.rport.parent.islinked ())
        # TODO: verify delivery to maintenance port, once we have one.
        #
        # Send another maintenance mode message
        maint = bytes (ddcmp.MaintMsg (payload = b"Another message"))
        self.sendpdu (maint)
        time.sleep (0.1)        
        # Restart
        self.sendpdu (start)
        self.start1 ()
        
    def test_maint2 (self):
        "Enter maintenance mode from AStart state"
        # Send START but not the ACK
        self.start2 (False)
        # Send a Maintenance message
        maint = bytes (ddcmp.MaintMsg (payload = testsdu ()))
        self.sendpdu (maint)
        time.sleep (0.1)
        # No timer running now
        self.assertFalse (self.rport.parent.islinked ())
        # Restart
        start = b"\x05\x06\xc0\x00\x00\x01\x75\x95"
        self.sendpdu (start)
        self.start1 ()

    def test_maint3 (self):
        "Enter maintenance mode from Running state"
        self.start1 ()
        # Send a Maintenance message
        maint = bytes (ddcmp.MaintMsg (payload = testsdu ()))
        self.sendpdu (maint)
        time.sleep (0.1)
        # Datalink should report DOWN
        w = self.lastdispatch (2, itype = datalink.DlStatus)
        self.assertEqual (w.status, w.DOWN)
        # No timer running now
        self.assertFalse (self.rport.parent.islinked ())
        # Restart
        start = b"\x05\x06\xc0\x00\x00\x01\x75\x95"
        self.sendpdu (start)
        self.start1 (3)

    def test_data_crcerr (self):
        "Test CRC error handling and recovery"
        self.start1 ()
        pdu = self.pdu (1, testsdu ())
        # Send a packet with a byte missing
        badpdu = pdu [:15] + pdu [16:]
        self.sendpdu (badpdu)
        time.sleep (0.1)
        # We should get an NAK back, saying "CRC error"
        expected_nak = bytes (ddcmp.NakMsg (resp = 0, subtype = 2))
        b = self.receivedata ()
        self.assertEqual (b, expected_nak)
        self.assertEqual (self.dmc.counters.bytes_recv, 0)
        self.assertEqual (self.dmc.counters.pkts_recv, 0)
        self.assertEqual (self.dmc.counters.data_errors_inbound, 1)
        self.assertEqual (self.dmc.counters.data_errors_inbound.map, 2)
        # Send a packet with a data byte corrupted
        badpdu = bytearray (pdu)
        badpdu[-5] ^= 1
        self.sendpdu (badpdu)
        time.sleep (0.1)
        # We should get an NAK back, saying "CRC error"
        b = self.receivedata ()
        self.assertEqual (b, expected_nak)
        self.assertEqual (self.dmc.counters.bytes_recv, 0)
        self.assertEqual (self.dmc.counters.pkts_recv, 0)
        self.assertEqual (self.dmc.counters.data_errors_inbound, 2)
        self.assertEqual (self.dmc.counters.data_errors_inbound.map, 2)
        # Now send a good packet
        self.sendpdu (pdu)
        time.sleep (0.1)
        w = self.lastdispatch (2, itype = Received)
        b = w.packet
        self.assertEqual (b, testsdu ())
        self.assertEqual (self.dmc.counters.bytes_recv, 30)
        self.assertEqual (self.dmc.counters.pkts_recv, 1)
        # We should get an Ack back
        expected_ack = b"\x05\x01\x00\x01\x00\x01\xad\x95"
        b = self.receivedata ()
        self.assertEqual (b, expected_ack)
        
    def test_hdr_crcerr (self):
        "Test header CRC error handling and recovery"
        self.start1 ()
        pdu = self.pdu (1, testsdu ())
        # Send a packet with a byte missing in the header
        badpdu = pdu [:6] + pdu [7:]
        self.sendpdu (badpdu)
        time.sleep (0.1)
        # We should get an NAK back, saying "Header CRC error"
        expected_nak = bytes (ddcmp.NakMsg (resp = 0, subtype = 1))
        b = self.receivedata ()
        self.assertEqual (b, expected_nak)
        self.assertEqual (self.dmc.counters.bytes_recv, 0)
        self.assertEqual (self.dmc.counters.pkts_recv, 0)
        self.assertEqual (self.dmc.counters.data_errors_inbound, 1)
        self.assertEqual (self.dmc.counters.data_errors_inbound.map, 1)
        # The previous error sets "out of sync" for the TCP case, so
        # send a valid packet that doesn't produce a response to get
        # back in sync.  An Ack will do.
        self.sendpdu (b"\x05\x01\x00\x00\x00\x01\xfc\x55")
        # Send a packet with a data byte corrupted
        badpdu = bytearray (pdu)
        badpdu[6] ^= 1
        self.sendpdu (badpdu)
        time.sleep (0.1)
        # We should get an NAK back, saying "Header CRC error"
        b = self.receivedata ()
        self.assertEqual (b, expected_nak)
        self.assertEqual (self.dmc.counters.bytes_recv, 0)
        self.assertEqual (self.dmc.counters.pkts_recv, 0)
        self.assertEqual (self.dmc.counters.data_errors_inbound, 2)
        self.assertEqual (self.dmc.counters.data_errors_inbound.map, 1)
        # Now send a good packet
        self.sendpdu (pdu)
        time.sleep (0.1)
        w = self.lastdispatch (2, itype = Received)
        b = w.packet
        self.assertEqual (b, testsdu ())
        self.assertEqual (self.dmc.counters.bytes_recv, 30)
        self.assertEqual (self.dmc.counters.pkts_recv, 1)
        # We should get an Ack back
        expected_ack = b"\x05\x01\x00\x01\x00\x01\xad\x95"
        b = self.receivedata ()
        self.assertEqual (b, expected_ack)

    def test_random1 (self):
        "Test with random blocks of bytes"
        for p in range (1000):
            pkt = randpkt (1, 100)
            self.sendpdu (pkt)

    def test_random2 (self):
        "Test with headers containing random garbage but good CRC"
        for p in range (1000):
            pkt = byte (ddcmp.ENQ) + randpkt (5, 5)
            pkt += bytes (ddcmp.CRC16 (pkt))
            self.sendpdu (pkt)

    def test_random3 (self):
        "Tests with random blocks of bytes, in running state"
        self.start1 ()
        self.test_random1 ()
        
    def test_random4 (self):
        "Tests with headers containing random bytes, in running state"
        self.start1 ()
        self.test_random2 ()
        
    def test_maxq_2 (self):
        "Test maxq handling (standard case, qmax of 2"
        assert self.rport.parent.qmax == 2
        self.start1 ()
        # Issue 7 send requests
        for n in range (7):
            self.rport.send (testsdu (n), None)
        # We should get exactly 2 data messages, since that's the
        # queue max value.
        p, b = ddcmp.DMHdr.decode (self.receivedata ())
        self.assertEqual (p.payload, testsdu (0))
        p, b = ddcmp.DMHdr.decode (self.receivedata ())
        self.assertEqual (p.payload, testsdu (1))
        self.assertEqual (self.dmc.counters.pkts_sent, 2)
        # Invalid ACK and NAK should be ignored entirely
        self.sendpdu (ddcmp.AckMsg (resp = 3))
        self.sendpdu (ddcmp.NakMsg (resp = 3, subtype = 3))
        self.assertEqual (self.dmc.counters.pkts_sent, 2)
        # Ack the first message.  We should get one more.
        self.sendpdu (ddcmp.AckMsg (resp = 1))
        p, b = ddcmp.DMHdr.decode (self.receivedata ())
        self.assertEqual (p.payload, testsdu (2))
        self.assertEqual (self.dmc.counters.pkts_sent, 3)
        # Do a timeout.
        DnTimeout (self.rport.parent)
        p, b = ddcmp.DMHdr.decode (self.receivedata ())
        self.assertIsInstance (p, ddcmp.RepMsg)
        self.assertEqual (p.num, 3)
        # NAK the second message.  That permits the fourth to be sent,
        # but in addition the third should be retransmitted.
        self.sendpdu (ddcmp.NakMsg (resp = 2))
        p, b = ddcmp.DMHdr.decode (self.receivedata ())
        self.assertEqual (p.payload, testsdu (2))
        p, b = ddcmp.DMHdr.decode (self.receivedata ())
        self.assertEqual (p.payload, testsdu (3))
        self.assertEqual (self.dmc.counters.pkts_sent, 4)
        # ACK the fourth message.  We'll get 5 and 6.
        self.sendpdu (ddcmp.AckMsg (resp = 4))
        p, b = ddcmp.DMHdr.decode (self.receivedata ())
        self.assertEqual (p.payload, testsdu (4))
        p, b = ddcmp.DMHdr.decode (self.receivedata ())
        self.assertEqual (p.payload, testsdu (5))
        self.assertEqual (self.dmc.counters.pkts_sent, 6)
        # Ack the sixth.  We'll get message 7.
        self.sendpdu (ddcmp.AckMsg (resp = 6))
        p, b = ddcmp.DMHdr.decode (self.receivedata ())
        self.assertEqual (p.payload, testsdu (6))
        self.assertEqual (self.dmc.counters.pkts_sent, 7)
        # Ack that last one
        self.sendpdu (ddcmp.AckMsg (resp = 7))
        time.sleep (0.1)
        self.assertFalse (self.rport.parent.islinked ())
        
class Qmax255:
    qmax = 255
    def test_maxq_255 (self):
        "Test qmax of 255 (max possible)"
        assert self.rport.parent.qmax == 255
        self.start1 ()
        # Issue 300 send requests
        for n in range (300):
            self.rport.send (testsdu (n), None)
        # We should get exactly 255 data messages, since that's the
        # queue max value.
        for n in range (255):
            p, b = ddcmp.DMHdr.decode (self.receivedata ())
            self.assertEqual (p.payload, testsdu (n))
        self.assertEqual (self.dmc.counters.pkts_sent, 255)
        # Do a timeout.
        DnTimeout (self.rport.parent)
        p, b = ddcmp.DMHdr.decode (self.receivedata ())
        self.assertIsInstance (p, ddcmp.RepMsg)
        self.assertEqual (p.num, 255)
        # Ack the first message.  We should get one more.
        self.sendpdu (ddcmp.AckMsg (resp = 1))
        p, b = ddcmp.DMHdr.decode (self.receivedata ())
        self.assertEqual (p.payload, testsdu (255))
        self.assertEqual (self.dmc.counters.pkts_sent, 256)
        # Do a timeout again
        DnTimeout (self.rport.parent)
        p, b = ddcmp.DMHdr.decode (self.receivedata ())
        self.assertIsInstance (p, ddcmp.RepMsg)
        self.assertEqual (p.num, 0)
        # NAK the second message.  That permits one more to be sent,
        # but in addition the 254 we did not ACK will be
        # retransmitted.  All at once...  Ouch.
        self.sendpdu (ddcmp.NakMsg (resp = 2))
        for n in range (255):
            p, b = ddcmp.DMHdr.decode (self.receivedata ())
            self.assertEqual (p.payload, testsdu (n + 2))
        self.assertEqual (self.dmc.counters.pkts_sent, 257)
        # ACK message 200.  We'll get the rest.
        self.sendpdu (ddcmp.AckMsg (resp = 200))
        for n in range (300 - 258):
            p, b = ddcmp.DMHdr.decode (self.receivedata ())
            self.assertEqual (p.payload, testsdu (n + 257))
        self.assertEqual (self.dmc.counters.pkts_sent, 300)
        # ACK message 300.
        self.sendpdu (ddcmp.AckMsg (resp = 300 % 256))
        time.sleep (0.1)
        self.assertFalse (self.rport.parent.islinked ())
    
class DdcmpUdp (DDCMPbase):
    def setUp (self):
        self.lport = nextport ()
        self.cport = nextport ()
        # UDP mode
        spec = "circuit dmc-0 DDCMP udp:{}:127.0.0.1:{}".format (self.lport,
                                                                 self.cport)
        self.tconfig = self.config (spec)
        super ().setUp ()
        # Verify the mapping from old format to new
        self.assertEqual (self.tconfig.mode, "udp")
        self.assertEqual (self.tconfig.destination, "127.0.0.1")
        self.assertEqual (self.tconfig.dest_port, self.cport)
        self.assertEqual (self.tconfig.source_port, self.lport)
        self.socket = socket.socket (socket.AF_INET, socket.SOCK_DGRAM,
                                     socket.IPPROTO_UDP)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind (("", self.cport))
        self.rport.open ()

    def tearDown (self):
        self.socket.close ()
        super ().tearDown ()

    def receivepdu (self):
        b, addr = self.socket.recvfrom (1500)
        self.assertEqual (addr, ("127.0.0.1", self.lport))
        return b
    
    def sendpdu (self, pdu):
        self.socket.sendto (makebytes (pdu), ("127.0.0.1", self.lport))

class TestDdcmpUdp (DdcmpUdp, CommonTests):
    "UDP tests"

class TestDdcmpUdpMax (Qmax255, DdcmpUdp):
    "Test large max queue, UDP mode"
    
class DdcmpStream (DDCMPbase):
    # Base class for stream connections that look like a TCP socket.
    # It assumes a socket API but doesn't create the socket object, so
    # the serial port tests can also use this.
    def tearDown (self):
        try:
            self.socket.shutdown (socket.SHUT_RDWR)
        except OSError:
            # If socket isn't connected a shutdown will fail
            pass
        self.socket.close ()
        super ().tearDown ()

    def recvall (self, n, start = b""):
        while len (start) < n:
            self.assertTrue (self.data_ready (0.1), "Data ready timeout")
            b = self.socket.recv (n - len (start))
            self.assertNotEqual (b, b"")
            start += b
        return start
    
    def receivepdu (self):
        "Return the next DDCMP frame from the TCP data stream"
        # This returns the first DDCMP frame, under the assumption
        # that the header is intact since it uses the length field of
        # data frames to get the payload portion.
        b = byte (ddcmp.SYN)
        # Skip any SYN or DEL bytes
        while b[0] in (ddcmp.SYN, ddcmp.DEL):
            b = self.recvall (1)
        # Next must be header start
        self.assertIn (b[0], (ddcmp.ENQ, ddcmp.SOH, ddcmp.DLE))
        # Get the rest of the header
        b = self.recvall (8, b)
        # If it's a data message, get the data also
        if b[0] != ddcmp.ENQ:
            mlen = int.from_bytes (b[1:3], "little") & 0x3fff
            b = self.recvall (mlen + 10, b)
        return b

    def sendpdu (self, pdu):
        # Send the packet without leading SYN.  We normally supply SYN
        # but things should work without it, so we'll test that in
        # this part of the tes suite.  In fact, RSTS doesn't supply
        # leading SYN for async serial links.
        self.socket.sendall (makebytes (pdu) + ddcmp.DEL1)
        
class DdcmpTcp (DdcmpStream):
    def setUp (self):
        self.lport = nextport ()
        self.cport = nextport ()
        # TCP mode
        spec = "circuit dmc-0 DDCMP tcp:{}:127.0.0.1:{}".format (self.lport,
                                                                 self.cport)
        self.tconfig = self.config (spec)
        super ().setUp ()
        # Verify the mapping from old format to new
        self.assertEqual (self.tconfig.mode, "tcp")
        self.assertEqual (self.tconfig.destination, "127.0.0.1")
        self.assertEqual (self.tconfig.dest_port, self.cport)
        self.assertEqual (self.tconfig.source_port, self.lport)
        self.socket = socket.socket (socket.AF_INET)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

class StreamTests:
    "Tests for the various kinds of stream based DDCMP implementations"
    def test_hcrc_resync (self):
        "Test Header CRC based resynchronization"
        # Rep (num = 1) message will produce a response if received
        # successfully.
        rep = b"\x05\x03\x00\x00\x01\x01\x84\x05"
        self.start1 ()
        self.sendpdu (rep)
        # Check the expected response
        b = self.receivedata ()
        msg, b1 = ddcmp.DMHdr.decode (b)
        self.assertIsInstance (msg, ddcmp.NakMsg)
        self.assertEqual (msg.subtype, 3)
        self.assertEqual (msg.resp, 0)
        self.assertEqual (self.dmc.counters.remote_reply_timeouts, 1)
        # Also check resulting counters
        self.assertEqual (self.dmc.counters.data_errors_inbound, 1)
        self.assertEqual (self.dmc.counters.data_errors_inbound.map, 4)
        badpdu = rep [:-1]
        self.sendpdu (badpdu)
        time.sleep (0.1)
        # We should get an NAK back, saying "Header CRC error"
        b = self.receivedata ()
        expected_nak = bytes (ddcmp.NakMsg (resp = 0, subtype = 1))
        self.assertEqual (b, expected_nak)
        self.assertEqual (self.dmc.counters.data_errors_inbound, 2)
        self.assertEqual (self.dmc.counters.data_errors_inbound.map, 5)
        # REP was not processed, count still 1
        self.assertEqual (self.dmc.counters.remote_reply_timeouts, 1)
        # Send the REP again.  We're out of sync so it isn't noticed
        # at all.
        self.sendpdu (badpdu)
        time.sleep (0.1)
        # Count doesn't change
        self.assertEqual (self.dmc.counters.data_errors_inbound, 2)
        self.assertEqual (self.dmc.counters.data_errors_inbound.map, 5)
        # REP was not processed, count still 1
        self.assertEqual (self.dmc.counters.remote_reply_timeouts, 1)
        # Send a good one, that restores sync and is received. 
        self.sendpdu (rep)
        # Check for response
        b = self.receivedata ()
        self.assertEqual (self.dmc.counters.remote_reply_timeouts, 2)
        # Also check resulting counters
        self.assertEqual (self.dmc.counters.data_errors_inbound, 3)
        self.assertEqual (self.dmc.counters.data_errors_inbound.map, 5)
        # Test the case of losing too many bytes
        badpdu = rep[:2]
        self.sendpdu (badpdu)
        time.sleep (0.1)
        # We won't even get a reply at all because the other end is
        # still looking for 8 bytes and that much hasn't been sent
        # yet.
        self.assertEqual (self.dmc.counters.data_errors_inbound, 3)
        # Send a good one.  That will finish out the 8 bytes and
        # generate a header CRC error for the previous fragment.
        # Since we search for headers after header CRC error in the
        # rest of the bad header, we WILL see this packet, and will
        # reply to it.
        self.sendpdu (rep)
        # We should get an NAK back, saying "Header CRC error",
        # followed by another NAK saying "REP reply".  The receivedata
        # method will hand those over one at a time.
        b = self.receivedata ()
        expected_nak = ddcmp.NakMsg (resp = 0, subtype = 1)
        self.assertEqual (b, expected_nak)
        # Check for the response to the REP
        b = self.receivedata ()
        msg, b = ddcmp.DMHdr.decode (b)
        self.assertIsInstance (msg, ddcmp.NakMsg)
        self.assertEqual (msg.subtype, 3)
        self.assertEqual (msg.resp, 0)
        self.assertEqual (self.dmc.counters.remote_reply_timeouts, 3)
        # Also check resulting counters.  Error counter goes up by 2:
        # one due to the header CRC error, one due to the inbound REP.
        self.assertEqual (self.dmc.counters.data_errors_inbound, 5)
        self.assertEqual (self.dmc.counters.data_errors_inbound.map, 5)

    def test_framing1 (self):
        "Test handling of a frame that arrives in pieces"
        self.start1 ()
        self.socket.setsockopt (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        pdu = self.pdu (1, testsdu ()) + ddcmp.DEL1
        # Send the beginning (note: not even a complete DDCMP header)
        self.socket.send (pdu[:5])
        time.sleep (0.1)
        self.lastdispatch (1, itype = datalink.DlStatus)
        # Send the rest of the header and most of the payload
        self.socket.send (pdu[5:-8])
        time.sleep (0.1)
        self.lastdispatch (1, itype = datalink.DlStatus)
        # Send the final part of the frame
        self.socket.send (pdu[-8:])
        time.sleep (0.1)
        #self.socket.send (ddcmp.DEL2 * 10)
        w = self.lastdispatch (2, itype = Received)
        b = w.packet
        self.assertEqual (b, testsdu ())
        self.assertEqual (self.dmc.counters.bytes_recv, 30)        
        self.assertEqual (self.dmc.counters.pkts_recv, 1)

    def test_framing2 (self):
        "Test handling of two frames arriving all at once"
        self.start1 ()
        # Construct two frames, including the required DEL after but
        # without SYN bytes since those are not required.
        pdus = self.pdu (1, b"test1") + ddcmp.DEL1 + \
               self.pdu (2, b"test2") + ddcmp.DEL1
        # Send the pair all at once
        self.socket.send (pdus)
        time.sleep (0.1)
        w1 = self.lastdispatch (3, back = 1, itype = Received)
        b1 = w1.packet
        self.assertEqual (b1, b"test1")
        w2 = self.lastdispatch (3, itype = Received)
        b2 = w2.packet
        self.assertEqual (b2, b"test2")
        self.assertEqual (self.dmc.counters.bytes_recv, 10)
        self.assertEqual (self.dmc.counters.pkts_recv, 2)

    def test_shutdown1 (self):
        "Test shutdown if the other end stops in mid packet"
        self.start1 ()
        self.socket.setsockopt (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        pdu = self.pdu (1, testsdu ()) + ddcmp.DEL1
        # Send the beginning (note: not even a complete DDCMP header)
        self.socket.send (pdu[:5])
        time.sleep (0.1)
        
    def test_shutdown2 (self):
        "Test shutdown if the other end stops in mid packet"
        self.start1 ()
        self.socket.setsockopt (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        pdu = self.pdu (1, testsdu ()) + ddcmp.DEL1
        # Send most (good header and part of the data)
        self.socket.send (pdu[:-8])
        time.sleep (0.1)
        
class TcpTests (StreamTests):
    "Tests for streams over TCP connections"
    def recon (self, when, how):
        # Common code for reconnect test.  The first argument says
        # when to break the connection: 0 = in Istart state, 1 = in
        # Astart state, 2 = in run state, 3 = in Maint state.  The
        # second argument says how to reconnect: 0 = listen, with the
        # listening socket ready before the disconnect, 1 = listen
        # with the socket created after, 2 = connect.
        start = b"\x05\x06\xc0\x00\x00\x01\x75\x95"
        stack = b"\x05\x07\xc0\x00\x00\x01\x48\x55"
        # Get us into the requested state.  For 0 (IStart) we're there
        # already.
        if when == 1:
            # AStart
            # Receive the START
            self.receivedata ()
            self.sendpdu (start)
            # Receive the STACK
            b = self.receivedata ()
            self.assertEqual (b, stack)
        elif when == 2:
            # Run
            self.start1 ()
        elif when == 3:
            # Maint
            # Receive the START
            self.receivedata ()
            maint = bytes (ddcmp.MaintMsg (payload = testsdu ()))
            self.sendpdu (maint)
            time.sleep (0.1)
            self.assertFalse (self.rport.parent.islinked ())
        if how == 0:
            # Early listen
            lsock = socket.socket (socket.AF_INET)
            lsock.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            lsock.bind (("", self.cport))
            lsock.listen (1)
        try:
            self.socket.shutdown (socket.SHUT_RDWR)
        except OSError:
            # If socket isn't connected a shutdown will fail
            pass
        self.socket.close ()
        logging.trace ("recon: disconnect done")
        time.sleep (0.1)
        # Expire the reconnect holdoff timer
        DnTimeout (self.rport.parent)
        time.sleep (0.1)
        if when == 2:
            # Datalink should report DOWN
            w = self.lastdispatch (2, itype = datalink.DlStatus)
            self.assertEqual (w.status, w.DOWN)
            count = 3
        else:
            count = 1
        if how == 1:
            # Late listen
            lsock = socket.socket (socket.AF_INET)
            lsock.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            lsock.bind (("", self.cport))
            lsock.listen (1)
            logging.trace ("recon: late listen, now listening")
            # Since DDCMP tried to connect before we listened, it
            # would have gotten a failure from that and we need to
            # tell it to do that again.
            DnTimeout (self.rport.parent)
        if how == 2:
            # Connect
            self.socket = socket.socket (socket.AF_INET)
            self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.connect (("127.0.0.1", self.lport))
            logging.trace ("recon: connect done")
        else:
            # Either kind of listen
            sock, ainfo = lsock.accept ()
            self.assertEqual (ainfo[0], "127.0.0.1")
            lsock.close ()
            logging.trace ("recon: accept done")
            self.socket = sock
        # Bring up DDCMP just to be sure
        logging.trace ("Final ddcmp startup")
        self.start1 (count)

    # What follows is a bunch of variations of the reconnect scenario.
    # We don't run all 12 variations, since the difference betwen
    # listen-early and listen-late is small.
    def test_reconnect_00 (self):
        self.recon (0, 0)

    def test_reconnect_01 (self):
        self.recon (0, 1)

    def test_reconnect_02 (self):
        self.recon (0, 2)

    def test_reconnect_10 (self):
        self.recon (1, 0)

    def test_reconnect_11 (self):
        self.recon (1, 1)

    def test_reconnect_12 (self):
        self.recon (1, 2)

    def test_reconnect_20 (self):
        self.recon (2, 0)

    def test_reconnect_22 (self):
        self.recon (2, 2)

    def test_reconnect_30 (self):
        self.recon (3, 0)

    def test_reconnect_32 (self):
        self.recon (3, 2)

class DdcmpTcplisten (DdcmpTcp):
    "TCP mode DDCMP, listening for connection"
    def setUp (self):
        super ().setUp ()
        self.socket.bind (("", self.cport))
        self.socket.listen (1)
        self.rport.open ()
        sock, ainfo = self.socket.accept ()
        self.assertEqual (ainfo[0], "127.0.0.1")
        self.socket.close ()
        self.socket = sock
        
    def sendpdu (self, pdu):
        # Override the base class version to send the packet with SYN
        # and DEL wrapping
        self.socket.sendall (SYN4 + makebytes (pdu) + ddcmp.DEL1)

class TestDdcmpTcplisten (DdcmpTcplisten, CommonTests, TcpTests):
    "TCP tests, listen (conn ction outbound)"
    
class DdcmpTcpconn (DdcmpTcp):
    "TCP mode DDCMP, connecting"

    def setUp (self):
        super ().setUp ()
        self.rport.open ()
        # Note that we don't bind the port that DDCMP is connecting
        # to, so that connect goes nowhere.  Depending on the OS, it
        # might be immediately rejected, or not.
        time.sleep (0.1)
        self.socket.connect (("127.0.0.1", self.lport))

class TestDdcmpTcpconn (DdcmpTcpconn, CommonTests, TcpTests):
    "TCP tests, connect (connection inbound)"

class TestDdcmpTcpMax (Qmax255, DdcmpTcpconn):
    "Test large max queue, TCP mode"
    
class PipeSerial:
    """An object that looks like a serial port to the DDCMP being
    tested, and like a TCP socket to the test code.
    """
    def __init__ (self):
        # The first pipe is the UUT output, the second its input.
        self.r1, self.w1 = os.pipe ()
        self.r2, self.w2 = os.pipe ()

    def Serial (self, *args, **kwargs):
        "Create (open) the serial port object"
        return self

    def read (self, n):
        # Serial port read returns up to the specified number of
        # bytes, but may return less.
        sellist = [ self.r2 ]
        try:
            r, w, e = select.select (sellist, [ ], sellist, 1)
        except OSError:
            return b""
        if e != [ ]:
            return b""
        ret = os.read (self.r2, n)
        return ret

    def write (self, data):
        os.write (self.w1, data)

    def shutdown (self, arg):
        pass
    
    def close (self):
        os.close (self.r1)
        os.close (self.w1)
        os.close (self.r2)
        os.close (self.w2)

    def fileno (self):
        # The file number of the "socket"
        return self.r1
    
    def sendall (self, data):
        os.write (self.w2, data)

    send = sendall
    
    def recv (self, n):
        return os.read (self.r1, n)

    def setsockopt (self, *args):
        pass
    
class DdcmpSerial (DdcmpStream):
    def setUp (self):
        # Create this before the DDCMP object is created, to make sure
        # ddcmp.serial is not None, otherwise the object creation
        # fails.
        ddcmp.serial = self.socket = PipeSerial ()
        # Serial mode, using the new specification format
        spec = "circuit dmc-0 DDCMP somename --mode serial"
        self.tconfig = self.config (spec)
        super ().setUp ()
        self.rport.open ()

class TestDdcmpSerial (DdcmpSerial, CommonTests, StreamTests):
    "Test serial port mode"

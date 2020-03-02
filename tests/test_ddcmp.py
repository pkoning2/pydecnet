#!/usr/bin/env python3

"DDCMP tests"

# TODO: add DDCMP protocol testing.

from tests.dntest import *
from decnet import ddcmp

class TestPackets (DnTest):
    def test_start (self):
        b = b"\x05\x06\xc0\x00\x00\x01\x75\x95"
        start, b1 = ddcmp.DMHdr.decode (b)
        self.assertEqual (b1, b"")
        self.assertIsInstance (start, ddcmp.StartMsg)
        b2 = start.encode ()
        self.assertEqual (b, b2)

    def test_stack (self):
        b = b"\x05\x07\xc0\x00\x00\x01\x48\x55"
        stack, b1 = ddcmp.DMHdr.decode (b)
        self.assertEqual (b1, b"")
        self.assertIsInstance (stack, ddcmp.StackMsg)
        b2 = stack.encode ()
        self.assertEqual (b, b2)
        
    def test_ack (self):
        b = b"\x05\x01\x00\x00\x00\x01\xfc\x55"
        ack, b1 = ddcmp.DMHdr.decode (b)
        self.assertEqual (b1, b"")
        self.assertIsInstance (ack, ddcmp.AckMsg)
        self.assertEqual (ack.resp, 0)
        self.assertEqual (ack.addr, 1)
        b2 = ack.encode ()
        self.assertEqual (b, b2)

    def test_data (self):
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
            

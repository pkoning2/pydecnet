#!/usr/bin/env python3

from tests.dntest import *

from decnet import nicepackets
from decnet.nice_coding import *

class SimpleResp (packet.Packet):
    _layout = ((NICE, True,
                ( 10, HI, "Physical Address" ),
                ( 100, AI, "Identification" )),)

class AllTypes (packet.Packet):
    _layout = ((NICE, True,
                ( 1, DU1, "Decimal 1" ),
                ( 2, DU2, "Decimal 2", "dec2" ),
                ( 4, DU4, "Decimal 4" ),
                ( 11, DS1, "Signed 1" ),
                ( 12, DS2, "Signed 2" ),
                ( 14, DS4, "Signed 4" ),
                ( 21, O1, "Octal 1" ),
                ( 38, H8, "Hex 1" ),
                ( 40, HI, "Hex string" ),
                ( 41, AI, "ASCII string" ),
                ( 51, C1, "Coded 1", None, ( "foo", "bar", "baz" ) ),
                ),)
        
class TestNiceResp (DnTest):
    def test_decode1 (self):
        "One parameter"
        b = b"\x0a\x00\x20\x04\xaa\x00\x04\x00"
        e, b2 = SimpleResp.decode (b)
        self.assertIsInstance (e, SimpleResp)
        self.assertEqual (b2, b"")
        self.assertEqual (e.physical_address, b"\xaa\x00\x04\x00")
        es = NICE.format (e)
        self.assertRegex (es, r"Physical Address = aa-00-04-00")
        # Check encoding
        self.assertEqual (b, bytes (e))

    def test_decode_n (self):
        "Lots of parameters"
        # Note parameter 11 is given as DS-1 in the code table but as
        # H-5 in the packet.
        b = b"\x01\x00\x01\x32" \
            b"\x02\x00\x02\x02\x04" \
            b"\x04\x00\x04\x01\x02\x03\x00" \
            b"\x0b\x00\x25\xf0\xff\x33\x42\x73" \
            b"\x0c\x00\x12\xf0\xff" \
            b"\x15\x00\x33\x01\x33\x02" \
            b"\x26\x00\x22\xaa\xbb" \
            b"\x28\x00\x20\x05\xaa\x02\x03\x00\x00" \
            b"\x29\x00\x40\x0dGood Morning!" \
            b"\x33\x00\x81\x01"
        e, b2 = AllTypes.decode (b)
        self.assertIsInstance (e, AllTypes)
        self.assertEqual (b2, b"")
        self.assertEqual (e.octal_1, 0o00431401)
        self.assertEqual (e.hex_1, 0xbbaa)
        self.assertEqual (e.coded_1, 1)
        es = NICE.format (e)
        self.assertRegex (es, r"Signed 1 = 734233fff0")
        self.assertRegex (es, r"ASCII string = Good Morning!")
        self.assertRegex (es, r"Coded 1 = bar")
        # Check encoding
        self.assertEqual (b, bytes (e))

    def test_decode_other (self):
        "Unknown values and fields"
        # Note that unknown fields are encoded last, so we'll send
        # them in last as well and in order, so the check on encoding
        # works.
        b = b"\x33\x00\x81\x42\x64\x00\x40\x05Hello"
        e, b2 = AllTypes.decode (b)
        self.assertIsInstance (e, AllTypes)
        self.assertEqual (b2, b"")
        self.assertEqual (e.coded_1, 0x42)
        self.assertEqual (e.field100, "Hello")
        es = NICE.format (e)
        self.assertRegex (es, r"Parameter #100 = Hello")
        self.assertRegex (es, r"Coded 1 = #66")
        # Check encoding
        self.assertEqual (b, bytes (e))
        
    def test_nodechar (self):
        "Executor characteristics reply"
        b = b"\x01\xff\xff\x00)\xa4\x86PYTS41d\x00@" \
            b"$DECnet/Python test system in NH, USA" \
            b"e\x00\xc3\x01\x04\x01\x00\x01\x00\xfe\x01" \
            b"\x02\x1e\x00\xff\x01\x02\x1e\x00\xbc\x02\xc3" \
            b"\x01\x04\x01\x00\x01\x00\xc6\x02\x02\xff" \
            b"\x0f\xd0\x02\x01 \xd1\x02\x01\x03\xd2\x02" \
            b"\x02,\x01\xd3\x02\x02\x05\x00\x84\x03\xc3" \
            b"\x01\x02\x01\x00\x01\x00\x85\x03\x81\x04" \
            b"\x8e\x03\x02X\x02\x90\x03\x02\n\x00\x98\x03" \
            b"\x02\xff\x03\x9a\x03\x02\x80\x00\x9b\x03" \
            b"\x01\x10\x9c\x03\x01 \xa4\x03\x02@\x02"
        e, b2 = nicepackets.NodeReply.decode (b)
        self.assertIsInstance (e, nicepackets.NodeReply)
        self.assertEqual (b2, b"")
        self.assertEqual (e.identification,
                          "DECnet/Python test system in NH, USA")
        self.assertEqual (e.maximum_links, 4095)
        es = NICE.format (e)
        self.assertRegex (es, r"Routing Version = 2\.0\.0")
        # Check encoding
        self.assertEqual (b, bytes (e))

class TestNiceReq (DnTest):
    def test_nodereadinfo (self):
        "get executor characteristics"
        b = b"\x14\x20\x00\x00\x00"
        e = nicepackets.NiceReadNode (b)
        self.assertTrue (e.char ())
        self.assertFalse (e.counters ())
        self.assertTrue (e.one ())
        self.assertEqual (e.entity.e_type, 0)    # Node
        self.assertEqual (e.entity.value, 0)     # Node 0, i.e., executor

    def test_circstat (self):
        "get circuit status"
        b = b"\x14\x13\x05ETH-0"
        e = nicepackets.NiceReadCircuit (b)
        self.assertTrue (e.stat ())
        self.assertTrue (e.sumstat ())
        self.assertFalse (e.char ())
        self.assertTrue (e.one ())
        self.assertEqual (e.entity.e_type, 3)    # Circuit
        self.assertEqual (e.entity.value, "ETH-0")
        

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
                ( 1, CTR1, "Counter 1" ),
                ( 2, CTR2, "Counter 2" ),
                ( 4, CTR4, "Counter 4" ),
                ( 11, CTM1, "Mapped counter 1" ),
                ( 12, CTM2, "Mapped counter 2", None, ( "hcrc", "one", "two" )),
                ( 14, CTM4, "Mapped counter 4" ),
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
            b"\x33\x00\x81\x01" \
            b"\x04\xe0\x01\x02\x03\x00" \
            b"\x0c\xd0\x05\x01\xff\xff"
        e, b2 = AllTypes.decode (b)
        self.assertIsInstance (e, AllTypes)
        self.assertEqual (b2, b"")
        self.assertEqual (e.octal_1, 0o00431401)
        self.assertEqual (e.hex_1, 0xbbaa)
        self.assertEqual (e.coded_1, 1)
        self.assertEqual (e.counter_4, 197121)
        self.assertEqual (e.mapped_counter_2, 65535)
        self.assertEqual (e.mapped_counter_2.map, 0x105)
        es = NICE.format (e)
        self.assertRegex (es, r"Signed 1 = 734233fff0")
        self.assertRegex (es, r"ASCII string = Good Morning!")
        self.assertRegex (es, r"Coded 1 = bar")
        self.assertRegex (es, r">65534 Mapped counter 2")
        self.assertRegex (es, r"hcrc")
        self.assertRegex (es, r"two")
        self.assertRegex (es, r"Qualifier #8")
        # Check encoding
        self.assertEqual (b, bytes (e))

    def test_decode_other (self):
        "Unknown values and fields"
        # Note that unknown fields are encoded last, so we'll send
        # them in last as well and in order, so the check on encoding
        # works.
        b = b"\x33\x00\x81\x42" \
            b"\x64\x00\x40\x05Hello" \
            b"\x65\x00\xc2\x40\x07Goodbye\x31\x0c"
        e, b2 = AllTypes.decode (b)
        self.assertIsInstance (e, AllTypes)
        self.assertEqual (b2, b"")
        self.assertEqual (e.coded_1, 0x42)
        self.assertEqual (e.field100, "Hello")
        es = NICE.format (e)
        self.assertRegex (es, r"Parameter #100 = Hello")
        self.assertRegex (es, r"Parameter #101 = Goodbye 014")
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
        
class TestP2Nice (DnTest):
    "Phase II NICE protocol"
    def test_show_exe_req (self):
        "read local (executor) status"
        b = b"\x08\x01"
        e = nicepackets.P2NiceReadExecStatus (b)
        # No fields to check
        # Check encode
        self.assertEqual (b, bytes (e))

    def test_show_exec_resp (self):
        "read local (executor) status response"
        b = b"\x01\x04TEST\x2a\x00\x00\x00\x03DEF\x03\x00\x01\x03\x01\x00\x05Ident"
        e = nicepackets.P2NiceReadExecStatusReply (b)
        self.assertEqual (e.name, "TEST")
        self.assertEqual (e.id, 42)
        self.assertEqual (e.state, 0)
        self.assertEqual (e.defhost, "DEF")
        self.assertEqual (e.routing_version, Version (3, 0, 1))
        self.assertEqual (e.comm_version, Version (3, 1, 0))
        self.assertEqual (e.system, "Ident")
        # Check encode
        self.assertEqual (b, bytes (e))

    def test_show_line_req (self):
        "read line requests"
        with self.subTest (what = "status known lines"):
            b = b"\x08\x05\x00"
            e = nicepackets.P2NiceReadLineStatus (b)
            self.assertTrue (e.entity.known ())
            # Check encode
            self.assertEqual (b, bytes (e))
        with self.subTest (what = "counters known lines"):
            b = b"\x08\x04\x00"
            e = nicepackets.P2NiceReadLineCounters (b)
            self.assertTrue (e.entity.known ())
            # Check encode
            self.assertEqual (b, bytes (e))
        with self.subTest (what = "status line DMC_3"):
            b = b"\x08\x05\x01\x0c\x03\x00\x00"
            e = nicepackets.P2NiceReadLineStatus (b)
            self.assertFalse (e.entity.known ())
            self.assertEqual (str (e.entity), "DMC_3")
            # Check encode
            self.assertEqual (b, bytes (e))
        with self.subTest (what = "counters line STR-12345"):
            # (Note that TOPS-20 doesn't support string format line IDs)
            b = b"\x08\x04\x02\x09STR-12345"
            e = nicepackets.P2NiceReadLineCounters (b)
            self.assertFalse (e.entity.known ())
            self.assertEqual (str (e.entity), "STR-12345")
            # Check encode
            self.assertEqual (b, bytes (e))

    def test_show_line_stat_resp (self):
        "read line status response"
        b = b"\x05\x01\x0c\x02\x00\x00\x01\x00\x00\x03ARK"
        e = nicepackets.P2NiceReadLineStatusReply (b)
        self.assertEqual (str (e.entity), "DMC_2")
        self.assertEqual (e.state, 1)
        self.assertEqual (e.adjacent_node, "ARK")
        # Check encode
        self.assertEqual (b, bytes (e))

    def test_show_line_counters_reply (self):
        "read line counters response"
        b = b"\x04\x01\x0c\x02\x04\x00\x01\x12\x00\x02\x00\x01"
        e = nicepackets.P2NiceReadLineCountersReply (b)
        self.assertEqual (str (e.entity), "DMC_2_4")
        self.assertEqual (e.pkts_recv, 18)
        self.assertEqual (e.pkts_sent, 256)
        # Check encode
        self.assertEqual (b, bytes (e))
        
    def test_line_ent (self):
        "Line entity handling"
        with self.subTest (what = "known"):
            l = nicepackets.P2LineEntity ("*")
            self.assertEqual (bytes (l), b"\x00")
            self.assertTrue (l.known ())
            l = nicepackets.P2LineEntity (b"\x00")
            self.assertEqual (str (l), "*")
            self.assertTrue (l.known ())
        with self.subTest (what = "standard dev"):
            l = nicepackets.P2LineEntity ("DMC_13_2")
            self.assertEqual (bytes (l), b"\x01\x0c\x0b\x02\x00")
            self.assertFalse (l.known ())
            l = nicepackets.P2LineEntity (b"\x01\x14\x11\x09\x00")
            self.assertEqual (str (l), "DTE_21_11")
            self.assertFalse (l.known ())
        with self.subTest (what = "string"):
            l = nicepackets.P2LineEntity ("MUL-123")
            self.assertEqual (bytes (l), b"\x02\x07MUL-123")
            self.assertFalse (l.known ())
            l = nicepackets.P2LineEntity (b"\x02\x07MUL-123")
            self.assertEqual (str (l), "MUL-123")
            self.assertFalse (l.known ())
        with self.subTest (what = "alias"):
            l = nicepackets.P2LineEntity ("MUL-123", 10)
            self.assertEqual (bytes (l), b"\x01\x14\x00\x0a\x00")
            self.assertEqual (str (l), "DTE_0_12")
            self.assertFalse (l.known ())

#!/usr/bin/env python3

from tests.dntest import *

from decnet import packet

class alltypes (packet.Packet):
    _layout = (( "bm",
                 ( "bit1", 0, 1 ),
                 ( "bit2", 1, 2 ),
                 ( "bit6", 3, 6 )),
               ( "i", "image", 10 ),
               ( "b", "int6", 6 ),
               ( "ex", "extended", 7 ),
               ( "signed", "sint", 2 ),
               ( "bv", "byte5", 5 ),
               ( "res", 1 ),
               ( "b", "int4", 4 ),
               ( Nodeid, "node" ))
class allpayload (alltypes): _addslots = { "payload" }

testdata = b"\025\001\006abcdef\001\000\000\001\000\000\200\003" \
           b"\012\377bytesX\001\001\000\000\003\004"
# In the above, X is the value for the one-byte "res" (reserved) field,
# which is don't care on decode but 0 on encode.  So construct the
# output we expect for encode:
testdata2 = testdata.replace (b"X", b"\000")

class alltlv (packet.Packet):
    _layout = (( "b", "int1", 1 ),
               ( "tlv", 1, 1, False,
                 { 1 : ( "bm",
                         ( "bit1", 0, 1 ),
                         ( "bit2", 1, 2 ),
                         ( "bit6", 3, 6 )),
                   2 : ( "i", "image", 10 ),
                   3 : ( "b", "int6", 6 ),
                   7 : ( "ex", "extended", 7 ),
                   8 : ( "signed", "sint", 2 ),
                   9 : ( "bv", "byte5", 5 ),
                   10: ( "b", "int4", 4 ),
                   11: ( "bs", "bytestring", 50 ),
                   12: ( Nodeid, "node" ) }))

tlvdata = b"\001\002\005\004abcd\013\024four score and seven" \
          b"\012\004\004\001\000\000\014\002\003\004"

class TestPacket (DnTest):
    def setUp (self):
        logging.exception = unittest.mock.Mock ()

    def tearDown (self):
        l = logging.exception.call_args_list
        if l:
            print (l)
        self.assertEqual (logging.exception.call_count, 0)
        
    def test_abc (self):
        # Can't instantiate the Packet base class
        with self.assertRaises (TypeError):
            a = packet.Packet ()

    def test_nolayout (self):
        # Can't define a packet subclass with no layout
        with self.assertRaises (TypeError):
            class foo (packet.Packet): pass

    def test_badlayout1 (self):
        # Can't define a packet subclass with undefined type code
        with self.assertRaises (TypeError):
            class foo (packet.Packet): _layout = ( ("invalid", 0, 0), )

    def test_badlayout2 (self):
        # Can't have a duplicate field name
        with self.assertRaises (TypeError):
            class foo (packet.Packet):
                _layout = ( ("b", "dupname", 2),
                            ("b", "dupname", 2))
    def test_badlayout3 (self):
        # Can't redefine a field from a base class
        class foo (packet.Packet):
            _layout = ( ("b", "dupname", 2),)
        with self.assertRaises (TypeError):
            class bar (foo):
                _layout = ( ("b", "dupname", 2),)

    def test_badlayout4 (self):
        # Field types that are a class must have a specified length
        with self.assertRaises (TypeError):
            class foo (packet.Packet):
                _layout = ( (int, "name"),)

    def test_alltypes_d (self):
        # Test decode of every non-TLV field type
        a = alltypes (testdata)
        self.assertEqual (a.bit1, 1)
        self.assertEqual (a.bit2, 2)
        self.assertEqual (a.bit6, 34)
        self.assertEqual (a.image, b"abcdef")
        self.assertEqual (a.int6, 16777217)
        self.assertEqual (a.extended, 384)
        self.assertEqual (a.sint, -246)
        self.assertEqual (a.byte5, b"bytes")
        self.assertEqual (a.int4, 257)
        self.assertEqual (a.node, Nodeid (1, 3))
        self.assertEqual (bytes (a), testdata2)

    def test_alltypes_e (self):
        a = alltypes (bit1 = 1, bit2 = 2, bit6 = 18,
                      image = b"defghi", int6 = 32767,
                      extended = 12, sint = -2,
                      byte5 = b"hound", int4 = 511,
                      node = Nodeid (2, 2))
        b = bytes (a)
        self.assertEqual (b, b"\x95\000\006defghi\377\177\000\000\000\000"
                          b"\014\376\377hound\000\377\001\000\000\002\010")

    def test_alltypes_def (self):
        a = alltypes (node = Nodeid (1))    # Default what can be
        b = bytes (a)
        self.assertEqual (b, b"\000\000\000\000\000\000\000\000\000"
                          b"\000\000\000\000\000\000\000\000\000"
                          b"\000\000\000\000\001\000")

    def test_payload (self):
        # Test layout with payload (whatever is left over, if permitted)
        a = allpayload (testdata + b"payload")
        self.assertEqual (a.bit1, 1)
        self.assertEqual (a.bit2, 2)
        self.assertEqual (a.bit6, 34)
        self.assertEqual (a.image, b"abcdef")
        self.assertEqual (a.int6, 16777217)
        self.assertEqual (a.extended, 384)
        self.assertEqual (a.sint, -246)
        self.assertEqual (a.byte5, b"bytes")
        self.assertEqual (a.int4, 257)
        self.assertEqual (a.node, Nodeid (1, 3))
        self.assertEqual (a.payload, b"payload")
        self.assertEqual (bytes (a), testdata2 + b"payload")
        with self.assertRaises (events.Event) as e:
            alltypes (testdata + b"x")
        self.assertEqual (e.exception.event, events.Event.fmt_err)

    def test_constfield (self):
        # Value defined in class is constant field
        class constimage (alltypes):
            image = b"foobar"
        a = constimage (testdata.replace (b"abcdef", b"foobar"))
        self.assertEqual (a.bit1, 1)
        self.assertEqual (a.bit2, 2)
        self.assertEqual (a.bit6, 34)
        self.assertEqual (a.image, b"foobar")
        self.assertEqual (a.int6, 16777217)
        self.assertEqual (a.extended, 384)
        self.assertEqual (a.sint, -246)
        self.assertEqual (a.byte5, b"bytes")
        self.assertEqual (a.int4, 257)
        self.assertEqual (a.node, Nodeid (1, 3))
        self.assertEqual (bytes (a), testdata2.replace (b"abcdef", b"foobar"))
        with self.assertRaises (events.Event) as e:
            constimage (testdata)
        self.assertEqual (e.exception.event, events.Event.fmt_err)

    def test_tlv (self):
        # TLV field parsing
        a = alltlv (tlvdata)
        self.assertEqual (a.int1, 1)
        self.assertEqual (a.int4, 260)
        self.assertEqual (a.image, b"abcd")
        self.assertEqual (a.bytestring, b"four score and seven")
        self.assertEqual (a.node, Nodeid (1, 3))
        self.assertFalse (hasattr (a, "bit1"))
        self.assertFalse (hasattr (a, "bit2"))
        self.assertFalse (hasattr (a, "bit6"))
        self.assertFalse (hasattr (a, "int6"))
        self.assertFalse (hasattr (a, "extended"))
        self.assertFalse (hasattr (a, "sint"))
        self.assertFalse (hasattr (a, "byte5"))
        # Check that invalid Type values are rejected
        with self.assertRaises (events.Event) as e:
            alltlv (tlvdata + b"\004xxx")
        self.assertEqual (e.exception.event, events.Event.fmt_err)
        
if __name__ == "__main__":
    unittest.main ()

#!/usr/bin/env python3

from tests.dntest import *

from decnet import packet

class BE2 (int):
    """2-byte big endian integer.
    """
    def __new__ (cls, val, bval = None):
        if bval is None:
            val = int.from_bytes (val.to_bytes (2, "little"), "big")
        else:
            val = bval
        return int.__new__ (cls, val)

    def __int__ (self):
        return int.from_bytes (self.to_bytes (2, "little"), "big")
    
class alltypes (packet.Packet):
    _layout = (( "bm",
                 ( "bit1", 0, 1 ),
                 ( "bit2", 1, 2 ),
                 ( "bit6", 3, 6 ),
                 ( "be", 9, 16, BE2 )),
               ( "i", "image", 10 ),
               ( "b", "int6", 6 ),
               ( "ex", "extended", 7 ),
               ( "signed", "sint", 2 ),
               ( "bv", "byte5", 5 ),
               ( "res", 1 ),
               ( "b", "int4", 4 ),
               ( Nodeid, "node" ))
class allpayload (alltypes): _addslots = { "payload" }

testdata = b"\025\x21\xc2\x01\006abcdef\001\000\000\001\000\000\200\003" \
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

class alltlv_w (packet.Packet):
    _layout = (( "b", "int1", 1 ),
               ( "tlv", 1, 1, True,
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
    def tearDown (self):
        self.assertEqual (logging.exception.call_count, 0)
        super ().tearDown ()
        
    def test_abc (self):
        # Can't instantiate the Packet base class
        with self.assertRaises (TypeError):
            a = packet.Packet ()

    def test_nolayout (self):
        # Can't define a packet subclass with no layout
        with self.assertRaises (packet.InvalidField):
            class foo (packet.Packet): pass

    def test_badlayout1 (self):
        # Can't define a packet subclass with undefined type code
        with self.assertRaises (TypeError):
            class foo (packet.Packet): _layout = ( ("invalid", 0, 0), )

    def test_badlayout2 (self):
        # Can't have a duplicate field name
        with self.assertRaises (packet.InvalidField):
            class foo (packet.Packet):
                _layout = ( ("b", "dupname", 2),
                            ("b", "dupname", 2))
    def test_badlayout3 (self):
        # Can't redefine a field from a base class
        class foo (packet.Packet):
            _layout = ( ("b", "dupname", 2),)
        with self.assertRaises (packet.InvalidField):
            class bar (foo):
                _layout = ( ("b", "dupname", 2),)

    def test_badlayout4 (self):
        # Field types that are a class must have a decode method
        with self.assertRaises (packet.InvalidField):
            class foo (packet.Packet):
                _layout = ( (int, "name"),)

    def test_alltypes_d (self):
        # Test decode of every non-TLV field type
        a = alltypes (testdata)
        self.assertEqual (a.bit1, 1)
        self.assertEqual (a.bit2, 2)
        self.assertEqual (a.bit6, 34)
        self.assertEqual (a.be, 4321)
        self.assertEqual (a.image, b"abcdef")
        self.assertEqual (a.int6, 16777217)
        self.assertEqual (a.extended, 384)
        self.assertEqual (a.sint, -246)
        self.assertEqual (a.byte5, b"bytes")
        self.assertEqual (a.int4, 257)
        self.assertEqual (a.node, Nodeid (1, 3))
        self.assertEqual (bytes (a), testdata2)

    def test_truncated (self):
        for l in range (1, len (testdata) - 1):
            try:
                a = alltypes (testdata[:l])
                self.fail ("Accepted truncated data: %d %s" % (l, a))
            except packet.DecodeError:
                pass
            except AssertionError:
                raise
            except Exception as e:
                self.fail ("Unexpected exception %s for input %s (len %d)"
                           % (e, testdata[:l], l))
        
    def test_alltypes_e (self):
        a = alltypes (bit1 = 1, bit2 = 2, bit6 = 18, be = BE2 (0, 511),
                      image = b"defghi", int6 = 32767,
                      extended = 12, sint = -2,
                      byte5 = b"hound", int4 = 511,
                      node = Nodeid (2, 2))
        print (a)
        b = bytes (a)
        self.assertEqual (b, b"\x95\x02\xfe\x01\006defghi\377\177\000\000\000\000"
                          b"\014\376\377hound\000\377\001\000\000\002\010")

    def test_alltypes_def (self):
        a = alltypes (node = Nodeid (1))    # Default what can be
        b = bytes (a)
        self.assertEqual (b, b"\000\000\000\000\000\000\000\000\000\000\000"
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
        with self.assertRaises (packet.ExtraData) as e:
            alltypes (testdata + b"x")

    def test_constfield (self):
        # Value defined in class is constant field
        class constimage (alltypes):
            image = b"foobar"
        a = constimage (testdata.replace (b"abcdef", b"foobar"))
        self.assertEqual (a.bit1, 1)
        self.assertEqual (a.bit2, 2)
        self.assertEqual (a.bit6, 34)
        self.assertEqual (a.be, 4321)
        self.assertEqual (a.image, b"foobar")
        self.assertEqual (a.int6, 16777217)
        self.assertEqual (a.extended, 384)
        self.assertEqual (a.sint, -246)
        self.assertEqual (a.byte5, b"bytes")
        self.assertEqual (a.int4, 257)
        self.assertEqual (a.node, Nodeid (1, 3))
        self.assertEqual (bytes (a), testdata2.replace (b"abcdef", b"foobar"))
        with self.assertRaises (packet.WrongValue) as e:
            constimage (testdata)

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

    def test_truncated_tlv (self):
        for l in range (1, len (tlvdata) - 1):
            try:
                a = alltlv (tlvdata[:l])
                # Truncated TLV still works if data ends on field boundary
            except packet.DecodeError:
                pass
            except Exception as e:
                self.fail ("Unexpected exception %s for input %s (len %d)"
                           % (e, tlvdata[:l], l))

    def test_tlv_err (self):
        # Check that unknown Type values are rejected if "wild" is False
        with self.assertRaises (packet.InvalidTag) as e:
            alltlv (tlvdata + b"\004\003xxx")

    def test_tlv_wild (self):
        # Check that unknown Type values are accepted if "wild" is True
        a = alltlv_w (tlvdata + b"\004\003abc\xfe\004Test")
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
        self.assertEqual (a.field4, b"abc")
        self.assertEqual (a.field254, b"Test")
        
if __name__ == "__main__":
    unittest.main ()

#!/usr/bin/env python3

from tests.dntest import *

import zlib

import crc
    
reverse = crc._reverse

# This table lists the parameters for all the CRCs given in the Wikipedia
# article, except for one whose length is unclear, plus one more taken
# from http://mathforum.org/kb/thread.jspa?threadID=508110&messageID=1553817
# It is used below to generate the test case classes for each of these.
generators = (( 1, "Parity", 0x1 ),
              ( 4, "ITU", 0x3 ),
              ( 5, "EPC", 0x9 ),
              ( 5, "ITU", 0x15 ),
              ( 5, "USB", 0x5 ),
              ( 6, "CDMA2000_A", 0x27 ),
              ( 6, "CDMA2000_B", 0x7 ),
              ( 6, "ITU", 0x3 ),
              ( 7, "", 0x9 ),
              ( 7, "MVB", 0x65 ),
              ( 8, "", 0xab ),
              ( 8, "CCITT", 0x7 ),
              ( 8, "Dallas", 0x31 ),
              ( 8, "SAE_J1850", 0x1d ),
              ( 8, "WCDMA", 0x9b ),
              ( 10, "", 0x233 ),
              ( 10, "CDMA2000", 0x3d9 ),
              ( 11, "", 0x385 ),
              ( 12, "", 0x80f ),
              ( 12, "CDMA2000", 0xf13 ),
              ( 13, "BBC", 0x1cf5 ),
              ( 15, "CAN", 0x4599 ),
              ( 15, "MPT1327", 0x6815 ),
              ( 16, "ARINC", 0xa02b ),
              ( 16, "CCITT", 0x1021 ),
              ( 16, "CDMA2000", 0xc867 ),
              ( 16, "DECT", 0x589 ),
              ( 16, "T10_DIF", 0x8bb7 ),
              ( 16, "DNP", 0x3d65 ),
              ( 16, "IBM", 0x8005 ),
              ( 17, "CAN", 0x1685b ),
              ( 21, "CAN", 0x102899 ),
              ( 24, "", 0x5d6dcb ),
              ( 24, "Radix_64", 0x864cfb ),
              ( 30, "", 0x2030b9c7 ),
              ( 32, "", 0x4c11db7 ),
              ( 32, "C", 0x1edc6f41 ),
              ( 32, "K", 0xeb31d82e ),
              ( 32, "Q", 0x814141ab ),
              ( 40, "GSM", 0x4820009 ),
              ( 64, "ECMA", 0x42f0e1eba9ea3693 ),
              ( 64, "ISO", 0x1b ),
              ( 128, "Zimmerman", 0x9b9346606fb953db45da2af80fb518cf ))

def randomdata (n, minlen, maxlen, step = 1):
    """Yield n pairs of length, value, where length is a random number
    from range (minlen, maxlen, step) and value is a random integer
    of that length.
    """
    for i in range (n):
        l = random.randrange (minlen, maxlen, step)
        yield l, random.getrandbits (l)

class Test_bitreverse (DnTest):
    """Test that crc._reverse works correctly.  It's an internal
    function so strictly speaking that isn't necessary, but we use
    it elsewhere in the tests and it's easy, so why not...
    """
    def ref_reverse (self, val, bits):
        """Bit-reverse val, which is "bits" bits long.  We do this by
        converting to a binary text string, reversing that, and converting
        back to integer.
        """
        s = "{:0>{}b}".format (val, bits)
        s = ''.join (reversed (s))
        return int (s, 2)

    def test_random (self):
        for l, v in randomdata (100, 1, 500):
            # reversal is symmetric
            self.assertEqual (v, reverse (reverse (v, l), l))
            # compare result against reference implementation
            self.assertEqual (reverse (v, l), self.ref_reverse (v, l))

class Test_lib_crc32 (DnTest):
    """Test CRC32 against the implementation in zlib.
    """
    class cls (crc.CRC, poly = 0x04c11db7, initial = True, final = True):
        pass

    def test_random (self):
        for l, v in randomdata (500, 8, 4096, 8):
            v = v.to_bytes (l // 8, "little")
            c1 = zlib.crc32 (v)
            c2 = self.cls (v).value
            self.assertEqual (c1, c2)

class crctestbase (DnTest):
    """Base class for testing a CRC with chosen parameters against
    the reference implementation.  The test case classes are derived
    from this, providing attributes poly, width, and reversed.
    The initial and final values are picked randomly.
    """
    @classmethod
    def setUpClass (cls):
        class testcrc (crc.CRC, poly = cls.poly, width = cls.width,
                       initial = cls.initial, final = cls.final,
                       reversed = cls.reversed):
            pass
        cls.cls = testcrc

    def ref_crc (self, data, bits):
        """Reference implementation of CRC -- the basic mechanism where
        the data bits are shifted into one end of the CRC register while
        the polynomial is XORed in based on the bit shifted out the other.
        """
        ini = self.cls.initial
        fin = self.cls.final
        # Flip data and initial/final around if reversed
        if self.reversed:
            ini = reverse (ini, self.width)
            fin = reverse (fin, self.width)
            data = reverse (data, bits)
        # Append zero bits
        data <<= self.width
        # Apply the initial XOR
        data ^= ini << bits
        ret = 0
        topbit = 1 << (bits + self.width - 1)
        mask = (1 << self.width) - 1
        # Loop through the data
        for i in range (bits + self.width):
            ret <<= 1
            if data & topbit:
                ret += 1
            data <<= 1
            if ret > mask:
                ret = (ret & mask) ^ self.poly
        # Apply the final XOR
        ret ^= fin
        # Flip result if reversed
        if self.reversed:
            ret = reverse (ret, self.width)
        return ret

    def test_attributes (self):
        """Verify that the attributes of the CRC class are correct.
        """
        self.assertEqual (self.cls.poly, self.poly)
        self.assertEqual (self.cls.width, self.width)
        self.assertEqual (self.cls.reversed, self.reversed)
        mask = (1 << self.width) - 1
        if self.initial is True:
            self.assertEqual (self.cls.initial, mask)
        else:
            self.assertEqual (self.cls.initial, self.initial)
        if self.final is True:
            self.assertEqual (self.cls.final, mask)
        else:
            self.assertEqual (self.cls.final, self.final)

    def test_random_bytes (self):
        """Check the CRC calculation for random byte strings.
        """
        for l, v in randomdata (100, 8, 2000, 8):
            c1 = self.ref_crc (v, l)
            if self.reversed:
                data = v.to_bytes (l // 8, "little")
            else:
                data = v.to_bytes (l // 8, "big")
            c = self.cls (data)
            self.assertEqual (c1, c.value)
            # Verify the "good" check
            c.update_bits (c.value, c.width)
            self.assertTrue (c.good)
        
    def test_random_bits (self):
        """Check the CRC calculation for random bit strings.
        """
        for l, v in randomdata (100, 8, 2000):
            c1 = self.ref_crc (v, l)
            c = self.cls ()
            c.update_bits (v, l)
            self.assertEqual (c1, c.value)
            # Verify the "good" check
            c.update_bits (c.value, c.width)
            self.assertTrue (c.good)
        
    def test_random_pieces (self):
        """Check the CRC calculation done piecemeal in random lengths.
        """
        for l, v in randomdata (100, 8, 2000):
            c1 = self.ref_crc (v, l)
            c = self.cls ()
            while l:
                if l <= 2:
                    p = l
                else:
                    p = random.randrange (2, l)
                if self.reversed:
                    mask = (1 << p) - 1
                    data = v & mask
                    v >>= p
                else:
                    rest = l - p
                    mask = (1 << rest) - 1
                    data = v >> rest
                    v &= mask
                l -= p
                c.update_bits (data, p)
            self.assertEqual (c1, c.value)
            # Verify the "good" check
            c.update_bits (c.value, c.width)
            self.assertTrue (c.good)

# Generate the specific test cases.  We do this by generating the
# classes dynamically, and adding them as module level names through
# the "global" dict.  
glob = globals ()
for width, name, poly in generators:
    if name:
        name = "Test_CRC_{}_{}".format (width, name)
    else:
        name = "Test_CRC_{}".format (width)
    cdict = dict (initial = random.getrandbits (width),
                  final = random.getrandbits (width),
                  poly = poly, width = width, reversed = False)
    # Generate the "forward" class
    glob[name] = type (name, (crctestbase,), cdict)
    # Now the "reverse" class
    name += "_rev"
    cdict["reversed"] = True
    glob[name] = type (name, (crctestbase,), cdict)

if __name__ == "__main__":
    unittest.main ()
    

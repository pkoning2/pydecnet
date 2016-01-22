#!/usr/bin/env python3

from tests.dntest import *

import zlib

import crc
    
reverse = crc._reverse

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
        cls.initial = ini = random.getrandbits (cls.width)
        cls.final = fin = random.getrandbits (cls.width)
        class testcrc (crc.CRC, poly = cls.poly, width = cls.width,
                       initial = ini, final = fin, reversed = cls.reversed):
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
        """Check the CRC class against a reference implementation for
        messages that are an integral multiple of 8 bits in length.
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
        """Check the CRC class against a reference implementation for
        messages that are any length (not just multiples of 8).
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
        """Check the CRC class against a reference implementation
        with the data supplies to the class in random length pieces.
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
        
# The following test classes check all the CRCs given in the Wikipedia
# article  (except for one whose length is unclear).  Both the regular
# and reversed cases are generated.
class Test_CRC_1_Parity (crctestbase):
    poly = 0x1
    width = 1
    reversed = False
class Test_CRC_1_Parity_r (Test_CRC_1_Parity):
    reversed = True
class Test_CRC_4_ITU (crctestbase):
    poly = 0x3
    width = 4
    reversed = False
class Test_CRC_4_ITU_r (Test_CRC_4_ITU):
    reversed = True
class Test_CRC_5_EPC (crctestbase):
    poly = 0x9
    width = 5
    reversed = False
class Test_CRC_5_EPC_r (Test_CRC_5_EPC):
    reversed = True
class Test_CRC_5_ITU (crctestbase):
    poly = 0x15
    width = 5
    reversed = False
class Test_CRC_5_ITU_r (Test_CRC_5_ITU):
    reversed = True
class Test_CRC_5_USB (crctestbase):
    poly = 0x5
    width = 5
    reversed = False
class Test_CRC_5_USB_r (Test_CRC_5_USB):
    reversed = True
class Test_CRC_6_CDMA2000_A (crctestbase):
    poly = 0x27
    width = 6
    reversed = False
class Test_CRC_6_CDMA2000_A_r (Test_CRC_6_CDMA2000_A):
    reversed = True
class Test_CRC_6_CDMA2000_B (crctestbase):
    poly = 0x7
    width = 6
    reversed = False
class Test_CRC_6_CDMA2000_B_r (Test_CRC_6_CDMA2000_B):
    reversed = True
class Test_CRC_6_ITU (crctestbase):
    poly = 0x3
    width = 6
    reversed = False
class Test_CRC_6_ITU_r (Test_CRC_6_ITU):
    reversed = True
class Test_CRC_7 (crctestbase):
    poly = 0x9
    width = 7
    reversed = False
class Test_CRC_7_r (Test_CRC_7):
    reversed = True
class Test_CRC_7_MVB (crctestbase):
    poly = 0x65
    width = 7
    reversed = False
class Test_CRC_7_MVB_r (Test_CRC_7_MVB):
    reversed = True
class Test_CRC_8 (crctestbase):
    poly = 0xab
    width = 8
    reversed = False
class Test_CRC_8_r (Test_CRC_8):
    reversed = True
class Test_CRC_8_CCITT (crctestbase):
    poly = 0x7
    width = 8
    reversed = False
class Test_CRC_8_CCITT_r (Test_CRC_8_CCITT):
    reversed = True
class Test_CRC_8_Dallas (crctestbase):
    poly = 0x31
    width = 8
    reversed = False
class Test_CRC_8_Dallas_r (Test_CRC_8_Dallas):
    reversed = True
class Test_CRC_8_SAE_J1850 (crctestbase):
    poly = 0x1d
    width = 8
    reversed = False
class Test_CRC_8_SAE_J1850_r (Test_CRC_8_SAE_J1850):
    reversed = True
class Test_CRC_8_WCDMA (crctestbase):
    poly = 0x9b
    width = 8
    reversed = False
class Test_CRC_8_WCDMA_r (Test_CRC_8_WCDMA):
    reversed = True
class Test_CRC_10 (crctestbase):
    poly = 0x233
    width = 10
    reversed = False
class Test_CRC_10_r (Test_CRC_10):
    reversed = True
class Test_CRC_10_CDMA2000 (crctestbase):
    poly = 0x3d9
    width = 10
    reversed = False
class Test_CRC_10_CDMA2000_r (Test_CRC_10_CDMA2000):
    reversed = True
class Test_CRC_11 (crctestbase):
    poly = 0x385
    width = 11
    reversed = False
class Test_CRC_11_r (Test_CRC_11):
    reversed = True
class Test_CRC_12 (crctestbase):
    poly = 0x80f
    width = 12
    reversed = False
class Test_CRC_12_r (Test_CRC_12):
    reversed = True
class Test_CRC_12_CDMA2000 (crctestbase):
    poly = 0xf13
    width = 12
    reversed = False
class Test_CRC_12_CDMA2000_r (Test_CRC_12_CDMA2000):
    reversed = True
class Test_CRC_13_BBC (crctestbase):
    poly = 0x1cf5
    width = 13
    reversed = False
class Test_CRC_13_BBC_r (Test_CRC_13_BBC):
    reversed = True
class Test_CRC_15_CAN (crctestbase):
    poly = 0x4599
    width = 15
    reversed = False
class Test_CRC_15_CAN_r (Test_CRC_15_CAN):
    reversed = True
class Test_CRC_15_MPT1327 (crctestbase):
    poly = 0x6815
    width = 15
    reversed = False
class Test_CRC_15_MPT1327_r (Test_CRC_15_MPT1327):
    reversed = True
class Test_CRC_16_ARINC (crctestbase):
    poly = 0xa02b
    width = 16
    reversed = False
class Test_CRC_16_ARINC_r (Test_CRC_16_ARINC):
    reversed = True
class Test_CRC_16_CCITT (crctestbase):
    poly = 0x1021
    width = 16
    reversed = False
class Test_CRC_16_CCITT_r (Test_CRC_16_CCITT):
    reversed = True
class Test_CRC_16_CDMA2000 (crctestbase):
    poly = 0xc867
    width = 16
    reversed = False
class Test_CRC_16_CDMA2000_r (Test_CRC_16_CDMA2000):
    reversed = True
class Test_CRC_16_DECT (crctestbase):
    poly = 0x589
    width = 16
    reversed = False
class Test_CRC_16_DECT_r (Test_CRC_16_DECT):
    reversed = True
class Test_CRC_16_T10_DIF (crctestbase):
    poly = 0x8bb7
    width = 16
    reversed = False
class Test_CRC_16_T10_DIF_r (Test_CRC_16_T10_DIF):
    reversed = True
class Test_CRC_16_DNP (crctestbase):
    poly = 0x3d65
    width = 16
    reversed = False
class Test_CRC_16_DNP_r (Test_CRC_16_DNP):
    reversed = True
class Test_CRC_16_IBM (crctestbase):
    poly = 0x8005
    width = 16
    reversed = False
class Test_CRC_16_IBM_r (Test_CRC_16_IBM):
    reversed = True
class Test_CRC_17_CAN (crctestbase):
    poly = 0x1685b
    width = 17
    reversed = False
class Test_CRC_17_CAN_r (Test_CRC_17_CAN):
    reversed = True
class Test_CRC_21_CAN (crctestbase):
    poly = 0x102899
    width = 21
    reversed = False
class Test_CRC_21_CAN_r (Test_CRC_21_CAN):
    reversed = True
class Test_CRC_24 (crctestbase):
    poly = 0x5d6dcb
    width = 24
    reversed = False
class Test_CRC_24_r (Test_CRC_24):
    reversed = True
class Test_CRC_24_Radix_64 (crctestbase):
    poly = 0x864cfb
    width = 24
    reversed = False
class Test_CRC_24_Radix_64_r (Test_CRC_24_Radix_64):
    reversed = True
class Test_CRC_30 (crctestbase):
    poly = 0x2030b9c7
    width = 30
    reversed = False
class Test_CRC_30_r (Test_CRC_30):
    reversed = True
class Test_CRC_32 (crctestbase):
    poly = 0x4c11db7
    width = 32
    reversed = False
class Test_CRC_32_r (Test_CRC_32):
    reversed = True
class Test_CRC_32_C (crctestbase):
    poly = 0x1edc6f41
    width = 32
    reversed = False
class Test_CRC_32_C_r (Test_CRC_32_C):
    reversed = True
class Test_CRC_32_K (crctestbase):
    poly = 0xeb31d82e
    width = 32
    reversed = False
class Test_CRC_32_K_r (Test_CRC_32_K):
    reversed = True
class Test_CRC_32_Q (crctestbase):
    poly = 0x814141ab
    width = 32
    reversed = False
class Test_CRC_32_Q_r (Test_CRC_32_Q):
    reversed = True
class Test_CRC_40_GSM (crctestbase):
    poly = 0x4820009
    width = 40
    reversed = False
class Test_CRC_40_GSM_r (Test_CRC_40_GSM):
    reversed = True
class Test_CRC_64_ECMA (crctestbase):
    poly = 0x42f0e1eba9ea3693
    width = 64
    reversed = False
class Test_CRC_64_ECMA_r (Test_CRC_64_ECMA):
    reversed = True
class Test_CRC_64_ISO (crctestbase):
    poly = 0x1b
    width = 64
    reversed = False
class Test_CRC_64_ISO_r (Test_CRC_64_ISO):
    reversed = True
# These two are from
# http://mathforum.org/kb/thread.jspa?threadID=508110&messageID=1553817
class Test_CRC_128_Zimmerman (crctestbase):
    poly = 0x9b9346606fb953db45da2af80fb518cf
    width = 128
    reversed = False
class Test_CRC_128_Zimmerman_r (Test_CRC_128_Zimmerman):
    reversed = True
    
if __name__ == "__main__":
    unittest.main ()
    

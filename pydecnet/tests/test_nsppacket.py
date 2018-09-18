#!/usr/bin/env python3

from tests.dntest import *

from decnet import nsp
from decnet import logging

rcount = 5000
rmin = 0
rmax = 40
    
class test_packets (DnTest):

    def test_ackdata (self):
        p = b"\x04\x03\x00\x05\x01\x02\x80"
        ackdat = self.short (p, nsp.AckData, maxlen = 6)
        self.assertEqual (ackdat.dstaddr, 3)
        self.assertEqual (ackdat.srcaddr, 261)
        self.assertEqual (ackdat.acknum.num, 2)
        self.assertFalse (ackdat.acknum.is_nak ())
        self.assertEqual (ackdat.acknum.chan (1, 2), 1)
        self.assertFalse (ackdat.acknum.is_cross ())
        self.assertIsNone (ackdat.acknum2)
        # encode
        p2 = nsp.AckData (dstaddr = 3, srcaddr = 261,
                          acknum = nsp.AckNum (2))
        self.assertEqual (p, bytes (p2))
        # With cross-channel field
        p = b"\x04\x03\x00\x05\x01\x02\x80\x05\xb0"
        ackdat = nsp.AckData (p)
        self.assertEqual (ackdat.dstaddr, 3)
        self.assertEqual (ackdat.srcaddr, 261)
        self.assertEqual (ackdat.acknum.num, 2)
        self.assertFalse (ackdat.acknum.is_nak ())
        self.assertEqual (ackdat.acknum.chan (1, 2), 1)
        self.assertFalse (ackdat.acknum.is_cross ())
        self.assertEqual (ackdat.acknum2.num, 5)
        self.assertTrue (ackdat.acknum2.is_nak ())
        self.assertEqual (ackdat.acknum2.chan (1, 2), 2)
        self.assertTrue (ackdat.acknum2.is_cross ())
        # encode
        p2 = nsp.AckData (dstaddr = 3, srcaddr = 261,
                          acknum = nsp.AckNum (2),
                          acknum2 = nsp.AckNum (5, nsp.AckNum.XNAK))
        self.assertEqual (p, bytes (p2))
        # Invalid qual subfield is not an error but the field is ignored
        p = b"\x04\x03\x00\x05\x01\x05\x80\x07\xc0"
        ackdat = nsp.AckData (p)
        self.assertIsNone (ackdat.acknum2)

    def test_ackother (self):
        p = b"\x14\x03\x00\x05\x01\x02\x80"
        ackoth = self.short (p, nsp.AckOther, maxlen = 6)
        self.assertEqual (ackoth.dstaddr, 3)
        self.assertEqual (ackoth.srcaddr, 261)
        self.assertEqual (ackoth.acknum.num, 2)
        self.assertFalse (ackoth.acknum.is_nak ())
        self.assertEqual (ackoth.acknum.chan (1, 2), 1)
        self.assertFalse (ackoth.acknum.is_cross ())
        self.assertIsNone (ackoth.acknum2)
        # encode
        p2 = nsp.AckOther (dstaddr = 3, srcaddr = 261,
                           acknum = nsp.AckNum (2))
        self.assertEqual (p, bytes (p2))
        # With cross-channel field
        p = b"\x14\x03\x00\x05\x01\x02\x80\x05\xb0"
        ackoth = nsp.AckOther (p)
        self.assertEqual (ackoth.dstaddr, 3)
        self.assertEqual (ackoth.srcaddr, 261)
        self.assertEqual (ackoth.acknum.num, 2)
        self.assertFalse (ackoth.acknum.is_nak ())
        self.assertEqual (ackoth.acknum.chan (1, 2), 1)
        self.assertFalse (ackoth.acknum.is_cross ())
        self.assertEqual (ackoth.acknum2.num, 5)
        self.assertTrue (ackoth.acknum2.is_nak ())
        self.assertEqual (ackoth.acknum2.chan (1, 2), 2)
        self.assertTrue (ackoth.acknum2.is_cross ())
        # encode
        p2 = nsp.AckOther (dstaddr = 3, srcaddr = 261,
                           acknum = nsp.AckNum (2),
                           acknum2 = nsp.AckNum (5, nsp.AckNum.XNAK))
        self.assertEqual (p, bytes (p2))
        # Invalid qual subfield is not an error but the field is ignored
        p = b"\x14\x03\x00\x05\x01\x05\x80\x07\xc0"
        ackoth = nsp.AckOther (p)
        self.assertIsNone (ackoth.acknum2)

    def test_ackconn (self):
        p = b"\x24\x03\x00"
        ackconn = self.short (p, nsp.AckConn)
        self.assertEqual (ackconn.dstaddr, 3)
        p2 = nsp.AckConn (dstaddr = 3)
        self.assertEqual (p, bytes (p2))
        
    def test_data (self):
        p = b"\x60\x03\x00\x05\x01\x07\x00payload"
        dat = self.short (p, nsp.DataSeg, maxlen = 6)
        self.assertTrue (dat.bom)
        self.assertTrue (dat.eom)
        self.assertEqual (dat.dstaddr, 3)
        self.assertEqual (dat.srcaddr, 261)
        self.assertIsNone (dat.acknum)
        self.assertIsNone (dat.acknum2)
        self.assertEqual (dat.segnum, 7)
        self.assertEqual (dat.payload, b"payload")
        # Ditto but no payload
        p0 = b"\x60\x03\x00\x05\x01\x07\x00"
        dat = self.short (p0, nsp.DataSeg, maxlen = 6)
        self.assertTrue (dat.bom)
        self.assertTrue (dat.eom)
        self.assertEqual (dat.dstaddr, 3)
        self.assertEqual (dat.srcaddr, 261)
        self.assertIsNone (dat.acknum)
        self.assertIsNone (dat.acknum2)
        self.assertEqual (dat.segnum, 7)
        self.assertEqual (dat.payload, b"")
        # encode
        dat = nsp.DataSeg (bom = True, eom = True, dstaddr = 3,
                           srcaddr = 261, segnum = 7, payload = b"payload")
        self.assertEqual (dat.encode (), p)
        # With one acknum
        p = b"\x00\x03\x00\x05\x01\x09\x80\x07\x00payload"
        dat = self.short (p, nsp.DataSeg, maxlen = 8)
        self.assertFalse (dat.bom)
        self.assertFalse (dat.eom)
        self.assertEqual (dat.dstaddr, 3)
        self.assertEqual (dat.srcaddr, 261)
        self.assertEqual (dat.acknum.num, 9)
        self.assertFalse (dat.acknum.is_nak ())
        self.assertFalse (dat.acknum.is_cross ())
        self.assertIsNone (dat.acknum2)
        self.assertEqual (dat.segnum, 7)
        self.assertEqual (dat.payload, b"payload")
        # encode
        dat = nsp.DataSeg (bom = False, eom = False, dstaddr = 3,
                           acknum = nsp.AckNum (9),
                           srcaddr = 261, segnum = 7, payload = b"payload")
        self.assertEqual (dat.encode (), p)
        # With two acknums
        p = b"\x40\x03\x00\x05\x01\x09\x80\x06\xa0\x07\x00payload"
        dat = self.short (p, nsp.DataSeg, maxlen = 10)
        self.assertFalse (dat.bom)
        self.assertTrue (dat.eom)
        self.assertEqual (dat.dstaddr, 3)
        self.assertEqual (dat.srcaddr, 261)
        self.assertEqual (dat.acknum.num, 9)
        self.assertFalse (dat.acknum.is_nak ())
        self.assertFalse (dat.acknum.is_cross ())
        self.assertEqual (dat.acknum2.num, 6)
        self.assertFalse (dat.acknum2.is_nak ())
        self.assertTrue (dat.acknum2.is_cross ())
        self.assertEqual (dat.segnum, 7)
        self.assertEqual (dat.payload, b"payload")
        # encode
        dat = nsp.DataSeg (bom = False, eom = True, dstaddr = 3,
                           acknum = nsp.AckNum (9),
                           acknum2 = nsp.AckNum (6, nsp.AckNum.XACK),
                           srcaddr = 261, segnum = 7, payload = b"payload")
        self.assertEqual (dat.encode (), p)
        # Verify that high order bits in segnum are ignored
        p = b"\x60\x03\x00\x05\x01\x07\x60payload"
        dat = nsp.DataSeg (p)
        self.assertTrue (dat.bom)
        self.assertTrue (dat.eom)
        self.assertEqual (dat.dstaddr, 3)
        self.assertEqual (dat.srcaddr, 261)
        self.assertIsNone (dat.acknum)
        self.assertIsNone (dat.acknum2)
        self.assertEqual (dat.segnum, 7)
        self.assertEqual (dat.payload, b"payload")
        
    def test_intmsg (self):
        p = b"\x30\x03\x00\x05\x01\x07\x00payload"
        dat = self.short (p, nsp.IntMsg, maxlen = 6)
        self.assertEqual (dat.dstaddr, 3)
        self.assertEqual (dat.srcaddr, 261)
        self.assertIsNone (dat.acknum)
        self.assertIsNone (dat.acknum2)
        self.assertEqual (dat.segnum, 7)
        self.assertEqual (dat.payload, b"payload")
        # encode
        dat = nsp.IntMsg (dstaddr = 3,
                          srcaddr = 261, segnum = 7, payload = b"payload")
        self.assertEqual (dat.encode (), p)
        # With one acknum
        p = b"\x30\x03\x00\x05\x01\x09\x80\x07\x00payload"
        dat = self.short (p, nsp.IntMsg, maxlen = 8)
        self.assertEqual (dat.dstaddr, 3)
        self.assertEqual (dat.srcaddr, 261)
        self.assertEqual (dat.acknum.num, 9)
        self.assertFalse (dat.acknum.is_nak ())
        self.assertFalse (dat.acknum.is_cross ())
        self.assertIsNone (dat.acknum2)
        self.assertEqual (dat.segnum, 7)
        self.assertEqual (dat.payload, b"payload")
        # encode
        dat = nsp.IntMsg (dstaddr = 3,
                          acknum = nsp.AckNum (9),
                          srcaddr = 261, segnum = 7, payload = b"payload")
        self.assertEqual (dat.encode (), p)
        # With two acknums
        p = b"\x30\x03\x00\x05\x01\x09\x80\x06\xa0\x07\x00payload"
        dat = self.short (p, nsp.IntMsg, maxlen = 10)
        self.assertEqual (dat.dstaddr, 3)
        self.assertEqual (dat.srcaddr, 261)
        self.assertEqual (dat.acknum.num, 9)
        self.assertFalse (dat.acknum.is_nak ())
        self.assertFalse (dat.acknum.is_cross ())
        self.assertEqual (dat.acknum2.num, 6)
        self.assertFalse (dat.acknum2.is_nak ())
        self.assertTrue (dat.acknum2.is_cross ())
        self.assertEqual (dat.segnum, 7)
        self.assertEqual (dat.payload, b"payload")
        # encode
        dat = nsp.IntMsg (dstaddr = 3,
                          acknum = nsp.AckNum (9),
                          acknum2 = nsp.AckNum (6, nsp.AckNum.XACK),
                          srcaddr = 261, segnum = 7, payload = b"payload")
        self.assertEqual (dat.encode (), p)
        # Verify that high order bits in segnum are ignored
        p = b"\x30\x03\x00\x05\x01\x07\x60payload"
        dat = nsp.IntMsg (p)
        self.assertEqual (dat.dstaddr, 3)
        self.assertEqual (dat.srcaddr, 261)
        self.assertIsNone (dat.acknum)
        self.assertIsNone (dat.acknum2)
        self.assertEqual (dat.segnum, 7)
        self.assertEqual (dat.payload, b"payload")
        
    def test_lsmsg (self):
        p = b"\x10\x03\x00\x05\x01\x07\x00\x06\xfd"
        dat = self.short (p, nsp.LinkSvcMsg)
        self.assertEqual (dat.dstaddr, 3)
        self.assertEqual (dat.srcaddr, 261)
        self.assertIsNone (dat.acknum)
        self.assertIsNone (dat.acknum2)
        self.assertEqual (dat.segnum, 7)
        self.assertEqual (dat.fcmod, 2)
        self.assertEqual (dat.fcval_int, 1)
        self.assertEqual (dat.fcval, -3)
        # encode
        dat = nsp.LinkSvcMsg (dstaddr = 3,
                              srcaddr = 261, segnum = 7,
                              fcmod = 2, fcval_int = 1, fcval = -3)
        self.assertEqual (dat.encode (), p)
        # With one acknum
        p = b"\x10\x03\x00\x05\x01\x09\x80\x07\x00\x06\x05"
        dat = nsp.LinkSvcMsg (p)
        self.assertEqual (dat.dstaddr, 3)
        self.assertEqual (dat.srcaddr, 261)
        self.assertEqual (dat.acknum.num, 9)
        self.assertFalse (dat.acknum.is_nak ())
        self.assertFalse (dat.acknum.is_cross ())
        self.assertIsNone (dat.acknum2)
        self.assertEqual (dat.segnum, 7)
        self.assertEqual (dat.fcmod, 2)
        self.assertEqual (dat.fcval_int, 1)
        self.assertEqual (dat.fcval, 5)
        # encode
        dat = nsp.LinkSvcMsg (dstaddr = 3,
                              acknum = nsp.AckNum (9),
                              srcaddr = 261, segnum = 7,
                              fcmod = 2, fcval_int = 1, fcval = 5)
        self.assertEqual (dat.encode (), p)
        # With two acknums
        p = b"\x10\x03\x00\x05\x01\x09\x80\x06\xa0\x07\x00\x05\x05"
        dat = nsp.LinkSvcMsg (p)
        self.assertEqual (dat.dstaddr, 3)
        self.assertEqual (dat.srcaddr, 261)
        self.assertEqual (dat.acknum.num, 9)
        self.assertFalse (dat.acknum.is_nak ())
        self.assertFalse (dat.acknum.is_cross ())
        self.assertEqual (dat.acknum2.num, 6)
        self.assertFalse (dat.acknum2.is_nak ())
        self.assertTrue (dat.acknum2.is_cross ())
        self.assertEqual (dat.segnum, 7)
        self.assertEqual (dat.fcmod, 1)
        self.assertEqual (dat.fcval_int, 1)
        self.assertEqual (dat.fcval, 5)
        # encode
        dat = nsp.LinkSvcMsg (dstaddr = 3,
                              acknum = nsp.AckNum (9),
                              acknum2 = nsp.AckNum (6, nsp.AckNum.XACK),
                              srcaddr = 261, segnum = 7,
                              fcmod = 1, fcval_int = 1, fcval = 5)
        self.assertEqual (dat.encode (), p)
        # Verify that high order bits in segnum are ignored
        p = b"\x10\x03\x00\x05\x01\x07\x60\x00\x04"
        dat = nsp.LinkSvcMsg (p)
        self.assertEqual (dat.dstaddr, 3)
        self.assertEqual (dat.srcaddr, 261)
        self.assertIsNone (dat.acknum)
        self.assertIsNone (dat.acknum2)
        self.assertEqual (dat.segnum, 7)
        self.assertEqual (dat.fcmod, 0)
        self.assertEqual (dat.fcval_int, 0)
        self.assertEqual (dat.fcval, 4)
        # Verify that high order bits in lsflags are ignored
        p = b"\x10\x03\x00\x05\x01\x07\x00\xf0\x04"
        dat = nsp.LinkSvcMsg (p)
        self.assertEqual (dat.dstaddr, 3)
        self.assertEqual (dat.srcaddr, 261)
        self.assertIsNone (dat.acknum)
        self.assertIsNone (dat.acknum2)
        self.assertEqual (dat.segnum, 7)
        self.assertEqual (dat.fcmod, 0)
        self.assertEqual (dat.fcval_int, 0)
        self.assertEqual (dat.fcval, 4)

    def test_ci (self):
        p = b"\x18\x00\x00\x03\x00\x05\x02\x04\x02payload"
        ci = self.short (p, nsp.ConnInit, maxlen = 8)
        self.assertEqual (ci.subtype, nsp.NspHdr.CI)
        self.assertEqual (ci.srcaddr, 3)
        self.assertEqual (ci.fcopt, 1)
        self.assertEqual (ci.info, 2)
        self.assertEqual (ci.segsize, 516)
        self.assertEqual (ci.payload, b"payload")
        # encode
        ci = nsp.ConnInit (srcaddr = 3, fcopt = 1, info = 2, segsize = 516,
                           payload = b"payload", subtype = nsp.NspHdr.CI)
        self.assertEqual (bytes (ci), p)
        # Ditto but Retransmitted CI
        pr = b"\x68\x00\x00\x03\x00\x05\x02\x04\x02payload"
        ci = self.short (pr, nsp.ConnInit, maxlen = 8)
        self.assertEqual (ci.subtype, nsp.NspHdr.RCI)
        self.assertEqual (ci.srcaddr, 3)
        self.assertEqual (ci.fcopt, 1)
        self.assertEqual (ci.info, 2)
        self.assertEqual (ci.segsize, 516)
        self.assertEqual (ci.payload, b"payload")
        # encode
        ci = nsp.ConnInit (srcaddr = 3, fcopt = 1, info = 2, segsize = 516,
                           payload = b"payload", subtype = nsp.NspHdr.RCI)
        self.assertEqual (ci.encode (), pr)

    def test_cc (self):
        p = b"\x28\x0b\x00\x03\x00\x05\x02\x04\x02\x07payload"
        cc = self.short (p, nsp.ConnConf, maxlen = 9)
        self.assertEqual (cc.dstaddr, 11)
        self.assertEqual (cc.srcaddr, 3)
        self.assertEqual (cc.fcopt, 1)
        self.assertEqual (cc.info, 2)
        self.assertEqual (cc.segsize, 516)
        self.assertEqual (cc.data_ctl, b"payload")
        # encode
        cc = nsp.ConnConf (dstaddr = 11, srcaddr = 3, fcopt = 1,
                           info = 2, segsize = 516,
                           data_ctl = b"payload")
        self.assertEqual (bytes (cc), p)

    def test_di (self):
        # No payload, just a reason code
        p = b"\x38\x0b\x00\x03\x00\x05\x00\x00"
        di = self.short (p, nsp.DiscInit)
        self.assertEqual (di.dstaddr, 11)
        self.assertEqual (di.srcaddr, 3)
        self.assertEqual (di.reason, 5)
        self.assertEqual (di.data_ctl, b"")
        # With session control payload
        p = b"\x38\x0b\x00\x03\x00\x05\x00\x07payload"
        di = nsp.DiscInit (p)
        self.assertEqual (di.dstaddr, 11)
        self.assertEqual (di.srcaddr, 3)
        self.assertEqual (di.reason, 5)
        self.assertEqual (di.data_ctl, b"payload")
        # encode
        di = nsp.DiscInit (dstaddr = 11, srcaddr = 3, reason = 5,
                           data_ctl = b"payload")
        self.assertEqual (bytes (di), p)

    def test_dc (self):
        p = b"\x48\x0b\x00\x03\x00\x05\x00"
        dc = self.short (p, nsp.DiscConf)
        self.assertEqual (dc.dstaddr, 11)
        self.assertEqual (dc.srcaddr, 3)
        self.assertEqual (dc.reason, 5)
        # encode
        dc = nsp.DiscConf (dstaddr = 11, srcaddr = 3, reason = 5)
        self.assertEqual (bytes (dc), p)
        # Check the special cases, which are like DC but with
        # predefined reason codes
        # No Resources (1)
        p = b"\x48\x0b\x00\x03\x00\x01\x00"
        dc = self.short (p, nsp.NoRes)
        self.assertEqual (dc.dstaddr, 11)
        self.assertEqual (dc.srcaddr, 3)
        dc = nsp.NoRes (dstaddr = 11, srcaddr = 3)
        self.assertEqual (dc.encode (), p)
        # Disconnect Complete (42)
        p = b"\x48\x0b\x00\x03\x00\x2a\x00"
        dc = self.short (p, nsp.DiscComp)
        self.assertEqual (dc.dstaddr, 11)
        self.assertEqual (dc.srcaddr, 3)
        dc = nsp.DiscComp (dstaddr = 11, srcaddr = 3)
        self.assertEqual (dc.encode (), p)
        # No Link Terminate (43)
        p = b"\x48\x0b\x00\x03\x00\x2b\x00"
        dc = self.short (p, nsp.NoLink)
        self.assertEqual (dc.dstaddr, 11)
        self.assertEqual (dc.srcaddr, 3)
        dc = nsp.NoLink (dstaddr = 11, srcaddr = 3)
        self.assertEqual (dc.encode (), p)
        
class test_packets_err (DnTest):
    loglevel = logging.CRITICAL
    
    def test_ackdata (self):
        # Missing acknum field
        p = b"\x04\x03\x00\x05\x01"
        with self.assertRaises (nsp.InvalidAck) as e:
            nsp.AckData (p)
        # Two references to this subchannel
        p = b"\x04\x03\x00\x05\x01\x02\x80\x05\x90"
        with self.assertRaises (nsp.InvalidAck) as e:
            nsp.AckData (p)
        # Two references to other subchannel
        p = b"\x04\x03\x00\x05\x01\x02\xa0\x05\xa0"
        with self.assertRaises (nsp.InvalidAck) as e:
            nsp.AckData (p)

    def test_ackother (self):
        # Missing acknum field
        p = b"\x14\x03\x00\x05\x01"
        with self.assertRaises (nsp.InvalidAck) as e:
            nsp.AckOther (p)
        # Two references to this subchannel
        p = b"\x14\x03\x00\x05\x01\x02\x80\x05\x90"
        with self.assertRaises (nsp.InvalidAck) as e:
            nsp.AckOther (p)
        # Two references to other subchannel
        p = b"\x14\x03\x00\x05\x01\x02\xa0\x05\xa0"
        with self.assertRaises (nsp.InvalidAck) as e:
            nsp.AckOther (p)
        
    def test_lsmsg (self):
        # Bad fcmod is rejected
        p = b"\x10\x03\x00\x05\x01\x07\x60\x03\x04"
        with self.assertRaises (nsp.InvalidLS) as e:
            nsp.LinkSvcMsg (p)
        # Bad fcval_int is rejected
        p = b"\x10\x03\x00\x05\x01\x07\x60\x08\x04"
        with self.assertRaises (nsp.InvalidLS) as e:
            nsp.LinkSvcMsg (p)

if __name__ == "__main__":
    unittest.main ()

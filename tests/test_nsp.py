#!/usr/bin/env python3

from tests.dntest import *

import logging

from decnet import nsp
from decnet.timers import Timeout

rcount = 5000
rmin = 0
rmax = 40
    
class test_packets (DnTest):

    def test_ackdata (self):
        p = b"\x04\x03\x00\x05\x01\x02\x80"
        ackdat = nsp.AckData (p)
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
        # Error checks
        # Missing acknum field
        p = b"\x04\x03\x00\x05\x01"
        with self.assertRaises (events.Event) as e:
            nsp.AckData (p)
        self.assertEqual (e.exception.event, events.Event.fmt_err)
        # Two references to this subchannel
        p = b"\x04\x03\x00\x05\x01\x02\x80\x05\x90"
        with self.assertRaises (events.Event) as e:
            nsp.AckData (p)
        self.assertEqual (e.exception.event, events.Event.fmt_err)
        # Two references to other subchannel
        p = b"\x04\x03\x00\x05\x01\x02\xa0\x05\xa0"
        with self.assertRaises (events.Event) as e:
            nsp.AckData (p)
        self.assertEqual (e.exception.event, events.Event.fmt_err)
        # Invalid qual subfield is not an error but the field is ignored
        p = b"\x04\x03\x00\x05\x01\x05\x80\x07\xc0"
        ackdat = nsp.AckData (p)
        self.assertIsNone (ackdat.acknum2)

    def test_ackother (self):
        p = b"\x14\x03\x00\x05\x01\x02\x80"
        ackoth = nsp.AckOther (p)
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
        # Error checks
        # Missing acknum field
        p = b"\x14\x03\x00\x05\x01"
        with self.assertRaises (events.Event) as e:
            nsp.AckOther (p)
        self.assertEqual (e.exception.event, events.Event.fmt_err)
        # Two references to this subchannel
        p = b"\x14\x03\x00\x05\x01\x02\x80\x05\x90"
        with self.assertRaises (events.Event) as e:
            nsp.AckOther (p)
        self.assertEqual (e.exception.event, events.Event.fmt_err)
        # Two references to other subchannel
        p = b"\x14\x03\x00\x05\x01\x02\xa0\x05\xa0"
        with self.assertRaises (events.Event) as e:
            nsp.AckOther (p)
        self.assertEqual (e.exception.event, events.Event.fmt_err)
        # Invalid qual subfield is not an error but the field is ignored
        p = b"\x14\x03\x00\x05\x01\x05\x80\x07\xc0"
        ackoth = nsp.AckOther (p)
        self.assertIsNone (ackoth.acknum2)
        
    def test_ackconn (self):
        p = b"\x24\x03\x00"
        ackconn = nsp.AckConn (p)
        self.assertEqual (ackconn.dstaddr, 3)
        p2 = nsp.AckConn (dstaddr = 3)
        self.assertEqual (p, bytes (p2))
        
    def test_data (self):
        p = b"\x60\x03\x00\x05\x01\x07\x00payload"
        dat = nsp.DataSeg (p)
        self.assertTrue (dat.bom)
        self.assertTrue (dat.eom)
        self.assertEqual (dat.dstaddr, 3)
        self.assertEqual (dat.srcaddr, 261)
        self.assertIsNone (dat.acknum)
        self.assertIsNone (dat.acknum2)
        self.assertEqual (dat.segnum, 7)
        self.assertEqual (dat.payload, b"payload")
        # encode
        dat = nsp.DataSeg (bom = True, eom = True, dstaddr = 3,
                           srcaddr = 261, segnum = 7, payload = b"payload")
        self.assertEqual (dat.encode (), p)
        # With one acknum
        p = b"\x00\x03\x00\x05\x01\x09\x80\x07\x00payload"
        dat = nsp.DataSeg (p)
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
        dat = nsp.DataSeg (p)
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
        # Errors and the like
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
        dat = nsp.IntMsg (p)
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
        dat = nsp.IntMsg (p)
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
        dat = nsp.IntMsg (p)
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
        # Errors and the like
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
        dat = nsp.LinkSvcMsg (p)
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
        # Errors and the like
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
        # Bad fcmod is rejected
        p = b"\x10\x03\x00\x05\x01\x07\x60\x03\x04"
        with self.assertRaises (events.Event) as e:
            nsp.LinkSvcMsg (p)
        self.assertEqual (e.exception.event, events.Event.fmt_err)
        # Bad fcval_int is rejected
        p = b"\x10\x03\x00\x05\x01\x07\x60\x08\x04"
        with self.assertRaises (events.Event) as e:
            nsp.LinkSvcMsg (p)
        self.assertEqual (e.exception.event, events.Event.fmt_err)

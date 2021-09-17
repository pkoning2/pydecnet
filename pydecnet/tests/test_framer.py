#!/usr/bin/env python3

"""DDCMP Framer tests

This is not really a PyDECnet test, but rather a design verification
and QA test for the DDCMP Framer (AK-005,
https://github.com/pkoning2/ddcmp).

The full set of tests assumes that both the integral modem and RS-232
options are included in the framer as built, and that both have a
loopback connection installed (RX to TX on the coax connectors; pin 2
to 3 on the RS-232 DTE connector, with an external (simulated modem)
clock connected to the receive and transmit clock inputs).  Since
RS-232 loses signal integrity around 250 kbps or so (depending on the
specifics of the transceiver chips) the external clock should be set
to around 250 kHz.

If environment variable INTERNAL_ONLY is defined, any tests that use
external loopback are skipped.  If NO_DTE is defined, any external
tests for the DTE interface (which needs an externally supplied bit
clock from the connected modem) are skipped.

The test script automatically finds the installed framer.  If more
than one is installed, the last one found in the list of interfaces
will be used by default.  To force the use of a particular fraomer,
define environment variable DEV to be the interface name of the
desired framer.  If no framer is found, the entire test suite is
skipped.
"""

import time
import socket
import queue
import os

from tests.dntest import *
from decnet.common import *
from decnet import pcap
from decnet.ddcmp import FramerOn, FramerStatus, CRC16

MAXLEN = 1486
SYN4 = b"\226" * 4
SYN8 = SYN4 + SYN4

# oui is used to find framers; the framer interface address starts
# with the same 3 bytes as this one.
oui = Macaddr ("AA-00-03-00-00-00")

pcapPort = None
framer = None

# Sometimes I don't have external loop connections plugged in, this
# allows all those tests to be skipped rather than having lots of
# failures produced from missing signal.
if "INTERNAL_ONLY" in os.environ:
    # Set up to skip external loopback tests
    def external (f):
        return unittest.skip ("Internal tests only") (f)
else:
    def external (f):
        return f

DEV = os.environ.get ("DEV", None)

# Similarly, this allows DTE related tests to be omitted.  Those are
# the ones that require an externally sourced modem clock.
if "NO_DTE" in os.environ:
    # Set up to skip external loopback tests
    def dte (f):
        return unittest.skip ("DTE (modem clock) tests suppressed") (f)
else:
    def dte (f):
        return f

def findFramers ():
    # Returns a dictionary of tuples, keyed by interface name, value
    # is a pair of interface address and framer address.
    ret = dict ()
    for dn, desc, alist, flgs in pcap.findalldevs ():
        for sa, mask, ba, da in alist:
            try:
                addr = Macaddr (sa)
                if addr[:3] == oui[:3]:
                    ia = addr
                    framer = dn
                    iab = bytearray (ia)
                    iab[-1] += 1
                    fa = Macaddr (iab)
                    ret[framer] = (ia, fa)
                    break
            except ValueError:
                pass    # address isn't a MAC address
    return ret

def setUpModule ():
    global pcapPort, framer, ia, fa, HDR
    fdict = findFramers ()
    if not fdict or (DEV and DEV not in fdict):
        if DEV:
            print ("\nNo framer found at", DEV)
        raise unittest.SkipTest ("DDCMP framer not connected")
    if DEV:
        ia, fa = fdict[DEV]
        framer = DEV
    else:
        framer, addr = fdict.popitem ()
        ia, fa = addr
    # Outbound (to framer) Ethernet header
    HDR = bytes (fa) + bytes (ia) + b"\x60\x06"
    pcapPort = pcap.pcapObject ()
    # Don't need promiscuous mode
    pcapPort.open_live (framer, 1518, 1, 100)

def tearDownModule ():
    global pcapPort
    if pcapPort:
        pcapPort.close ()
        pcapPort = None
        
class FramerTest (DnTest):
    report_stats = False

    def setUp (self):
        self.last_status = None
        self.status_cnt = 0
        self.received = queue.Queue ()
        self.rthread = StopThread (target = self.rloop)
        self.rthread.start ()

    def tearDown (self):
        # Always send a stop, and flush the receive queue
        stat = self.send_off ()
        if self.report_stats:
            self.print_stat (stat - self.start_stat)
        self.rthread.stop (True)
        self.rthread = None
        
    def receive_frame (self, plen, packet, ts):
        if packet and packet[:6] == ia and \
           packet[12] == 0x60 and packet[13] == 0x06:
            pdusize = int.from_bytes (packet[14:16], "little")
            self.received.put (packet[16:16 + pdusize])
            
    def rloop (self):
        while not self.rthread.stopnow:
            try:
                cnt = pcapPort.dispatch (1, self.receive_frame)
            except pcap._pcap.error:
                raise
            
    def send_eth (self, buf):
        buf = makebytes (buf)
        l2 = pcapPort.inject (buf)
        if l2 < 0:
            # Error status
            print ("Error status: {}", pcapPort.geterr ())

    def send (self, buf):
        buf = makebytes (buf)
        self.send_eth (HDR + len (buf).to_bytes (2, "little") + buf)

    def send_cmd (self, data):
        self.send (b"\021" + data)
        return self.rcvstat ()

    def get_stat (self):
        return self.send_cmd (b"\000")
    
    def send_on (self, mode, speed, *, txspeed = 0,
                 loop = 0, bist = 0, split = 0, ddcmp_v3 = 0):
        cmd = FramerOn (da = fa, sa = ia)
        cmd.mode = mode
        cmd.speed = speed
        cmd.loop = loop
        cmd.bist = bist
        cmd.split = split
        cmd.ddcmp_v3 = ddcmp_v3
        cmd.txspeed = txspeed
        cmd.data_len = 12
        self.send_eth (cmd)
        ret = self.rcvstat ()
        self.start_stat = ret
        if ret.last_cmd_sts:
            # Some sort of error, stop now
            return ret
        for i in range (8):
            if ret.sync:
                self.start_stat = ret
                break
            time.sleep (0.1)
            ret = self.get_stat ()
        else:
            if mode != 1:
                self.assertNotEqual (ret.freq, 0, "Modem clock not present")
            self.fail ("No received data, check loopback connection")
        return ret

    def send_off (self):
        self.send (b"\021\x02")
        while True:
            stat = self.rcvstat ()
            if not stat.on:
                return stat

    def rcv (self, timeout = 2, stat = False):
        while True:
            try:
                pkt = self.received.get (timeout = timeout)
                if not pkt:
                    return None
                if pkt[2] == 0x11:
                    # Control message, save it and keep looking
                    self.last_status = FramerStatus (pkt[2:])
                    self.status_cnt += 1
                    if stat:
                        return 0, self.last_status
                else:
                    return int.from_bytes (pkt[:2], "little"), pkt[2:]
            except queue.Empty:
                return None

    def rcvstat (self, timeout = 2):
        cnt = self.status_cnt
        while True:
            ret = self.rcv (timeout, True)
            if ret is None:
                if self.status_cnt != cnt:
                    return self.last_status
                return None
            timeout = 0
            
    def print_stat (self, stat):
        flags = "on" if stat.on else "off"
        if stat.sync:
            flags += ", sync"
        print ("\nStatus:   ", flags)
        flags = ("rs-232 (modem clock)", "integral modem",
                 "rs-232 (local clock)", "??")[stat.mode]
        if stat.loop:
            flags += ", loopback"
        if stat.bist:
            flags += ", bist"
        if stat.split:
            flags += ", split speed"
        if stat.ddcmp_v3:
            flags += ", ddcmp dmc"
        print ("Flags:    ", flags)
        print ("SDU size: ", stat.sdusize)
        print ("Speed:    ", stat.speed, stat.txspeed)
        print ("Rx frames:", stat.rxframes)
        print ("Rx bytes :", stat.rxbytes)
        print ("Tx frames:", stat.txframes)
        print ("Tx bytes :", stat.txbytes)
        print ("HCRC err: ", stat.hcrc_err)
        print ("CRC err:  ", stat.crc_err)
        print ("Len err:  ", stat.len_err)
        print ("Nobuf err:", stat.nobuf_err)
        print ("Cmd sts:  ", stat.last_cmd_sts)
        print ("Frequency:", stat.freq)
        #print ("Version:  ", stat.version)
        if stat.hcrc_err or stat.crc_err:
            ber = stat.rxbytes * 8 / (stat.hcrc_err + stat.crc_err)
            print ("BER:       {:.2e}".format (ber))

    def looptest (self, n, timeout = 2):
        # Do n loop tests, each consisting of one each of the three
        # frame types.
        for i in range (n):
            for t in ( b"\005\000",
                       b"\201\004\000\001\002\003\000\000",
                       b"\220\004\000\001\002\003\000\000" ):
                buf = t + i.to_bytes (4, "little")
                self.send (buf)
                rstat, rdata = self.rcv (timeout)
                self.assertEqual (rstat, 0)
                self.assertEqual (rdata[:6] + rdata[8:-2],
                                  buf[:6] + buf[8:])

    def send_raw (self, buf):
        self.send (b"\021\003" + buf)
        
class Test00First (FramerTest):
    def test_status (self):
        stat = self.send_off ()
        print ("\n\nUnit under test: {} interface {} framer {},\n version: {}\n".format (framer, ia, fa, stat.version))
        # Expect status = off
        self.assertFalse (stat.on)
        self.assertEqual (stat.sdusize, MAXLEN)
        
class TestBasic (FramerTest):
    LOOP_TIME = 10
    
    def looptest (self, mode, speed, loop = 0, bist = 0):
        stat = self.send_on (mode, speed, loop = loop, bist = bist)
        self.assertTrue (stat.on)
        super ().looptest (self.LOOP_TIME)
        
    @external
    @dte
    def test_extloop_rs232_modem (self):
        "External loop test, RS-232 modem clock"
        # Set RS232, 56 kbps
        self.looptest (0, 0)
        stat = self.send_off ()
        self.assertNotEqual (stat.freq, 0, "Modem clock not connected")
        print ("\nModem clock frequency is {}".format (stat.freq))
        
    @external
    def test_extloop_rs232 (self):
        "External loop test, RS-232 local clock"
        # Set RS232, 56 kbps
        self.looptest (2, 56000)
        
    @external
    def test_extloop_im (self):
        "External loop test, integral modem"
        # Set integral modem, 1 Mb/s
        self.looptest (1, 1000000)
        
    def test_intloop_rs232 (self):
        "Internal loop test, RS-232"
        # Set RS232, loopback, 56 kbps
        self.looptest (2, 56000, loop = 1)
        
    def test_intloop_im (self):
        "Internal loop test, integral modem"
        # Set integral modem, loopback, 1 Mb/s
        self.looptest (1, 1000000, loop = 1)
        
    def test_sizes (self):
        "Loop test of a range of packet sizes"
        stat = self.send_on (1, 1000000, loop = 1)
        self.assertTrue (stat.on)
        for r in ( range (1, MAXLEN + 1, 50),
                   range (1, 30),
                   range (1450, MAXLEN + 1) ):
            for s in r:
                hdr = b"\201" + s.to_bytes (2, "little") + b"\003\004\005\000\000"
                self.send (hdr + bytes (s))
                rstat, rdata = self.rcv ()
                self.assertEqual (rstat, 0)
                self.assertEqual (rdata[:6], hdr[:6])
                self.assertEqual (len (rdata), s + 10)

class TestFreq (FramerTest):
    def test_freq_im_loop (self, loop = 1):
        "Measure frequency, integral modem loopback"
        stat = self.send_on (1, 1000000, loop = loop)
        self.assertTrue (stat.on)
        time.sleep (0.5)
        stat = self.get_stat ()
        # Look for a tolerance of 0.5 % (integral modem measurement is
        # approximate due to the fact it looks at the modulated signal
        # rather than an actual clock signal).
        self.assertAlmostEqual (stat.speed, stat.freq,
                                delta = stat.speed // 200)
        
    @external
    def test_freq_im (self):
        "Measure frequency, integral modem external loopback"
        self.test_freq_im_loop (0)
        
    def test_freq_rs232 (self):
        "Measure frequency, RS-232 local clock"
        stat = self.send_on (2, 250000, loop = 1)
        self.assertTrue (stat.on)
        time.sleep (0.5)
        stat = self.get_stat ()
        # Look for a tolerance of 0.2 %
        self.assertAlmostEqual (stat.speed, stat.freq,
                                delta = stat.speed // 500)

    @external
    @dte
    def test_freq_rs232_modem (self):
        "Measure frequency, RS-232 modem clock"
        stat = self.send_on (0, 0)
        self.assertTrue (stat.on)
        time.sleep (0.5)
        stat = self.get_stat ()
        self.assertNotEqual (stat.freq, 0, "Modem clock not connected")
        print ("\nModem clock frequency is {}".format (stat.freq))

class TestBist (FramerTest):
    BIST_TIME = 10
    
    def bisttest (self, mode, speed, txspeed = 0, loop = 0,
                  split = 0, ddcmp_v3 = 0):
        stat = self.send_on (mode, speed, txspeed = txspeed,
                             loop = loop, bist = 1, split = split,
                             ddcmp_v3 = ddcmp_v3)
        self.assertTrue (stat.on)
        if not speed:
            # Modem clock, display the speed
            time.sleep (1)
            stat = self.get_stat ()
            print ("\nModem speed:", stat.freq)
        time.sleep (self.BIST_TIME)
        stat = self.send_off ()
        stat = stat - self.start_stat
        # Receive and transmit frame counts may differ by up to 8 due
        # to queueing between core 0 and core 1, and the fact that
        # transmits are counted when submitted, not when completed.
        # Also force stats if report_stats is set.  Doing this here
        # rather than relying on tearDown to do it gives us stats for
        # tests like "long" which invokes several other test methods
        # one after the other.
        if stat.hcrc_err or stat.crc_err or stat.len_err or stat.nobuf_err \
           or not (0 <= stat.txframes - stat.rxframes <= 8) \
           or stat.rxframes <= 10 or self.report_stats:
            self.print_stat (stat)
            self.report_stats = False
            self.assertGreater (stat.rxframes, 10)
    @external
    @dte
    def test_bist_ext_rs232_modem (self):
        "Built-in self test, external loopback, RS-232 modem clock"
        # Set BIST, RS232, modem clock
        self.bisttest (0, 0)
        if not self.report_stats:
            stat = self.send_off ()
            self.assertNotEqual (stat.freq, 0, "Modem clock not connected")
            print ("\nModem clock frequency is {}".format (stat.freq))

    @external
    def test_bist_ext_rs232 (self):
        "Built-in self test, external loopback, RS-232 local clock"
        # Set BIST, RS232, 250 kbps
        self.bisttest (2, 250000)

    @external
    def test_bist_ext_im_56k (self):
        "Built-in self test, external loopback, integral modem, min speed"
        # Set BIST, integral modem, 56 kbps
        self.bisttest (1, 56000)
        
    @external
    def test_bist_ext_im_250k (self):
        "Built-in self test, external loopback, integral modem, min speed"
        # Set BIST, integral modem, 250 kbps
        self.bisttest (1, 250000)
        
    @external
    def test_bist_ext_im_500k (self):
        "Built-in self test, external loopback, integral modem, min speed"
        # Set BIST, integral modem, 500 kbps
        self.bisttest (1, 500000)
        
    @external
    def test_bist_ext_im_1m (self):
        "Built-in self test, external loopback, integral modem, max speed"
        # Set BIST, integral modem, 1 Mbps
        self.bisttest (1, 1000000)

    @external
    def test_bist_ext_im_1m_fasttx (self):
        "Built-in self test, external loopback, integral modem, 10% fast"
        # Set BIST, integral modem, 1 Mbps, transmit (inbound data) fast
        self.bisttest (1, 1000000, txspeed = 1100000, split = 1)
        
    @external
    def test_bist_ext_im_1m_slowtx (self):
        "Built-in self test, external loopback, integral modem, 10% slow"
        # Set BIST, integral modem, 1 Mbps, transmit (inbound data) slow
        self.bisttest (1, 1000000, txspeed = 900000, split = 1)
        
    @external
    def test_bist_ext_im_56k_fasttx (self):
        "Built-in self test, external loopback, integral modem, 10% fast"
        # Set BIST, integral modem, 56 kbps, transmit (inbound data)
        # ~10% fast.  This test helps confirm any data integrity
        # issues from the transformer coupling at the minimum
        # supported speed.
        self.bisttest (1, 56000, txspeed = 61600, split = 1)
        
    @external
    def test_bist_ext_im_56k_slowtx (self):
        "Built-in self test, external loopback, integral modem, 10% slow"
        # Set BIST, integral modem, 56 kbps, transmit (inbound data)
        # ~10% slow.  This test helps confirm any data integrity
        # issues from the transformer coupling at the minimum
        # supported speed.
        self.bisttest (1, 56000, txspeed = 50400, split = 1)
        
    def test_bist_int_rs232 (self):
        "Built-in self test, internal loopback, RS232"
        # Set BIST, RS232, 250 kbps
        self.bisttest (2, 250000, loop = 1)

    def test_bist_int_im (self):
        "Built-in self test, internal loopback, integral modem"
        # Set BIST, integral modem, 1 Mbps
        self.bisttest (1, 1000000, loop = 1)

    def test_bist_int_rs232_v3 (self):
        "Built-in self test, internal loopback, RS232, DDCMP DMC"
        # Set BIST, RS232, 250 kbps
        self.bisttest (2, 250000, loop = 1, ddcmp_v3 = 1)

    def test_bist_int_im_v3 (self):
        "Built-in self test, internal loopback, integral modem, DDCMP DMC"
        # Set BIST, integral modem, 1 Mbps
        self.bisttest (1, 1000000, loop = 1, ddcmp_v3 = 1)

    def test_bist_int_im_1m_fasttx (self):
        "Built-in self test, internal loopback, integral modem, 10% fast"
        # Set BIST, integral modem, 1 Mbps, transmit (inbound data) fast
        self.bisttest (1, 1000000, txspeed = 1100000, loop = 1, split = 1)
        
    def test_bist_int_im_1m_slowtx (self):
        "Built-in self test, internal loopback, integral modem, 10% slow"
        # Set BIST, integral modem, 1 Mbps, transmit (inbound data) slow
        self.bisttest (1, 1000000, txspeed = 900000, loop = 1, split = 1)
        
    # Methods below this point do not have test_<name> method names so
    # they are not run by default, but they can be invoked by their
    # full name.
    def bist_int_im_t2p5 (self):
        "Built-in self test, internal loopback integral modem, extra fast"
        # Set BIST, integral modem, 2.5 Mbps.
        self.bisttest (1, 2500000, loop = 1)

    def bist_int_im_t5 (self):
        "Built-in self test, internal loopback integral modem, extra fast"
        # Set BIST, integral modem, 5 Mbps.
        self.bisttest (1, 5000000, loop = 1)

    @external
    def bist_ext_im_t2p5 (self):
        "Built-in self test, external loopback integral modem, extra fast"
        # Set BIST, integral modem, 2.5 Mbps.
        self.bisttest (1, 2500000)

    @external
    def bist_ext_im_t5 (self):
        "Built-in self test, external loopback integral modem, extra fast"
        # Set BIST, integral modem, 5 Mbps.
        self.bisttest (1, 5000000)

    @external
    def long_bist_im_5m (self):
        "Run BIST for half an hour, external loop, integral modem, 5 Mbps"
        self.BIST_TIME = 600
        self.report_stats = True
        self.bisttest (1, 5000000)
        
    @external
    def long_bist_im_1m (self):
        "Run BIST for half an hour, external loop, integral modem, 1 Mbps"
        self.BIST_TIME = 600
        self.report_stats = True
        self.bisttest (1, 1000000)
        
    @external
    def long_bist_im_56k (self):
        "Run BIST for 10 minutes, external loop, integral modem, 56kbps"
        self.BIST_TIME = 600
        self.report_stats = True
        self.bisttest (1, 56000)
        
    @external
    def long_bist_rs232 (self):
        "Run BIST for 10 minutes, external loop, RS-232"
        self.BIST_TIME = 600
        self.report_stats = True
        self.bisttest (2, 250000)
        
    def long_bist_rs232_modem (self):
        "Run BIST for 10 minutes, external loop, RS-232 (modem clock)"
        self.BIST_TIME = 600
        self.report_stats = True
        self.bisttest (0, 0)

    def long (self):
        "Run five long BIST cases, 50 minutes total"
        self.long_bist_rs232_modem ()
        self.long_bist_rs232 ()
        self.long_bist_im_56k ()
        self.long_bist_im_1m ()
        # And overspeed
        self.long_bist_im_5m ()
        
class TestRaw (FramerTest):
    @external
    def test_concat_data (self, loop = 0):
        "Test concatenated data frames, external loop"
        #self.report_stats = True
        stat = self.send_on (1, 1000000, loop = loop)
        self.assertTrue (stat.on)
        buf = [ SYN8 ]
        count = 50
        payload = bytes (20)
        for i in range (count):
            msg = b"\201\022\000\001" + i.to_bytes (2, "little")
            crc = CRC16 (msg)
            buf.append (msg)
            buf.append (bytes (crc))
            buf.append (payload)
        buf = b"".join (buf)
        self.send_raw (buf)
        for i in range (count):
            rstat, msg = self.rcv ()
            self.assertEqual (rstat, 0)
            seq = int.from_bytes (msg[4:6], "little")
            self.assertEqual (seq, i)

    def test_concat_data_loop (self):
        "Test concatenated data frames, internal loop"
        self.test_concat_data (1)
        
    @external
    def test_concat_ctl (self, loop = 0):
        "Test concatenated control frames, external loop"
        # Speed 500k because faster causes no-buffers error due to the
        # overhead of padding.
        stat = self.send_on (1, 500000, loop = loop)
        self.assertTrue (stat.on)
        buf = [ SYN8 ]
        count = 150
        for i in range (count):
            msg = b"\005\000\000\001" + i.to_bytes (2, "little")
            crc = CRC16 (msg)
            buf.append (msg)
            buf.append (bytes (crc))
        buf = b"".join (buf)
        self.send_raw (buf)
        for i in range (count):
            ret = self.rcv ()
            if not ret:
                self.report_stats = True
                self.assertEqual (i, count, "Not enough received messages")
            rstat, msg = ret
            self.assertEqual (rstat, 0)
            seq = int.from_bytes (msg[4:6], "little")
            self.assertEqual (seq, i)

    def test_concat_ctl_loop (self):
        "Test concatenated control frames, internal loop"
        self.test_concat_ctl (1)
        
    def test_minsync (self):
        "Test resync with just 4 SYN bytes"
        stat = self.send_on (1, 1000000, loop = 1)
        self.assertTrue (stat.on)
        msg = SYN8 + b"\005" + bytes (99) + SYN4
        msg2 = b"\005abcde"
        msg += msg2 + bytes (CRC16 (msg2))
        self.send_raw (msg)
        rstat, rdata = self.rcv ()
        self.assertEqual (rstat, 1)
        self.assertEqual (rdata[:6], b"\005" + bytes (5))
        rstat, rdata = self.rcv ()
        self.assertEqual (rstat, 0)
        self.assertEqual (rdata[:6], msg2)
        
class TestErrors (FramerTest):
    "Test handling of invalid inputs"
    def test_slow (self):
        "Too slow speed"
        stat = self.send_on (1, 476)
        self.assertFalse (stat.on)
        self.assertEqual (stat.last_cmd_sts, 4)  # bad speed

    def test_fast (self):
        "Too fast speed"
        stat = self.send_on (1, 11000000)
        self.assertFalse (stat.on)
        self.assertEqual (stat.last_cmd_sts, 4)  # bad speed

    def test_bad_cmd (self):
        "Invalid command code"
        stat = self.send_cmd (b"\004")
        self.assertFalse (stat.on)
        self.assertEqual (stat.last_cmd_sts, 2)  # unknown command

    def test_short_start_cmd (self):
        "Short start command"
        stat = self.send_cmd (b"\001\001\000\001\002\003")
        self.assertFalse (stat.on)
        self.assertEqual (stat.last_cmd_sts, 1)  # short command

    def test_short_cmd (self):
        "Short command"
        stat = self.send_cmd (b"")
        self.assertFalse (stat.on)
        self.assertEqual (stat.last_cmd_sts, 1)  # short command
        
    def test_start2 (self):
        "Start when active"
        stat = self.send_on (1, 1000000, loop = 1)
        self.assertTrue (stat.on)
        stat = self.send_on (1, 1000000, loop = 1)
        self.assertTrue (stat.on)
        self.assertEqual (stat.last_cmd_sts, 3)  # Already active

    def test_txoff (self):
        "Transmit when not active"
        # Make sure we're off
        stat = self.send_cmd (b"\002")
        self.assertFalse (stat.on)
        msg = b"\005abcde"
        self.send (msg)
        # Receive status triggered by the error
        stat = self.rcvstat ()
        self.assertFalse (stat.on)
        self.assertEqual (stat.last_cmd_sts, 6)
        
    def test_txshort_ctl (self):
        "Transmit too short control message"
        stat = self.send_on (1, 1000000, loop = 1)
        self.assertTrue (stat.on)
        msg = b"\005abcd"
        self.send (msg)
        # Receive status triggered by the error
        stat = self.rcvstat ()
        self.assertTrue (stat.on)
        self.assertEqual (stat.last_cmd_sts, 5)

    def test_txshort_data (self):
        "Transmit too short data message"
        stat = self.send_on (1, 1000000, loop = 1)
        self.assertTrue (stat.on)
        msg = b"\201\005\000abcpqrs"
        self.send (msg)
        # Receive status triggered by the error
        stat = self.rcvstat ()
        self.assertTrue (stat.on)
        self.assertEqual (stat.last_cmd_sts, 5)
        
    def test_txempty_data (self):
        "Transmit data message with zero length"
        stat = self.send_on (1, 1000000, loop = 1)
        self.assertTrue (stat.on)
        msg = b"\201\000\000abc"
        self.send (msg)
        # Receive status triggered by the error
        stat = self.rcvstat ()
        self.assertTrue (stat.on)
        self.assertEqual (stat.last_cmd_sts, 5)
        
    def test_txlong_data (self):
        "Transmit oversized data message"
        stat = self.send_on (1, 1000000, loop = 1)
        self.assertTrue (stat.on)
        long = 1487
        msg = b"\201" + long.to_bytes (2, "little") + bytes (long + 4)
        self.send (msg)
        # Receive status triggered by the error
        stat = self.rcvstat ()
        self.assertTrue (stat.on)
        self.assertEqual (stat.last_cmd_sts, 5)
        
    def test_rxlong_data (self):
        "Receive oversized data message"
        stat = self.send_on (1, 1000000, loop = 1)
        self.assertTrue (stat.on)
        long = 1487
        msg = b"\201" + long.to_bytes (2, "little") + bytes (3)
        msg += bytes (CRC16 (msg))
        self.send_raw (SYN8 + msg)
        rstat, msg = self.rcv ()
        self.assertEqual (rstat, 3)  # too long
        # Receive status message
        stat = self.get_stat ()
        diff = stat - self.start_stat
        self.assertEqual (diff.len_err, 1)

    def test_rxshort_data (self):
        "Receive zero length data message"
        stat = self.send_on (1, 1000000, loop = 1)
        self.assertTrue (stat.on)
        msg = b"\201" + bytes (5)
        msg += bytes (CRC16 (msg))
        self.send_raw (SYN8 + msg)
        rstat, msg = self.rcv ()
        self.assertEqual (rstat, 3)  # length error
        # Receive status message
        stat = self.get_stat ()
        diff = stat - self.start_stat
        self.assertEqual (diff.len_err, 1)

    def test_hcrc (self):
        "Test header CRC error"
        stat = self.send_on (1, 1000000, loop = 1)
        self.assertTrue (stat.on)
        msg = b"\005" + bytes (7)
        self.send_raw (SYN8 + msg)
        rstat, rmsg = self.rcv ()
        self.assertEqual (rstat, 1)
        self.assertEqual (rmsg, msg)
        stat = self.get_stat ()
        diff = stat - self.start_stat
        self.assertEqual (diff.hcrc_err, 1)
        
    def test_crc (self):
        "Test data CRC error"
        stat = self.send_on (1, 1000000, loop = 1)
        self.assertTrue (stat.on)
        hdr = b"\201\002" + bytes (4)
        msg1 = hdr + bytes (CRC16 (hdr)) + b"\001\000\000\000"
        # Put another message immediately after to confirm that data
        # CRC does not restart sync search
        msg2 = b"\005abcde"
        msg2 += bytes (CRC16 (msg2))
        msg = msg1 + msg2
        self.send_raw (SYN8 + msg)
        rstat, rmsg = self.rcv ()
        self.assertEqual (rstat, 2)
        self.assertEqual (rmsg, msg1)
        rstat, rmsg = self.rcv ()
        self.assertEqual (rstat, 0)
        self.assertEqual (rmsg, msg2)
        stat = self.get_stat ()
        diff = stat - self.start_stat
        self.assertEqual (diff.crc_err, 1)
        

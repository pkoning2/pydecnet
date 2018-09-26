#!/usr/bin/env python3

"""Unit test for the NSP layer.
"""

# To do:
# 1. Various ACK cases for outbound data
# 2. Out of order packets
# 3. Duplicate packets
# 4. Xoff flow control  **DONE
# 5. Queue limit
# 6. Bad ACKs
# 7. Bad flow control updates
# 8. Outbound disconnect (with data pending)
# 9. Outbound abort
# 10. Outbound connection accept and reject
# 11. Packets that are wrong for a given state (if any?)
# 12. Packets not matched to an open port (connection)
# 13. Phase II behavior: no CD, no CC state, DC instead of DI message.
# etc.

from tests.dntest import *
from decnet import nsp
from decnet import routing
from decnet import logging
from decnet import timers

class ntest (DnTest):
    myphase = 4
    qmax = nsp.Seq.maxdelta
    
    def setUp (self):
        super ().setUp ()
        self.node.phase = self.myphase
        self.config = container ()
        self.config.nsp = container ()
        self.config.nsp.max_connections = 511
        self.config.nsp.nsp_delay = 3
        self.config.nsp.nsp_weight = 3
        self.config.nsp.qmax = self.qmax
        self.node.routing = unittest.mock.Mock ()
        self.node.session = unittest.mock.Mock ()
        self.nsp = nsp.NSP (self.node, self.config)
        #self.setloglevel (logging.TRACE)
        self.nsp.start ()

class inbound_base (ntest):
    services = b'\x01'   # Services, which carries FCOPT in bits 2-3
    info = b'\x02'       # Info, which carries NSP version in bits 0-1
    remnode = Nodeid (1, 42)
    cdadj = 1            # Outbound packet adjustment because of CD
    phase = 4
    
    def setUp (self):
        super ().setUp ()
        r = self.node.routing
        s = self.node.session
        # Connect Init, flow control and version from class attributes
        # Sender's link address is 3, segsize is 0x100, i.e., 256.
        p = b"\x18\x00\x00\x03\x00" + self.services + self.info + \
            b"\x00\x01payload"
        rla = 3
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p, rts = False)
        self.nsp.dispatch (w)
        # Check reply
        self.assertEqual (r.send.call_count, self.cdadj)
        if self.cdadj:
            args, kwargs = r.send.call_args
            ack, dest = args
            self.assertEqual (dest, self.remnode)
            self.assertEqual (ack.dstaddr, rla)
        # Check data to Session Control
        self.assertEqual (self.node.addwork.call_count, 1)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.ConnInit)
        self.assertEqual (pkt.payload, b"payload")
        # Check connection state
        nc = w.connection
        self.assertIs (self.nsp.rconnections[(self.remnode, rla)], nc)
        self.assertEqual (nc.dstaddr, rla)
        self.assertEqual (len (self.nsp.rconnections), 1)
        lla = nc.srcaddr
        self.assertIs (self.nsp.connections[lla], nc)
        self.assertEqual (nc.state, nc.cr)
        self.assertEqual (len (self.nsp.connections), 1)
        # Verify that the connection timeout is running
        self.assertTrue (nc.islinked ())
        # Remember the connection
        self.nspconn = nc

    def accept (self):
        # Accept the inbound connection, and ack that if phase 3 or
        # later.  On exit, connection is in RUN state.
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session        
        # SC send accept
        nc.accept (b"excellent")
        # Verify confirm went out
        r = self.node.routing
        self.assertEqual (r.send.call_count, 1 + self.cdadj)
        args, kwargs = r.send.call_args
        cc, dest = args
        self.assertIsInstance (cc, nsp.ConnConf)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (cc.srcaddr, nc.srcaddr)
        self.assertEqual (cc.dstaddr, 3)
        self.assertEqual (cc.data_ctl, b"excellent")
        # Make sure phase is set properly
        self.assertEqual (nc.cphase, min (self.phase, self.node.phase))
        # Check new connection state
        if nc.cphase > 2:
            self.assertEqual (nc.state, nc.cc)
            # Try to send an interrupt outbound
            with self.assertRaises (nsp.WrongState):
                nc.interrupt (b"frob")
            # Incoming ACK (of the connect confirm)
            ack = b"\x04" + lla.to_bytes (2, "little") + b"\x03\x00\x00\x80"
            w = Received (owner = self.nsp, src = self.remnode,
                          packet = ack, rts = False)
            self.nsp.dispatch (w)
        # That should get us into RUN state, and empty queue
        self.assertEqual (nc.state, nc.run)
        self.assertEqual (len (nc.data.pending_ack), 0)
        
    def test_normalconn (self):
        # Basic good inbound connection (accept, data, disconnect)
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session        
        self.accept ()
        # Deliver a data segment
        d = b"\x60" + lla.to_bytes (2, "little") + \
            b"\x03\x00\x01\x00data payload"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = d, rts = False)
        self.nsp.dispatch (w)
        # Check data to Session Control
        self.assertEqual (self.node.addwork.call_count, 2)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.DataSeg)
        self.assertEqual (pkt.payload, b"data payload")
        # Check connection state
        self.assertEqual (nc.state, nc.run)
        # No reply yet
        self.assertEqual (r.send.call_count, 1 + self.cdadj)
        # Deliver an XOFF message
        p = b"\x10" + lla.to_bytes (2, "little") + \
            b"\x03\x00\x01\x00\x01\x00"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p, rts = False)
        self.nsp.dispatch (w)
        # Not delivered to Session Control
        self.assertEqual (self.node.addwork.call_count, 2)
        # Send a data message
        nc.send_data (b"hello world")
        # It should be on the pending queue
        self.assertEqual (len (nc.data.pending_ack), 1)
        # It wasn't sent (due to XOFF)
        self.assertEqual (r.send.call_count, 1 + self.cdadj)
        # Incoming Link Service XON
        p = b"\x10" + lla.to_bytes (2, "little") + \
            b"\x03\x00\x02\x00\x02\x00"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p, rts = False)
        self.nsp.dispatch (w)
        # Not delivered to Session Control
        self.assertEqual (self.node.addwork.call_count, 2)
        # If we have explicit flow control, it still wasn't sent yet.
        if self.services != b'\x01':
            self.assertEqual (r.send.call_count, 1 + self.cdadj)
            # Incoming Link Service to ask for 2 more items
            p = b"\x10" + lla.to_bytes (2, "little") + \
                b"\x03\x00\x03\x00\x00\x02"
            w = Received (owner = self.nsp, src = self.remnode,
                          packet = p, rts = False)
            self.nsp.dispatch (w)
            # Not delivered to Session Control
            self.assertEqual (self.node.addwork.call_count, 2)
        # Verify data was sent, with piggyback ack
        self.assertEqual (r.send.call_count, 2 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.DataSeg)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertTrue (ds.bom)
        self.assertTrue (ds.eom)
        self.assertEqual (ds.acknum, nsp.AckNum (1))
        if self.services != b'\x01' and nc.cphase == 4:
            # There should be a cross subchannel ack of the link
            # service (flow on) message.
            self.assertEqual (ds.acknum2, nsp.AckNum (3, nsp.AckNum.XACK))
        elif nc.cphase == 4:
            self.assertEqual (ds.acknum2, nsp.AckNum (2, nsp.AckNum.XACK))
        else:
            self.assertFalse (hasattr (ds, "acknum2"))
        self.assertEqual (ds.payload, b"hello world")
        # Send a big data message (11 * 40 bytes, two segments)
        nc.send_data (b"hello world" * 40)
        # If we have segment flow control, one segment is blocked
        if self.services == b'\x05':
            self.assertEqual (r.send.call_count, 3 + self.cdadj)
            # Incoming Link Service to ask for 5 more items
            p = b"\x10" + lla.to_bytes (2, "little") + \
                b"\x03\x00\x04\x00\x00\x05"
            w = Received (owner = self.nsp, src = self.remnode,
                          packet = p, rts = False)
            self.nsp.dispatch (w)
            # Not delivered to Session Control
            self.assertEqual (self.node.addwork.call_count, 2)
        # Verify all data was sent now
        self.assertEqual (r.send.call_count, 4 + self.cdadj)
        d1, d2 = r.send.call_args_list[-2:]
        args, kwargs = d1
        ds, dest = args
        self.assertIsInstance (ds, nsp.DataSeg)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertTrue (ds.bom)
        self.assertFalse (ds.eom)
        self.assertFalse (hasattr (ds, "acknum"))
        self.assertFalse (hasattr (ds, "acknum2"))
        args, kwargs = d2
        ds2, dest = args
        self.assertIsInstance (ds2, nsp.DataSeg)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds2.srcaddr, lla)
        self.assertEqual (ds2.dstaddr, rla)
        self.assertFalse (ds2.bom)
        self.assertTrue (ds2.eom)
        self.assertFalse (hasattr (ds2, "acknum"))
        # If doing segment flow control, this one was originally
        # blocked, then unblocked by the second LS message, so it
        # should carry the piggyback LS ack if phase 4.
        if self.services == b'\x05' and nc.cphase == 4:
            self.assertEqual (ds2.acknum2, nsp.AckNum (4, nsp.AckNum.XACK))
        else:
            self.assertFalse (hasattr (ds2, "acknum2"))
        self.assertEqual (ds.payload + ds2.payload, b"hello world" * 40)
        # These transmitted messages have not yet been acked, so they
        # should be on the pending queue.
        self.assertEqual (len (nc.data.pending_ack), 3)
        # Ack just segment 1
        ack = b"\x04" + lla.to_bytes (2, "little") + b"\x03\x00\x01\x80"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = ack, rts = False)
        self.nsp.dispatch (w)
        # Should have two segments left on the pending queue
        self.assertEqual (len (nc.data.pending_ack), 2)
        # Ack through segment 3
        ack = b"\x04" + lla.to_bytes (2, "little") + b"\x03\x00\x03\x80"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = ack, rts = False)
        self.nsp.dispatch (w)
        # Should have nothing left on the pending queue
        self.assertEqual (len (nc.data.pending_ack), 0)
        # Send one more message.  It should be blocked only for
        # message flow control, which just had the original request
        # for 2.
        nc.send_data (b"hello world again")
        # If we have message flow control, this message is blocked
        if self.services == b'\x09':
            self.assertEqual (r.send.call_count, 4 + self.cdadj)
            # Incoming Link Service to ask for 4 more items
            p = b"\x10" + lla.to_bytes (2, "little") + \
                b"\x03\x00\x04\x00\x00\x04"
            w = Received (owner = self.nsp, src = self.remnode,
                          packet = p, rts = False)
            self.nsp.dispatch (w)
            # Not delivered to Session Control
            self.assertEqual (self.node.addwork.call_count, 2)
        # Verify all data was sent now
        self.assertEqual (r.send.call_count, 5 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.DataSeg)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertTrue (ds.bom)
        self.assertTrue (ds.eom)
        self.assertFalse (hasattr (ds, "acknum"))
        if self.services == b'\x09' and nc.cphase == 4:
            # There should be a cross subchannel ack of the link
            # service (flow on) message if we sent one.
            self.assertEqual (ds.acknum2, nsp.AckNum (4, nsp.AckNum.XACK))
        else:
            self.assertFalse (hasattr (ds, "acknum2"))
        self.assertEqual (ds.payload, b"hello world again")
        # Inbound disconnect
        disc = b"\x38" + lla.to_bytes (2, "little") + \
               b"\x03\x00\x05\x00\x07payload"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = disc, rts = False)
        self.nsp.dispatch (w)
        # Check data to Session Control
        self.assertEqual (self.node.addwork.call_count, 3)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.DiscInit)
        self.assertEqual (pkt.data_ctl, b"payload")
        self.assertEqual (pkt.reason, 5)
        # Check new connection state, and that there no longer is an
        # NSP connection in its database.
        self.assertEqual (nc.state, nc.closed)
        self.assertEqual (len (self.nsp.connections), 0)
        self.assertEqual (len (self.nsp.rconnections), 0)

    def test_timers (self):
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session
        self.accept ()
        # Check the timers are all in the correct state.
        if nc.cphase == 2:
            self.assertFalse (nc.islinked ())
        else:
            self.assertTrue (nc.islinked ())
        self.assertFalse (nc.data.islinked ())
        self.assertFalse (nc.other.islinked ())
        # Nothing in the queues
        self.assertEqual (len (nc.data.pending_ack), 0)
        self.assertEqual (len (nc.other.pending_ack), 0)
        # Test ack holdoff, data subchannel
        d = b"\x60" + lla.to_bytes (2, "little") + \
            b"\x03\x00\x01\x00data payload"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = d, rts = False)
        self.nsp.dispatch (w)
        # Check data to Session Control
        self.assertEqual (self.node.addwork.call_count, 2)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.DataSeg)
        self.assertEqual (pkt.payload, b"data payload")
        self.assertTrue (nc.data.islinked ())
        # Holdoff timer expiration should generate explicit ACK
        w = timers.Timeout (self.nsp)
        nc.data.dispatch (w)
        self.assertEqual (r.send.call_count, 2 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.AckData)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertEqual (ds.acknum, nsp.AckNum (1))
        self.assertFalse (hasattr (ds, "acknum2"))
        self.assertFalse (nc.data.islinked ())
        # Incoming Link Service to ask for 2 items.  With no flow
        # control, the count is ignored.
        p = b"\x10" + lla.to_bytes (2, "little") + \
            b"\x03\x00\x01\x00\x00\x02"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p, rts = False)
        self.nsp.dispatch (w)
        # Not delivered to Session Control
        self.assertEqual (self.node.addwork.call_count, 2)
        # Send two data packets
        nc.send_data (b"packet")
        nc.send_data (b"packet2")
        self.assertEqual (r.send.call_count, 4 + self.cdadj)
        self.assertEqual (len (nc.data.pending_ack), 2)
        self.assertTrue (nc.data.pending_ack[0].sent)
        self.assertTrue (nc.data.pending_ack[0].islinked ())
        self.assertTrue (nc.data.pending_ack[1].sent)
        self.assertTrue (nc.data.pending_ack[1].islinked ())
        # Time out the first packet
        w = timers.Timeout (self.nsp)
        nc.data.pending_ack[0].dispatch (w)
        self.assertEqual (r.send.call_count, 5 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.DataSeg)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertFalse (hasattr (ds, "acknum"))
        if nc.cphase == 4:
            self.assertEqual (ds.acknum2, nsp.AckNum (1, nsp.AckNum.XACK))
        else:
            self.assertFalse (hasattr (ds, "acknum2"))
        self.assertEqual (ds.payload, b"packet")
        # Turn off flow
        if self.services == b'\x05':
            # Send segment count delta -1
            p = b"\x10" + lla.to_bytes (2, "little") + \
                b"\x03\x00\x02\x00\x00\xff"
        else:
            # Not segment flow control, send xoff
            p = b"\x10" + lla.to_bytes (2, "little") + \
                b"\x03\x00\x02\x00\x01\x00"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p, rts = False)
        self.nsp.dispatch (w)
        # Holdoff timer expiration should generate explicit ACK
        w = timers.Timeout (self.nsp)
        nc.other.dispatch (w)
        self.assertEqual (r.send.call_count, 6 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.AckOther)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertEqual (ds.acknum, nsp.AckNum (2))
        self.assertFalse (hasattr (ds, "acknum2"))
        self.assertFalse (nc.other.islinked ())
        # Time out the second packet, should not send
        w = timers.Timeout (self.nsp)
        nc.data.pending_ack[1].dispatch (w)
        self.assertFalse (nc.data.pending_ack[1].sent)
        # Skip this test because our simulated timeout doesn't unlink
        # the timer, the way a real timeout does.
        #self.assertFalse (nc.data.pending_ack[1].islinked ())
        self.assertEqual (r.send.call_count, 6 + self.cdadj)
        # Turn off flow
        if self.services == b'\x05':
            # Send segment count delta +1
            p = b"\x10" + lla.to_bytes (2, "little") + \
                b"\x03\x00\x03\x00\x00\x01"
        else:
            # Not segment flow control, send xon
            p = b"\x10" + lla.to_bytes (2, "little") + \
                b"\x03\x00\x03\x00\x02\x00"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p, rts = False)
        self.nsp.dispatch (w)
        # Second packet resend should have happened now
        self.assertEqual (r.send.call_count, 7 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.DataSeg)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertFalse (hasattr (ds, "acknum"))
        if nc.cphase == 4:
            self.assertEqual (ds.acknum2, nsp.AckNum (3, nsp.AckNum.XACK))
        else:
            self.assertFalse (hasattr (ds, "acknum2"))
        self.assertEqual (ds.payload, b"packet2")
        # Test inactivity timer, if applicable
        if nc.cphase > 2:
            w = timers.Timeout (self.nsp)
            nc.dispatch (w)
            self.assertEqual (r.send.call_count, 8 + self.cdadj)
            args, kwargs = r.send.call_args
            ds, dest = args
            self.assertIsInstance (ds, nsp.LinkSvcMsg)
            self.assertEqual (dest, self.remnode)
            self.assertEqual (ds.srcaddr, lla)
            self.assertEqual (ds.dstaddr, rla)
            if nc.cphase == 3:
                # For phase 3, the cross-channel acknum above (in the
                # retransmission of the second packet) is not done, so
                # we get the ack here in-subchannel.
                self.assertEqual (ds.acknum, nsp.AckNum (3))
            else:
                self.assertFalse (hasattr (ds, "acknum"))
            self.assertFalse (hasattr (ds, "acknum2"))
            self.assertEqual (ds.fcmod, 0)
            self.assertEqual (ds.fcval_int, 0)
            self.assertEqual (ds.fcval, 0)
            
class test_inbound_noflow_phase4 (inbound_base):
    def test_interrupt (self):
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session        
        self.accept ()
        # Send an interrupt message
        nc.interrupt (b"hello decnet")
        # Verify data was sent
        self.assertEqual (r.send.call_count, 2 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.IntMsg)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertTrue (ds.int)
        self.assertFalse (hasattr (ds, "acknum"))
        self.assertFalse (hasattr (ds, "acknum2"))
        self.assertEqual (ds.payload, b"hello decnet")
        # Incoming interrupt, with piggyback ACK
        p = b"\x30" + lla.to_bytes (2, "little") + \
            b"\x03\x00\x01\x80\x01\x00payload"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p, rts = False)
        self.nsp.dispatch (w)
        self.assertEqual (self.node.addwork.call_count, 2)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.IntMsg)
        self.assertEqual (pkt.payload, b"payload")
        # Try sending another interrupt
        with self.assertRaises (nsp.CantSend):
            nc.interrupt (b"frob again")
        # Incoming Link Service to ask for more interrupts
        p = b"\x10" + lla.to_bytes (2, "little") + \
            b"\x03\x00\x02\x00\x06\x02"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p, rts = False)
        self.nsp.dispatch (w)
        # Not delivered to Session Control
        self.assertEqual (self.node.addwork.call_count, 2)
        # Send a second interrupt
        nc.interrupt (b"interrupt 2")
        # Verify data was sent
        self.assertEqual (r.send.call_count, 3 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.IntMsg)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertTrue (ds.int)
        self.assertEqual (ds.acknum, nsp.AckNum (2))
        self.assertFalse (hasattr (ds, "acknum2"))
        self.assertEqual (ds.payload, b"interrupt 2")
        # Send a third interrupt
        nc.interrupt (b"interrupt 3")
        # Verify data was sent
        self.assertEqual (r.send.call_count, 4 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.IntMsg)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertTrue (ds.int)
        self.assertFalse (hasattr (ds, "acknum"))
        self.assertFalse (hasattr (ds, "acknum2"))
        self.assertEqual (ds.payload, b"interrupt 3")
        # A fourth one should be refused
        with self.assertRaises (nsp.CantSend):
            nc.interrupt (b"frob again")
        
    def test_conntimeout (self):
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session
        # Time out session control's response to the CI
        w = timers.Timeout (self.nsp)
        nc.dispatch (w)
        self.assertEqual (r.send.call_count, 1 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.DiscInit)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertEqual (ds.reason, 38)
        self.assertEqual (nc.state, nc.di)
        
class test_inbound_noflow_phase3 (test_inbound_noflow_phase4):
    info = b'\x00'       # NSP 3.2 (phase 3)
    remnode = Nodeid (42)
    phase = 3

class test_inbound_noflow_phase2 (test_inbound_noflow_phase3):
    info = b'\x01'       # NSP 3.1 (phase 2)
    cdadj = 0
    phase = 2
    
class test_inbound_segflow_phase4 (inbound_base):
    services = b'\x05'   # Segment flow control

class test_inbound_msgflow_phase4 (inbound_base):
    services = b'\x09'   # Message flow control

class test_random (ntest):
    def test_random (self):
        src = Nodeid (1, 42)
        for i in range (5000):
            pkt = randpkt (8, 64)
            w = Received (owner = self.nsp, src = src,
                          packet = pkt, rts = False)
            self.nsp.dispatch (w)
            
if __name__ == "__main__":
    unittest.main ()

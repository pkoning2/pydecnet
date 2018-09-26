#!/usr/bin/env python3

"""Unit test for the NSP layer.
"""

# To do:
# 1. Various ACK cases for outbound data
# 2. Out of order packets     ** DONE
# 3. Duplicate packets    **DONE
# 4. Xoff flow control  **DONE
# 5. Queue limit
# 6. Bad ACKs
# 7. Bad flow control updates
# 8. Outbound disconnect (with and without data pending)  **DONE
# 9. Outbound abort    **DONE
# 10. Outbound connection accept and reject     **DONE
# 11. Packets that are wrong for a given state (if any?)
# 12. Packets not matched to an open port (connection)
# 13. Phase II behavior: no CD, no CC state, DC instead of DI message.
# 14. Timeouts. **DONE except for outbound CI
# 15. Inbound connection reject.    **DONE
# 16. Returned CI    **DONE

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
            self.assertIsInstance (ack, nsp.AckConn)
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
        """Basic good inbound connection (accept, data, disconnect)"""
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
        """Timeouts: inactivity, ack holdoff, packet timeout"""
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
        """Interrupt messages (in and out)"""
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
        """Timeout on inbound CI (no answer from application)"""
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
        # Check that the timeout came to session control as a disconnect
        self.assertEqual (self.node.addwork.call_count, 2)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.DiscInit)
        self.assertEqual (pkt.reason, 38)

    def test_crtimeout (self):
        """Timeout of CR message"""
        if self.phase == 2:
            # Test does not apply, handle as pass
            return
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
        self.assertEqual (nc.state, nc.cc)
        self.assertTrue (nc.data.pending_ack[0].islinked ())
        # Time out the confirm
        w = timers.Timeout (self.nsp)
        nc.data.pending_ack[0].dispatch (w)
        self.assertEqual (r.send.call_count, 2 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (cc, nsp.ConnConf)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (cc.srcaddr, nc.srcaddr)
        self.assertEqual (cc.dstaddr, 3)
        self.assertEqual (cc.data_ctl, b"excellent")
        
    def test_reject (self):
        """Inbound connection, rejected by application"""
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session
        # SC send accept
        nc.reject (0, b"not excellent")
        # Verify reject went out
        r = self.node.routing
        self.assertEqual (r.send.call_count, 1 + self.cdadj)
        args, kwargs = r.send.call_args
        rj, dest = args
        self.assertIsInstance (rj, nsp.DiscInit)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (rj.srcaddr, nc.srcaddr)
        self.assertEqual (rj.dstaddr, 3)
        self.assertEqual (rj.reason, 0)
        self.assertEqual (rj.data_ctl, b"not excellent")
        self.assertEqual (nc.state, nc.di)
        self.assertEqual (len (nc.data.pending_ack), 1)
        self.assertTrue (nc.data.pending_ack[0].islinked ())
        # Time out the reject
        w = timers.Timeout (self.nsp)
        nc.data.pending_ack[0].dispatch (w)
        self.assertEqual (r.send.call_count, 2 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        rj, dest = args
        self.assertIsInstance (rj, nsp.DiscInit)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (rj.srcaddr, nc.srcaddr)
        self.assertEqual (rj.dstaddr, 3)
        self.assertEqual (rj.reason, 0)
        self.assertEqual (rj.data_ctl, b"not excellent")
        self.assertEqual (nc.state, nc.di)
        # Deliver a confirm (disconnect complete)
        p = b"\x48" + lla.to_bytes (2, "little") + b"\x03\x00\x2a\x00"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p, rts = False)
        self.nsp.dispatch (w)
        # Check new connection state, and that there no longer is an
        # NSP connection in its database.
        self.assertEqual (nc.state, nc.closed)
        self.assertEqual (len (self.nsp.connections), 0)
        self.assertEqual (len (self.nsp.rconnections), 0)

    def test_ooo (self):
        """Out of order packets, data subchannel"""
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session
        self.accept ()
        # Build four data packets
        d1 = b"\x60" + lla.to_bytes (2, "little") + \
             b"\x03\x00\x01\x00data 1"
        d2 = b"\x60" + lla.to_bytes (2, "little") + \
             b"\x03\x00\x02\x00data 2"
        d3 = b"\x60" + lla.to_bytes (2, "little") + \
             b"\x03\x00\x03\x00data 3"
        d4 = b"\x60" + lla.to_bytes (2, "little") + \
             b"\x03\x00\x04\x00data 4"
        # Deliver packets 2 and 4 (both out of order)
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = d2, rts = False)
        self.nsp.dispatch (w)
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = d4, rts = False)
        self.nsp.dispatch (w)
        # Nothing yet to session control
        self.assertEqual (self.node.addwork.call_count, 1)
        # No acks yet
        self.assertFalse (nc.data.islinked ())
        # Two packets in out of order cache
        self.assertEqual (len (nc.data.ooo), 2)
        # Deliver packet 1
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = d1, rts = False)
        self.nsp.dispatch (w)
        # This should produce two packets to session control
        self.assertEqual (self.node.addwork.call_count, 3)
        r1, r2 = self.node.addwork.call_args_list[-2:]
        args, kwargs = r1
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.DataSeg)
        self.assertEqual (pkt.payload, b"data 1")
        args, kwargs = r2
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.DataSeg)
        self.assertEqual (pkt.payload, b"data 2")
        # One packet left in OOO cache
        self.assertEqual (len (nc.data.ooo), 1)
        # Force ACK
        w = timers.Timeout (self.nsp)
        nc.data.dispatch (w)
        self.assertEqual (r.send.call_count, 2 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.AckData)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertEqual (ds.acknum, nsp.AckNum (2))
        self.assertFalse (hasattr (ds, "acknum2"))
        self.assertFalse (nc.data.islinked ())
        # Deliver packet 3
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = d3, rts = False)
        self.nsp.dispatch (w)
        # This should produce the other two packets to session control
        self.assertEqual (self.node.addwork.call_count, 5)
        r1, r2 = self.node.addwork.call_args_list[-2:]
        args, kwargs = r1
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.DataSeg)
        self.assertEqual (pkt.payload, b"data 3")
        args, kwargs = r2
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.DataSeg)
        self.assertEqual (pkt.payload, b"data 4")
        # OOO cache now empty
        self.assertEqual (len (nc.data.ooo), 0)
        # Force ACK
        w = timers.Timeout (self.nsp)
        nc.data.dispatch (w)
        self.assertEqual (r.send.call_count, 3 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.AckData)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertEqual (ds.acknum, nsp.AckNum (4))
        self.assertFalse (hasattr (ds, "acknum2"))
        self.assertFalse (nc.data.islinked ())

    def test_ooo_other (self):
        """Out of order packets, Int/LS subchannel"""
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session
        self.accept ()
        # Build two link service packets (XOFF then XON)
        p1 = b"\x10" + lla.to_bytes (2, "little") + \
             b"\x03\x00\x01\x00\x01\x00"
        p2 = b"\x10" + lla.to_bytes (2, "little") + \
             b"\x03\x00\x02\x00\x02\x00"
        # Deliver packet 2 (out of order)
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p2, rts = False)
        self.nsp.dispatch (w)
        # Nothing to session control
        self.assertEqual (self.node.addwork.call_count, 1)
        # No acks yet
        self.assertFalse (nc.other.islinked ())
        # One packet in out of order cache for Int/LS subchannel (yes,
        # we have one)
        self.assertEqual (len (nc.other.ooo), 1)
        # Deliver packet 1
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p1, rts = False)
        self.nsp.dispatch (w)
        # Still nothing to session control (not SC data)
        self.assertEqual (self.node.addwork.call_count, 1)
        # OOO cache is now empty
        self.assertEqual (len (nc.data.ooo), 0)
        # Force ACK
        w = timers.Timeout (self.nsp)
        nc.other.dispatch (w)
        self.assertEqual (r.send.call_count, 2 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.AckOther)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertEqual (ds.acknum, nsp.AckNum (2))
        self.assertFalse (hasattr (ds, "acknum2"))
        self.assertFalse (nc.data.islinked ())
        # Resulting flow control state should be XON (since that was
        # what the highest numbered LS message said)
        self.assertTrue (nc.data.xon)

    def test_disc_out (self):
        """Outbound disconnect, no pending data"""
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session
        self.accept ()
        nc.disconnect (payload = b"goodbye")
        self.assertEqual (r.send.call_count, 2 + self.cdadj)
        args, kwargs = r.send.call_args
        d, dest = args
        self.assertIsInstance (d, nsp.DiscInit)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (d.dstaddr, rla)
        self.assertEqual (d.srcaddr, lla)
        self.assertEqual (d.data_ctl, b"goodbye")
        # It should be on the queue
        self.assertEqual (len (nc.data.pending_ack), 1)
        # State is now DI
        self.assertEqual (nc.state, nc.di)
        
    def test_abort_out (self):
        """Outbound abort with pending data"""
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session
        self.accept ()
        nc.send_data (b"data packet")
        self.assertEqual (len (nc.data.pending_ack), 1)
        # Abort will go out anyway
        nc.abort (payload = b"goodbye")
        self.assertEqual (r.send.call_count, 3 + self.cdadj)
        args, kwargs = r.send.call_args
        d, dest = args
        self.assertIsInstance (d, nsp.DiscInit)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (d.dstaddr, rla)
        self.assertEqual (d.srcaddr, lla)
        self.assertEqual (d.data_ctl, b"goodbye")
        # It should be on the queue
        self.assertEqual (len (nc.data.pending_ack), 1)
        # State is now DI
        self.assertEqual (nc.state, nc.di)

    def test_acks (self):
        """Partial acks (less than total currently pending)"""
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session
        self.accept ()
        nc.send_data (b"packet 1")
        nc.send_data (b"packet 2")
        # Both should have been sent
        self.assertEqual (r.send.call_count, 3 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.DataSeg)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertFalse (hasattr (ds, "acknum"))
        self.assertFalse (hasattr (ds, "acknum2"))
        self.assertEqual (ds.payload, b"packet 2")
        # Both are awaiting ack
        self.assertEqual (len (nc.data.pending_ack), 2)
        # Ack only one of them
        ack = b"\x04" + lla.to_bytes (2, "little") + b"\x03\x00\x01\x80"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = ack, rts = False)
        self.nsp.dispatch (w)
        # No retransmits, but queue length is now 1
        self.assertEqual (r.send.call_count, 3 + self.cdadj)
        self.assertEqual (len (nc.data.pending_ack), 1)
        # Same, but for interrupts
        # Incoming Link Service to ask for more interrupts
        p = b"\x10" + lla.to_bytes (2, "little") + \
            b"\x03\x00\x01\x00\x06\x02"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p, rts = False)
        self.nsp.dispatch (w)
        nc.interrupt (b"int 1")
        nc.interrupt (b"int 2")
        # Both should have been sent
        self.assertEqual (r.send.call_count, 5 + self.cdadj)
        args, kwargs = r.send.call_args
        ds, dest = args
        self.assertIsInstance (ds, nsp.IntMsg)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ds.srcaddr, lla)
        self.assertEqual (ds.dstaddr, rla)
        self.assertFalse (hasattr (ds, "acknum"))
        self.assertFalse (hasattr (ds, "acknum2"))
        self.assertEqual (ds.payload, b"int 2")
        # Both are awaiting ack
        self.assertEqual (len (nc.other.pending_ack), 2)
        # Ack only one of them
        ack = b"\x14" + lla.to_bytes (2, "little") + b"\x03\x00\x01\x80"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = ack, rts = False)
        self.nsp.dispatch (w)
        # No retransmits, but queue length is now 1
        self.assertEqual (r.send.call_count, 5 + self.cdadj)
        self.assertEqual (len (nc.other.pending_ack), 1)

    def test_dup_ci (self):
        """Duplicate Connect Initiate packets"""
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session
        # Deliver a copy of the original CI
        p = b"\x18\x00\x00\x03\x00" + self.services + self.info + \
            b"\x00\x01payload"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p, rts = False)
        self.nsp.dispatch (w)
        # Check reply
        self.assertEqual (r.send.call_count, self.cdadj * 2)
        if self.cdadj:
            args, kwargs = r.send.call_args
            ack, dest = args
            self.assertIsInstance (ack, nsp.AckConn)
            self.assertEqual (dest, self.remnode)
            self.assertEqual (ack.dstaddr, rla)
        # Not delivered to session control
        self.assertEqual (self.node.addwork.call_count, 1)
        if self.phase > 2:
            # Deliver a Retransmitted CI
            p = b"\x68\x00\x00\x03\x00" + self.services + self.info + \
                b"\x00\x01payload"
            w = Received (owner = self.nsp, src = self.remnode,
                          packet = p, rts = False)
            self.nsp.dispatch (w)
            # Check reply
            self.assertEqual (r.send.call_count, self.cdadj * 3)
            if self.cdadj:
                args, kwargs = r.send.call_args
                ack, dest = args
                self.assertIsInstance (ack, nsp.AckConn)
                self.assertEqual (dest, self.remnode)
                self.assertEqual (ack.dstaddr, rla)
            # Not delivered to session control
            self.assertEqual (self.node.addwork.call_count, 1)

    def test_dup_data (self):
        """Duplicate data packets"""
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session
        self.accept ()
        d1 = b"\x60" + lla.to_bytes (2, "little") + \
             b"\x03\x00\x01\x00data 1"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = d1, rts = False)
        self.nsp.dispatch (w)
        # Check data to Session Control
        self.assertEqual (self.node.addwork.call_count, 2)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.DataSeg)
        self.assertEqual (pkt.payload, b"data 1")
        # ACK is pending
        self.assertTrue (nc.data.islinked ())
        self.assertEqual (r.send.call_count, 1 + self.cdadj)
        # Deliver it again
        w2 = Received (owner = self.nsp, src = self.remnode,
                       packet = d1, rts = False)
        self.nsp.dispatch (w2)
        # Not delivered to SC
        self.assertEqual (self.node.addwork.call_count, 2)
        # Forces explicit ack
        self.assertFalse (nc.data.islinked ())
        self.assertEqual (r.send.call_count, 2 + self.cdadj)
        args, kwargs = r.send.call_args
        ack, dest = args
        self.assertIsInstance (ack, nsp.AckData)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ack.srcaddr, lla)
        self.assertEqual (ack.dstaddr, rla)
        self.assertEqual (ack.acknum, nsp.AckNum (1))

    def test_dup_int (self):
        """Duplicate interrupt packets"""
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session
        self.accept ()
        d1 = b"\x30" + lla.to_bytes (2, "little") + \
             b"\x03\x00\x01\x00int 1"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = d1, rts = False)
        self.nsp.dispatch (w)
        # Check data to Session Control
        self.assertEqual (self.node.addwork.call_count, 2)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.IntMsg)
        self.assertEqual (pkt.payload, b"int 1")
        # ACK is pending
        self.assertTrue (nc.other.islinked ())
        self.assertEqual (r.send.call_count, 1 + self.cdadj)
        # Deliver it again
        w2 = Received (owner = self.nsp, src = self.remnode,
                       packet = d1, rts = False)
        self.nsp.dispatch (w2)
        # Not delivered to SC
        self.assertEqual (self.node.addwork.call_count, 2)
        # Forces explicit ack
        self.assertFalse (nc.other.islinked ())
        self.assertEqual (r.send.call_count, 2 + self.cdadj)
        args, kwargs = r.send.call_args
        ack, dest = args
        self.assertIsInstance (ack, nsp.AckOther)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ack.srcaddr, lla)
        self.assertEqual (ack.dstaddr, rla)
        self.assertEqual (ack.acknum, nsp.AckNum (1))

    def test_dup_di (self):
        """Duplicate disconnect initiate packets"""
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session
        self.accept ()
        # Inbound disconnect
        disc = b"\x38" + lla.to_bytes (2, "little") + \
               b"\x03\x00\x05\x00\x07payload"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = disc, rts = False)
        self.nsp.dispatch (w)
        # Check data to Session Control
        self.assertEqual (self.node.addwork.call_count, 2)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.DiscInit)
        self.assertEqual (pkt.data_ctl, b"payload")
        self.assertEqual (pkt.reason, 5)
        # Disconnect Complete reply expected
        self.assertEqual (r.send.call_count, 2 + self.cdadj)
        args, kwargs = r.send.call_args
        ack, dest = args
        self.assertIsInstance (ack, nsp.DiscComp)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ack.srcaddr, lla)
        self.assertEqual (ack.dstaddr, rla)
        # Check new connection state, and that there no longer is an
        # NSP connection in its database.
        self.assertEqual (nc.state, nc.closed)
        self.assertEqual (len (self.nsp.connections), 0)
        self.assertEqual (len (self.nsp.rconnections), 0)
        # Deliver it again
        w2 = Received (owner = self.nsp, src = self.remnode,
                       packet = disc, rts = False)
        self.nsp.dispatch (w2)
        # Not delivered to SC
        self.assertEqual (self.node.addwork.call_count, 2)
        # No Link reply expected
        self.assertEqual (r.send.call_count, 3 + self.cdadj)
        args, kwargs = r.send.call_args
        ack, dest = args
        self.assertIsInstance (ack, nsp.NoLink)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ack.srcaddr, lla)
        self.assertEqual (ack.dstaddr, rla)
        
    def test_dc_in (self):
        """Disconnect Confirm inbound to a running connection"""
        nc = self.nspconn
        lla = nc.srcaddr
        rla = 3
        r = self.node.routing
        s = self.node.session
        self.accept ()
        # Inbound disconnect confirm
        disc = b"\x48" + lla.to_bytes (2, "little") + \
               b"\x03\x00\x2b\x00"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = disc, rts = False)
        self.nsp.dispatch (w)
        # Check data to Session Control
        self.assertEqual (self.node.addwork.call_count, 2)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        # NoLink is a subclass of DiscConf, for the specific reason
        # code 43 (no link terminate)
        self.assertIsInstance (pkt, nsp.NoLink)
        self.assertEqual (pkt.reason, 43)
        # Check new connection state, and that there no longer is an
        # NSP connection in its database.
        self.assertEqual (nc.state, nc.closed)
        self.assertEqual (len (self.nsp.connections), 0)
        self.assertEqual (len (self.nsp.rconnections), 0)

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

class outbound_base (ntest):
    services = b'\x01'   # Services, which carries FCOPT in bits 2-3
    info = b'\x02'       # Info, which carries NSP version in bits 0-1
    remnode = Nodeid (1, 42)
    cdadj = 1            # Inbound packet adjustment because of CD
    phase = 4
    
    def setUp (self):
        super ().setUp ()
        r = self.node.routing
        s = self.node.session
        # Issue connect initiate
        self.nsp.connect (self.remnode, b"connect")
        # We should have one connection
        self.assertEqual (len (self.nsp.connections), 1)
        # Not yet in the remote connection table (no remote address
        # yet)
        self.assertEqual (len (self.nsp.rconnections), 0)
        for lla, nc in self.nsp.connections.items ():
            break
        # Check that it was sent
        self.assertEqual (r.send.call_count, 1)
        args, kwargs = r.send.call_args
        ci, dest = args
        self.assertIsInstance (ci, nsp.ConnInit)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (ci.dstaddr, 0)
        self.assertEqual (ci.srcaddr, lla)
        self.assertEqual (ci.payload, b"connect")
        # Check connection state
        self.assertEqual (nc.srcaddr, lla)
        self.assertEqual (nc.state, nc.ci)
        # Verify that the connection timeout is running
        self.assertTrue (nc.islinked ())
        # Remember the connection
        self.nspconn = nc

    def test_outbound_basic (self):
        """Outbound connection accepted"""
        nc = self.nspconn
        lla = nc.srcaddr
        r = self.node.routing
        s = self.node.session
        if self.phase > 2:
            self.assertTrue (nc.data.pending_ack[0].islinked ())
            p = b"\x24" + lla.to_bytes (2, "little")
            w = Received (owner = self.nsp, src = self.remnode,
                          packet = p, rts = False)
            self.nsp.dispatch (w)
            self.assertEqual (len (nc.data.pending_ack), 0)
            self.assertEqual (nc.state, nc.cd)
        # Deliver a connect confirm
        # Connect Confirm, flow control and version from class attributes
        # Sender's link address is 3, segsize is 0x100, i.e., 256.
        p = b"\x28" + lla.to_bytes (2, "little") + \
            b"\x03\x00" + self.services + self.info + \
            b"\x00\x01\x07payload"
        rla = 3
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p, rts = False)
        self.nsp.dispatch (w)
        # Check data to Session Control
        self.assertEqual (self.node.addwork.call_count, 1)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.ConnConf)
        self.assertEqual (pkt.data_ctl, b"payload")
        # Check connection state
        self.assertEqual (nc.state, nc.run)
        # Ack for connect confirm should have gone out
        if nc.cphase > 2:
            self.assertEqual (r.send.call_count, 2)
            args, kwargs = r.send.call_args
            ack, dest = args
            self.assertIsInstance (ack, nsp.AckData)
            self.assertEqual (dest, self.remnode)
            self.assertEqual (ack.dstaddr, rla)
            self.assertEqual (ack.srcaddr, lla)
            self.assertEqual (ack.acknum, nsp.AckNum (0))
            self.assertFalse (hasattr (ack, "acknum2"))
        # Send a data packet
        nc.send_data (b"data packet")
        self.assertEqual (r.send.call_count, 2 + self.cdadj)
        args, kwargs = r.send.call_args
        d, dest = args
        self.assertIsInstance (d, nsp.DataSeg)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (d.dstaddr, rla)
        self.assertEqual (d.srcaddr, lla)
        self.assertTrue (d.bom)
        self.assertTrue (d.eom)
        self.assertEqual (d.payload, b"data packet")
        # It should be on the queue
        self.assertEqual (len (nc.data.pending_ack), 1)
        # Request shutdown (clean disconnect)
        nc.disconnect (reason = 69)
        # State is still run
        self.assertEqual (nc.state, nc.run)
        # More transmits should be rejected
        with self.assertRaises (nsp.WrongState):
            nc.send_data (b"frob")
        with self.assertRaises (nsp.WrongState):
            nc.interrupt (b"frob")
        # Deliver an inbound data segment
        d = b"\x60" + lla.to_bytes (2, "little") + \
            b"\x03\x00\x01\x00inbound data"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = d, rts = False)
        self.nsp.dispatch (w)
        # Check data to Session Control
        self.assertEqual (self.node.addwork.call_count, 2)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.DataSeg)
        self.assertEqual (pkt.payload, b"inbound data")
        # Should still be in run state
        self.assertEqual (nc.state, nc.run)
        # Ack the outbound data
        ack = b"\x04" + lla.to_bytes (2, "little") + b"\x03\x00\x01\x80"
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = ack, rts = False)
        self.nsp.dispatch (w)
        # That should trigger the disconnect
        self.assertEqual (r.send.call_count, 3 + self.cdadj)
        args, kwargs = r.send.call_args
        d, dest = args
        self.assertIsInstance (d, nsp.DiscInit)
        self.assertEqual (dest, self.remnode)
        self.assertEqual (d.dstaddr, rla)
        self.assertEqual (d.srcaddr, lla)
        self.assertEqual (d.reason, 69)
        # It should be on the queue
        self.assertEqual (len (nc.data.pending_ack), 1)
        # State is now DI
        self.assertEqual (nc.state, nc.di)
        
    def test_outbound_reject (self):
        """Outbound connection rejected"""
        nc = self.nspconn
        lla = nc.srcaddr
        r = self.node.routing
        s = self.node.session
        if self.phase > 2:
            self.assertTrue (nc.data.pending_ack[0].islinked ())
            p = b"\x24" + lla.to_bytes (2, "little")
            w = Received (owner = self.nsp, src = self.remnode,
                          packet = p, rts = False)
            self.nsp.dispatch (w)
            self.assertEqual (len (nc.data.pending_ack), 0)
            self.assertEqual (nc.state, nc.cd)
        # Deliver a connect confirm
        # Connect reject, reason 1
        p = b"\x38" + lla.to_bytes (2, "little") + \
            b"\x03\x00\x01\x00\x07payload"
        rla = 3
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p, rts = False)
        self.nsp.dispatch (w)
        # Check data to Session Control
        self.assertEqual (self.node.addwork.call_count, 1)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.DiscInit)
        self.assertTrue (w.reject)
        self.assertEqual (pkt.reason, 1)
        self.assertEqual (pkt.data_ctl, b"payload")
        # Check connection state
        self.assertEqual (nc.state, nc.closed)

    def test_outbound_unreachable (self):
        """Outbound connection request returned by routing"""
        nc = self.nspconn
        lla = nc.srcaddr
        r = self.node.routing
        s = self.node.session
        # Pick up what we sent
        args, kwargs = r.send.call_args
        ci, dest = args
        self.assertIsInstance (ci, nsp.ConnInit)
        # Convert it to bytes so NSP top level input can parse it
        ci = bytes (ci)
        # Deliver it as a returned packet
        w = Received (owner = self.nsp, src = self.node.nodeid,
                      packet = ci, rts = True)
        self.nsp.dispatch (w)
        # Check data to Session Control
        self.assertEqual (self.node.addwork.call_count, 1)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.DiscInit)
        self.assertTrue (w.reject)
        # Reason is unreachable
        self.assertEqual (pkt.reason, 39)
        # Check connection state
        self.assertEqual (nc.state, nc.closed)

    def test_dup_cr (self):
        """Duplicate connect confirm"""
        nc = self.nspconn
        lla = nc.srcaddr
        r = self.node.routing
        s = self.node.session
        if self.phase > 2:
            self.assertTrue (nc.data.pending_ack[0].islinked ())
            p = b"\x24" + lla.to_bytes (2, "little")
            w = Received (owner = self.nsp, src = self.remnode,
                          packet = p, rts = False)
            self.nsp.dispatch (w)
            self.assertEqual (len (nc.data.pending_ack), 0)
            self.assertEqual (nc.state, nc.cd)
        # Deliver a connect confirm
        # Connect Confirm, flow control and version from class attributes
        # Sender's link address is 3, segsize is 0x100, i.e., 256.
        p = b"\x28" + lla.to_bytes (2, "little") + \
            b"\x03\x00" + self.services + self.info + \
            b"\x00\x01\x07payload"
        rla = 3
        w = Received (owner = self.nsp, src = self.remnode,
                      packet = p, rts = False)
        self.nsp.dispatch (w)
        # Check data to Session Control
        self.assertEqual (self.node.addwork.call_count, 1)
        args, kwargs = self.node.addwork.call_args
        w, owner = args
        pkt = w.packet
        self.assertIsInstance (pkt, nsp.ConnConf)
        self.assertEqual (pkt.data_ctl, b"payload")
        # Check connection state
        self.assertEqual (nc.state, nc.run)
        # Ack for connect confirm should have gone out
        if nc.cphase > 2:
            self.assertEqual (r.send.call_count, 2)
            args, kwargs = r.send.call_args
            ack, dest = args
            self.assertIsInstance (ack, nsp.AckData)
            self.assertEqual (dest, self.remnode)
            self.assertEqual (ack.dstaddr, rla)
            self.assertEqual (ack.srcaddr, lla)
            self.assertEqual (ack.acknum, nsp.AckNum (0))
            self.assertFalse (hasattr (ack, "acknum2"))
        # Deliver it again
        w2 = Received (owner = self.nsp, src = self.remnode,
                       packet = p, rts = False)
        self.nsp.dispatch (w2)
        # Not delivered to SC
        self.assertEqual (self.node.addwork.call_count, 1)
        # Check connection state
        self.assertEqual (nc.state, nc.run)
        # Another ack for connect confirm should have gone out
        if nc.cphase > 2:
            self.assertEqual (r.send.call_count, 3)
            args, kwargs = r.send.call_args
            ack, dest = args
            self.assertIsInstance (ack, nsp.AckData)
            self.assertEqual (dest, self.remnode)
            self.assertEqual (ack.dstaddr, rla)
            self.assertEqual (ack.srcaddr, lla)
            self.assertEqual (ack.acknum, nsp.AckNum (0))
            self.assertFalse (hasattr (ack, "acknum2"))
        
class test_outbound_phase4 (outbound_base):
    pass

class test_outbound_phase3 (test_outbound_phase4):
    info = b'\x00'       # NSP 3.2 (phase 3)
    remnode = Nodeid (42)
    phase = 3

class test_outbound_phase2 (test_outbound_phase3):
    info = b'\x01'       # NSP 3.1 (phase 2)
    cdadj = 0
    phase = 2
    
    
class test_random (ntest):
    def test_random (self):
        """Random packets inbound"""
        src = Nodeid (1, 42)
        for i in range (5000):
            pkt = randpkt (8, 64)
            w = Received (owner = self.nsp, src = src,
                          packet = pkt, rts = False)
            self.nsp.dispatch (w)
            
if __name__ == "__main__":
    unittest.main ()

#!/usr/bin/env python3

from tests.dntest import *

from decnet import events
from decnet.nice import *

class TestEventDecode (DnTest):
    def test_decode00 (self):
        # The most basic event: no parameters.
        b = b"\x01\x07\x00\x00\x00\x00\x00\x00\x00\x80\x03\x04\x04GROK\x80"
        e = events.Event.decode (b)
        self.assertIsInstance (e, events.events_lost)
        self.assertFalse (e._ms_valid)
        self.assertEqual (e._class, 0)
        self.assertEqual (e._code, 0)
        self.assertEqual (e._local_node.nodeid, Nodeid (1, 3))
        self.assertEqual (e._local_node.nodename, "GROK")
        e = str (e)
        # Event type 0.0, Event records lost
        # From node 1.3 (GROK), occurred 01-Jan-1977 00:00:00
        self.assertRegex (e, r"Event type 0\.0")
        self.assertRegex (e, r"Event records lost")
        self.assertRegex (e, r"From node 1\.3 \(GROK\)")
        self.assertRegex (e, r"occurred 01-Jan-1977 00:00:00")

    def test_decodems (self):
        # Similar to above but with ms field included
        b = b"\x01\x07\x00\x00\x00\x00\x00\x00\x0c\x00\x03\x04\x04GROK\x80"
        e = events.Event.decode (b)
        self.assertIsInstance (e, events.events_lost)
        self.assertTrue (e._ms_valid)
        self.assertEqual (e._class, 0)
        self.assertEqual (e._code, 0)
        self.assertEqual (e._local_node.nodeid, Nodeid (1, 3))
        self.assertEqual (e._local_node.nodename, "GROK")
        e = str (e)
        # Event type 0.0, Event records lost
        # From node 1.3 (GROK), occurred 01-Jan-1977 00:00:00.012
        self.assertRegex (e, r"Event type 0\.0")
        self.assertRegex (e, r"Event records lost")
        self.assertRegex (e, r"From node 1\.3 \(GROK\)")
        self.assertRegex (e, r"occurred 01-Jan-1977 00:00:00\.012")

    def test_decode_bigts (self):
        # High timestamp
        b = b"\x01\x07\x00\x00\xff\x7f\xbe\xa8\xdb\x03\x03\x04\x04GROK\x80"
        e = events.Event.decode (b)
        self.assertIsInstance (e, events.events_lost)
        e = str (e)
        # Event type 0.0, Event records lost
        # From node 1.3 (GROK), occurred 09-Nov-2021 23:59:58.987
        self.assertRegex (e, r"Event type 0\.0")
        self.assertRegex (e, r"Event records lost")
        self.assertRegex (e, r"From node 1\.3 \(GROK\)")
        self.assertRegex (e, r"occurred 09-Nov-2021 23:59:58\.987")

    def test_unk_code (self):
        # Known class but unknown event number
        b = b"\x01\x07\x0f\x00\x00\x00\x00\x00\x00\x80\x03\x04\x04GROK\x80"
        e = events.Event.decode (b)
        self.assertEqual (type (e), events.NetmanEvent)
        self.assertFalse (e._ms_valid)
        self.assertEqual (e._class, 0)
        self.assertEqual (e._code, 15)
        self.assertEqual (e._local_node.nodeid, Nodeid (1, 3))
        self.assertEqual (e._local_node.nodename, "GROK")
        e = str (e)
        # Event type 0.15
        # From node 1.3 (GROK), occurred 01-Jan-1977 00:00:00
        self.assertRegex (e, r"Event type 0\.15")
        self.assertRegex (e, r"From node 1\.3 \(GROK\)")
        self.assertRegex (e, r"occurred 01-Jan-1977 00:00:00")

    def test_unk_cls (self):
        # Unknown class
        b = b"\x01\x07\x0f\x40\x00\x00\x00\x00\x00\x80\x03\x04\x04GROK\x80"
        e = events.Event.decode (b)
        self.assertEqual (type (e), events.Event)
        self.assertFalse (e._ms_valid)
        self.assertEqual (e._class, 256)
        self.assertEqual (e._code, 15)
        self.assertEqual (e._local_node.nodeid, Nodeid (1, 3))
        self.assertEqual (e._local_node.nodename, "GROK")
        e = str (e)
        # Event type 256.15
        # From node 1.3 (GROK), occurred 01-Jan-1977 00:00:00
        self.assertRegex (e, r"Event type 256\.15")
        self.assertRegex (e, r"From node 1\.3 \(GROK\)")
        self.assertRegex (e, r"occurred 01-Jan-1977 00:00:00")

    def test_unk_cls_params (self):
        # Unknown class
        b = b"\x01\x07\x0f\x40\x00\x00\x00\x00\x00\x80\x03\x04\x04GROK\x80" \
            b"\x01\x00\x40\x06Foobar" \
            b"\x05\x00\x81\x0f" \
            b"\x07\x00\x11\xfe" \
            b"\x08\x00\x22\xab\x31" \
            b"\x09\x00\x31\xaa" \
            b"\x02\x01\xc2\x02\x12\x00\x20\x06\xaa\x00\x04\x00\x12\x08"
        e = events.Event.decode (b)
        self.assertEqual (type (e), events.Event)
        self.assertFalse (e._ms_valid)
        self.assertEqual (e._class, 256)
        self.assertEqual (e._code, 15)
        self.assertEqual (e._local_node.nodeid, Nodeid (1, 3))
        self.assertEqual (e._local_node.nodename, "GROK")
        self.assertEqual (e.param_1.val, "Foobar")
        self.assertEqual (e.param_5.val, 15)
        self.assertEqual (e.param_7.val, -2)
        self.assertEqual (e.param_8.val, 0x31ab)
        self.assertEqual (e.param_9.val, 0o252)
        self.assertEqual (e.param_258.val, [(18, DU (2)),
                                            (b"\xaa\x00\x04\x00\x12\x08",
                                             HI (0))])
        # Test some aspects of the Param classes
        p = e.param_1
        self.assertEqual (str (p), "Foobar")
        self.assertEqual (repr (p), "Parameter # 1 = Foobar")
        #
        e = str (e)
        # Event type 256.15
        # From node 1.3 (GROK), occurred 01-Jan-1977 00:00:00
        # Parameter # 1 = Foobar
        # Parameter # 5 = 15
        # Parameter # 7 = -2
        # Parameter # 8 = 31ab
        # Parameter # 9 = 252
        # Parameter # 258 = 18 aa-00-04-00-12-08
        self.assertRegex (e, r"Event type 256\.15")
        self.assertRegex (e, r"From node 1\.3 \(GROK\)")
        self.assertRegex (e, r"occurred 01-Jan-1977 00:00:00")
        self.assertRegex (e, r"Parameter # 1 = Foobar")
        self.assertRegex (e, r"Parameter # 5 = 15")
        self.assertRegex (e, r"Parameter # 7 = -2")
        self.assertRegex (e, r"Parameter # 8 = 31ab")
        self.assertRegex (e, r"Parameter # 9 = 252")
        self.assertRegex (e, r"Parameter # 258 = 18 aa-00-04-00-12-08")

    def test_node_ent (self):
        # Event with Node entity
        b = b"\x01\x07\x01\x00\x00\x00\x00\x00\x00\x80\x03\x04\x04GROK" \
            b"\x00\x05\x08\x03ARK"
        e = events.Event.decode (b)
        self.assertIsInstance (e, events.node_ctrs)
        self.assertFalse (e._ms_valid)
        self.assertEqual (e._class, 0)
        self.assertEqual (e._code, 1)
        self.assertEqual (e._local_node.nodeid, Nodeid (1, 3))
        self.assertEqual (e._local_node.nodename, "GROK")
        self.assertIsInstance (e._entity, events.NodeEntity)
        self.assertEqual (e._entity.val.nodeid, Nodeid (2, 5))
        self.assertEqual (e._entity.val.nodename, "ARK")
        e = str (e)
        # Event type 0.1, Automatic node counters
        # From node 1.3 (GROK), occurred 01-Jan-1977 00:00:00
        # Node = 2.5 (ARK)
        self.assertRegex (e, r"Event type 0\.1")
        self.assertRegex (e, r"Automatic node counters")
        self.assertRegex (e, r"From node 1\.3 \(GROK\)")
        self.assertRegex (e, r"occurred 01-Jan-1977 00:00:00")
        self.assertRegex (e, r"Node = 2\.5 \(ARK\)")

    def test_line_ent (self):
        # Event with Line entity
        b = b"\x01\x07\x08\x00\x00\x00\x00\x00\x00\x80\x03\x04\x04GROK" \
            b"\x01\x05DMC-0"
        e = events.Event.decode (b)
        self.assertIsInstance (e, events.auto_ctrs)
        self.assertFalse (e._ms_valid)
        self.assertEqual (e._class, 0)
        self.assertEqual (e._code, 8)
        self.assertEqual (e._local_node.nodeid, Nodeid (1, 3))
        self.assertEqual (e._local_node.nodename, "GROK")
        self.assertIsInstance (e._entity, events.LineEntity)
        self.assertEqual (e._entity.val, "DMC-0")
        e = str (e)
        # Event type 0.8, Automatic counters
        # From node 1.3 (GROK), occurred 01-Jan-1977 00:00:00
        # Line = DMC-0
        self.assertRegex (e, r"Event type 0\.8")
        self.assertRegex (e, r"Automatic counters")
        self.assertRegex (e, r"From node 1\.3 \(GROK\)")
        self.assertRegex (e, r"occurred 01-Jan-1977 00:00:00")
        self.assertRegex (e, r"Line = DMC-0")

    def test_circ_ent (self):
        # Event with Circuit entity
        b = b"\x01\x07\x08\x00\x00\x00\x00\x00\x00\x80\x03\x04\x04GROK" \
            b"\x03\x05DMC-0"
        e = events.Event.decode (b)
        self.assertIsInstance (e, events.auto_ctrs)
        self.assertFalse (e._ms_valid)
        self.assertEqual (e._class, 0)
        self.assertEqual (e._code, 8)
        self.assertEqual (e._local_node.nodeid, Nodeid (1, 3))
        self.assertEqual (e._local_node.nodename, "GROK")
        self.assertIsInstance (e._entity, events.CircuitEntity)
        self.assertEqual (e._entity.val, "DMC-0")
        e = str (e)
        # Event type 0.8, Automatic counters
        # From node 1.3 (GROK), occurred 01-Jan-1977 00:00:00
        # Circuit = DMC-0
        self.assertRegex (e, r"Event type 0\.8")
        self.assertRegex (e, r"Automatic counters")
        self.assertRegex (e, r"From node 1\.3 \(GROK\)")
        self.assertRegex (e, r"occurred 01-Jan-1977 00:00:00")
        self.assertRegex (e, r"Circuit = DMC-0")

    def test_module_ent (self):
        # Event with Line entity
        b = b"\x01\x07\x08\x00\x00\x00\x00\x00\x00\x80\x03\x04\x04GROK" \
            b"\x04\x05AX.25"
        e = events.Event.decode (b)
        self.assertIsInstance (e, events.auto_ctrs)
        self.assertFalse (e._ms_valid)
        self.assertEqual (e._class, 0)
        self.assertEqual (e._code, 8)
        self.assertEqual (e._local_node.nodeid, Nodeid (1, 3))
        self.assertEqual (e._local_node.nodename, "GROK")
        self.assertIsInstance (e._entity, events.ModuleEntity)
        self.assertEqual (e._entity.val, "AX.25")
        e = str (e)
        # Event type 0.8, Automatic counters
        # From node 1.3 (GROK), occurred 01-Jan-1977 00:00:00
        # Module = AX.25
        self.assertRegex (e, r"Event type 0\.8")
        self.assertRegex (e, r"Automatic counters")
        self.assertRegex (e, r"From node 1\.3 \(GROK\)")
        self.assertRegex (e, r"occurred 01-Jan-1977 00:00:00")
        self.assertRegex (e, r"Module = AX.25")

    def test_area_ent (self):
        # Event with Line entity
        b = b"\x01\x07\x08\x00\x00\x00\x00\x00\x00\x80\x03\x04\x04GROK" \
            b"\x05\x0251"
        e = events.Event.decode (b)
        self.assertIsInstance (e, events.auto_ctrs)
        self.assertFalse (e._ms_valid)
        self.assertEqual (e._class, 0)
        self.assertEqual (e._code, 8)
        self.assertEqual (e._local_node.nodeid, Nodeid (1, 3))
        self.assertEqual (e._local_node.nodename, "GROK")
        self.assertIsInstance (e._entity, events.AreaEntity)
        self.assertEqual (e._entity.val, "51")
        e = str (e)
        # Event type 0.8, Automatic counters
        # From node 1.3 (GROK), occurred 01-Jan-1977 00:00:00
        # Area = 51
        self.assertRegex (e, r"Event type 0\.8")
        self.assertRegex (e, r"Automatic counters")
        self.assertRegex (e, r"From node 1\.3 \(GROK\)")
        self.assertRegex (e, r"occurred 01-Jan-1977 00:00:00")
        self.assertRegex (e, r"Area = 51")

    def test_unk_ent (self):
        # Event with Line entity
        b = b"\x01\x07\x08\x00\x00\x00\x00\x00\x00\x80\x03\x04\x04GROK" \
            b"\x09\x05DMC-0"
        e = events.Event.decode (b)
        self.assertIsInstance (e, events.auto_ctrs)
        self.assertFalse (e._ms_valid)
        self.assertEqual (e._class, 0)
        self.assertEqual (e._code, 8)
        self.assertEqual (e._local_node.nodeid, Nodeid (1, 3))
        self.assertEqual (e._local_node.nodename, "GROK")
        self.assertIsInstance (e._entity, events.EventEntity)
        self.assertEqual (e._entity._code, 9)
        self.assertEqual (e._entity.val, "DMC-0")
        e = str (e)
        # Event type 0.8, Automatic counters
        # From node 1.3 (GROK), occurred 01-Jan-1977 00:00:00
        # Entity # 9 = DMC-0
        self.assertRegex (e, r"Event type 0\.8")
        self.assertRegex (e, r"Automatic counters")
        self.assertRegex (e, r"From node 1\.3 \(GROK\)")
        self.assertRegex (e, r"occurred 01-Jan-1977 00:00:00")
        self.assertRegex (e, r"Entity # 9 = DMC-0")

    def test_routing_evt (self):
        # Event 4.7
        b = b"\x01\x07\x07\x01\x00\x00\x00\x00\x00\x80\x03\x04\x04GROK" \
            b"\x03\x05DMC-0" \
            b"\x00\x00\xc4\x21\x42\x02\x10\x00\x02\x03\x00\x01\x17" \
            b"\x05\x00\x81\x0b" \
            b"\x07\x00\x81\x07"
        e = events.Event.decode (b)
        self.assertIsInstance (e, events.circ_fault)
        self.assertFalse (e._ms_valid)
        self.assertEqual (e._class, 4)
        self.assertEqual (e._code, 7)
        self.assertEqual (e._local_node.nodeid, Nodeid (1, 3))
        self.assertEqual (e._local_node.nodename, "GROK")
        self.assertEqual (e.packet_header.val[0][0], 0x42)
        self.assertEqual (e.reason.val, 11)
        self.assertEqual (e.status.val, 7)
        e = str (e)
        # Event type 4.7, Circuit down, circuit fault
        #  From node 1.3 (GROK), occurred 01-Jan-1977 00:00:00
        #  Circuit = DMC-0
        #  Packet header = 42 16 3 23
        #  Reason = Adjacency listener received invalid data
        #  Status = 7
        self.assertRegex (e, r"Event type 4\.7")
        self.assertRegex (e, r"Circuit down, circuit fault")
        self.assertRegex (e, r"From node 1\.3 \(GROK\)")
        self.assertRegex (e, r"occurred 01-Jan-1977 00:00:00")
        self.assertRegex (e, r"Circuit = DMC-0")
        self.assertRegex (e, r" Packet header = 42 16 3 23")
        self.assertRegex (e, r"Reason = Adjacency listener received "
                          "invalid data")
        self.assertRegex (e, r"Status = 7")

class TestEventEncode (DnTest):
    def test_routing_evt (self):
        # Event 4.7
        e = events.circ_fault (entity = "DMC-0",
                               packet_header = (0x42, 16, 3, 23),
                               reason = "listener_invalid_data",
                               status = 7)
        e._timestamp = events.jbase
        e._ms_valid = False
        e.setsource (NiceNode (Nodeid (1, 3), "GROK"))
        e2 = str (e)
        # Event type 4.7, Circuit down, circuit fault
        #  From node 1.3 (GROK), occurred 01-Jan-1977 00:00:00
        #  Circuit = DMC-0
        #  Packet header = 42 16 3 23
        #  Reason = Adjacency listener received invalid data
        #  Status = 7
        self.assertRegex (e2, r"Event type 4\.7")
        self.assertRegex (e2, r"Circuit down, circuit fault")
        self.assertRegex (e2, r"From node 1\.3 \(GROK\)")
        self.assertRegex (e2, r"occurred 01-Jan-1977 00:00:00")
        self.assertRegex (e2, r"Circuit = DMC-0")
        self.assertRegex (e2, r" Packet header = 42 16 3 23")
        self.assertRegex (e2, r"Reason = Adjacency listener received "
                          "invalid data")
        self.assertRegex (e2, r"Status = 7")
        # TODO: Add encode method, then check it
        return
        #
        b = b"\x01\x07\x07\x01\x00\x00\x00\x00\x00\x80\x03\x04\x04GROK" \
            b"\x03\x05DMC-0" \
            b"\x00\x00\xc4\x21\x42\x02\x10\x00\x02\x03\x00\x01\x17" \
            b"\x05\x00\x81\x0b" \
            b"\x07\x00\x81\x07"
        b2 = e.encode ()
        self.assertEqual (b, b2)
    

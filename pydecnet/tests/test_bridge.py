#!/usr/bin/env python3

from tests.dntest import *

from decnet import bridge
from decnet import ethernet
from decnet.datalink import Received

def makeport (*args, **kwargs):
    ret = unittest.mock.Mock ()
    ret.__class__ = ethernet.EthPort
    return ret

def pad (pkt):
    if len (pkt) >= 60:
        return pkt
    return pkt + b'.' * (60 - len (pkt))

class brtest (DnTest):
    def setUp (self):
        super ().setUp ()
        self.config = container ()
        self.config.bridge = container ()
        self.config.bridge.name = "testbridge"
        self.config.circuit = dict ()
        self.node.datalink = unittest.mock.Mock ()
        self.node.datalink.circuits = dict ()
        for n, mop in self.circ:
            self.config.circuit[n] = container ()
            self.config.circuit[n].mop = mop
            self.node.datalink.circuits[n] = unittest.mock.Mock ()
            self.node.datalink.circuits[n].__class__ = ethernet.Ethernet
            self.node.datalink.circuits[n].create_port.side_effect = makeport
        #self.setloglevel (logging.TRACE)
        self.bridge = bridge.Bridge (self.node, self.config)
        self.bridge.start ()
        i = 1
        for n, mop in self.circ:
            c = self.bridge.circuits[n]
            setattr (self, "c%d" % i, c)
            setattr (self, "d%d" % i, c.datalink)
            i += 1

class test_bridge (brtest):
    circ = ( ("lan-1", True),
             ("lan-2", True),
             ("lan-3", True) )

    def test_unicast (self):
        d = self.node.datalink
        p = pad (b"bcdefgBCDEFG\x90\x00test data")
        w = Received (owner = self.c1, pdu = p, src = self.c1, extra = None)
        self.node.addwork (w)
        # Check that it was flooded
        self.assertEqual (self.d1.parent.send_frame.call_count, 0)
        self.assertEqual (self.d2.parent.send_frame.call_count, 1)
        self.assertEqual (self.d2.parent.send_frame.call_args[0], (p, None))
        self.assertEqual (self.d3.parent.send_frame.call_count, 1)
        self.assertEqual (self.d3.parent.send_frame.call_args[0], (p, None))
        # Check that address was learned
        self.assertEqual (len (self.bridge.addrdb), 1)
        ent = self.bridge.addrdb[Macaddr (b"BCDEFG")]
        self.assertTrue (ent.islinked ())
        self.assertIs (ent.circuit, self.c1)
        # Directed reply
        p2 = pad (b"BCDEFGbcdefg\x90\x00test reply")
        w = Received (owner = self.c2, pdu = p2, src = self.c2, extra = None)
        self.node.addwork (w)
        # Check that it was sent only to port 1
        self.assertEqual (self.d1.parent.send_frame.call_count, 1)
        self.assertEqual (self.d1.parent.send_frame.call_args[0], (p2, None))
        self.assertEqual (self.d2.parent.send_frame.call_count, 1)
        self.assertEqual (self.d3.parent.send_frame.call_count, 1)
        # Check that replying address was learned
        self.assertEqual (len (self.bridge.addrdb), 2)
        ent = self.bridge.addrdb[Macaddr (b"bcdefg")]
        self.assertTrue (ent.islinked ())
        self.assertIs (ent.circuit, self.c2)
        # Move the first station to another port
        w = Received (owner = self.c3, pdu = p, src = self.c3, extra = None)
        self.node.addwork (w)
        # Check that it was sent to port 2
        self.assertEqual (self.d1.parent.send_frame.call_count, 1)
        self.assertEqual (self.d2.parent.send_frame.call_count, 2)
        self.assertEqual (self.d2.parent.send_frame.call_args[0], (p, None))
        self.assertEqual (self.d3.parent.send_frame.call_count, 1)
        # Check that address db was updated
        self.assertEqual (len (self.bridge.addrdb), 2)
        ent = self.bridge.addrdb[Macaddr (b"BCDEFG")]
        self.assertTrue (ent.islinked ())
        self.assertIs (ent.circuit, self.c3)
        # Send to station on this port
        p3 = pad (b"BCDEFG012345\x90\x00test data")
        w = Received (owner = self.c3, pdu = p3, src = self.c3, extra = None)
        self.node.addwork (w)
        # Check that it was not sent
        self.assertEqual (self.d1.parent.send_frame.call_count, 1)
        self.assertEqual (self.d2.parent.send_frame.call_count, 2)
        self.assertEqual (self.d3.parent.send_frame.call_count, 1)
        # Check that third address was learned
        self.assertEqual (len (self.bridge.addrdb), 3)
        src = Macaddr (b"012345")
        ent = self.bridge.addrdb[src]
        self.assertTrue (ent.islinked ())
        self.assertIs (ent.circuit, self.c3)
        # Expire the third address
        DnTimeout (ent)
        self.assertEqual (len (self.bridge.addrdb), 2)
        self.assertNotIn (src, self.bridge.addrdb)
        p4 = pad (b"012345bcdefg\x90\x00test reply")
        w = Received (owner = self.c2, pdu = p4, src = self.c2, extra = None)
        self.node.addwork (w)
        # Check that it was flooded
        self.assertEqual (self.d1.parent.send_frame.call_count, 2)
        self.assertEqual (self.d1.parent.send_frame.call_args[0], (p4, None))
        self.assertEqual (self.d2.parent.send_frame.call_count, 2)
        self.assertEqual (self.d3.parent.send_frame.call_count, 2)
        self.assertEqual (self.d3.parent.send_frame.call_args[0], (p4, None))

    def test_multicast (self):
        d = self.node.datalink
        p = pad (b"aaaaaaBCDEFG\x90\x00test data")
        w = Received (owner = self.c1, pdu = p, src = self.c1, extra = None)
        self.node.addwork (w)
        # Check that it was flooded
        self.assertEqual (self.d1.parent.send_frame.call_count, 0)
        self.assertEqual (self.d2.parent.send_frame.call_count, 1)
        self.assertEqual (self.d2.parent.send_frame.call_args[0], (p, None))
        self.assertEqual (self.d3.parent.send_frame.call_count, 1)
        self.assertEqual (self.d3.parent.send_frame.call_args[0], (p, None))
        # Check that address was learned
        self.assertEqual (len (self.bridge.addrdb), 1)
        ent = self.bridge.addrdb[Macaddr (b"BCDEFG")]
        self.assertTrue (ent.islinked ())
        self.assertIs (ent.circuit, self.c1)

if __name__ == "__main__":
    unittest.main ()

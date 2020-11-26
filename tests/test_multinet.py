#!/usr/bin/env python3

from tests.dntest import *

import socket
import select

from decnet import datalink
from decnet import multinet
from decnet.host import dualstack

class MultinetBase (DnTest):
    def setUp (self):
        super ().setUp ()
        logging.warning = unittest.mock.Mock ()
        self.mult = multinet.Multinet (self.node, "multinet-0", self.tconfig)
        self.rport = self.mult.create_port (self.node)
        self.node.enable_dispatcher ()
        
    def tearDown (self):
        thread = self.mult.rthread
        self.rport.close ()
        if thread:
            for i in range (15):
                time.sleep (0.1)
                if not thread.is_alive ():
                    break
            self.assertFalse (thread.is_alive ())
        self.mult.close ()
        super ().tearDown ()

    def receivedata (self):
        sellist = [ self.socket.fileno () ]
        r, w, e = select.select (sellist, [ ], sellist, 1)
        self.assertFalse (e, "Socket error")
        self.assertTrue (r, "Nothing received in send test")
        b = self.receivepdu ()
        return b

class MultinetCommonTests:
    def test_xmit (self):
        expected = self.pdu (0, testsdu ())
        self.rport.send (testsdu (), None)
        b = self.receivedata ()
        self.assertEqual (b, expected)
        self.assertEqual (self.mult.counters.bytes_sent, len (testsdu ()))
        self.assertEqual (self.mult.counters.pkts_sent, 1)
        # and another
        expected = self.pdu (1, testsdu ())
        self.rport.send (testsdu (), None)
        b = self.receivedata ()
        self.assertEqual (b, expected)
        self.assertEqual (self.mult.counters.bytes_sent, 2 * len (testsdu ()))
        self.assertEqual (self.mult.counters.pkts_sent, 2)

    def test_rcv1 (self):
        pdu = self.pdu (0, testsdu ())
        self.sendpdu (pdu)
        time.sleep (0.1)
        w = self.lastdispatch (2, itype = Received)
        b = w.packet
        self.assertEqual (b, testsdu ())
        self.assertEqual (self.mult.counters.bytes_recv, 30)        
        self.assertEqual (self.mult.counters.pkts_recv, 1)

class TestMultinetUDP (MultinetBase, MultinetCommonTests):
    def setUp (self):
        self.lport = nextport ()
        self.cport = nextport ()
        # UDP mode
        spec = "circuit mul-0 Multinet 127.0.0.1:{}:{}".format (self.lport,
                                                                self.cport)
        self.tconfig = self.config (spec)
        # Initially turn off warnings such as the Multinet UDP "don't
        # do this" warning.
        self.loglevel = logging.ERROR
        super ().setUp ()
        self.assertEqual (logging.warning.call_count, 1)
        # Revert to the default logging level, set in the class
        self.setloglevel (self.__class__.loglevel)
        self.socket = socket.socket (socket.AF_INET, socket.SOCK_DGRAM,
                                     socket.IPPROTO_UDP)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind (("", self.lport))
        self.rport.open ()
        time.sleep (0.1)
        self.assertUp ()

    def tearDown (self):
        self.socket.close ()
        super ().tearDown ()

    def pdu (self, n, sdu):
        return n.to_bytes (2, "little") + b"\000\000" + sdu
    
    def receivepdu (self):
        b, addr = self.socket.recvfrom (1500)
        self.assertEqual (addr, ("127.0.0.1", self.cport))
        return b
    
    def sendpdu (self, pdu):
        self.socket.sendto (pdu, ("127.0.0.1", self.cport))

class TestMultinetUDPnodest (MultinetBase):
    def setUp (self):
        self.lport = nextport ()
        self.cport = nextport ()
        spec = "circuit mul-0 Multinet 127.0.0.1:{}:{}".format (self.lport,
                                                                self.cport)
        self.tconfig = self.config (spec)
        # Initially turn off warnings such as the Multinet UDP "don't
        # do this" warning.
        self.loglevel = logging.ERROR
        super ().setUp ()
        self.assertEqual (logging.warning.call_count, 1)
        # Revert to the default logging level, set in the class
        self.setloglevel (self.__class__.loglevel)
        self.rport.open ()
    
    def test_xmit (self):
        "Try sending, but of course they go into a black hole"
        # Allow a few moments for the receive thread to come up, which
        # is what declares "connected"
        time.sleep (0.3)
        self.rport.send (testsdu (), None)
        self.assertEqual (self.mult.counters.bytes_sent, len (testsdu ()))
        self.assertEqual (self.mult.counters.pkts_sent, 1)
        # and another
        self.rport.send (testsdu (), None)
        self.assertEqual (self.mult.counters.bytes_sent, 2 * len (testsdu ()))
        self.assertEqual (self.mult.counters.pkts_sent, 2)

class MultinetTCPbase (MultinetBase, MultinetCommonTests):
    def tearDown (self):
        try:
            self.socket.shutdown (socket.SHUT_RDWR)
        except OSError:
            # If socket isn't connected a shutdown will fail
            pass
        self.socket.close ()
        super ().tearDown ()

    def pdu (self, n, sdu):
        return len (sdu).to_bytes (2, "little") + b"\000\000" + sdu
    
    def sendpdu (self, pdu):
        self.socket.send (pdu)

    def receivepdu (self):
        hdr = self.socket.recv (4)
        self.assertEqual (len (hdr), 4)
        plen = int.from_bytes (hdr[:2], "little")
        b = self.socket.recv (plen)
        return hdr + b

    def test_close (self):
        "Test port close"
        self.rport.close ()
        time.sleep (0.1)
        try:
            b = self.socket.recv (1)
            self.assertEqual (b, b"")
        except OSError:
            # This is also a valid outcome
            pass
        
    def test_restart (self):
        "Test local restart to force disconnect, then reconnect"
        self.rport.restart ()
        time.sleep (0.1)
        b = self.socket.recv (1)
        self.assertEqual (b, b"")
        self.socket.close ()
        # Local restart skips the holdoff, so no timer to be expired.
        self.do_reconnect (3, False)

    def test_reconnect (self):
        "Test remote restart which closes the connection"
        logging.trace ("Disconnecting the socket")
        self.socket.shutdown (socket.SHUT_RDWR)
        self.socket.close ()
        time.sleep (0.1)
        w = self.lastdispatch (2, itype = datalink.DlStatus)
        self.assertEqual (w.status, w.DOWN)
        self.do_reconnect (3)

    def test_framing1 (self):
        "Test handling of a frame that arrives in pieces"
        self.socket.setsockopt (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        pdu = self.pdu (0, testsdu ())
        # Send the start (note: not even a complete Multinet header)
        self.socket.send (pdu[:3])
        time.sleep (0.1)
        self.lastdispatch (1, itype = datalink.DlStatus)
        # Send the rest of the header and most of the payload
        self.socket.send (pdu[3:-8])
        time.sleep (0.1)
        self.lastdispatch (1, itype = datalink.DlStatus)
        # Send the final part of the frame
        self.socket.send (pdu[-8:])
        time.sleep (0.1)
        w = self.lastdispatch (2, itype = Received)
        b = w.packet
        self.assertEqual (b, testsdu ())
        self.assertEqual (self.mult.counters.bytes_recv, 30)        
        self.assertEqual (self.mult.counters.pkts_recv, 1)

    def test_framing2 (self):
        "Test handling of two frames arriving all at once"
        pdus = self.pdu (0, bytes (4)) + self.pdu (1, bytes (6))
        # Send the pair all at once
        self.socket.send (pdus)
        time.sleep (0.1)
        w1 = self.lastdispatch (3, back = 1, itype = Received)
        b1 = w1.packet
        self.assertEqual (b1, bytes (4))
        w2 = self.lastdispatch (3, itype = Received)
        b2 = w2.packet
        self.assertEqual (b2, bytes (6))
        self.assertEqual (self.mult.counters.bytes_recv, 10)
        self.assertEqual (self.mult.counters.pkts_recv, 2)
        
class TestMultinetTCPconnect (MultinetTCPbase):
    "Test TCP connect mode"

    def setUp (self):
        self.lport = nextport ()
        # TCP connect mode
        spec = "circuit mul-0 Multinet 127.0.0.1:{}:connect".format (self.lport)
        self.tconfig = self.config (spec)
        super ().setUp ()
        self.socket = socket.socket (socket.AF_INET)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind (("", self.lport))
        self.socket.listen (1)
        self.rport.open ()
        sock, ainfo = self.socket.accept ()
        self.assertEqual (ainfo[0], "127.0.0.1")
        self.socket.close ()
        self.socket = sock
        time.sleep (0.1)
        self.assertUp ()        

    def do_reconnect (self, count, expire = True):
        self.socket = socket.socket (socket.AF_INET)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind (("", self.lport))
        self.socket.listen (1)
        time.sleep (0.3)
        DnTimeout (self.rport.parent)
        sock, ainfo = self.socket.accept ()
        self.assertEqual (ainfo[0], "127.0.0.1")
        self.socket.close ()
        self.socket = sock
        self.assertUp (count)

@unittest.skipUnless (dualstack, "Test needs IPv4/v6 dual stack support")
class TestMultinetTCPconnect2 (MultinetTCPbase):
    "Test TCP connect mode, two addresses"
    def setUp (self):
        self.lport = nextport ()
        # TCP connect mode
        spec = "circuit mul-0 Multinet localhost:{}:connect -446".format (self.lport)
        self.tconfig = self.config (spec)
        super ().setUp ()
        self.socket = socket.socket (socket.AF_INET)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind (("", self.lport))
        self.socket.listen (1)
        logging.trace ("Listening to IPv4")
        self.rport.open ()
        sock, ainfo = self.socket.accept ()
        self.assertEqual (ainfo[0], "127.0.0.1")
        self.socket.close ()
        self.socket = sock
        self.socket2 = socket.socket (socket.AF_INET6)
        self.socket2.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket2.setsockopt (socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.socket2.bind (("", self.lport))
        self.socket2.listen (1)
        time.sleep (0.1)
        self.assertUp ()        

    def tearDown (self):
        self.socket2.close ()
        super ().tearDown ()
        
    def do_reconnect (self, count, expire = True):
        time.sleep (0.3)
        DnTimeout (self.rport.parent)
        sock, ainfo = self.socket2.accept ()
        self.assertEqual (ainfo[0], "::1")
        self.socket2.close ()
        self.socket = sock
        self.assertUp (count)

class TestMultinetTCPconnectLate (MultinetBase):
    def setUp (self):
        self.lport = nextport ()
        # TCP connect mode
        spec = "circuit mul-0 Multinet 127.0.0.1:{}:connect".format (self.lport)
        self.tconfig = self.config (spec)
        super ().setUp ()

    def tearDown (self):
        try:
            self.socket.shutdown (socket.SHUT_RDWR)
        except (OSError, AttributeError):
            # If socket isn't connected, or hasn't been created yet, a
            # shutdown will fail
            pass
        try:
            self.socket.close ()
        except (OSError, AttributeError):
            # In case socket is None, or hasn't been created yet.
            pass
        super ().tearDown ()

    def createTestListener (self):
        self.socket = socket.socket (socket.AF_INET)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind (("", self.lport))
        self.socket.listen (1)
        DnTimeout (self.rport.parent)
        sock, ainfo = self.socket.accept ()
        self.assertEqual (ainfo[0], "127.0.0.1")
        self.socket.close ()
        self.socket = sock
        time.sleep (0.1)
        self.assertUp ()        

    def test_nolistener (self):
        "Test operation when the listener doesn't appear until later"
        self.rport.open ()
        time.sleep (0.1)
        logging.trace ("opened the port")
        self.lastdispatch (0, itype = datalink.DlStatus)
        logging.trace ("about to create listener")
        self.createTestListener ()
        logging.trace ("listener created")
        
class TestMultinetTCPlisten (MultinetTCPbase):
    def setUp (self):
        self.lport = nextport ()
        # TCP listen mode
        spec = "circuit mul-0 Multinet 127.0.0.1:{}:listen".format (self.lport)
        self.tconfig = self.config (spec)
        super ().setUp ()
        self.rport.open ()
        time.sleep (0.1)
        self.socket = socket.socket (socket.AF_INET)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect (("127.0.0.1", self.lport))
        time.sleep (0.1)
        self.assertUp ()

    def do_reconnect (self, count, expire = True):
        self.socket = socket.socket (socket.AF_INET)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if expire:
            DnTimeout (self.rport.parent)
        time.sleep (0.1)
        self.socket.connect (("127.0.0.1", self.lport))
        time.sleep (0.1)
        self.assertUp (count)

@unittest.skipUnless (socket.has_ipv6, "Test needs IPv6 support")
class TestMultinetTCP6listen (MultinetTCPbase):
    def setUp (self):
        self.lport = nextport ()
        # TCP listen mode
        spec = "circuit mul-0 Multinet --mode listen --source ::1 --source-port {}".format (self.lport)
        self.tconfig = self.config (spec)
        super ().setUp ()
        self.rport.open ()
        time.sleep (0.1)
        self.socket = socket.socket (socket.AF_INET6)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect (("::1", self.lport))
        time.sleep (0.1)
        self.assertUp ()

    def do_reconnect (self, count, expire = True):
        self.socket = socket.socket (socket.AF_INET6)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if expire:
            DnTimeout (self.rport.parent)
        time.sleep (0.1)
        self.socket.connect (("::1", self.lport))
        time.sleep (0.1)
        self.assertUp (count)
        
@unittest.skipUnless (dualstack, "Test needs IPv4/v6 dual stack support")
class TestMultinetTCP46listen (MultinetTCPbase):
    "Test mixed IPv4/v6 operation"
    
    def setUp (self):
        self.lport = nextport ()
        # TCP listen mode
        spec = "circuit mul-0 Multinet --mode listen -46 --source-port {}".format (self.lport)
        self.tconfig = self.config (spec)
        super ().setUp ()
        self.rport.open ()
        time.sleep (0.1)
        self.socket = socket.socket (socket.AF_INET6)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect (("::1", self.lport))
        time.sleep (0.1)
        self.assertUp ()

    def do_reconnect (self, count, expire = True):
        # Reconnect with IPv4.
        self.socket = socket.socket (socket.AF_INET)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if expire:
            DnTimeout (self.rport.parent)
        time.sleep (0.1)
        self.socket.connect (("127.0.0.1", self.lport))
        time.sleep (0.1)
        self.assertUp (count)
        
if __name__ == "__main__":
    unittest.main ()

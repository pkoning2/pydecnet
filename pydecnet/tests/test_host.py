#!/usr/bin/env python3

from tests.dntest import *

import socket
import time

from decnet import host
from decnet import config

class TestHost (DnTest):
    @unittest.skipUnless (host.dualstack, "Need dual stack support")
    def test_goodhost46 (self):
        spec = "circuit mul-0 Multinet"
        tconfig = self.config (spec)
        s = host.SourceAddress (tconfig)
        h = host.HostAddress ("localhost", 42, s)
        self.assertEqual (h.listen_family, socket.AF_INET6)
        self.assertIn (("127.0.0.1", 42), h.sockaddrset)
        self.assertIn (("::1", 42, 0, 0), h.sockaddrset)
        self.assertTrue (h.use_dualstack)
            
    @unittest.skipUnless (host.dualstack, "Need dual stack support")
    def test_goodhost446 (self):
        spec = "circuit mul-0 Multinet -446"
        tconfig = self.config (spec)
        s = host.SourceAddress (tconfig)
        h = host.HostAddress ("localhost", 42, s)
        # Verify that we get the IPv4 address first, then IPv6
        self.assertEqual (("127.0.0.1", 42), h.sockaddr)
        next (h)
        self.assertEqual (("::1", 42, 0, 0), h.sockaddr)
        # ...and they cycle
        next (h)
        self.assertEqual (("127.0.0.1", 42), h.sockaddr)
            
    @unittest.skipUnless (host.dualstack, "Need dual stack support")
    def test_goodhost466 (self):
        spec = "circuit mul-0 Multinet -466"
        tconfig = self.config (spec)
        s = host.SourceAddress (tconfig)
        h = host.HostAddress ("localhost", 42, s)
        # Verify that we get the IPv6 address first, then IPv4
        self.assertEqual (("::1", 42, 0, 0), h.sockaddr)
        next (h)
        self.assertEqual (("127.0.0.1", 42), h.sockaddr)
        # ...and they cycle
        next (h)
        self.assertEqual (("::1", 42, 0, 0), h.sockaddr)
            
    def test_goodhost4 (self):
        spec = "circuit mul-0 Multinet -4"
        tconfig = self.config (spec)
        s = host.SourceAddress (tconfig)
        h = host.HostAddress ("localhost", 42, s)
        self.assertEqual (h.listen_family, socket.AF_INET)
        self.assertIn (("127.0.0.1", 42), h.sockaddrset)
        self.assertNotIn (("::1", 42, 0, 0), h.sockaddrset)
        self.assertFalse (h.use_dualstack)

    @unittest.skipUnless (socket.has_ipv6, "Need IPv6 support")
    def test_goodhost6 (self):
        spec = "circuit mul-0 Multinet -6"
        tconfig = self.config (spec)
        s = host.SourceAddress (tconfig)
        h = host.HostAddress ("localhost", 42, s)
        self.assertEqual (h.listen_family, socket.AF_INET6)
        self.assertNotIn (("127.0.0.1", 42), h.sockaddrset)
        self.assertIn (("::1", 42, 0, 0), h.sockaddrset)
        self.assertFalse (h.use_dualstack)

    def test_badhost (self):
        spec = "circuit mul-0 Multinet"
        tconfig = self.config (spec)
        s = host.SourceAddress (tconfig)
        with self.assertRaises (ValueError):
            h = host.HostAddress ("nosuchnameexists", 42, s)

    def test_badhost2 (self):
        spec = "circuit mul-0 Multinet -4"
        tconfig = self.config (spec)
        s = host.SourceAddress (tconfig)
        # Create with a good name
        h = host.HostAddress ("localhost", 42, s)
        self.assertIn (("127.0.0.1", 42), h.sockaddrset)
        # Hack: set the name to a bad name and force a refresh, which
        # should fail.  The expected outcome is that the address info
        # is unchanged.
        h.name = "nosuchnameexists"
        h.next_check = 1
        # Reference the address to trigger a lookup
        h.sockaddr
        self.assertNotEqual (h.next_check, 1)
        # The lookup is asynchronous, so give it a bit of time.
        time.sleep (0.1)
        self.assertIn (("127.0.0.1", 42), h.sockaddrset)
        self.assertTrace ("DNS error looking up")

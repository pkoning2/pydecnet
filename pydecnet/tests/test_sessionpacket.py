#!/usr/bin/env python3

from tests.dntest import *

from decnet import session
from decnet import logging

class test_packets (DnTest):

    def test_enduser (self):
        # Type 0
        p = b"\x00\x19"
        user25 = self.shortfield (p, session.EndUser)
        self.assertEqual (user25.fmt, 0)
        self.assertEqual (user25.num, 25)
        self.assertEqual (user25.name, "")
        self.assertIsNone (user25.group)
        self.assertIsNone (user25.user)
        # Type 1
        p = b"\x01\x00\x03FOO"
        userfoo = self.shortfield (p, session.EndUser)
        self.assertEqual (userfoo.fmt, 1)
        self.assertEqual (userfoo.num, 0)
        self.assertIsNone (userfoo.group)
        self.assertIsNone (userfoo.user)
        self.assertEqual (userfoo.name, "FOO")
        # Type 2
        p = b"\x02\x00\x11\x00\x22\x01\x03BAR"
        userbar = self.shortfield (p, session.EndUser)
        self.assertEqual (userbar.fmt, 2)
        self.assertEqual (userbar.num, 0)
        self.assertEqual (userbar.group, 17)
        self.assertEqual (userbar.user, 290)
        self.assertEqual (userbar.name, "BAR")

    def test_bad_enduser (self):
        # Type 0, no num
        p = b"\x00\x00"
        with self.assertRaises (session.BadEndUser):
            user25, x = session.EndUser.decode (p)
        # Type 1, no name
        p = b"\x01\x00\x00"
        with self.assertRaises (session.BadEndUser):
            userfoo, x = session.EndUser.decode (p)
        # Type 1, with num
        p = b"\x01\x66\x03FOO"
        with self.assertRaises (session.BadEndUser):
            userfoo, x = session.EndUser.decode (p)
        # Type 3
        p = b"\x03\x00\x11\x00\x22\x01\x03BAR"
        with self.assertRaises (session.BadEndUser):
            userbar,x = session.EndUser.decode (p)
        # Oversized name
        p = b"\x01\x00\x11AAAAAAAAAAAAAAAAA"
        with self.assertRaises (FieldOverflow):
            userfoo, x = session.EndUser.decode (p)
        # Oversized name, type 2
        p = b"\x01\x00GGUU\x0dAAAAAAAAAAAAA"
        with self.assertRaises (FieldOverflow):
            userfoo, x = session.EndUser.decode (p)
        
    def test_ci (self):
        # Basic CI, no optional fields
        p = b"\x00\x15\x01\x00\x04PAUL\x00"
        baseci = self.short (p, session.SessionConnInit)
        self.assertEqual (baseci.dstname.num, 21)
        self.assertEqual (baseci.srcname.name, "PAUL")
        self.assertEqual (baseci.auth, 0)
        self.assertEqual (baseci.rqstrid, "")
        self.assertEqual (baseci.passwrd, "")
        self.assertEqual (baseci.account, "")
        self.assertEqual (baseci.userdata, 0)
        self.assertEqual (baseci.connectdata, b"")
        # CI with auth data
        p = b"\x00\x15\x01\x00\x04PAUL\x01\x04User\x08Password\x03Act"
        baseci = self.short (p, session.SessionConnInit)
        self.assertEqual (baseci.dstname.num, 21)
        self.assertEqual (baseci.srcname.name, "PAUL")
        self.assertEqual (baseci.auth, 1)
        self.assertEqual (baseci.rqstrid, "User")
        self.assertEqual (baseci.passwrd, "Password")
        self.assertEqual (baseci.account, "Act")
        self.assertEqual (baseci.userdata, 0)
        self.assertEqual (baseci.connectdata, b"")
        # CI with application connect data
        p = b"\x00\x15\x01\x00\x04PAUL\x02\x04Conn"
        baseci = self.short (p, session.SessionConnInit)
        self.assertEqual (baseci.dstname.num, 21)
        self.assertEqual (baseci.srcname.name, "PAUL")
        self.assertEqual (baseci.auth, 0)
        self.assertEqual (baseci.rqstrid, "")
        self.assertEqual (baseci.passwrd, "")
        self.assertEqual (baseci.account, "")
        self.assertEqual (baseci.userdata, 1)
        self.assertEqual (baseci.connectdata, b"Conn")
        # CI with both optional elements
        p = b"\x00\x15\x01\x00\x04PAUL\x03\x04User\x08Password\x03Act\x05Hello"
        baseci = self.short (p, session.SessionConnInit)
        self.assertEqual (baseci.dstname.num, 21)
        self.assertEqual (baseci.srcname.name, "PAUL")
        self.assertEqual (baseci.auth, 1)
        self.assertEqual (baseci.rqstrid, "User")
        self.assertEqual (baseci.passwrd, "Password")
        self.assertEqual (baseci.account, "Act")
        self.assertEqual (baseci.userdata, 1)
        self.assertEqual (baseci.connectdata, b"Hello")

if __name__ == "__main__":
    unittest.main ()

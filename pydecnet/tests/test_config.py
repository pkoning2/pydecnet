#!/usr/bin/env python3

from tests.dntest import *
import io
try:
    import pam
except ImportError:
    pam = None

from decnet import config
from decnet import ethernet
from decnet import logging
from decnet.host import dualstack

def errmsg ():
    if not config.logging.error.called:
        return None
    args, kwargs = config.logging.error.call_args
    return args[2]

class Logchecker (DnTest):
    req = ""

    def setUp (self):
        super ().setUp ()
        config.logging.error = unittest.mock.Mock ()

    def ctest (self, s):
        # Supply a config file which has the given entries, plus
        # enough other stuff to keep Config happy.
        f = io.StringIO (self.req + s + '\n')
        f.name = "test"
        return config.Config (f)

    def checkerr (self, s, re):
        self.assertRaises (SystemExit, self.ctest, s)
        self.assertRegex (errmsg (), re)
        
class TestCircuit (Logchecker):
    req = """routing 1.1
    """
    
    def test_basic (self):
        # Test the basic parsing, multiple entries, defaults.
        # Note that some defaults are handled at a higher layer, so
        # those defaulted values end up as None here. 
        c = self.ctest ("circuit test-0 Ethernet foo\n"
                        "circuit test-1 Multinet bar --cost 5")
        cc = c.circuit["TEST-0"]
        self.assertEqual (cc.cost, 4)
        self.assertIsNone (cc.t1)
        self.assertIsNone (cc.t3)
        self.assertIsNone (cc.console)
        self.assertEqual (cc.type, "Ethernet")
        self.assertEqual (cc.device, "foo")
        self.assertFalse (cc.random_address)
        self.assertFalse (cc.verify)
        self.assertEqual (cc.nr, 10)
        self.assertEqual (cc.priority, 64)
        cc = c.circuit["TEST-1"]
        self.assertEqual (cc.cost, 5)
        self.assertIsNone (cc.t1)
        self.assertIsNone (cc.t3)
        self.assertIsNone (cc.console)
        self.assertEqual (cc.type, "Multinet")
        self.assertEqual (cc.device, "bar")
        self.assertFalse (cc.random_address)
        self.assertEqual (cc.nr, 10)
        self.assertEqual (cc.priority, 64)
        self.assertEqual (set (c.circuit), { "TEST-0", "TEST-1" })

    def test_allargs (self):
        c = self.ctest ("circuit test-0 GRE foo --cost 2 --t1 5 --t3 15 " \
                        "--console 'abcdef' " \
                        "--random-address --nr 15 " \
                        "--priority 12 --verify")
        cc = c.circuit["TEST-0"]
        self.assertEqual (cc.cost, 2)
        self.assertEqual (cc.t1, 5)
        self.assertEqual (cc.t3, 15)
        self.assertEqual (cc.console, b"abcdef\000\000")
        self.assertEqual (cc.type, "GRE")
        self.assertEqual (cc.device, "foo")
        self.assertTrue (cc.random_address)
        self.assertTrue (cc.verify)
        self.assertEqual (cc.nr, 15)
        self.assertEqual (cc.priority, 12)

    def test_alltypes (self):
        # Check that all datalink types are accepted
        c = self.ctest ("""circuit eth-0 Ethernet dev
        circuit gre-0 GRE dev
        circuit mul-0 Multinet dev
        circuit dmc-0 DDCMP dev""")
        self.assertEqual (set (c.circuit), { "ETH-0", "GRE-0",
                                             "MUL-0", "DMC-0" })

class TestCircuit_err (Logchecker):
    req = """routing 1.1
    """
    loglevel = logging.CRITICAL
    
    def test_errors (self):
        self.checkerr ("circuit", "arguments are required")
        self.checkerr ("circuit name", "arguments are required")
        self.checkerr ("circuit foo-0 GRE foo --frob", "unrecognized argument")
        self.checkerr ("circuit foo-0 GRE foo --t1 wrong", "invalid int value")
        self.checkerr ("circuit foo-0 GRE foo --console wrongstring",
                       "invalid scan_ver value")
        self.checkerr ("circuit foo-0 unknown foo", "invalid choice")
        self.checkerr ("circuit foo-0 GRE foo --nr 0", "invalid choice")
        self.checkerr ("circuit foo-0 GRE foo --nr 35", "invalid choice")
        if dualstack:
            self.checkerr ("circuit foo-0 GRE foo --prio -1",
                           "expected one argument")
        else:
            self.checkerr ("circuit foo-0 GRE foo --prio -1", "invalid choice")
        self.checkerr ("circuit foo-0 GRE foo --prio 128", "invalid choice")
        self.checkerr ("circuit foo-0 GRE foo\ncircuit foo-0 Ethernet dev",
                       "Conflicting value for circuit name")
        
class TestLogging (Logchecker):
    req = """bridge br-0
    """

    def test_basic (self):
        c = self.ctest ("logging console")
        cc = c.logging[(None, "console")]
        self.assertEqual (cc.type, "console")
        self.assertIsNone (cc.sink_node)
        self.assertEqual (cc.events, "")
        self.assertEqual (cc.sink_file, "events.dat")

    def test_allargs (self):
        c = self.ctest ("logging file --sink-node foo --sink-file file.dat "
                        "--events '1.2,2.2-7,4.*'")
        cc = c.logging[("foo", "file")]
        self.assertEqual (cc.type, "file")
        self.assertEqual (cc.sink_node, "foo")
        self.assertEqual (cc.events, "1.2,2.2-7,4.*")
        self.assertEqual (cc.sink_file, "file.dat")

    def test_repeated (self):
        c = self.ctest ("logging console\nlogging console")
        cc = c.logging[(None, "console")]
        self.assertEqual (cc.type, "console")
        self.assertIsNone (cc.sink_node)
        self.assertEqual (cc.events, "")
        self.assertEqual (cc.sink_file, "events.dat")
        
class TestLogging_err (Logchecker):
    req = """routing 1.1
    """
    loglevel = logging.CRITICAL

    def test_errors (self):
        self.checkerr ("logging", "required: type")
        self.checkerr ("logging wrongsink", "invalid choice")
        self.checkerr ("logging console --frob", "unrecognized argument")
        self.checkerr ("logging console\nlogging console --sink-file foo.dat",
                       "Conflicting value for logger name")

class TestHttp (Logchecker):
    req = ""
    
    def test_basic (self):
        c = self.ctest ("http").http
        self.assertEqual (c.http_port, 8000)
        self.assertEqual (c.https_port, 8443)
        self.assertEqual (c.certificate, "decnet.pem")
        
    def test_allargs (self):
        c = self.ctest ("http --http-port 99 --https 102 --certificate frob.pem").http
        self.assertEqual (c.http_port, 99)
        self.assertEqual (c.https_port, 102)
        self.assertEqual (c.certificate, "frob.pem")
        
class TestHttp_err (Logchecker):
    req = ""
    loglevel = logging.CRITICAL
    
    def test_errors (self):
        self.checkerr ("http --frob", "unrecognized argument")
        if dualstack:
            self.checkerr ("http --http-port -1", "expected one argument")
        else:
            self.checkerr ("http --http-port -1", "invalid choice")
        self.checkerr ("http --http-port 65536", "invalid choice")
        if dualstack:
            self.checkerr ("http --https-port -1", "expected one argument")
        else:
            self.checkerr ("http --https-port -1", "invalid choice")
        self.checkerr ("http --https-port 65536", "invalid choice")
        
class TestApi (Logchecker):
    req = ""

    def test_basic (self):
        c = self.ctest ("api").api
        self.assertEqual (c.name, config.defsockname)
        self.assertEqual (c.mode, 0o666)

    def test_allarts (self):
        c = self.ctest ("api othersocket --mode 123").api
        self.assertEqual (c.name, "othersocket")
        self.assertEqual (c.mode, 0o123)
        
class TestApi_err (Logchecker):
    req = ""
    loglevel = logging.CRITICAL
    
    def test_errors (self):
        self.checkerr ("api --frob", "unrecognized argument")
        self.checkerr ("api --mode 1000", "invalid choice")
        self.checkerr ("api --mode 668", "Invalid octal number")
        
class TestRouting (Logchecker):
    def test_basic (self):
        c = self.ctest ("routing 1.1").routing
        self.assertEqual (c.id, Nodeid (1, 1))
        self.assertEqual (c.type, "l2router")
        self.assertEqual (c.maxhops, 16)
        self.assertEqual (c.maxcost, 128)
        self.assertEqual (c.amaxhops, 16)
        self.assertEqual (c.amaxcost, 128)
        self.assertEqual (c.maxvisits, 32)
        self.assertEqual (c.maxnodes, 1023)
        self.assertEqual (c.maxarea, 63)
        self.assertEqual (c.t1, 600)
        self.assertEqual (c.bct1, 10)
        self.assertIsNone (c.intercept)
        
    def test_allargs (self):
        c = self.ctest ("routing 1.2 --type l1router --maxhops 9 " \
                        "--maxcost 42 --amaxhops 11 --amaxcost 49 " \
                        "--maxvisits 17 --maxnodes 999 --maxarea 43 " \
                        "--t1 124 --bct1 17 --no-intercept").routing
        self.assertEqual (c.id, Nodeid (1, 2))
        self.assertEqual (c.type, "l1router")
        self.assertEqual (c.maxhops, 9)
        self.assertEqual (c.maxcost, 42)
        self.assertEqual (c.amaxhops, 11)
        self.assertEqual (c.amaxcost, 49)
        self.assertEqual (c.maxvisits, 17)
        self.assertEqual (c.maxnodes, 999)
        self.assertEqual (c.maxarea, 43)
        self.assertEqual (c.t1, 124)
        self.assertEqual (c.bct1, 17)
        self.assertEqual (c.intercept, 0)

class TestRouting_err (Logchecker):
    loglevel = logging.CRITICAL
    
    def test_errors (self):
        self.checkerr ("routing", "arguments are required")
        self.checkerr ("routing 1.1 --frob", "unrecognized argument")
        self.checkerr ("routing 1.1 --type phase5router", "invalid choice")
        self.checkerr ("routing 1.1 --maxhops 0", "invalid choice")
        self.checkerr ("routing 1.1 --maxhops 31", "invalid choice")
        self.checkerr ("routing 1.1 --maxcost 0", "invalid choice")
        self.checkerr ("routing 1.1 --maxcost 1023", "invalid choice")
        self.checkerr ("routing 1.1 --amaxhops 0", "invalid choice")
        self.checkerr ("routing 1.1 --amaxhops 31", "invalid choice")
        self.checkerr ("routing 1.1 --amaxcost 0", "invalid choice")
        self.checkerr ("routing 1.1 --amaxcost 1023", "invalid choice")
        self.checkerr ("routing 1.1 --maxvisits 0", "invalid choice")
        self.checkerr ("routing 1.1 --maxvisits 64", "invalid choice")
        self.checkerr ("routing 1.1 --maxnodes 0", "invalid choice")
        self.checkerr ("routing 1.1 --maxnodes 1024", "invalid choice")
        self.checkerr ("routing 1.1 --maxarea 0", "invalid choice")
        self.checkerr ("routing 1.1 --maxarea 64", "invalid choice")
        self.checkerr ("routing 1.1 --t1 wrong", "invalid int value")

class TestNode (Logchecker):
    req = """routing 1.1
    """
    
    def test_basic (self):
        c = self.ctest ("node 1.2 foo")
        cc = c.node["FOO"]
        self.assertEqual (cc.id, Nodeid (1, 2))
        self.assertIsNone (cc.inbound_verification)
        self.assertIsNone (cc.outbound_verification)
        self.assertEqual (set (c.node), { "FOO" })

    def test_allargs (self):
        c = self.ctest ("node 4.2 foo --inbound-verification bar --out baz")
        cc = c.node["FOO"]
        self.assertEqual (cc.id, Nodeid (4, 2))
        self.assertEqual (cc.inbound_verification, "bar")
        self.assertEqual (cc.outbound_verification, "baz")

    def test_repeated (self):
        c = self.ctest ("node 1.3 foo\nnode 1.3 foo")
        cc = c.node["FOO"]
        self.assertEqual (cc.id, Nodeid (1, 3))
        self.assertIsNone (cc.inbound_verification)
        self.assertIsNone (cc.outbound_verification)
        self.assertEqual (set (c.node), { "FOO" })
        
    def test_moreargs (self):
        c = self.ctest ("node 1.3 foo\nnode 1.3 foo --inboun bar")
        cc = c.node["FOO"]
        self.assertEqual (cc.id, Nodeid (1, 3))
        self.assertEqual (cc.inbound_verification, "bar")
        self.assertIsNone (cc.outbound_verification)
        self.assertEqual (set (c.node), { "FOO" })
        

class TestNode_err (Logchecker):
    req = """routing 1.1
    """
    loglevel = logging.CRITICAL
    
    def test_errors (self):
        self.checkerr ("node", "arguments are required")
        self.checkerr ("node 1.4", "arguments are required")
        self.checkerr ("node 1.2 foo --frob", "unrecognized argument")
        self.checkerr ("node 1.3 foo\nnode 1.42 foo",
                       "Conflicting value for node name")
        self.checkerr ("node 1.3 foo\nnode 1.3 bar",
                       "Conflicting value for node address")

class TestNSP (Logchecker):
    req = """routing 1.1
    """
    
    def test_basic (self):
        c = self.ctest ("").nsp
        self.assertEqual (c.max_connections, 4095)
        self.assertEqual (c.nsp_weight, 3)
        self.assertEqual (c.nsp_delay, 2.0)
        self.assertEqual (c.qmax, 20)    # Default is 20, FIXME?
        self.assertEqual (c.retransmits, 5)

    def test_allargs (self):
        c = self.ctest ("nsp --max-conn 1023 --nsp-weight 8 " \
                        "--nsp-delay 13.5 --qmax 14 --retransmits 7").nsp
        self.assertEqual (c.max_connections, 1023)
        self.assertEqual (c.nsp_weight, 8)
        self.assertEqual (c.nsp_delay, 13.5)
        self.assertEqual (c.qmax, 14)
        self.assertEqual (c.retransmits, 7)

class TestNSP_err (Logchecker):
    req = """routing 1.1
    """
    loglevel = logging.CRITICAL
    
    def test_errors (self):
        self.checkerr ("nsp --frob", "unrecognized argument")
        self.checkerr ("nsp --max-connections 1024", "invalid choice")
        self.checkerr ("nsp --nsp-weight -1", "invalid choice")
        self.checkerr ("nsp --nsp-weight 256", "invalid choice")
        self.checkerr ("nsp --qmax 2048", "invalid choice")
        self.checkerr ("nsp --retransmits 20", "invalid choice")

class TestBridge (Logchecker):

    def test_basic (self):
        c = self.ctest ("bridge br-0").bridge
        self.assertEqual (c.name, "br-0")

class TestBridge_err (Logchecker):
    loglevel = logging.CRITICAL
    
    def test_errors (self):
        self.checkerr ("bridge", "arguments are required")
        self.checkerr ("bridge", "name")
        self.checkerr ("bridge -frob br-0 cir-0", "unrecognized argument")

class TestObject (Logchecker):
    req = """routing 1.1
    """

    def test_num (self):
        c = self.ctest ("object --number 25")
        cc = c.object[0]
        self.assertEqual (cc.number, 25)
        self.assertIsNone (cc.name)
        self.assertFalse (cc.disable)
        self.assertIsNone (cc.file)
        self.assertIsNone (cc.module)
        self.assertEqual (cc.authentication, "off")
        self.assertEqual (cc.argument, [ ])
        
    def test_name (self):
        c = self.ctest ("object --name frob")
        cc = c.object[0]
        self.assertEqual (cc.number, 0)
        self.assertEqual (cc.name, "frob")
        self.assertFalse (cc.disable)
        self.assertIsNone (cc.file)
        self.assertIsNone (cc.module)
        self.assertEqual (cc.authentication, "off")
        self.assertEqual (cc.argument, [ ])
        
    @unittest.skipIf (pam is None, "No PAM support")
    def test_allargs1 (self):
        c = self.ctest ("object --number 25 --name mirror --file mir.tec --argument hello --authentication on")
        cc = c.object[0]
        self.assertEqual (cc.number, 25)
        self.assertEqual (cc.name, "mirror")
        self.assertFalse (cc.disable)
        self.assertEqual (cc.file, "mir.tec")
        self.assertIsNone (cc.module)
        self.assertEqual (cc.authentication, "on")
        self.assertEqual (cc.argument, [ "hello" ])
        
    def test_allargs2 (self):
        # Not quite all; omit authentication so this can run without PAM.
        c = self.ctest ("object --number 25 --name mirror --disable --argument hello")
        cc = c.object[0]
        self.assertEqual (cc.number, 25)
        self.assertEqual (cc.name, "mirror")
        self.assertTrue (cc.disable)
        self.assertIsNone (cc.file)
        self.assertIsNone (cc.module)
        self.assertEqual (cc.argument, [ "hello" ])
        
    def test_allargs3 (self):
        # Not quite all; omit authentication so this can run without PAM.
        c = self.ctest ("object --number 25 --name mirror --module decnet.mirror --argument hello --argument goodbye")
        cc = c.object[0]
        self.assertEqual (cc.number, 25)
        self.assertEqual (cc.name, "mirror")
        self.assertFalse (cc.disable)
        self.assertIsNone (cc.file)
        self.assertEqual (cc.module, "decnet.mirror")
        self.assertEqual (cc.authentication, "off")
        self.assertEqual (cc.argument, [ "hello", "goodbye" ])
        
class TestObject_err (Logchecker):
    req = """routing 1.1
    """
    loglevel = logging.CRITICAL
    
    def test_errors (self):
        self.checkerr ("object --frob", "unrecognized arguments")
        self.checkerr ("object --disable --file foo", "not allowed with argument")
        self.checkerr ("object --disable --module foo", "not allowed with argument")
        self.checkerr ("object --file bar --module foo", "not allowed with argument")
        self.checkerr ("object --number 25 --name mirror\n"
                       "object --number 42 --name mirror",
                       "Conflicting value for object name")
        self.checkerr ("object --number 25 --name mirror\n"
                       "object --number 25 --name bouncer",
                       "Conflicting value for object number")
        
if __name__ == "__main__":
    unittest.main ()

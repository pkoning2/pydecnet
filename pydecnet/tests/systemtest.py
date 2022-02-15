#!/usr/bin/env python3

import sys
import unittest
try:
    unittest.IsolatedAsyncioTestCase
except AttributeError:
    print ("Python 3.8 or later required")
    sys.exit (1)
    
import os
import re
import tempfile
import asyncio
import time

try:
    # For the HTTP page scan subtests
    import aiohttp
except ImportError:
    aiohttp = None
    
from tests.dntest import *
from decnet import async_connectors

# Test parameters
QD = 4
RUNTIME = 60
DCOUNT = 20
STARTWAIT = 20
TIMELIMIT = RUNTIME * 3

# This is a full-system test as opposed to a subsystem (layer) test.
# We build a set of configuration files to describe a network of a
# number of nodes of different types, then set everything in motion
# and exercise various interfaces.
#
# Because of the file name is is not included in the standard suite of
# unit tests run by a simple "python3 -m unittest" invocation.
# Instead, it can be run by itself, by invoking it by file name.

# Test config node names.
#
# A is phase 4 area, R is phase 4 L1, E is phase 4 endnode, T is phase
# 3 router, W is phase 2; Z is external nodes (can connect to the test
# setup but aren't built as part of it)
nodes = """1.1 a11
1.2 r12
1.3 w13
1.4 t14
1.5 t15
1.6 e16
1.7 e17
1.42 zzrsts
1.43 zzz
2.1 a21
2.2 t22
2.3 w23
2.4 w24
2.5 r25
2.6 e26
3.1 a31
3.2 e32
"""

# Connections between the nodes.  "eth" circuits have an implicit
# bridge generated for them, the others are point to point
# connections.  For point to point we just use DDCMP; there isn't much
# reason to use Multinet, not for system test.
circuits = """eth-1 a11 e26 a21 e17 r25 zzrsts zzz
eth-2 a11 a31 e16
dmc-1 a11 r12
dmc-2 r12 w13
dmc-3 r12 t14
dmc-4 r12 t15
dmc-5 a31 e32
dmc-6 a21 t22
dmc-7 a21 w23
dmc-8 t22 w23
dmc-9 w23 w24
dmc-10 r12 zzrsts
"""

HTTP = 8421
API = "/tmp/systemtest.sock"

http = """http --http-port {} --https-port 0
api {}
""".format (HTTP, API)

_a_re = re.compile (r'href="(.+?)"')

class Eth:
    def __init__ (self, name, p1, p2):
        self.name = name
        self.p1 = p1
        self.p2 = p2

    def writeconfig (self, f, addr):
        if addr:
            addr = "--hwaddr " + addr
        else:
            addr = "--random-address"
        print ("circuit {} Ethernet udp:{}:127.0.0.1:{} {} --t3 5"
                   .format (self.name, self.p1, self.p2, addr), file = f)
        
class Ddcmp:
    def __init__ (self, name, p1, p2):
        self.name = name
        self.p1 = p1
        self.p2 = p2

    def writeconfig (self, f, addr):
        print ("circuit {} DDCMP udp:{}:127.0.0.1:{} --t3 5"
                   .format (self.name, self.p1, self.p2), file = f)
        
class Conf:
    def __init__ (self, name):
        self.fn = os.path.join (tempdir, "{}.conf".format (name))
        self.name = name
        self.circuits = list ()
        self.addr = None

    def addcirc (self, circ):
        self.circuits.append (circ)

    def writeconfig (self, *hdr):
        with open (self.fn, "wt") as f:
            print ('\n'.join (hdr), file = f)
            for c in self.circuits:
                c.writeconfig (f, self.addr)
            
class NodeConf (Conf):
    def __init__ (self, addr, name):
        super ().__init__ (name)
        self.neighbors = set ()
        n1 = name[0]
        a, i = addr.split (".")
        self.area = a
        t = None
        self.onlyarea = self.myarea = None
        if n1 == "a":
            t = "l2router"
        elif n1 == "r":
            t = "l1router"
        elif n1 == "e":
            t = "endnode"
        elif n1 == "t":
            t = "phase3router"
            self.onlyarea = a
            addr = i
        elif n1 == "w":
            t = "phase2"
            self.myarea = a
            addr = i
        else:
            raise ValueError
        self.ntype = t
        self.addr = addr

    def addneighbor (self, name):
        self.neighbors.add (name)

    def adjacent (self, name):
        return name in self.neighbors

    def hasint (self):
        for n in self.neighbors:
            if n[0] != "w":
                return True
        return False
    
    def reachable (self, n):
        if self.name[0] in "are" and n.name[0] in "are":
            # Both Phase 4, full connectivity
            return True
        if self.name[0] == "t" or n.name[0] == "t":
            # Either is Phase 3, must be same area
            return self.area == n.area
        if self.ntype == "phase2" and n.ntype == "phase2":
            # Both are phase 2, neighbor only
            return self.adjacent (n.name)
        # One is phase 2 but other is phase 4, see if phase 2 node has
        # a phase 4 neighbor (for intercept service)
        if self.ntype == "phase2":
            # From phase 2 to not 2
            return self.hasint ()
        return n.hasint ()
    
    def writeconfig (self):
        if self.ntype == "phase2":
            int = "--request-intercept"
        else:
            int = ""
        hdr = [ "routing {} --type {} --maxnodes 200 --t1 5 --bct1 5 {}".format (self.addr, self.ntype, int) ]
        hdr.append ("nsp --qmax {}".format (QD))
        #hdr.append ("logging console")
        for nc in nodes.splitlines ():
            na, nr = nc.split (".", 1)
            if self.onlyarea:
                if na == self.onlyarea:
                    hdr.append ("node {}".format (nr))
            elif self.myarea:
                if na == self.myarea:
                    hdr.append ("node {}".format (nr))
                else:
                    hdr.append ("node {}.{}".format (na, nr))
            else:
                hdr.append ("node {}.{}".format (na, nr))
        super ().writeconfig (*hdr)

class BridgeConf (Conf):
    def __init__ (self, cname):
        name = cname.replace ("eth", "br")
        super ().__init__ (name)

    def writeconfig (self):
        super ().writeconfig ("bridge {}".format (self.name))
        
def ppair ():
    global portnum
    ret = portnum, portnum + 1
    portnum += 2
    return ret

def tnode (name):
    return name[0] in "aretw"
    
def setUpModule ():
    global tempdir, tempdirobj, configs, portnum, nodeconf, cfns
    tempdirobj = tempfile.TemporaryDirectory ()
    tempdir = tempdirobj.name
    httpconf = os.path.join (tempdir, "http.conf")
    with open (httpconf, "wt") as f:
        f.write (http)
    configs = dict ()
    portnum = 15000
    for n in nodes.splitlines ():
        a, n = n.split ()
        if tnode (n):
            configs[n] = NodeConf (a, n)
    for c in circuits.splitlines ():
        c, *nlist = c.split ()
        if c.startswith ("eth"):
            # LAN, create a bridge for it
            bridge = BridgeConf (c)
            configs[bridge.name] = bridge
            for n in nlist:
                p, p2 = ppair ()
                bridge.addcirc (Eth ("{}{}".format (c, p2), p, p2))
                if tnode (n):
                    configs[n].addcirc (Eth (c, p2, p))
        else:
            # Point to point
            n1, n2 = nlist
            p, p2 = ppair ()
            if tnode (n1):
                configs[n1].addcirc (Ddcmp (c, p, p2))
                configs[n1].addneighbor (n2)
            if tnode (n2):
                configs[n2].addcirc (Ddcmp (c, p2, p))
                configs[n2].addneighbor (n1)
    cfns = list ()
    for c in configs.values ():
        cfns.append (c.fn)
        c.writeconfig ()
    cfns.append (httpconf)
        
def tearDownModule ():
    pass
    #tempdirobj.cleanup ()
    
class TestSystem (ADnTest):
    sut = None
    
    def tearDown (self):
        if self.sut:
            self.sut.terminate ()
            
    async def test_systems (self):
        nodepairs = list ((n1.name, n2.name) for n1 in configs.values ()
                          for n2 in configs.values ()
                          if n1 is not n2 and
                          isinstance (n1, NodeConf) and
                          isinstance (n2, NodeConf) and
                          n1.reachable (n2))
        self.totalmsg = 0
        try:
            # We don't want to call pydecnet because that might point
            # to a different version and/or use a different Python
            # 3.x.  So invoke the current Python 3.x and have it call
            # decnet.main directly, which will run the startup
            # sequence with the rest of the command line arguments.
            loglevel = os.getenv ("LOGLEVEL") or "INFO"
            args = [ "-m", "decnet.main", "-e", loglevel ]
            logfile = os.getenv ("LOGFILE")
            if logfile:
                args += [ "-L", logfile ]
            self.sut = await asyncio.create_subprocess_exec \
                             (sys.executable, *(args + cfns),
                              stdin = asyncio.subprocess.DEVNULL)
            # Wait a bit for all the connections to come up and routes to
            # settle.
            await asyncio.sleep (2)
            print ("waiting", STARTWAIT, "seconds for topology to stabilize")
            await asyncio.sleep (STARTWAIT)
            # Now run some tests
            print ("Starting test phase")
            # Use two API connectors.  Not that two are needed, but
            # this will test the proper dispatching of work to each.
            conns = [ async_connectors.AsyncApiConnector (API),
                      async_connectors.AsyncApiConnector (API) ]
            for c in conns:
                await c.start ()
            tests = list ()
            # Test 1: Walk the entire HTTP interface
            tests.append (asyncio.create_task (self.httpwalk ()))
            # Test 2: Run 12 concurrent data streams, with staggered
            # start and stop.
            for i, np in enumerate (random.sample (nodepairs, DCOUNT)):
                c = conns[i % len (conns)]
                n1, n2 = np
                tests.append (asyncio.create_task (self.dtest (c, n1, n2, i)))
            # Wait for them all to finish
            done, pending = await asyncio.wait (tests, timeout = TIMELIMIT,
                                                return_when = asyncio.FIRST_EXCEPTION)
            if pending:
                print ("Some tasks are not yet finished")
                for t in pending:
                    t.cancel ()
            for t in done:
                t.result ()
            # Do a few more (quick) tests at the end
            await self.httpwalk ()
            # Print some stats
            print ("{} total messages, {:>.0f} messages/second".format (self.totalmsg, self.totalmsg / RUNTIME))
            # All done, close the connectors
            for c in conns:
                await c.close ()
            # Stop PyDECnet
            self.sut.terminate ()
            await self.sut.wait ()
            self.sut = None
            # Make sure the API named socket has been cleaned up
            with self.assertRaises (OSError):
                os.stat (API)
        finally:
            try:
                os.remove (API)
            except OSError:
                pass

    async def dtest (self, conn, n1, n2, delay):
        await asyncio.sleep (delay)
        endtime = time.time () + RUNTIME
        # Leading 0x00 byte is the MIRROR "loop request" message code
        data = b"\x00" + bytes (("test {} {} ".format (n1, n2)) * 10, "latin1")
        if delay & 1:
            print ("send test from", n1, "to", n2)
            # Bind the receiving end, use sending side to make object name
            rcv = "rcv_{}".format (n1)
            bound = await conn.bind (0, rcv, system = n2)
        else:
            print ("echo test from", n1, "to", n2)
            rcv = 25    # MIRROR
        sender, x = await conn.connect (dest = n2, remuser = rcv, system = n1)
        if not sender:
            print ("Failed to connect from", n1, "to", n2, "obj", rcv)
            return
        if delay & 1:
            # Get the connect from the sender
            listener = await bound.listen ()
            listener.accept ()
            receiver = listener
        else:
            receiver = sender
        # Get the accept from the receiver
        ac = await sender.recv ()
        if sender.closed:
            print ("Connect from", n1, "to", n2, "rejected:", ac, ac.reason)
            return
        # fill the pipe
        for i in range (QD):
            sender.data (data)
        count = 0
        while time.time () < endtime:
            await receiver.recv ()
            sender.data (data)
            count += 1
        # Time's up, drain the pipe
        for i in range (QD):
            await asyncio.wait_for (receiver.recv (), 1)
        sender.disconnect ()
        if delay & 1:
            bound.close ()
            what = "sent"
        else:
            what = "echoed"
        self.totalmsg += count
        print (n1, "to", n2, what, count, "messages")
        
    async def httpwalk (self):
        if not aiohttp:
            print ("HTTP check skipped")
            return
        walked = set ()
        todo = { "/" }
        n = 0
        async with aiohttp.ClientSession () as s:
            while todo:
                t = todo.pop ()
                walked.add (t)
                async with s.get ("http://127.0.0.1:{}{}".format (HTTP, t)) as g:
                    n += 1
                    resp = await g.text ()
                    for m in _a_re.finditer (resp):
                        u = m.group (1)
                        if u not in walked:
                            todo.add (u)
        print (n, "HTTP pages visited")
        
if __name__ == "__main__":
    unittest.main ()

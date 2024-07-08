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
import random
import collections
import traceback

try:
    # For the HTTP page scan subtests
    import aiohttp
except ImportError:
    aiohttp = None
    
pydecnet = os.path.normpath (os.path.join (os.path.dirname (__file__), ".."))
sys.path.insert (0, pydecnet)

from tests.dntest import *
from decnet import async_connectors
from decnet import mop

mop.SYSID_STARTRATIO = 100

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
nodes = """1.1 A11
1.2 R12
1.3 W13
1.4 T14
1.5 T15
1.6 E16
1.7 E17
1.42 ZZRSTS
1.43 ZZZ
2.1 A21
2.2 T22
2.3 W23
2.4 W24
2.5 R25
2.6 E26
3.1 A31
3.2 E32
"""
# temp no phase 2
nodes = """1.1 A11
1.2 R12
1.4 T14
1.5 T15
1.6 E16
1.7 E17
1.42 ZZRSTS
1.43 ZZZ
2.1 A21
2.2 T22
2.5 R25
2.6 E26
3.1 A31
3.2 E32
"""

# Connections between the nodes.  "eth" circuits have an implicit
# bridge generated for them, the others are point to point
# connections.  For point to point we just use DDCMP; there isn't much
# reason to use Multinet, not for system test.
circuits = """ETH-1 A11 E26 A21 E17 R25 ZZRSTS ZZZ
ETH-2 A11 A31 E16
DMC-1 A11 R12
DMC-2 R12 W13
DMC-3 R12 T14
DMC-4 R12 T15
DMC-5 A31 E32
DMC-6 A21 T22
DMC-7 A21 W23
DMC-8 T22 W23
DMC-9 W23 W24
DMC-10 R12 ZZRSTS
"""
# temp no phase 2
circuits = """ETH-1 A11 E26 A21 E17 R25 ZZRSTS ZZZ
ETH-2 A11 A31 E16
DMC-1 A11 R12
DMC-3 R12 T14
DMC-4 R12 T15
DMC-5 A31 E32
DMC-6 A21 T22
DMC-10 R12 ZZRSTS
"""

HTTP = 8421
API = "/tmp/systemtest.sock"

http = """http --http-port {} --https-port 0
api {}
""".format (HTTP, API)

_a_re = re.compile (r'href="(.+?)"')

lanaddresses = collections.defaultdict (set)

class Eth:
    def __init__ (self, name, p1, p2):
        self.name = name
        self.p1 = p1
        self.p2 = p2

    def writeconfig (self, f, addr):
        if addr:
            addr = Macaddr (addr)
            lanaddresses[self.name].add (addr)
            addr = "--hwaddr {}".format (addr)
        else:
            addr = "--random-address"
        print ("circuit {} Ethernet udp:{}:127.0.0.1:{} {} --t3 5 --mop"
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
        if n1 == "A":
            t = "l2router"
        elif n1 == "R":
            t = "l1router"
        elif n1 == "E":
            t = "endnode"
        elif n1 == "T":
            t = "phase3router"
            self.onlyarea = a
            addr = i
        elif n1 == "W":
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
            if n[0] != "W":
                return True
        return False
    
    def reachable (self, n):
        if self.name[0] in "ARE" and n.name[0] in "ARE":
            # Both Phase 4, full connectivity
            return True
        if self.name[0] == "T" or n.name[0] == "T":
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
        name = cname.replace ("ETH", "BR")
        super ().__init__ (name)

    def writeconfig (self):
        super ().writeconfig ("bridge {}".format (self.name))
        
def ppair ():
    global portnum
    ret = portnum, portnum + 1
    portnum += 2
    return ret

def tnode (name):
    return name[0] in "ARETW"
    
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
        if c.startswith ("ETH"):
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
            self.conns = [ async_connectors.AsyncApiConnector (API),
                           async_connectors.AsyncApiConnector (API) ]
            for c in self.conns:
                await c.start ()
            tests = list ()
            # Test 1: Walk the entire HTTP interface
            tests.append (asyncio.create_task (self.httpwalk (), name = "httpwalk"))
            # Test 2: Walk the API
            tests.append (asyncio.create_task (self.apiwalk (False), name = "apiwalk"))
            # Test 3: Run DCOUNT concurrent data streams, with staggered
            # start and stop.
            for i, np in enumerate (random.sample (nodepairs, DCOUNT)):
                c = self.conns[i % len (self.conns)]
                n1, n2 = np
                tests.append (asyncio.create_task (self.dtest (c, n1, n2, i),
                                                   name = f"data_{n1}_{n2}"))
            # Wait for them all to finish
            done, pending = await asyncio.wait (tests, timeout = TIMELIMIT)
            print (f"{len (done)} tasks completed out of {len (tests)}")
            if pending:
                print (f"{len (pending)} tasks are not yet finished")
                for t in pending:
                    print (f"canceling {t.get_name ()}")
                    t.cancel ()
                # Update the pending and done lists after the cancels
                done, pending = await asyncio.wait (tests, timeout = TIMELIMIT)
                if pending:
                    print (f"{len (pending)} tasks still active after cancel")
            for t in done:
                try:
                    t.result ()
                    print (f"task {t.get_name ()} done")
                except Exception:
                    print (f"task {t.get_name ()} raised exception:")
                    traceback.print_exc (file = sys.stdout)
            # Do a few more (quick) tests at the end
            await self.httpwalk ()
            # API also (quick mode)
            await self.apiwalk (True)
            # Print some stats
            print ("{} total messages, {:>.0f} messages/second".format (self.totalmsg, self.totalmsg / RUNTIME))
            # All done, close the connectors
            for c in self.conns:
                await c.close ()
            # Stop PyDECnet
            self.sut.terminate ()
            await self.sut.wait ()
            self.sut = None
            # Make sure the API named socket has been cleaned up
            with self.assertRaises (OSError):
                os.stat (API)
        finally:
            pass    # No cleanup needed at the moment

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
            receiver = await bound.listen ()
            # First message on an inbound connection is the connect
            # message, receive that to dispose of it but do nothing
            # with it.
            msg = await receiver.recv ()
            assert msg.type == "connect"
            await receiver.accept ()
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
        try:
            while time.time () < endtime:
                await receiver.recv ()
                sender.data (data)
                count += 1
        except asyncio.CancelledError:
            print (f"test from {n1} to {n2} cancelled at message {count}")
        # Time's up, drain the pipe
        for i in range (QD):
            await asyncio.wait_for (receiver.recv (), 5)
        sender.disconnect ()
        if delay & 1:
            # Receive the disconnect
            await asyncio.wait_for (receiver.recv (), 5)
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
        pages = other = 0
        async with aiohttp.ClientSession (auto_decompress = False) as s:
            while todo:
                t = todo.pop ()
                walked.add (t)
                async with s.get ("http://127.0.0.1:{}{}".format (HTTP, t)) as g:
                    #print ("processing page", t, g.content_type)
                    if g.content_type == "text/html":
                        # HTTP page, fetch it and parse it
                        resp = await g.text ()
                        pages += 1
                        for m in _a_re.finditer (resp):
                            u = m.group (1)
                            if not u.startswith ("/"):
                                # Relative name, make it absolute by
                                # applying the path of the page in which
                                # it occurs.
                                u = os.path.dirname (t) + "/" + u
                            if u not in walked:
                                todo.add (u)
                    else:
                        # Fetch and ignore the content
                        await g.read ()
                        other += 1
        print (pages, "HTTP pages visited,", other, "other files")

    async def apiexch (self, **req):
        #print ("req", req)
        rc, resp = await self.conns[0].exch (**req)
        self.assertIsNone (rc)
        rdict = resp.__dict__
        rdict.pop ("tag")
        self.apicount += 1
        return rdict

    async def loopreq (self, s, circ, others, count):
        st = time.time ()
        dest = random.sample (list (others), min (len (others), 3))
        resp = await self.apiexch (system = s, api = "mop", type = "loop",
                                   circuit = circ.name, fast = True,
                                   dest = dest,
                                   timeout = 1, packets = count)
        et = time.time () - st
        t = 0
        for d in resp["delays"]:
            if d < 0:
                t += 1
        print ("Loop on {} circuit {}, {} timeouts, {:.1f} seconds"
               .format (s, circ.name, t, et))
        
    async def apiwalk (self, quick):
        if quick:
            count = 500
        else:
            count = 2000
        systems = set (configs.keys ())
        self.apicount = 0
        # Check systems list (empty API request)
        self.assertEqual (systems, set (await self.apiexch ()))
        reqs = list ()
        for s in systems:
            c = configs[s]
            if s.startswith ("BR-"):
                apis = ( "bridge", )
            else:
                apis = ( "mop", "routing", "nsp" )
            for a in apis:
                reqs.append (asyncio.create_task (self.apiexch (system = s, api = a),
                                                  name = f"api_{a}_config"))
            for cir in c.circuits:
                if isinstance (cir, Eth) and "mop" in apis:
                    a = lanaddresses[cir.name]
                    others = a - { Macaddr (c.addr) }
                    reqs.append (asyncio.create_task (self.loopreq (s, cir, others, count),
                                                      name = f"api_loop_{cir.name}"))
        try:
            done, pending = await asyncio.wait (reqs, timeout = TIMELIMIT,
                                                return_when = asyncio.FIRST_EXCEPTION)
        except asyncio.CancelledError:
            # API walk was cancelled, go cancel its tasks and collect
            # any information we did get.
            done, pending = await asyncio.wait (reqs, timeout = 0)
        if pending:
            print ("Some API requests are not yet finished")
            for t in pending:
                print (f"canceling {t.get_name ()}")
                t.cancel ()
        for t in done:
            try:
                t.result ()
                print (f"API request {t.get_name ()} done")
            except Exception:
                print (f"API request {t.get_name ()} raised exception:")
                traceback.print_exc (file = sys.stdout)
        # All done
        print (self.apicount, "API requests processed")
        
if __name__ == "__main__":
    unittest.main ()

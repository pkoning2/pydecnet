#!/usr/bin/env python3

"""DECnet/Python utility for updating the node configuration data

This program takes one or two arguments.  The first argument is the
name of the node configuration file for pydecnet, expected to be
referenced from the main configuration file with a command of the
form:
        node @nodenames.dat

The creation date of that file is used as a starting point for a data
update query to the MIM database server, and any received data is
added to the configuration.  If there is no new data, the program
exits.  Otherwise, it writes the updated file to the supplied file
name, saving the previous file as a backup file with ~ suffix.

If the first file name is not an existing file, a full database query
is done to obtain all currently defined nodes, and the file is created
with that content.

If a second file name argument is supplied, that file will contain a
DCL command file for defining the node names, i.e., the same node
definitions appear but with NCP command syntax.
"""

import time
import re
import sys
import os
import socket

nodeconf_re = re.compile (r"(node +)?([0-9.]+) +([0-9a-z]+)", re.I)
dtr_re = re.compile (r"(.+?): +(.+)")

# Lifted from decnet.common, trimmed:
_nodeid_re = re.compile (r"^(?:(\d+)\.)?(\d+)$")
class Nodeid (int):
    """A DECnet Node ID.
    """
    def __new__ (cls, s = 0, id2 = None, wild = False):
        """Create a Nodeid from a string, an integer, a pair of integers,
        a Mac address, or anything that can be converted to a byte string
        of length 2.

        Node 0 is accepted for string or integer inputs; that is
        intended to represent the local node but that conversion has to
        be handled by the caller.

        For non-zero addresses, the node-in-area part must be non-zero 
        unless "wild" is True.
        """
        if isinstance (s, str):
            m = _nodeid_re.match (s)
            if not m:
                raise ValueError ("Invalid node ID {}".format (s))
            a, n = m.groups ()
            n = int (n)
            if a is None:
                # Phase 3 ID
                a = 0
            else:
                a = int (a)
        elif isinstance (s, int):
            if id2 is None:
                a, n = divmod (s, 1024)
            else:
                a, n = s, id2
        if a > 63 or n > 1023 or (n == 0 and a != 0 and not wild):
            raise ValueError ("Invalid node ID {}".format (s))
        return int.__new__ (cls, (a << 10) + n)

    def split (self):
        return divmod (int (self), 1024)

    def __str__ (self):
        a, t = self.split ()
        if a:
            return "{}.{}".format (a, t)
        else:
            return "{}".format (t)

def dbupdate (ts):
    nodes = dict ()
    dtr = dtrf = None
    try:
        dtr = socket.create_connection (("mim.update.uu.se", 1234))
        print ("Connected to database server at MIM")
        dtrf = dtr.makefile (mode = "r", encoding = "latin1")
        l = dtrf.readline ()
        l = l.rstrip ("\n")
        if l != "Ready":
            print ("Unexpected prompt:", l)
            return
        if ts == 0:
            print ("Requesting full database")
            dtr.send (b"\n")
        else:
            ts = time.strftime ("%d-%b-%Y %H:%M:%S", time.gmtime (ts))
            print ("Requesting changes since", ts)
            dtr.send (bytes ('TIME > "{}"\n'.format (ts), encoding = "latin1"))
        name = addr = None
        for l in dtrf:
            l = l.rstrip ("\n")
            if l == "Done":
                break
            rm = dtr_re.match (l)
            if not rm:
                print ("Unexpected record in reply:", l)
                continue
            k, v = rm.groups ()
            v = v.strip ()
            if k == "Node":
                name = v
            elif k == "Address":
                nodes[Nodeid (v)] = name
    finally:
        if dtrf:
            dtrf.close ()
        if dtr:
            dtr.close ()
    return nodes

prefix = ""

def getconf (fn):
    # Read the existing nodes config file, return contents as a dict
    # and timestamp, or empty dict and 0 if not found.
    global prefix
    nodes = dict ()
    ts = 0
    try:
        with open (fn, "rt") as f:
            ts = os.fstat (f.fileno ()).st_mtime
            for l in f:
                m = nodeconf_re.match (l)
                if m:
                    prefix, addr, name = m.groups ()
                    nodes[Nodeid (addr)] = name
    except OSError:
        pass
    prefix = prefix or ""
    return nodes, ts

def update (fn, fn2 = None):
    nodes, ts = getconf (fn)
    newnodes = dbupdate (ts)
    if newnodes:
        nodes.update (newnodes)
        if ts:
            # Rename existing file to backup
            os.rename (fn, fn + "~")
        with open (fn, "wt") as f:
            for k, v in sorted (nodes.items ()):
                print ("{}{} {}".format (prefix, k, v), file = f)
        if fn2:
            with open (fn2, "wt") as f:
                print ("$ ncp", file = f)
                for k, v in sorted (nodes.items ()):
                    print ("def node {} name {}".format (k, v), file = f)
                print ("$! end", file = f)
        print (len (newnodes), "nodes updated")
    else:
        print ("No changes, files not modified")
        
if __name__ == "__main__":
    fn = sys.argv[1]
    fn2 = None
    if len (sys.argv) > 2:
        fn2 = sys.argv[2]
    update (fn, fn2)
    

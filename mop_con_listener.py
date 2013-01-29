#!/usr/bin/env python3.2

"""Skeleton of a MOP console listener.

"""

import sys

from decnet.datalink import *
from decnet.node import *
from decnet.mop import *

class MopListener (Element):
    def __init__ (self, parent):
        super ().__init__ (parent)
        self.heard = dict ()
        
    def dispatch (self, work, pkt):
        if isinstance (work, DlReceive):
            src, buf = pkt
            print (src, bytes(buf), buf[0])
            if buf[0] == SysId.code:
                sysid = SysId (buf)
                if src in self.heard:
                    print ("update from", format_macaddr (src))
                else:
                    print ("new node heard from:", format_macaddr (src))
                self.heard[src] = sysid
                for k, v in sysid.__dict__:
                    print ("{}: {}".format (k, v))
            else:
                print ("mop message code", buf[0])

def main (args):
    try:
        ethname = args[0]
    except IndexError:
        print ("Usage: %s ethport" % sys.argv[0])
        sys.exit (1)
    node = Node ()
    eth = Ethernet (node, ethname)
    dl = MopListener (node)
    eport = eth.create_port (dl, 0x6002)
    eport.add_multicast ("AB-00-00-02-00-00")
    eth.open ()

    # All set, start running the node dispatch loop
    try:
        node.run ()
    finally:
        eth.close ()

        
if __name__ == "__main__":
    main (sys.argv[1:])
    

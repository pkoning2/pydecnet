#!/usr/bin/env python3.2

"""Testing MOP support

"""

import sys

from decnet.datalink import *
from decnet.node import *
from decnet.mop import *

def main (args):
    try:
        ethname = args[0]
    except IndexError:
        print ("Usage: %s ethport" % sys.argv[0])
        sys.exit (1)
    node = Node ()
    eth = Ethernet (node, ethname)
    eth.open ()
    mop = Mop (node)
    mopeth = MopCircuit (mop, eth)

    # All set, start running the node dispatch loop
    try:
        print ("Running -- Ctrl/C to exit")
        while True:
            task = input ("What do you want to do? ").lower ()
            if task == "loop":
                dest = input ("destination? ")
                if dest:
                    dest = scan_macaddr (dest)
                else:
                    dest = Mop.loopmc
                data = bytes (input ("test data? " ), "ascii")
                req = LoopExchange (mopeth,
                                    dest = dest, payload = data,
                                    output = sys.stdout)
                node.addwork (req)
    finally:
        eth.close ()
        node.addwork (Shutdown (node))
        
if __name__ == "__main__":
    main (sys.argv[1:])
    

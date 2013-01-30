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
        node.run ()
    finally:
        eth.close ()

        
if __name__ == "__main__":
    main (sys.argv[1:])
    

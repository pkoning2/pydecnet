from decnet.datalink import *
from decnet.node import *
from decnet.mop import *

import sys

class DlListener (Element):
    def dispatch (self, work, arg):
        print (work.__class__.__name__, arg)
        
node = Node()
eth = Ethernet (node, sys.argv[1])
dl = DlListener (node)
eport = eth.create_port (dl, int (sys.argv[2], 16))
eport.add_multicast (sys.argv[3])
eth.open ()

try:
    node.run ()
except KeyboardInterrupt:
    #eth.close ()
    pass

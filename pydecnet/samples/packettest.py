#!/usr/bin/env python3.2

"""Some simple tests of the packet encoding machinery.
"""

from decnet.routing import *
from decnet.route_ptp import *

r3 = PhaseIIIRouting ()
r3.srcnode = 3
ents = [ ]
for i in range(1, 30):
    e = RouteSegEntry ()
    e.hops = i
    e.cost = i * 3
    ents.append (e)
r3.segments = ents[2:9]

r4 = L1Routing ()
r4.srcnode = 95
s1 = L1Segment ()
s1.startid = 42
s1.entries = ents
s2 = L1Segment ()
s2.startid = 200
s2.entries = ents[5:]
s2.entries[3].hops = 4
s2.entries[3].cost = 230
r4.segments = [ s1, s2 ]

def dump (b):
    s = 0
    while s < len (b):
        l = [ ]
        c = [ ]
        d = b[s:s + 16]
        for e in d:
            l.append ("%03o " % e)
            if e > 32 and e < 128:
                c.append (chr (e))
            else:
                c.append ('.')
        l = ''.join (l)
        c = ''.join (c)
        print ("%04o/ %-64s %s" % (s, l, c))
        s += 16

b = r3.encode ()
dump (b)
print (r3.entries ())

b = r4.encode ()
dump (b)
r4a = L1Routing (b)
print (r4a.entries ())

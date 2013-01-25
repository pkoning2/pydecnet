#!/usr/bin/env python3

"""DECnet protocol implementation

Various utility functions
"""

def nodeid (n):
    """Format a node ID
    """
    return "%d.%d" % divmod (n, 1024)


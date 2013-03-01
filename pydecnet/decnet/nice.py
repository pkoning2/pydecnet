#!

"""NICE protocol definitions

"""

# We start with lots of symbolic constants, taken from the network
# management specification (netman40.txt)

# NICE protocol function codes
LOAD = 15          # Request down-line load
DUMP = 16          # Request up-line dump
BOOT = 17          # Trigger bootstrap
TEST = 18          # Test
CHANGE = 19        # Change parameter
READ = 20          # Read information
ZERO = 21          # Zero counters
SYSSPEC = 22       # System-specific function

# Entities
NODE = 0
LINE = 1
LOGGING = 2
CIRCUIT = 3
MODULE = 4
AREA = 5

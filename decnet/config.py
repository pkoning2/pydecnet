#!

"""DECnet config

"""

import io
import argparse
import shlex

from .common import *

configparser = argparse.ArgumentParser (prog = "", add_help = False)
configparser.add_argument ("-h", action = "help", help = argparse.SUPPRESS)
subparser = configparser.add_subparsers ()
cmd_init = set ()

def config_cmd (name, help, collection = False):
    cp = subparser.add_parser (name, add_help = False)
    cp.add_argument ("-h", action = "help", help = argparse.SUPPRESS)
    cp.set_defaults (collection = collection, attr = name)
    if collection:
        cmd_init.add (name)
    return cp

# Each of the config file entries is defined as a subparser, for a command
# name (the entity being configured) and a set of arguments to configure it.
# As with the way NCP does things, this puts related stuff together without
# paying attention to layering, so for example a "circuit" gives things
# relating to the datalink layer, routing layer, and so on.

cp = config_cmd ("circuit", "Circuit configuration", True)
cp.add_argument ("name", help = "Circuit name", type = name)
cp.add_argument ("--cost", type = int, metavar = "N",
                 help = "Circuit cost (1..25, default 1)",
                 choices = range (1, 26), default = 1)
cp.add_argument ("--t3", type = int,
                 help = "Hello interval (default = 10 for LAN else 60)")
cp.add_argument ("--console", const = bytes (8), metavar = "V",
                 nargs = "?", type = scan_ver,
                 help = "Enable MOP console (V = verification)")
cp.add_argument ("--type", default = "Ethernet",
                 choices = ("Ethernet",),
                 help = "Datalink type (default: Ethernet)")
cp.add_argument ("--device",
                 help = "Device or connection string (default: same as name)")
cp.add_argument ("--random-address", action = "store_true", default = False,
                 help = "Generate random \"hardware address\" (Ethernet only)")

cp = config_cmd ("node", "Overall node configuration")
cp.add_argument ("--api-socket", metavar = "S", default = DEFAPISOCKET,
                 help = "Unix socket name for DECnet API")

cp = config_cmd ("routing", "Routing layer configuration")
cp.add_argument ("id", choices = range (1, 65536), type = scan_nodeid,
                 help = "Node address")
cp.add_argument ("--type", metavar = "T", default = "l2router",
                 choices = ("l2router", "l1router", "endnode",
                            "phase3router", "phase3endnode", "phase2"))
cp.add_argument ("--maxhops", metavar = "Maxh", type = int, default = 16,
                 choices = range (1, 31), help = "Max L1 hops")
cp.add_argument ("--maxcost", metavar = "Maxc", type = int, default = 128,
                 choices = range (1, 1023), help = "Max L1 cost")
cp.add_argument ("--maxahops", metavar = "AMaxh", type = int, default = 16,
                 choices = range (1, 31), help = "Max L2 hops")
cp.add_argument ("--maxacost", metavar = "AMaxc", type = int, default = 128,
                 choices = range (1, 1023), help = "Max L2 cost")
cp.add_argument ("--maxvisits", metavar = "Maxv", type = int, default = 32,
                 choices = range (1, 64), help = "Max visits")
cp.add_argument ("--maxnodes", metavar = "NN", type = int, default = 1023,
                 choices = range (1, 1024), help = "Max node number in area")
cp.add_argument ("--maxarea", metavar = "NA", type = int, default = 63,
                 choices = range (1, 64), help = "Max area number")
cp.add_argument ("--t1", type = int, default = 600,
                 help = "Non-LAN background routing message interval")
cp.add_argument ("--bct1", type = int, default = 10,
                 help = "LAN background routing message interval")

class Config (object):
    """Container for configuration data.
    """
    def __init__ (self, f = None):
        if not f:
            f = open (DEFCONFIG, "rt")
        # First supply empty dicts for each collection config component
        for name in cmd_init:
            setattr (self, name, dict ())
        for l in f:
            l = l.rstrip ("\n").strip ()
            if not l or l[0] == "#":
                continue
            p = configparser.parse_args (shlex.split (l))
            if p.collection:
                getattr (self, p.attr)[p.name] = p
            else:
                setattr (self, p.attr, p)

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
cp.add_argument ("name", help = "Circuit name")
cp.add_argument ("--cost", type = int, metavar = "N",
                 help = "Circuit cost (1..25, default 1)",
                 choices = range (1, 25), default = 1)
cp.add_argument ("--console", const = bytes (8), metavar = "V",
                 nargs = "?", type = scan_ver,
                 help = "Enable MOP console (V = verification)")
cp.add_argument ("--type", default = "Ethernet",
                 choices = ("Ethernet",),
                 help = "Datalink type (default: Ethernet)")
cp.add_argument ("--device",
                 help = "Device or connection name (default: same as name)")
cp.add_argument ("--primary", action = "store_true", default = False,
                 help = "Primary mode for SIMH DDCMP")
cp.add_argument ("--secondary", dest = "primary", action = "store_false",
                 help = "Secondary mode for SIMH DDCMP (default)")

cp = config_cmd ("node", "Overall node configuration")
cp.add_argument ("--api-socket", metavar = "S", default = DEFAPISOCKET,
                 help = "Unix socket name for DECnet API")

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

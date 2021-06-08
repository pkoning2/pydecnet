#!

"""DECnet config

"""

import io
import os
import sys
import argparse
import shlex
try:
    import pam
except ImportError:
    pam = None

# SSL is documented as a standard module, but in embedded system
# builds where the SSL library is omitted, the Python library of
# course does not exist either.
try:
    import ssl
except ImportError:
    ssl = None
    
from .common import *
from . import datalink
from . import datalinks    # All the datalinks we know
from . import logging
from .nsp import Seq
from .host import dualstack

SvnFileRev = "$LastChangedRevision$"

class dnparser_message (Exception): pass
class dnparser_error (Exception): pass

class dnparser (argparse.ArgumentParser):
    """A subclass of argparse.ArgumentParser that overrides the
    error handling and program exits in the standard parser so
    control always comes back to the caller.
    """
    def _print_message (self, message, file = None):
        raise dnparser_message (message)

    def error (self, message):
        raise dnparser_error (message)

    def parse_args (self, args):
        """Parse an argument list.  Return value is a tuple consisting
        of the parse output (a Namespace object, or the object supplied
        in the namespace argument if any) and the message generated by
        the parse.  One of these will be None or False: for a successful parse,
        there is no message, and for a failed one or a help request,
        there is no result.  More precisely, the result is None for
        a help message, False for an error message.
        """
        try:
            return super ().parse_args (args), None
        except dnparser_message as e:
            return None, e.args[0]
        except dnparser_error as e:
            return False, e.args[0]

configparser = dnparser (prog = "", add_help = False)
configparser.add_argument ("-h", action = "help", help = argparse.SUPPRESS)
subparser = configparser.add_subparsers ()
coll_init = set ()
list_init = set ()
single_init = set ()

class LoggingConfig (argparse.Namespace):

    @property
    def name (self):
        return (self.sink_node, self.type)

class ConflictingEntry (DNAException):
    "Conflicting value"
    
class checkdict (dict):
    """A variation of dictionary, which does not allow an existing entry
    to be replaced by a different value.  Used by config parsing to
    detect redefinition of an element with different parameters.  If the
    "new" value is the same as the old, that is accepted, so identical
    duplicate entries in the config are permitted.
    """
    def __init__ (self, keyname):
        self.keyname = keyname

    def __setitem__ (self, key, val):
        try:
            prev = self[key]
            if prev == val:
                return
            for k in dir (prev):
                if k.startswith ("_"):
                    continue
                ov = getattr (prev, k)
                nv = getattr (val, k, None)
                if ov != nv and ov is not None:
                    raise ConflictingEntry ('Conflicting value for {}'.format (self.keyname),
                                   prev, val)
        except KeyError:
            pass
        super ().__setitem__ (key, val)


class Circuits (checkdict):
    def __init__ (self, keyname = "circuit name"):
        super ().__init__ (keyname)

    def add (self, val):
        self[val.name] = val

class Loggers (checkdict):
    def __init__ (self):
        super ().__init__ ("logger name")

    def add (self, val):
        # Logger entries are keyed by sink node (None for local) and
        # sink type.
        self[(val.sink_node, val.type)] = val
        
class Nodes (Circuits):
    def __init__ (self):
        super ().__init__ ("node name")
        self.ids = checkdict ("node address")

    def add (self, val):
        # For nodes we check for both conflicts for a given name, and
        # conflicts for a given node ID (node address)
        self.ids[val.id] = val
        super ().add (val)

class Objects (list):
    def __init__ (self):
        self.names = checkdict ("object name")
        self.nums = checkdict ("object number")

    def add (self, val):
        # We record object entries in a list because they don't all have
        # a common key.  If the object number is non-zero, the entry
        # must be consistent.  Likewise, if it has a name, the entry
        # must be consistent.  Any given object might have a name, a
        # number, or both.
        if val.name:
            self.names[val.name] = val
        if val.number:
            self.nums[val.number] = val
        self.append (val)

def dualstack_switches (cp):
    # Add switches to enable dual stack handling, if available
    if dualstack:
        # Note: these are "count" switches but for the moment are
        # treated as Booleans.  At some point we'll implement
        # prioritizing one or the other if it its switch is specified
        # more than once (e.g., "-466")
        cp.add_argument ("-4", "--ipv4", action = "count", default = 0,
                         help = "Use IPv4")
        cp.add_argument ("-6", "--ipv6", action = "count", default = 0,
                         help = "Use IPv6")
    else:
        cp.set_defaults (ipv4 = 1)
        cp.set_defaults (ipv6 = 0)
        
def config_cmd (name, help, collection = None):
    # collection, if specified, is a checkdict subclass that is used to
    # collect all the items for this component name.  If collection is
    # omitted, this is a single instance component (may not be repeated
    # within the config file).
    cp = subparser.add_parser (name, add_help = False)
    cp.add_argument ("-h", action = "help", help = argparse.SUPPRESS)
    cp.set_defaults (collection = collection, attr = name)
    if collection:
        coll_init.add ((name, collection))
    else:
        single_init.add (name)
    return cp

# Each of the config file entries is defined as a subparser, for a command
# name (the entity being configured) and a set of arguments to configure it.
# As with the way NCP does things, this puts related stuff together without
# paying attention to layering, so for example a "circuit" gives things
# relating to the datalink layer, routing layer, and so on.

datalinks = [ d.__name__ for d in datalink.Datalink.leafclasses () ]
datalinks.sort ()

cp = config_cmd ("circuit", "Circuit configuration", collection = Circuits)
cp.add_argument ("name", help = "Circuit name", type = circname)
cp.add_argument ("type", choices = datalinks, metavar = "type",
                 help = "Datalink type; one of {}.".format (", ".join (datalinks)))
cp.add_argument ("device", help = "Device name", nargs = "?")
cp.add_argument ("--cost", type = int, metavar = "N",
                 help = "Circuit cost (range 1..25, default 4)",
                 choices = range (1, 26), default = 4)
cp.add_argument ("--latency", type = int, metavar = "L",
                 choices = range (1, 440),
                 help = "Circuit latency in ms (range 1..439), used to compute cost")
dualstack_switches (cp)
cp.add_argument ("--t1", type = int, 
                 help = "Background routing message interval "
                 "(overrides exec setting)")
cp.add_argument ("--t3", type = int,
                 help = "Hello interval (default = 10 for LAN else 60)")
if WIN:
    cp.set_defaults (console = None)
else:
    cp.add_argument ("--console", const = bytes (8), metavar = "V",
                     nargs = "?", type = scan_ver,
                     help = "Enable MOP console (V = verification)")
cp.add_argument ("--mode",
                 help = """Connection mode.  Permitted values vary with
                 device type, see doc/config.txt for details.""")
# New preferred names for addresses and ports.  Note that the code
# continues to refer to them by their earlier names, hence the "dest="
# arguments.
cp.add_argument ("--remote-address", metavar = "R",
                 dest = "destination",
                 help = """Remote IP address to use for IP based
                 device communication""")
cp.add_argument ("--remote-port", type = int, metavar = "DP",
                 dest = "dest_port",
                 choices = range (1, 65536),
                 help = """Remote TCP or UDP port to use for IP based
                 device communication""")
cp.add_argument ("--local-address", metavar = "S",
                 dest = "source",
                 help = """Local IP address to use for IP based
                 device communication (default: auto-select)""")
cp.add_argument ("--local-port", type = int, metavar = "SP",
                 dest = "source_port", choices = range (65536),
                 help = """Local TCP or UDP port to use for IP based
                 device communication.  Required for UDP, optional for TCP.""")
# Old synonyms for the above
cp.add_argument ("--destination", help = argparse.SUPPRESS)
cp.add_argument ("--dest-port", type = int, choices = range (1, 65536),
                 help = argparse.SUPPRESS)
cp.add_argument ("--source", help = argparse.SUPPRESS)
cp.add_argument ("--source-port", type = int, choices = range (65536),
                 help = argparse.SUPPRESS)

cp.add_argument ("--single-address", action = "store_true", default = False,
                 help = "Use a single MAC address for all Ethernet"
                 " clients on this circuit (default: use separate MAC address for"
                 " each client)")
agroup = cp.add_mutually_exclusive_group ()
agroup.add_argument ("--random-address", action = "store_true", default = False,
                     help = "Generate random \"hardware address\" (Ethernet only)")
agroup.add_argument ("--hwaddr", type = Macaddr, default = NULLID, metavar = "H",
                     help = "Specify hardware address (Ethernet only)")
cp.add_argument ("--qmax", type = int, metavar = "Q",
                 default = 7, choices = range (1, 256),
                 help = "DDCMP max pending frame count (1..255, default 7)")

# The spec says the valid range is 0..255 but that is wrong, because the list
# of routers has to fit in a field of the router hello message that can at
# most hold 33.7 (!) entries.
cp.add_argument ("--nr", type = int, choices = range (1, 34), metavar = "N",
                 help = "Maximum routers on this LAN (range 1..33)",
                 default = 10)
cp.add_argument ("--priority", metavar = "P", type = int,
                 choices = range (128), default = 64,
                 help = "Designated router priority (range 0..127)")
cp.add_argument ("--verify", action = "store_true", default = False,
                 help = "Require routing verification (point to point only)")
cp.add_argument ("--mop", action = "store_true", default = False,
                 help = "Enable MOP and LAT (bridge circuit only)")

cp = config_cmd ("http", "HTTP access")
cp.add_argument ("--http-port", metavar = "S", default = 8000,
                 type = int, choices = range (65536),
                 help = "Port number for HTTP access, 0 to disable")
dualstack_switches (cp)
cp.add_argument ("--local-address", type = IpAddr, dest = "source",
                 help = """Local IP address to use for the HTTP server
                        (default: auto-select)""")
# Synonym for the above for older configs
cp.add_argument ("--source", help = argparse.SUPPRESS)
cp.add_argument ("--http-root", metavar = "R",
                 help = """Root directory for files served by the HTTP
                        server.  Must contain the "resources" directory
                        which contains the resource files.  Default:
                        the directory containing the PyDECnet source.""")

# Restricted use arguments, see config.txt
cp.add_argument ("--mapper", default = "", help = argparse.SUPPRESS)
cp.add_argument ("--mapdb", default = "/var/db/decnet/mapdata.json",
                 help = argparse.SUPPRESS)
cp.add_argument ("--nodedbserver", default = "mim.update.uu.se",
                 help = argparse.SUPPRESS)
cp.add_argument ("--nodedbtz", default = "Europe/Stockholm",
                 help = argparse.SUPPRESS)
cp.add_argument ("--dbpassword", default = "", help = argparse.SUPPRESS)
if ssl:
    cp.add_argument ("--https-port", metavar = "S", default = 8443,
                     type = int, choices = range (65536),
                     help = "Port number for HTTPS access, 0 to disable")
    cp.add_argument ("--certificate", metavar = "C", default = "decnet.pem",
                     help = "Name of certificate file for HTTPS, default = decnet.pem")
    cp.add_argument ("--api", action = "store_true", default = False,
                     help = "Enable JSON API, by default over HTTPS only")
    cp.add_argument ("--insecure-api", action = "store_true", default = False,
                     help = "Allow JSON API over HTTP")
else:
    # This option exists with or without SSL, but the help text changes.
    cp.add_argument ("--api", action = "store_true", default = False,
                     help = """Enable JSON API.  Note that this uses
                     HTTP (no encryption) because SSL is not available
                     on this installation.  This may be a security
                     concern.  Proceed with caution.""")
    cp.set_defaults (insecure_api = True)
    cp.set_defaults (https_port = None)

cp = config_cmd ("routing", "Routing layer configuration")
cp.add_argument ("id", type = Nodeid, metavar = "NodeID",
                 help = "Node address")
cp.add_argument ("--type", default = "l2router",
                 choices = sorted ([ "l2router", "l1router", "endnode",
                                     "phase3router", "phase3endnode",
                                     "phase2" ]))
cp.add_argument ("--maxhops", metavar = "Maxh", type = int, default = 16,
                 choices = range (1, 31), help = "Max L1 hops (range 1..30)")
cp.add_argument ("--maxcost", metavar = "Maxc", type = int, default = 128,
                 choices = range (1, 1023),
                 help = "Max L1 cost (range 1..1022)")
cp.add_argument ("--amaxhops", metavar = "AMaxh", type = int, default = 16,
                 choices = range (1, 31), help = "Max L2 hops (range 1..30)")
cp.add_argument ("--amaxcost", metavar = "AMaxc", type = int, default = 128,
                 choices = range (1, 1023),
                 help = "Max L2 cost (range 1..1022)")
cp.add_argument ("--maxvisits", metavar = "Maxv", type = int, default = 32,
                 choices = range (1, 64), help = "Max visits (range 1..63)")
cp.add_argument ("--maxnodes", metavar = "NN", type = int, default = 1023,
                 choices = range (1, 1024),
                 help = "Max node number in area (range 1..1023)")
cp.add_argument ("--maxarea", metavar = "NA", type = int, default = 63,
                 choices = range (1, 64),
                 help = "Max area number (range 1..63)")
cp.add_argument ("--t1", type = int, default = 600,
                 help = "Non-LAN background routing message interval")
cp.add_argument ("--bct1", type = int, default = 10,
                 help = "LAN background routing message interval")

cp = config_cmd ("node", "DECnet node database", collection = Nodes)
cp.add_argument ("id", choices = range (1, 65536), type = Nodeid,
                 metavar = "id", help = "Node address")
cp.add_argument ("name", type = nodename, help = "Node name")
cp.add_argument ("--outbound-verification", default = None,
                 help = "Verification value to send to this node")
cp.add_argument ("--inbound-verification", default = None,
                 help = "Verification value to require from this node")

cp = config_cmd ("nsp", "NSP layer configuration")
# The choices are given as a list not a set so they will be shown
# in order in the help string:
cp.add_argument ("--max-connections", type = int, default = 4095, metavar = "MC",
                 choices = [ (1 << i) - 1 for i in range (8, 16) ],
                 help = """Maximum number of connections, choice of
                        255, 511, 1023, 2047, 4095, 8191, 16383, 32767""")
cp.add_argument ("--nsp-weight", type = int, default = 3, metavar = "W",
                 choices = range (1, 256),
                 help = "NSP round trip averaging weight (range 1..255)")
cp.add_argument ("--nsp-delay", type = float, default = 2.0, metavar = "D",
                 help = "NSP round trip delay factor (range 1..15.94)")
cp.add_argument ("--qmax", default = 20, metavar = "Q", 
                 choices = range (1, Seq.maxdelta + 1), type = int,
                 help = "Max data queue entries")
cp.add_argument ("--retransmits", type = int, default = 5, metavar = "R",
                 choices = range (2, 16),
                 help = "NSP maximum retransmits (range 2..15)")

cp = config_cmd ("system", "System level configuration")
cp.add_argument ("--identification", metavar = "ID",
                 help = "Identification string shown by NML")

cp = config_cmd ("logging", "Event logging configuration",
                 collection = Loggers)
cp.add_argument ("type", choices = ("console", "file", "monitor"),
                 help = "Sink type")
cp.add_argument ("--sink-node", metavar = "N",
                 help = "Remote sink node (default: local)")
cp.add_argument ("--sink-username", metavar = "U",
                 default = "",
                 help = "Remote sink connection username")
cp.add_argument ("--sink-password", metavar = "PW",
                 default = "",
                 help = "Remote sink connection password")
cp.add_argument ("--sink-account", metavar = "A",
                 default = "",
                 help = "Remote sink connection account")
cp.add_argument ("--sink-file", default = "events.dat",
                 metavar = "FN",
                 help = "File name for File sink")
cp.add_argument ("--events", default = "",
                 help = """Events to enable (default: known events for
                        local console, none otherwise""")

cp = config_cmd ("session", "Session Control layer configuration")
cp.add_argument ("--default-user", metavar = "DEF",
                 help = """Default username for objects with default
                        authentication enabled""")

cp = config_cmd ("object", "Session Control object", collection = Objects)
cp.add_argument ("--name", help = "Object name")
cp.add_argument ("--number", type = int, choices = range (1, 256),
                 default = 0, metavar = "N", help = "Object number")
ogroup = cp.add_mutually_exclusive_group ()
ogroup.add_argument ("--file", metavar = "FN",
                     help = "Program file name to execute")
ogroup.add_argument ("--module", metavar = "M",
                     help = "Python module identifier to execute")
ogroup.add_argument ("--disable", action = "store_true", default = False,
                     help = "Disable built-in object")
cp.add_argument ("--argument", metavar = "A",
                 default = [ ], action = "append",
                 help = """Optional argument to pass to application
                        when started.  May be repeated to supply an
                        argument list.""")
if pam:
    cp.add_argument ("--authentication", choices = ("on", "off"),
                     default = "off",
                     help = """'on' to have PyDECnet verify username/password,
                            'off' to ignore username/password.  
                            Default: off.""")
else:
    cp.set_defaults (authentication = "off")

cp = config_cmd ("bridge", "LAN bridge layer")
cp.add_argument ("name", help = "Bridge name")

class Config (object):
    """Container for configuration data.
    """
    def __init__ (self, f = None):
        if not f:
            f = open (DEFCONFIG, "rt")
        logging.debug ("Reading config {}", f.name)
        self.configfilename = f.name
        
        # Remove routing, bridge,and http from single_init set, because we
        # handle those separately.
        single_init.discard ("routing")
        single_init.discard ("bridge")
        single_init.discard ("http")
        
        # First supply empty dicts for each collection config component
        for name, cls in coll_init:
            setattr (self, name, cls ())
        # Also set defaults for non-collections:
        for name in single_init:
            p, msg = configparser.parse_args ([ name ])
            if p:
                setattr (self, name, p)
        self.scanconfig (f)

    def scanconfig (self, f, nested = False, prefix = None):
        ok = True
        for l in f:
            l = l.rstrip ("\n").strip ()
            if not l or l.startswith ("#"):
                continue
            if prefix:
                l = "{} {}".format (prefix, l)
            entity, *rest = l.split (None, 1)
            ifn = None
            if rest:
                rest = rest[0]
                if rest.startswith ("@"):
                    ifn = rest[1:]
            elif l.startswith ("@"):
                ifn = l[1:]
                entity = None
            if ifn:
                # Indirect file, read it recursively.  The supplied file
                # name is relative to the current file.
                fn = os.path.join (os.path.dirname (f.name), ifn)
                ok = self.scanconfig (open (fn, "rt"), True, entity) and ok
                continue
            p, msg = configparser.parse_args (shlex.split (l))
            if not p:
                logging.error ("Config file parse error in {}:\n {}\n {}",
                               f, msg, l)
                ok = False
            else:
                if p.collection:
                    c = getattr (self, p.attr)
                    try:
                        c.add (p)
                    except ConflictingEntry as e:
                        logging.error ("Config file parse error in {}:\n"
                                       " {}\n {}", f, str (e), l)
                        ok = False
                else:
                    setattr (self, p.attr, p)
        f.close ()
        if not nested:
            if not ok:
                sys.exit (1)
            # See if anything is missing.  The only required elements
            # are single-instance elements (the layers), and then only
            # if they have at least one required argument.  For example,
            # "routing" is required because node address is required,
            # but "system" is optional because it has no required arguments.
            for name in single_init:
                p = getattr (self, name, None)
                if not p:
                    logging.error ("Missing config element: {}", name)
                    ok = False
            if hasattr (self, "bridge") + hasattr (self, "routing") + \
                hasattr (self, "http") != 1:
                logging.error ("Exactly one of routing, bridge, or http required, config file {}",
                               self.configfilename)
                ok = False
            if not ok:
                sys.exit (1)
        return ok
        
            

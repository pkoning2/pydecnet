#!

"""NICE protocol message formats
"""

from .common import *
from .nice_coding import *

# Return code message strings.  None is for codes that are not errors.
retcode_text = {
    1 :  None,
    2 :  None,
    3 :  None,
    -1 :  "Unrecognized function or option",
    -2 :  "Invalid message format",
    -3 :  "Privilege violation",
    -4 :  "Oversized Management command message",
    -5 :  "Management program error",
    -6 :  "Unrecognized parameter type",
    -7 :  "Incompatible Management version",
    -8 :  "Unrecognized component",
    -9 :  "Invalid identification",
    -10 :  "Line communication error",
    -11 :  "Component in wrong state",
    -13 :  "File open error",
    -14 :  "Invalid file contents",
    -15 :  "Resource error",
    -16 :  "Invalid parameter value",
    -17 :  "Line protocol error",
    -18 :  "File I/O error",
    -19 :  "Mirror link disconnected",
    -20 :  "No room for new entry",
    -21 :  "Mirror connect failed",
    -22 :  "Parameter not applicable",
    -23 :  "Parameter value too long",
    -24 :  "Hardware failure",
    -25 :  "Operation failure",
    -26 :  "System-specific Management function not supported",
    -27 :  "Invalid parameter grouping",
    -28 :  "Bad loopback response",
    -29 :  "Parameter missing",
    -128 :  None
}

# Detail code dictionary for "file" related errors
file_text = {
    0 :  "Permanent database",
    1 :  "Load file",
    2 :  "Dump file",
    3 :  "Secondary loader",
    4 :  "Tertiary loader",
    5 :  "Secondary dumper",
    6 :  "Volatile database",
    7 :  "Diagnostic file"
}

# Detail code dictionary for "mirror" related errors
mirror_text = {
    0 :  "No node name set",
    1 :  "Invalid node name format",
    2 :  "Unrecognized node name",
    3 :  "Node unreachable",
    4 :  "Network resources",
    5 :  "Rejected by object",
    6 :  "Invalid object name format",
    7 :  "Unrecognized object",
    8 :  "Access control rejected",
    9 :  "Object too busy",
    10 :  "No response from object",
    11 :  "Remote node shut down",
    12 :  "Node or object failed",
    13 :  "Disconnect by object",
    14 :  "Abort by object",
    15 :  "Abort by Management",
    16 :  "Local node shut down"
}

# This gives the detail message dictionaries for retcode values that
# have coded detail information.  A number of others have numeric values
# that may be parameter numbers or entity numbers; those are printed as
# the numeric value if encountered.
detail_text = {
    -13 : file_text,
    -14 : file_text,
    -18 : file_text,
    -19 : mirror_text,
    -21 : mirror_text,
}

# Similar to collections.defaultdict but with the item key passed as
# parameter to the item creator.
class KPdict (dict):
    def __getitem__ (self, k):
        try:
            return super ().__getitem__ (k)
        except KeyError:
            pass
        self[k] = ret = self.makeitem (k)
        return ret

class ReplyDict (KPdict):
    def __init__ (self, replyclass, node):
        super ().__init__ (self)
        self.replyclass = replyclass
        self.node = node
        
    def makeitem (self, k):
        rc = self.replyclass
        ret = rc ()
        ret.entity = rc.entity_class (k)
        return ret

    def sorted (self, req):
        # Like items() but in sorted order by key
        return sorted (self.items ())

class NodeReplyDict (ReplyDict):
    def makeitem (self, k):
        k = self.node.nodeinfo (k)
        return super ().makeitem (k)
        
    def sorted (self, req):
        # Special handler for sorting node replies.  Executor always
        # comes first, followed by the others.  If the request was a
        # wild card, filter the results accordingly.  This is somewhat
        # inefficient in that we produce the full list and then trim
        # it, but it is good enough and it's very easy to implement.
        # Optimization can certainly be done without too much effort
        # if it turns out to be worth doing.
        e = self.node.routing.nodeid
        ent = req.entity
        # Check explicitly since just trying to access self[e] would
        # create a record for e...
        if e in self and ent.match (e):
            yield e, self[e]
        for k, v in sorted (self.items ()):
            if k != e and ent.match (k):
                yield k, v
                
# Base class for NICE reply packets.  These need to be subclassed for
# each entity code in the reply header.
class NiceReply (NicePacket):
    _layout = (( "signed", "retcode", 1 ),
               ( "b", "detail", 2))

    def __init__ (self, *args):
        self.detail = 0xffff
        super ().__init__ (*args)

class NiceReadReply (NiceReply):
    replydict = ReplyDict
    _layout = (( EntityBase, "entity" ),)

rvalues = ( "Routing III", "Non-Routing III", "Phase II", "Area",
            "Routing IV", "Non-Routing IV" )

ed_values = ( "Enabled", "Disabled" )

class NodeReply (NiceReadReply):
    entity_class = NodeEntity
    replydict = NodeReplyDict
  
    _layout = (( "nice",
                 [ ( 0, C1, "State", None,
                         ( "On",
                           "Off",
                           "Shut",
                           "Restricted",
                           "Reachable",
                           "Unreachable" ) ),
                   ( 10, HI, "Physical Address" ),
                   ( 100, AI, "Identification" ),
                   ( 101, CMVersion, "Management Version" ),
                   ( 110, AI, "Service Circuit" ),
                   ( 111, H8, "Service Password" ),
                   ( 112, C1, "Service Device" ),
                   ( 113, C1, "CPU", None,
                           ( "PDP8",
                             "PDP11",
                             "DECSystem-10/20",
                             "VAX" ) ),
                   ( 114, HI, "Hardware Address" ),
                   ( 115, C1, "Service Node Version", None, 
                           ( "Phase III",
                             "Phase IV" ) ),
                   ( 120, AI, "Load File" ),
                   ( 121, AI, "Secondary Loader" ),
                   ( 122, AI, "Tertiary Loader" ),
                   ( 123, AI, "Diagnostic File" ),
                   ( 125, C1, "Software Type", None,
                           ( "Secondary Loader",
                             "Tertiary Loader",
                             "System" ) ),
                   ( 126, AI, "Software Identification" ),
                   ( 130, AI, "Dump File" ),
                   ( 131, AI, "Secondary Dumper" ),
                   ( 135, O4, "Dump Address" ),
                   ( 136, DU4, "Dump Count" ),
                   ( 140, CMNode, "Host" ),
                   ( 150, DU2, "Loop Count" ),
                   ( 151, DU2, "Loop Length" ),
                   ( 152, C1, "Loop With", None,
                           ( "Zeroes",
                             "Ones",
                             "Mixed" ) ),
                   ( 153, HI, "Loop Assistant Physical Address" ),
                   ( 154, C1, "Loop Help", None,
                           ( "Transmit",
                             "Receive",
                             "Full" ) ),
                   ( 160, DU2, "Counter Timer" ),
                   ( 501, AI, "Circuit" ),
                   ( 502, DU2, "Address" ),
                   ( 510, DU2, "Incoming Timer" ),
                   ( 511, DU2, "Outgoing Timer" ),
                   ( 600, DU2, "Active Links" ),
                   ( 601, DU2, "Delay" ),
                   ( 700, CMVersion, "ECL Version" ),
                   ( 710, DU2, "Maximum Links" ),
                   ( 720, DU1, "Delay Factor" ),
                   ( 721, DU1, "Delay Weight" ),
                   ( 722, DU2, "Inactivity Timer" ),
                   ( 723, DU2, "Retransmit Factor" ),
                   ( 810, C1, "Type", "adj_type", rvalues ),
                   ( 820, DU2, "Cost" ),
                   ( 821, DU1, "Hops" ),
                   ( 822, AI, "Circuit", "adj_circuit" ),
                   ( 830, CMNode, "Next Node" ),
                   ( 900, CMVersion, "Routing Version" ),
                   ( 901, C1, "Type", None, rvalues ),
                   ( 910, DU2, "Routing Timer" ),
                   ( 911, CM, "Subaddresses" ),
                   ( 912, DU2, "Broadcast Routing Timer" ),
                   ( 920, DU2, "Maximum Address" ),
                   ( 921, DU2, "Maximum Circuits" ),
                   ( 922, DU2, "Maximum Cost" ),
                   ( 923, DU1, "Maximum Hops" ),
                   ( 924, DU1, "Maximum Visits" ),
                   ( 925, DU1, "Maximum Area" ),
                   ( 926, DU2, "Max Broadcast Nonrouters" ),
                   ( 927, DU2, "Max Broadcast Routers" ),
                   ( 928, DU2, "Area Maximum Cost" ),
                   ( 929, DU1, "Area Maximum Hops" ),
                   ( 930, DU2, "Maximum Buffers" ),
                   ( 931, DU2, "Buffer Size" ),
                   ( 932, DU2, "Segment Buffer Size" ),
                   # RSTS/E (DECnet/E) specific code points
                   ( 2120, AI, "Recv Org. Password", "rec_orig_pw" ),
                   ( 2121, AI, "Recv Ans. Password", "rec_ans_pw" ),
                   ( 2122, AI, "Xmit Org. Password", "xmit_orig_pw" ),
                   ( 2123, AI, "Xmit Ans. Password", "xmit_ans_pw" ),
                   ( 2124, AI, "Alias" ),
                   ( 2125, AI, "Default Account" ),
                   ( 2126, DU1, "Data Xmit Queue Max" ),
                   ( 2127, DU1, "Int/LS Queue Max", "int_max" ),
                   ( 2128, AI, "Volatile Param File Name" ),
                   ( 2129, DU2, "Maximum Nodes" ),
                   # RSX specific code points
                   ( 522, C1, "Incoming proxy", None, ed_values ),
                   ( 523, C1, "Outgoing proxy", None, ed_values ),
                   # VMS specific code points
                   ( 933, DU1, "Maximum path splits" ),
                   ( 2731, C1, "Default access", None,
                     # Guesses:
                     ( "Disabled", "Incoming", "Outgoing",
                       "Incoming and outgoing" )),
                   ( 2740, DU2, "Pipeline quota" ),
                   ( 2743, DU2, "Alias maximum links" ),
                   ( 2780, C1, "Path split policy", None, ed_values ),
                   ( 2785, DU2, "Maximum declared objects" )
                 ] + node_counters ),)

# RSX:
# Parameter #522             = %H'00' 
# Parameter #523             = %H'00' 
# MIM says:
#   Incoming proxy = Enabled
#   Outgoing proxy = Enabled
# VMS also has these.  And more:
# ...Max Broadcast Routers      = 32
# Parameter #933             = %D'1' 
# Area Maximum Cost          = 1022
# Area Maximum Hops          = 30
# Maximum Buffers            = 100
# Buffer Size                = 576
# Parameter #2731            = %H'03' 
# Parameter #2740            = %D'4032' 
# Parameter #2743            = %D'32' 
# Parameter #2780            = %H'00' 
# Parameter #2785            = %D'31' 
# MIM says:
#    Maximum broadcast routers = 32
#    Maximum path splits = 1
#    Area maximum cost = 1022, Area maximum hops = 30
#    Maximum buffers = 100, Buffer size = 576
#    Default access = Incoming and outgoing
#    Pipeline quota = 4032
#    Alias maximum links = 32, Path split policy = Enabled
#    Maximum Declared Objects = 31

class CircuitReply (NiceReadReply):
    entity_class = CircuitEntity

    _layout = (( "nice",
                 [( 0, C1, "State", None,
                       ( "On", "Off", "Service", "Cleared" )),
                  ( 1, C1, "Substate", None,
                       ( "Starting", "Reflecting", "Looping",
                         "Loading", "Dumping", "Triggering",
                         "Autoservice", "Autoloading",
                         "Autodumping", "Autotriggering",
                         "Synchronizing", "Failed" )),
                  ( 100, C1, "Service", None, ( "Enabled", "Disabled" )),
                  ( 110, DU2, "Counter timer" ),
                  ( 120, HI, "Service physical address" ),
                  ( 121, C1, "Service substate" ),
                  ( 200, CMNode, "Connected node" ),
                  ( 201, CM, "Connected object", None, ( DU1, AI )),
                  ( 400, AI, "Loopback name" ),
                  ( 800, CMNode, "Adjacent node" ),
                  ( 801, CMNode, "Designated router" ),
                  ( 810, DU2, "Block size" ),
                  ( 811, DU2, "Originating queue limit" ),
                  ( 900, DU1, "Cost" ),
                  ( 901, DU1, "Maximum routers" ),
                  ( 902, DU1, "Router priority" ),
                  ( 906, DU2, "Hello timer" ),
                  ( 907, DU2, "Listen timer" ),
                  ( 910, C1, "Blocking", None, ( "Enabled", "Disabled" )),
                  ( 920, DU1, "Maximum recalls" ),
                  ( 921, DU2, "Recall timer" ),
                  ( 930, AI, "Number" ),
                  ( 1000, CM, "User", None, ( C1, DUNode, AI )),
                  ( 1010, C1, "Polling state", None,
                          ( "Automatic", "Active",
                            "Inactive", "Dying", "Dead" )),
                  ( 1011, C1, "Polling substate", None,
                          { 1 : "Active",
                            2 : "Inactive",
                            3 : "Dying",
                            4 : "Dead" }),
                  ( 1100, CM, "Owner", None, ( C1, DUNode, AI )),
                  ( 1110, AI, "Line" ),
                  ( 1111, C1, "Usage", None,
                          ( "Permanent", "Incoming", "Outgoing" )),
                  ( 1112, C1, "Type", None,
                          { 0 : "DDCMP point",
                            1 : "DDCMP control",
                            2 : "DDCMP tributary",
                            3 : "X.25",
                            4 : "DDCMP DMC",
                            6 : "Ethernet",
                            7 : "CI",
                            8 : "QP2 (DTE20)",
                            9 : "BISYNC" }),
                  ( 1120, AI, "Dte" ),
                  ( 1121, DU2, "Channel" ),
                  ( 1122, DU2, "Maximum data" ),
                  ( 1123, DU1, "Maximum window" ),
                  ( 1140, DU1, "Tributary" ),
                  ( 1141, DU2, "Babble timer" ),
                  ( 1142, DU2, "Transmit timer" ),
                  ( 1145, DU1, "Maximum buffers" ),
                  ( 1146, DU1, "Maximum transmits" ),
                  ( 1150, DU1, "Active base" ),
                  ( 1151, DU1, "Active increment" ),
                  ( 1152, DU1, "Inactive base" ),
                  ( 1153, DU1, "Inactive increment" ),
                  ( 1154, DU1, "Inactive threshold" ),
                  ( 1155, DU1, "Dying base" ),
                  ( 1156, DU1, "Dying increment" ),
                  ( 1157, DU1, "Dying threshold" ),
                  ( 1158, DU1, "Dead threshold" )
                 ] + circuit_counters ),)
    
class LineReply (NiceReadReply):
    entity_class = LineEntity
    
    _layout = (( "nice",
                 [( 0, C1, "State", None,
                       ( "On", "Off", "Service", "Cleared" )),
                  ( 1, C1, "Substate", None,
                       ( "Starting", "Reflecting", "Looping",
                         "Loading", "Dumping", "Triggering",
                         "Autoservice", "Autoloading",
                         "Autodumping", "Autotriggering",
                         "Synchronizing", "Failed" )),
                  ( 100, C1, "Service", None,
                         ( "Enabled", "Disabled" )),
                  ( 110, DU2, "Counter timer" ),
                  ( 1100, AI, "Device" ),
                  ( 1105, DU2, "Receive buffers" ),
                  ( 1110, C1, "Controller", None,
                          ( "Normal", "Loopback" )),
                  ( 1111, C1, "Duplex", None,
                          ( "Full", "Half" )),
                  ( 1112, C1, "Protocol", None,
                          { 0 : "DDCMP point",
                            1 : "DDCMP control",
                            2 : "DDCMP tributary",
                            4 : "DDCMP DMC",
                            5 : "LAPB",
                            6 : "Ethernet",
                            7 : "CI",
                            8 : "QP2 (DTE20)" }),
                  ( 1113, C1, "Clock", None, ( "External", "Internal" )),
                  ( 1120, DU2, "Service timer" ),
                  ( 1121, DU2, "Retransmit timer" ),
                  ( 1122, DU2, "Holdback timer" ),
                  ( 1130, DU2, "Maximum block" ),
                  ( 1131, DU1, "Maximum retransmits" ),
                  ( 1132, DU1, "Maximum window" ),
                  ( 1150, DU2, "Scheduling timer" ),
                  ( 1151, DU2, "Dead timer" ),
                  ( 1152, DU2, "Delay timer" ),
                  ( 1153, DU2, "Stream timer" ),
                  ( 1160, HI, "Hardware address" )
                 ] + line_counters ),)

class LoggingReply (NiceReadReply):
    entity_class = LoggingEntity
    
    _layout = (( "nice", ()),)

class ModuleReply (NiceReadReply):
    entity_class = ModuleEntity
    
    _layout = (( "nice", ()),)

class AreaReply (NiceReadReply):
    entity_class = AreaEntity
    
    _layout = (( "nice",
                 (( 0, C1, "State", None,
                        { 4 : "Reachable",
                          5 : "Unreachable" } ),
                  ( 820, DU2, "Cost" ),
                  ( 821, DU1, "Hops" ),
                  ( 822, AI, "Circuit", "adj_circuit" ),
                  ( 830, CMNode, "Next Node" ))),)

# Entity encoding in requests.  This is as opposed to
# nice_coding.EntityBase which is for replies and for event messages.
class ReqEntityBase (packet.Indexed):
    classindex = { }
    classindexkey = "e_type"

    def __init__ (self, code, value = None):
        super ().__init__ ()
        self.code = code
        self.value = value
            
    @classmethod
    def defaultclass (cls, x):
        raise DecodeError ("Invalid entity code {}".format (x))
    
    @classmethod
    def decode (cls, b, *x):
        require (b, 1)
        code = b[0]
        # Convert to a signed byte value
        if code >= 128:
            code -= 256
        if code < 0:
            return cls (code), b[1:]
        if code:
            require (b, 1 + code)
            s = str (b[1:1 + code], "latin1")
            return cls (code, s), b[1 + code:]
        raise DecodeError

    def encode (self):
        c = self.code
        if c < 0:
            return byte (c & 0xff)
        v = self.value
        if not isinstance (v, (bytes, bytearray, memoryview)):
            v = bytes (str (v), "latin1")
        if len (v) > 127:
            raise LengthError
        return byte (len (v)) + v

    def __str__ (self):
        en = self.__class__.__name__[:-9]
        if self.code < 0:
            mult = ( None, "known", "active",
                     "loop", "adjacent", "significant" )[-self.code]
            return "{} {}s".format (mult, en)
        return "{} {}".format (en, self.value)
    
class NodeReqEntity (ReqEntityBase):
    e_type = 0

    @classmethod
    def decode (cls, b, *x):
        require (b, 1)
        code = b[0]
        # Convert to a signed byte value
        if code >= 128:
            code -= 256
        # -6, -7 are (partial) wildcards, which also take a node numer.
        if not code or code < -5:
            require (b, 3)
            nn = int.from_bytes (b[1:3], "little")
            nn = Nodeid (nn, wild = True)
            return cls (code, nn), b[3:]
        v, b = ReqEntityBase.decode (b)
        v.__class__ = cls
        return v, b

    def encode (self):
        if self.code == 0:
            return byte (0) + self.value.to_bytes (2, "little")
        return super ().encode ()

    def __str__ (self):
        if self.code == 0 and self.value == 0:
            return "executor"
        return super ().__str__ ()

    def match (self, n):
        return self.code >= -5 or \
               self.code == -6 and n.area == self.value.area or \
               self.code == -7 and n.tid == self.value.tid

class LineReqEntity (ReqEntityBase): e_type = 1
class LoggingReqEntity (ReqEntityBase): e_type = 2
class CircuitReqEntity (ReqEntityBase): e_type = 3
class ModuleReqEntity (ReqEntityBase): e_type = 4
    
class AreaReqEntity (ReqEntityBase):
    e_type = 5

    @classmethod
    def decode (cls, b, *x):
        require (b, 1)
        code = b[0]
        if not code:
            require (b, 2)
            return cls (code, b[1]), b[2:]
        if code >= 128:
            code -= 256
        if code > 0:
            raise DecodeError ("String format invalid for area entity")
        return cls (code), b[1:]

    def encode (self):
        if self.code == 0:
            return byte (0) + byte (self.value)
        elif self.code > 0:
            raise ValueError ("Area number must be integer, not string")
        return super ().encode ()
    
# Base class for NICE Read Information request packets
class NiceReadInfoHdr (NicePacket):
    function = 20
    
    classindex = { }

    @classmethod
    def classindexkey (cls):
        try:
            return cls.entity_class.e_type
        except AttributeError:
            return None
        
    _layout = (( "b", "function", 1 ),
               ( "bm",
                 ( "permanent", 7, 1 ),
                 ( "info", 4, 3 ),
                 ( "entity_type", 0, 3 )))

    def makereplydict (self, node):
        rc = self.replyclass
        return rc.replydict (rc, node)

    def sum (self):
        return self.info == 0

    def stat (self):
        return self.info == 1

    def sumstat (self):
        return self.info < 2

    def char (self):
        return self.info == 2

    def counters (self):
        return self.info == 3

    def events (self):
        return self.info == 4

    # The following methods reference self.entity which has to be
    # defined in each subclass.
    def mult (self):
        return self.entity.code < 0

    def one (self):
        return self.entity.code >= 0

    def known (self):
        # This includes the node wildcard cases
        return self.entity.code in (-1, -6, -7)

    def act (self):
        return self.entity.code == -2

    def loop (self):
        return self.entity.code == -3
    
    def adj (self):
        return self.entity.code == -4
    
    def sig (self):
        return self.entity.code == -5

    def sigact (self):
        return self.entity.code == -2 or self.entity.code == -5

    def wild (self):
        return self.entity.code < -5

# For most of these we don't actually expect any additional data, but
# set the "payload" slot to permit it.  Module does use it.  The spec
# makes it sound like NICE coded data but it isn't, so we'll
# special-case the parsing for those cases that are supported.
class NiceReadNode (NiceReadInfoHdr):
    entity_class = NodeReqEntity
    replyclass = NodeReply
    _addslots = { "payload" }

    _layout = (( NodeReqEntity, "entity" ),)
        
class NiceReadLine (NiceReadInfoHdr):
    entity_class = LineReqEntity
    replyclass = LineReply
    _addslots = { "payload" }

    _layout = (( LineReqEntity, "entity" ),)
        
class NiceReadLogging (NiceReadInfoHdr):
    entity_class = LoggingReqEntity
    replyclass = LoggingReply
    _addslots = { "payload" }

    _layout = (( LoggingReqEntity, "entity" ),)
        
class NiceReadCircuit (NiceReadInfoHdr):
    entity_class = CircuitReqEntity
    replyclass = CircuitReply
    _addslots = { "payload" }

    _layout = (( CircuitReqEntity, "entity" ),)
        
class NiceReadModule (NiceReadInfoHdr):
    entity_class = ModuleReqEntity
    replyclass = ModuleReply
    _addslots = { "payload" }

    _layout = (( ModuleReqEntity, "entity" ),)
        
class NiceReadArea (NiceReadInfoHdr):
    entity_class = AreaReqEntity
    replyclass = AreaReply
    _addslots = { "payload" }

    _layout = (( AreaReqEntity, "entity" ),)

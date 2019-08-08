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

# Base class for NICE reply packets.  These need to be subclassed for
# each entity code in the reply header.
class NiceReply (NicePacket):
    classindex = { }
    classindexkey = "entity_code"
    
    _layout = (( "signed", "retcode", 1 ),
               ( "b", "detail", 2), 
               ( EntityBase, "entity" ))

rvalues = ( "Routing III", "Non-Routing III", "Phase II", "Area",
                           "Routing IV", "Non-Routing IV" )

class NodeReply (NiceReply):
  entity_code = 0
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
                 ( 810, C1, "Type", None, rvalues ),
                 ( 820, DU2, "Cost" ),
                 ( 821, DU1, "Hops" ),
                 ( 822, AI, "Circuit", "circuit_822" ),
                 ( 830, CMNode, "Next Node" ),
                 ( 900, CMVersion, "Routing Version" ),
                 ( 901, C1, "Type", "adj_type", rvalues ),
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
                 ( 2120, AI, "Recv Org. Password", "rec_orig_pw" ),
                 ( 2121, AI, "Recv Ans. Password", "rec_ans_pw" ),
                 ( 2122, AI, "Xmit Org. Password", "xmit_orig_pw" ),
                 ( 2123, AI, "Xmit Ans. Password", "xmit_ans_pw" ),
                 ( 2124, AI, "Alias" ),
                 ( 2125, AI, "Default Account" ),
                 ( 2126, DU1, "Data Xmit Queue Max" ),
                 ( 2127, DU1, "Int/LS Queue Max", "int_max" ),
                 ( 2128, AI, "Volatile Param File Name" ),
                 ( 2129, DU2, "Maximum Nodes" )
               ] + node_counters ),)

#!

"""NICE protocol message formats
"""

import re

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

p2retcode_text = {
    1 : None,
    -1 : "Invalid function code or option",
    -2 : "Invalid message format",
    -3 : "Insufficient status",
    -4 : "NICE protocol error",
    -5 : "NICE process program error",
    -8 : "Invalid line ID",
    -9 : "Invalid line state",
    -10 : "Line communications error",
    -11 : "Invalid node ID",
    -12 : "Invalid server node ID",
    -13 : "Invalid file",
    -14 : "Invalid configuration file",
    -15 : "Resource error",
    -16 : "Invalid parameter value",
    -17 : "Line protocol error",
    -18 : "File I/O error",
    -19 : "Network communications error",
    -20 : "No room for new entry",
    -21 : "Remote NCU process not available"
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

# Coding common to MOP and NICE
MOPdevices2 = { 0 : ( "DP", "DP11-DA (OBSOLETE)" ),
                1 : ( "UNA", "DEUNA UNIBUS CSMA/CD communication link" ),
                2 : ( "DU", "DU11-DA synchronous line interface" ),
                3 : ( "CNA", "DECNA Professional CSMA/CD communication link" ),
                4 : ( "DL", "DL11-C, -E or -WA asynchronous line interface" ),
                5 : ( "QNA", "DEQNA Q-bus CSMA/CD communication link" ),
                6 : ( "DQ", "DQ11-DA (OBSOLETE)" ),
                7 : ( "CI", "Computer Interconnect interface" ),
                8 : ( "DA", "DA11-B or -AL UNIBUS link" ),
                9 : ( "PCL", "PCL11-B UNIBUS multiple CPU link" ),
                10 : ( "DUP", "DUP11-DA synchronous line interface" ),
                11 : ( "LUA", "DELUA UNIBUS CSMA/CD communication link" ),
                12 : ( "DMC", "DMC11-DA/AR, -FA/AR, -MA/AL or -MD/AL synchronous link" ),
                13 : ( "LNA", "MicroServer Lance CSMA/CD communication link" ),
                14 : ( "DN", "DN11-BA or -AA automatic calling unit" ),
                16 : ( "DLV", "DLV11-E, -F, -J, MXV11-A or -B asynchronous line interface" ),
                17 : ( "LCS", "LANCE/DECserver100 CSMA/CD communication link" ),
                18 : ( "DMP", "DMP11 UNIBUS multipoint synchronous link" ),
                20 : ( "DTE", "DTE20 PDP-11 to KL10 interface" ),
                21 : ( "DBT", "DEBET CSMA/CD communication link" ),
                22 : ( "DV", "DV11-AA/BA UNIBUS synchronous line multiplexer" ),
                23 : ( "BNA", "DEBNT BI CSMA/CD communication link" ),
                24 : ( "DZ", "DZ11-A, -B, -C, or -D UNIBUS asynchronous line multiplexer" ),
                25 : ( "LPC", "VAXmate (LANCE) CSMA/CD communication link" ),
                26 : ( "DSV", "DSV11 Q-bus synchronous link" ),
                27 : ( "CEC", "3Com 3C501, IBM-PC CSMA/CD adapter" ),
                28 : ( "KDP", "KMC11/DUP11-DA synchronous line multiplexer" ),
                29 : ( "IEC", "Micom/Interlan 5010, IBM-PC CSMA/CD adapter" ),
                30 : ( "KDZ", "KMC11/DZ11-A, -B, -C, or -D asynchronous line multiplexer" ),
                31 : ( "LQA", "DELQA CSMA/CD communication link, alternate assignment" ),
                32 : ( "KL", "KL8-J (OBSOLETE)" ),
                33 : ( "DS2", "LANCE/DECserver 200 CSMA/CD communication link" ),
                34 : ( "DMV", "DMV11 Q-bus synchronous link" ),
                35 : ( "DS5", "DECserver 500 CSMA/CD communication link" ),
                36 : ( "DPV", "DPV11 Q-bus synchronous line interface" ),
                37 : ( "LQA", "DELQA CSMA/CD communication link" ),
                38 : ( "DMF", "DMF-32 UNIBUS synchronous line unit" ),
                39 : ( "SVA", "DESVA Microvax-2000, 3100, 3300 CSMA/CD communication link" ),
                40 : ( "DMR", "DMR11-AA, -AB, -AC, or -AE UNIBUS interprocessor link" ),
                41 : ( "MUX", "MUXServer 100 CSMA/CD communication link" ),
                42 : ( "KMY", "KMS11-PX UNIBUS synchronous line interface with X.25 level 2 microcode" ),
                43 : ( "DEP", "DEPCA PCSG/IBM-PC CSMA/CD communication link" ),
                44 : ( "KMX", "KMS11-BD/BE UNIBUS synchronous line interface with X.25 level 2 microcode" ),
                45 : ( "LTM", "LTM (911) Ethernet monitor" ),
                46 : ( "DMB", "DMB-32 BI synchronous line multiplexer" ),
                47 : ( "DES", "DESNC Ethernet Encryption Module" ),
                48 : ( "KCP", "KCP Professional synchronous/asynchronous comm port" ),
                49 : ( "MX3", "MUXServer 300 CSMA/CD communication link" ),
                50 : ( "SYN", "MicroServer Synchronous line interface" ),
                52 : ( "DSB", "DSB32 BI Synchronous Line Interface" ),
                53 : ( "BAM", "DEBAM LANBridge-200 Data Link" ),
                54 : ( "DST", "DST-32 TEAMmate Synchronous Line Interface (DEC423)" ),
                55 : ( "FAT", "DEFAT DataKit Server CSMA/CD communication link" ),
                58 : ( "3C2", "3COM Etherlink II (part number 3C503)" ),
                59 : ( "3CM", "3COM Etherlink/MC (part number 3C523)" ),
                60 : ( "DS3", "DECServer 300 CSMA/CD communication link" ),
                61 : ( "MF2", "MicroVAX 3300 CSMA/CD communication link" ),
                63 : ( "VIT", "Vitalink TransLAN III/IV (NP3A) Bridge" ),
                64 : ( "VT5", "Vitalink TransLAN 350 (NPC25) Bridge, TransPATH 350 BRouter" ),
                65 : ( "BNI", "DEBNI BI CSMA/CD communication link" ),
                66 : ( "MNA", "DEMNA XMI CSMA/CD communication link" ),
                67 : ( "PMX", "DECstation-3100 CSMA/CD communication link" ),
                68 : ( "NI5", "Interlan NI5210-8 CSMA/CD communication link" ),
                69 : ( "NI9", "Interlan NI9210 CSMA/CD communication link" ),
                70 : ( "KMK", "KMS11-K DataKit UNIBUS adapter" ),
                71 : ( "3CP", "3COM Etherlink Plus (part number 3C505)" ),
                72 : ( "DP2", "DECserver-250 (parallel printer server) CSMA/CD communication link" ),
                73 : ( "ISA", "Pele SGEC-based CSMA/CD communication link" ),
                74 : ( "DIV", "DIV-32 Q-bus ISDN (2B+D) adapter" ),
                75 : ( "QTA", "DEQTA (DELQA-YM) CSMA/CD comm link" ),
                76 : ( "B15", "LANbridge-150 CSMA/CD comm link" ),
                77 : ( "WD8", "Western Digital WD8003 family CSMA/CD comm link" ),
                78 : ( "ILA", "BICC ISOLAN 4110-2 CSMA/CD comm link" ),
                79 : ( "ILM", "BICC ISOLAN 4110-3 CSMA/CD comm link" ),
                80 : ( "APR", "Apricot Xen-S and Qi series workstation CSMA/CD comm link" ),
                81 : ( "ASN", "AST EtherNode CSMA/CD comm link" ),
                82 : ( "ASE", "AST Ethernet CSMA/CD comm link" ),
                83 : ( "TRW", "TRW HC-2001 CSMA/CD comm link" ),
                84 : ( "EDX", "EDEN Sistemas de Computaçao Ltda ED586/32 CSMA/CD comm link" ),
                85 : ( "EDA", "EDEN Sistemas de Computaçao Ltda ED586/AT CSMA/CD comm link" ),                
                86 : ( "DR2", "DECrouter-250 CSMA/CD comm link" ),
                87 : ( "SCC", "DECrouter-250 DUSCC serial comm link (DDCMP or HDLC)" ),
                88 : ( "DCA", "DCA Series 300 Network Processor CSMA/CD comm link" ),
                89 : ( "TIA", "Tiara Computers Systems: LANcard/E CSMA/CD controllers" ),
                90 : ( "FBN", "DECbridge-5xx CSMA/CD comm link" ),
                91 : ( "FEB", "DECbridge-5xx, -6xx FDDI comm link" ),
                92 : ( "FCN", "DECconcentrator-500 wiring concentrator FDDI comm link" ),
                93 : ( "MFA", "DEMFA XMI ~ FDDI comm link" ),
                94 : ( "MXE", "MIPS workstation family CSMA/CD comm links" ),
                95 : ( "CED", "Cabletron Ethernet Desktop Network Interface CSMA/CD comm link" ),
                96 : ( "C20", "3Com CS/200 terminal server CSMA/CD comm link" ),
                97 : ( "CS1", "3Com CS/1 terminal server CSMA/CD comm link" ),
                98 : ( "C2M", "3Com CS/210, CS/2000, CS/2100 terminal server CSMA/CD comm link" ),
                99 : ( "ACA", "Advanced Computer Applications ACA/32000 system CSMA/CD comm link" ),
                100 : ( "GSM", "Gandalf StarMaster 5855 Network Processor CSMA/CD comm link" ),
                101 : ( "DSF", "DSF-32 2 line synchronous comm link for Cirrus" ),
                102 : ( "CS5", "3Com CS/50 terminal server CSMA/CD comm link" ),
                103 : ( "XIR", "XIRCOM PE10B2 Pocket Ethernet Adapter CSMA/CD comm link" ),
                104 : ( "KFE", "VAXft-3000 KFE52 CSMA/CD comm link" ),
                105 : ( "RT3", "rtVAX-300 SGEC-based CSMA/CD comm link" ),
                106 : ( "SPI", "Spider Systems Inc. SPiderport M250 terminal server CSMA/CD comm link" ),
                107 : ( "FOR", "Forest Computer Inc. Connection System LAT gateway CSMA/CD comm link" ),
                108 : ( "MER", "Meridian Technology Corp CSMA/CD comm link drivers" ),
                109 : ( "PER", "Persoft Inc.  CSMA/CD comm link drivers" ),
                110 : ( "STR", "AT&T StarLan-10 twisted pair comm link" ),
                111 : ( "MPS", "MIPSfair SGEC CSMA/CD comm link" ),
                112 : ( "L20", "LPS20 print server CSMA/CD comm link" ),
                113 : ( "VT2", "Vitalink TransLAN 320 Bridge" ),
                114 : ( "DWT", "VT-1000 DECwindows terminal" ),
                115 : ( "WGB", "DEWGB Work Group Bridge CSMA/CD comm link" ),
                116 : ( "ZEN", "Zenith Z-LAN4000 Z-LAN comm link" ),
                117 : ( "TSS", "Thursby Software Systems CSMA/CD comm link drivers" ),
                118 : ( "MNE", "3MIN (KN02-BA) integral CSMA/CD comm link" ),
                119 : ( "FZA", "DEFZA TurboChannel FDDI comm link" ),
                120 : ( "90L", "DS90L terminal server CSMA/CD comm link" ),
                121 : ( "CIS", "cisco Systems terminal servers CSMA/CD comm link" ),
                122 : ( "STC", "STRTC Inc. terminal servers" ),
                123 : ( "UBE", "Ungermann-Bass PC2030, PC3030 CSMA/CD comm link" ),
                124 : ( "DW2", "DECwindows terminal II CSMA/CD comm link" ),
                125 : ( "FUE", "Fujitsu Etherstar MB86950 CSMA/CD comm link" ),
                126 : ( "M38", "MUXServer 380 CSMA/CD communication link" ),
                127 : ( "NTI", "NTI Group PC Ethernet card CSMA/CD comm link" ),
                128 : ( "LT2", "LPS20-turbo print server CSMA/CD comm link" ),
                129 : ( "L17", "LPS17 print server CSMA/CD comm link" ),
                130 : ( "RAD", "RADLINX LAN Gateway CSMA/CD comm link" ),
                131 : ( "INF", "Infotron Commix series terminal server CSMA/CD comm link" ),
                132 : ( "XMX", "Xyplex MAXserver series terminal server CSMA/CD comm link" ),
                133 : ( "NDI", "NDIS driver on MS-DOS" ),
                134 : ( "ND2", "NDIS driver on OS/2" ),
                135 : ( "TRN", "DEQRA token ring (802.5) comm link" ),
                136 : ( "DEV", "Develcon Electronics Ltr. LAT gateway CSMA/CD comm link" ),
                137 : ( "ACE", "Acer 5220, 5270 adapter CSMA/CD comm link" ),
                138 : ( "PNT", "PROnet-4/16 (802.5) comm link" ),
                139 : ( "ISE", "Network Integration Server 600 (Hastings) CSMA/CD line card" ),
                140 : ( "IST", "Network Integration Server 600 (Hastings) T1 sync line card" ),
                141 : ( "ISH", "Network Integration Server 600 (Hastings) 64 kb HDLC line card" ),
                142 : ( "ISF", "Network Integration Server 600 (Hastings) FDDI line card" ),
                143 : ( "DR1", "DECrouter-150 CSMA/CD comm link" ),
                144 : ( "SC1", "DECrouter-150 DUSCC serial comm link (DDCMP or HDLC)" ),
                145 : ( "FB3", "DECbridge-6xx CSMA/CD (3 port) comm link" ),
                146 : ( "CET", "Thomson CSMA/CD adapter for CETIA Unigraph" ),
                147 : ( "EIC", "ECI/FMR91515 CSMA/CD comm link" ),
                148 : ( "ETS", "Cabletron (Xyplex) ETSMIM terminal server CSMA/CD comm link" ),
                149 : ( "DSW", "DSW-21 single line serial comm link" ),
                150 : ( "DW4", "DSW-41/42 single/dual line serial comm link" ),
                151 : ( "ETW", "Etherworks (DE206) router CSMA/CD comm link" ),
                152 : ( "IBM", "IBM PS/2 adapter CSMA/CD comm link" ),
                154 : ( "ITC", "DEC/4000 (Cobra) TGEC based CSMA/CD comm link" ),
                156 : ( "ACS", "DECserver 700 (Whitewater) terminal server CSMA/CD comm link" ),
                157 : ( "9LP", "DECserver-90L+ CSMA/CD comm link" ),
                158 : ( "92M", "DECserver-90TL CSMA/CD comm link" ),
                159 : ( "SSL", "Spider Systems SL8, SL16 CSMA/CD comm link" ),
                160 : ( "FTA", "DEFTA Turbochannel-plus adapter FDDI comm link" ),
                161 : ( "FAA", "DEFAA Futurebus+ adapter FDDI comm link" ),
                162 : ( "FEA", "DEFEA EISA bus adapter FDDI comm link" ),
                163 : ( "FIA", "DEFIA ISA bus adapter FDDI comm link" ),
                164 : ( "FNA", "DEFNA S-bus adapter FDDI comm link" ),
                165 : ( "NMA", "DENMA DEChub-90 network management agent CSMA/CD comm link" ),
                166 : ( "M32", "MUXServer 320 CSMA/CD communication link" ),
                167 : ( "90W", "WANrouter-90 multiprotocol router CSMA/CD comm link" ),
                168 : ( "9WS", "WANrouter-90 multiprotocol router DDCMP/HDLC comm link" ),
                169 : ( "FQA", "DEFQA Q-bus adapter FDDI comm link" ),
                170 : ( "A35", "DEC/3000 model 400/500 (Sandpiper/Flamingo) Alpha AXP workstation CSMA/CD comm link" ),
                172 : ( "V49", "VAXstation 400 model 90 workstation CSMA/CD comm link" ),
                173 : ( "IS4", "NIS400 bridge/router CSMA/CD comm link" ),
                174 : ( "I4E", "NIS400 bridge/router Ethernet option module CSMA/CD comm link" ),
                175 : ( "TRA", "DETRA-AA Turbochannel 802.5 token ring comm link" ),
                176 : ( "TRB", "DETRA-BA Turbochannel 802.5 token ring comm link" ),
                177 : ( "MX9", "MUXserver 90 CSMA/CD comm link" ),
                178 : ( "90M", "DECserver-90M CSMA/CD comm link" ),
                179 : ( "M9S", "MUXserver 90 synchronous (HDLC/DDCMP) comm link" ),
                180 : ( "FEN", "DECserver 900-04 CSMA/CD comm link" ),
                181 : ( "FGL", "Gigaswitch DEFGL line card FDD comm link" ),
                182 : ( "ERA", "DE422 EISA-bus PC CSMA/CD comm link" ),
                183 : ( "RMN", "DECpacketprobe 90 Ethernet RMON agent CSMA/CD comm link" ),
                184 : ( "TMN", "DECpacketprobe 900 Token Ring RMON agent 802.5 comm link" ),
}

# The above is the full registry, but we actually only want the string
# (the second item).
MOPdevices = { k : v[1] for (k, v) in MOPdevices2.items () }

MOPdatalinks = { 1 : "CSMA-CD",
                 2 : "DDCMP",
                 3 : "LAPB (frame level of X.25)",
                 4 : "HDLC",
                 5 : "FDDI",
                 6 : "Token-passing Ring (IEEE 802.5)",
                11 : "Token-passing Bus (IEEE 802.4)",
                12 : "Z-LAN 4000: Zenith 4 Megabit/second broadband CSMA/CD LAN",
}

MOPCPUs = { 1 : "PDP-11 (UNIBUS)",
            2 : "Communication Server",
            3 : "Professional"
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
        ret = self.replyclass ()
        # Put in the entity
        ret.entity = ret.entity_class (k)
        return ret
    
    def sorted (self, req):
        # Like items() but in sorted order by key
        return sorted (self.items ())

class P2ReplyDict (ReplyDict):
    def makeitem (self, k):
        return self.replyclass ()
    
class NodeReplyDict (ReplyDict):
    def makeitem (self, k):
        ret = super ().makeitem (k)
        k = self.node.nodeinfo (k)
        ret.entity = k
        return ret
        
    def sorted (self, req):
        # Special handler for sorting node replies.  Executor always
        # comes first, followed by regular nodes, then finally loop
        # nodes.  If the request was a wild card, filter the results
        # accordingly.  This is somewhat inefficient in that we
        # produce the full list and then trim it, but it is good
        # enough and it's very easy to implement.  Optimization can
        # certainly be done without too much effort if it turns out to
        # be worth doing.
        e = self.node.routing.nodeid
        ent = req.entity
        # Check explicitly since just trying to access self[e] would
        # create a record for e...
        if e in self and ent.match (e):
            yield e, self[e]
        for k, v in sorted ((k, v) for k, v in self.items ()
                            if isinstance (k, Nodeid)):
            if k != e and ent.match (k):
                yield k, v
        for k, v in sorted ((k, v) for k, v in self.items ()
                            if not isinstance (k, Nodeid)):
            if ent.match (k):
                yield k, v
                
# Base class for NICE reply packets.  These need to be subclassed for
# each entity code in the reply header.
class NiceReply (packet.Packet):
    _layout = (( packet.SIGNED, "retcode", 1 ),
               ( packet.B, "detail", 2 ),
               ( packet.A, "message", 255 ))
    replydict = ReplyDict

    # Dummy values for the row formatting machinery
    rowheader = None
    rowformat = None
    rowfields = ()
    
    def fixsubstates (self, *names):
        for sname, ssname, ssvdict in names:
            s = getattr (self, sname, None)
            ss = getattr (self, ssname, None)
            if s is not None:
                s.substate = ss
                s.ssvdict = ssvdict
                if ss is not None:
                    delattr (self, ssname)

class CState (C1):
    # This class is used for a "state" value that has an associated
    # "substate", to print the two together.  For this to work, the
    # NiceReply.fixstates method has to be invoked for those
    # attributes; see the class definition of CircuitReply for an
    # example.
    def format (self, vdict = {}):
        ret = super ().format (vdict)
        if self.substate is not None:
            ret = "{}-{}".format (ret, self.substate.format (self.ssvdict))
        return ret

class NiceReplyHeader (NiceReply):
    # Use this class to decode the header (only) of a NICE reply that
    # may be an error with the detail and/or message fields omitted
    # (since they are optional and not always sent).  Don't use this
    # as a base class because the decoder will mess up the handling of
    # subclass decoding.

    @classmethod
    def decode (cls, buf, *decodeargs):
        ret = cls ()
        ret.detail = 0xffff
        ret.message = ""
        ret.retcode, buf = packet.SIGNED.decode (buf, 1)
        if buf:
            ret.detail, buf = packet.B.decode (buf, 2)
        if buf:
            ret.message, buf = packet.A.decode (buf, 255)
        return ret, b""
    
# NICE codes and corresponding strings for node types.  Note that
# these are different from node type as encoded in routing layer
# protocol messages.
ROUTING3 = 0
ENDNODE3 = 1
PHASE2 = 2
AREA = 3
ROUTING4 = 4
ENDNODE4 = 5

rvalues = ( "Routing III", "Non-Routing III", "Phase II", "Area",
            "Routing IV", "Non-Routing IV" )

ed_values = ( "Enabled", "Disabled" )

class NiceLoopReply (NiceReply):
    _layout = (( NICE, True,
                 ( 10, HI, "Physical Address" )),)

class NiceLoopErrorReply (NiceReply):
    _layout = (( packet.B, "notlooped", 2 ),)
    
class NodeReply (NiceReply):
    replydict = NodeReplyDict
    entity_class = NodeEntity
  
    _layout = (( NodeEntity, "entity" ),
               ( NICE, True,
                 ( 0, C1, "State", None,
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
                 ( 155, CMNode, "Loop node" ),
                 ( 156, CMNode, "Loop assistant node" ),
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
                 ( 2785, DU2, "Maximum declared objects" ))
                 + node_counters)

    rowheader = ( "Node            State        Links   Delay  Circuit      Next Node",
                  "Node            State        Links  Delay  Type           Cost  Hops  Circuit" )
    rowformat = ( "{0.entity!s:<16s}{0.state:<13s}{0.active_links:<8s}{0.delay:<7s}{0.adj_circuit:<13s}{0.next_node}",
                  "{0.entity!s:<16s}{0.state:<13s}{0.active_links:<7s}{0.delay:<7s}{0.adj_type:<15s}{0.cost:<6s}{0.hops:<6s}{0.adj_circuit:<13s}" )
    rowfields = ((0, 600, 601, 822, 830),
                 (0, 600, 601, 810, 820, 821, 822))

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

# R/W params, used both in show replies and set requests
circuit_set_params = (( 0, CState, "State", None,
                           ( "On", "Off", "Service", "Cleared" )),
                      ( 100, C1, "Service", None, ( "Enabled", "Disabled" )),
                      ( 110, DU2, "Counter timer" ),
                      ( 811, DU2, "Originating queue limit" ),
                      ( 900, DU1, "Cost" ),
                      ( 901, DU1, "Maximum routers" ),
                      ( 902, DU1, "Router priority" ),
                      ( 906, DU2, "Hello timer" ),
                      ( 907, DU2, "Listen timer" ),    # For Phase III (RO in 4)
                      ( 910, C1, "Blocking", None,
                              ( "Enabled", "Disabled" )),
                      ( 920, DU1, "Maximum recalls" ),
                      ( 921, DU2, "Recall timer" ),
                      ( 930, AI, "Number" ),
                      ( 1010, CState, "Polling state", None,
                              ( "Automatic", "Active",
                                "Inactive", "Dying", "Dead" )),
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
                      ( 1158, DU1, "Dead threshold" ))

class CircuitReply (NiceReply):
    entity_class = CircuitEntity

    _layout = ( ( CircuitEntity, "entity" ),
                ( NICE, True,
                 ( 1, C1, "Substate", None,
                      ( "Starting", "Reflecting", "Looping",
                        "Loading", "Dumping", "Triggering",
                        "Autoservice", "Autoloading",
                        "Autodumping", "Autotriggering",
                        "Synchronizing", "Failed" )),
                 ( 120, HI, "Service physical address" ),
                 ( 121, C1, "Service substate" ),
                 ( 200, CMNode, "Connected node" ),
                 ( 201, CM, "Connected object", None, ( DU1, AI )),
                 ( 400, AI, "Loopback name" ),
                 ( 800, CMNode, "Adjacent node" ),
                 ( 801, CMNode, "Designated router" ),
                 ( 810, DU2, "Block size" ),
                 ( 1000, CM, "User", None, ( C1, DUNode, AI )),
                 ( 1011, C1, "Polling substate", None,
                         { 1 : "Active",
                           2 : "Inactive",
                           3 : "Dying",
                           4 : "Dead" }))
                 + circuit_set_params + circuit_counters)

    rowheader = ( "Circuit         State             Loop Node        Adjacent Node",
                  "Circuit         State             Loop Node        Adjacent Node    Block Size" )
    rowformat = ( "{0.entity!s:<16s}{0.state:<18s}{0.loopback_name:<17s}{0.adjacent_node:<17s}",
                   "{0.entity!s:<16s}{0.state:<18s}{0.loopback_name:<17s}{0.adjacent_node:<17s}{0.block_size}" )
    rowfields = ((0, 400, 800), (0, 400, 800, 810))

    def check (self):
        self.fixsubstates (("state", "substate",
                                ( "Starting", "Reflecting", "Looping",
                                  "Loading", "Dumping", "Triggering",
                                  "Autoservice", "Autoloading",
                                  "Autodumping", "Autotriggering",
                                  "Synchronizing", "Failed" )),
                           ("polling_state", "polling_substate",
                                { 1 : "Active",
                                  2 : "Inactive",
                                  3 : "Dying",
                                  4 : "Dead" }))
                           
class LineReply (NiceReply):
    entity_class = LineEntity
    
    _layout = ( ( LineEntity, "entity" ),
                ( NICE, True,
                 ( 0, CState, "State", None,
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
                 ( 1160, HI, "Hardware address" ))
                 + line_counters)

    rowheader = "Line            State"
    rowformat = "{0.entity!s:<16s}{0.state}"
    rowfields = (0,)

    def check (self):
        self.fixsubstates (("state", "substate",
                                ( "Starting", "Reflecting", "Looping",
                                  "Loading", "Dumping", "Triggering",
                                  "Autoservice", "Autoloading",
                                  "Autodumping", "Autotriggering",
                                  "Synchronizing", "Failed" )))

class LoggingReply (NiceReply):
    entity_class = LoggingEntity
    
    _layout = ( ( LoggingEntity, "entity" ),
                ( NICE, True ) )

class C1Fun (C1):
    vlist = ( "Loop", "Dump", "Primary loader",
              "Secondary loader", "Boot", "Console carrier",
              "Counters")

class C1Mon (C1):
    vlist = ( "#0", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

class DU1_2d (DU1):
    fmt = "{0:0>2d}"

class CMEtime (CM3):
    delim = ":"

class CMTS (CM5):
    delim = "- ::"
    
class ModuleReply (NiceReply):
    entity_class = ModuleEntity
    
    _layout = ( ( ModuleEntity, "entity" ),
                ( NICE, True,
                 ( 100, AI, "Circuit" ),
                 ( 110, C1, "Surveillance", None, ("Enabled", "Disabled") ),
                 ( 111, CMEtime, "Elapsed time", None, ( DU2, DU1_2d, DU1_2d )),
                 ( 120, HI, "Physical address" ),
                 ( 130, CMTS, "Last report", None,
                        ( DU1, C1Mon, DU1, DU1_2d, DU1_2d )),
                 ( 1001, CMVersion, "Maintenance version", "version" ),
                 ( 1002, CM10, "Functions", None, [ C1Fun ] * 10),
                 ( 1003, HI, "Console user", "console_user" ),
                 ( 1004, DU2, "Reservation timer", "reservation_timer" ),
                 ( 1005, DU2, "Command size", "console_cmd_size", ),
                 ( 1006, DU2, "Response size", "console_resp_size" ),
                 ( 1007, HI, "Hardware address", "hwaddr" ),
                 ( 1100, C1, "Device", "device", MOPdevices ),
                 ( 1200, CM2, "Software identification", None, ( C1, AI )),
                 ( 1300, C1, "System processor", "processor", MOPCPUs ),
                 ( 1400, C1, "Data link", "datalink", MOPdatalinks ),
                 ( 1401, DU2, "Data link buffer size", "bufsize" )))

class AreaReply (NiceReply):
    entity_class = AreaEntity
    
    _layout = ( ( AreaEntity, "entity" ),
                ( NICE, True,
                 ( 0, C1, "State", None,
                       { 4 : "Reachable",
                         5 : "Unreachable" } ),
                 ( 820, DU2, "Cost" ),
                 ( 821, DU1, "Hops" ),
                 ( 822, AI, "Circuit", "adj_circuit" ),
                 ( 830, CMNode, "Next Node" )))

    rowheader = ( "Area    State        Circuit      Next Node",
                  "Area    State        Cost  Hops  Circuit      Next Node" )
    rowformat = ( "{0.entity!s:<8s}{0.state:<13s}{0.adj_circuit:<13s}{0.next_node}",
                  "{0.entity!s:<8s}{0.state:<13s}{0.cost:<6s}{0.hops:<6s}{0.adj_circuit:<13s}{0.next_node}" )
    rowfields = ((0, 822, 830),
                 (0, 820, 821, 822, 830))

# Entity encoding in requests.  This is as opposed to
# nice_coding.EntityBase which is for replies and for event messages.
class ReqEntityBase (packet.IndexedField):
    classindex = { }
    classindexkey = "e_type"

    numeric = False
    counter = False
    
    def __init__ (self, code, value = None):
        super ().__init__ ()
        if isinstance (code, str):
            value = code
        if isinstance (value, str):
            code = len (value)
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

    def encode (self, *x):
        c = self.code
        if c < 0:
            return byte (c & 0xff)
        v = self.value
        if not isinstance (v, bytetypes):
            v = bytes (str (v), "latin1")
        if len (v) > 127:
            raise LengthError
        return byte (len (v)) + v

    def __str__ (self):
        en = self.__class__.__name__[:-9]
        if self.code < 0:
            mult = ( None, "Known", "Active",
                     "Loop", "Adjacent", "Significant" )[-self.code]
            return "{} {}s".format (mult, en)
        return "{} {}".format (en, self.value)
    
class NodeReqEntity (ReqEntityBase):
    e_type = 0

    def __init__ (self, code, value = None):
        if isinstance (code, str):
            value = code
        if isinstance (value, str):
            try:
                n = Nodeid (value)
                code = 0
                value = n
            except ValueError:
                pass
        super ().__init__ (code, value)

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
        v, b = super (__class__, cls).decode (b)
        v.__class__ = cls
        return v, b

    def encode (self, *x):
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
    numeric = True

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

    def encode (self, *x):
        if self.code == 0:
            return byte (0) + byte (self.value)
        elif self.code > 0:
            raise ValueError ("Area number must be integer, not string")
        return super ().encode ()

# OS-specific entities.
class RSXProcessReqEntity (ReqEntityBase): e_type = 5
class RSXObjReqEntity (AreaReqEntity): e_type = 7
class RSXAliasReqEntity (ReqEntityBase): e_type = 8
class RSXSysReqEntity (ReqEntityBase):
    e_type = 6

class RSTSLinkReqEntity (ReqEntityBase):
    e_type = 6
    numeric = True
    
    @classmethod
    def decode (cls, b, *x):
        require (b, 2)
        code = b[0]
        if not code:
            require (b, 3)
            return cls (code, int.from_bytes (b[:2], LE)), b[2:]
        if code >= 128:
            code -= 256
        if code > 0:
            raise DecodeError ("String format invalid for link entity")
        return cls (code), b[1:]

    def encode (self):
        if self.code == 0:
            return byte (self.code) + self.value.to_bytes (2, LE)
        elif self.code > 0:
            raise ValueError ("Link number must be integer, not string")
        return super ().encode ()

class RSTSObjReqEntity (NodeReqEntity): e_type = 7

class VMSLinkReqEntity (RSTSLinkReqEntity): e_type = 7
class VMSObjReqEntity (RSTSObjReqEntity): e_type = 4

# Qualifiers are encoded like request entities but since they go into
# NICE data blocks we need to supply a dummy type code in the encode
# method which the common code will then strip off.

class NodeQualEntity (NodeReqEntity):
    def encode (self, *x):
        return b"\x00" + super ().encode ()

class StringQualEntity (CircuitReqEntity):
    def encode (self, *x):
        return b"\x00" + super ().encode ()

# Base class for NICE request packets.  This is used both for Phase II
# and for Phase III/IV -- the packet formats are rather different but
# the packet function codes (first byte) are distinct between the two
# protocol versions.
class NiceRequestHeader (packet.IndexedPacket):
    classindex = { }
    classindexkey = "function"
    
    _layout = (( packet.B, "function", 1 ),)

# Loop node parameters
loop_params = (( 150, DU2, "Count", "loop_count" ),
               ( 151, DU2, "Length", "loop_length" ),
               ( 152, C1, "With", "loop_with",
                       ( "Zeroes",
                         "Ones",
                         "Mixed" )))

loop_circ_params = (( 10, HI, "Physical Address" ),
                    ( 153, HI, "Assistant Physical Address", "assistant_pa" ),
                    ( 154, C1, "Help", "loop_help",
                            ( "Transmit",
                              "Receive",
                              "Full" ) ),
                    # TODO: the next two should be NodeReqEntity, but
                    # that doesn't work at the moment, the NICE packet
                    # format machinery isn't flexible enough.
                    ( 155, AI, "Node", "loop_node" ),
                    ( 156, AI, "Assistant node" ))

# Base class for NICE Test packets
class NiceTestHeader (NiceRequestHeader):
    function = 18

    classindex = { }
    classindexkey = "test_type"

    _layout = (( packet.BM,
                 ( "test_type", 0, 3 ),
                 ( "access_ctl", 7, 1 )),)

class NiceLoopNodeBase (NiceTestHeader):
    test_type = 0
    
    classindex = { }
    classindexkey = "access_ctl"

    _layout = (( NodeReqEntity, "entity" ),)
    
class NiceLoopNode (NiceLoopNodeBase):
    username = password = account = b""
    access_ctl = 0

    _layout = (( NICE, False ) + loop_params,) 
    
class NiceLoopNodeAcc (NiceLoopNodeBase):
    access_ctl = 1

    _layout = (( packet.A, "username", 39 ),
               ( packet.A, "password", 39 ),
               ( packet.A, "account", 39 ),
               ( NICE, False ) + loop_params )

class NiceLoopLine (NiceTestHeader):
    test_type = 1

    _layout = (( LineReqEntity, "entity" ),
               ( NICE, False ) + loop_params )

class NiceLoopCircuit (NiceTestHeader):
    test_type = 3

    _layout = (( CircuitReqEntity, "entity" ),
               ( NICE, False ) + loop_params + loop_circ_params )

# Base class for NICE Read Information request packets
class NiceReadInfoHdr (NiceRequestHeader):
    function = 20
    
    classindex = { }
    classindexkey = "entity_type"
        
    _layout = (( packet.BM,
                 ( "permanent", 7, 1 ),
                 ( "info", 4, 3 ),
                 ( "entity_type", 0, 3 )),)

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
# set the "payload" slot to permit it.  Module does use it.  
class NiceReadNode (NiceReadInfoHdr):
    entity_class = NodeReqEntity
    entity_type = entity_class.e_type
    replyclass = NodeReply

    _layout = (( NodeReqEntity, "entity" ),
               ( NICE, False,
                 ( 501, StringQualEntity, "Circuit" ),
                 # Bug workaround: the spec is clear that 501 is the
                 # correct code but VMS wants this one.  So use the
                 # qualifier "vms circuit" when talking to VMS.
                 ( 822, StringQualEntity, "VMS Circuit" )))
        
class NiceReadLine (NiceReadInfoHdr):
    entity_class = LineReqEntity
    entity_type = entity_class.e_type
    replyclass = LineReply

    _layout = (( LineReqEntity, "entity" ),
               packet.Payload )
        
class NiceReadLogging (NiceReadInfoHdr):
    entity_class = LoggingReqEntity
    entity_type = entity_class.e_type
    replyclass = LoggingReply

    _layout = (( LoggingReqEntity, "entity" ),
               packet.Payload )
        
class NiceReadCircuit (NiceReadInfoHdr):
    entity_class = CircuitReqEntity
    entity_type = entity_class.e_type
    replyclass = CircuitReply

    _layout = (( CircuitReqEntity, "entity" ),
               ( NICE, False,
                 ( 800, NodeQualEntity, "Adjacent node" )))
        
class NiceReadModule (NiceReadInfoHdr):
    entity_class = ModuleReqEntity
    entity_type = entity_class.e_type
    replyclass = ModuleReply

    _layout = (( ModuleReqEntity, "entity" ),
               ( NICE, False,
                 # Configurator
                 ( 100, StringQualEntity, "Circuit" ),
                 ( 120, HI, "Physical address" ),
                 # X.25 Access
                 ( 1110, StringQualEntity, "Network" ),
                 # X.25 Protocol
                 ( 1100, StringQualEntity, "DTE" ),
                 ( 1101, StringQualEntity, "Group" ),
                 # X.25 Server
                 ( 300, StringQualEntity, "Destination" )))
        
class NiceReadArea (NiceReadInfoHdr):
    entity_class = AreaReqEntity
    entity_type = entity_class.e_type
    replyclass = AreaReply

    _layout = (( AreaReqEntity, "entity" ),
               packet.Payload )

# Base class for NICE Change Parameter request packets
class NiceSetParamHdr (NiceRequestHeader):
    function = 19
    
    classindex = { }
    classindexkey = "entity_type"
        
    _layout = (( packet.BM,
                 ( "permanent", 7, 1 ),
                 ( "info", 4, 3 ),
                 ( "entity_type", 0, 3 )),)

    def makereplydict (self, node):
        rc = self.replyclass
        return rc.replydict (rc, node)

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

class NiceSetCircuit (NiceSetParamHdr):
    entity_class = CircuitReqEntity
    entity_type = entity_class.e_type

    #replyclass = CircuitSetReply

    # These are somewhat different from the (read info) response since
    # status (read-only or output only) values are omitted.
    _layout = (( CircuitReqEntity, "entity" ),
                ( NICE, False ) + circuit_set_params )
    
# Base class for NICE Read Information request packets
class NiceZeroCtrHdr (NiceRequestHeader):
    function = 21
    
    classindex = { }
    classindexkey = "entity_type"
        
    _layout = (( packet.BM,
                 ( "readzero", 7, 1 ),
                 ( "entity_type", 0, 3 )),)

    def makereplydict (self, node):
        rc = self.replyclass
        return rc.replydict (rc, node)

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
#
# Note that there are no logging or area counters.
class NiceZeroNode (NiceZeroCtrHdr):
    entity_class = NodeReqEntity
    entity_type = entity_class.e_type
    replyclass = NodeReply

    _layout = (( NodeReqEntity, "entity" ),
               packet.Payload )
        
class NiceZeroLine (NiceZeroCtrHdr):
    entity_class = LineReqEntity
    entity_type = entity_class.e_type
    replyclass = LineReply

    _layout = (( LineReqEntity, "entity" ),
               packet.Payload )
        
class NiceZeroCircuit (NiceZeroCtrHdr):
    entity_class = CircuitReqEntity
    entity_type = entity_class.e_type
    replyclass = CircuitReply

    _layout = (( CircuitReqEntity, "entity" ),
               packet.Payload )
        
class NiceZeroModule (NiceZeroCtrHdr):
    entity_class = ModuleReqEntity
    entity_type = entity_class.e_type
    replyclass = ModuleReply

    _layout = (( ModuleReqEntity, "entity" ),
               packet.Payload )

# System-specific responses
class RSXObjEntity (AreaEntity):
    label = "Object"
    
class RSXProcessEntity (StringEntityBase):
    label = "Process"

class RSXAliasEntity (StringEntityBase):
    label = "Alias"

class RSTSObjEntity (AreaEntity):
    label = "Object"
    
class RSTSLinkEntity (EntityBase, int):
    label = "Link"
    def encode (self):
        return self.bytes (2, LE)

    @classmethod
    def decode (cls, buf):
        return cls (int.from_bytes (buf[:2], LE)), buf[2:]

class VMSObjEntity (StringEntityBase):
    label = "Object"

class VMSLinkEntity (RSTSLinkEntity): 
    label = "Link"

    def encode (self):
        return b'\x00' + self.bytes (2, LE)

    @classmethod
    def decode (cls, buf):
        if buf[0]:
            raise DecodeError ("Code is not zero")
        return cls (int.from_bytes (buf[1:3], LE)), buf[3:]

class CCopies (C1):
    def format (self, tlist = None):
        if not self:
            return "Single"
        return "{:d}".format (self)
    
class NiceRSXObjReply (NiceReply):
    replydict = ReplyDict
    entity_class = RSXObjEntity
    _layout = (( RSXObjEntity, "entity" ),
               ( NICE, True,
                 ( 400, AI, "Active name" ),
                 ( 410, DU2, "Active links" ),
                 ( 500, AI, "Name" ),
                 ( 510, CCopies, "Copies" ),
                 ( 511, C1, "User", None,
                         ( "Default", "Login" )),
                 ( 520, C1, "Verification", None,
                         ( "On", "Off", "Inspect" ))))
    rowheader = "Object  Name    Copies  User     Verification"
    rowformat = "{0.entity!s:<8s}{0.name:<8s}{0.copies:<8s}{0.user:<9s}{0.verification}"
    rowfields = (500, 510, 511, 520)
    
class NiceRSXProcessReply (NiceReply):
    replydict = ReplyDict
    entity_class = RSXProcessEntity
    _layout = (( RSXProcessEntity, "entity" ),
               ( NICE, True,
                 ( 0, C1, "State", None,
                       ( "On", "Off" )),
                 ( 10, AI, "Location" ),
                 ( 20, DU2, "Maximum controllers" ),
                 ( 21, DU2, "Maximum lines" ),
                 ( 30, AI, "Partition" )))

    rowheader = "Process  State"
    rowformat = "{0.entity!s:<9s}{0.state}"
    rowfields = (0,)

class NiceRSXSystemReply (NiceReply):
    replydict = ReplyDict
    _layout = (( NICE, True,
                 ( 10, DU2, "Active control buffers" ),
                 ( 20, DU2, "Active small buffers" ),
                 ( 30, DU2, "Active large buffers" ),
                 ( 110, DU2, "Maximum control buffers" ),
                 ( 120, DU2, "Maximum small buffers" ),
                 ( 130, DU2, "Maximum large buffers" ),
                 ( 131, DU2, "Large buffer size" ),
                 ( 140, DU2, "Minimum receive buffers" ),
                 ( 160, DU2, "Extended pool bytes" ),
                 ( 162, DU2, "Extended pool segments" ),
                 ( 164, DU2, "Maximum extended pool segments" ),
                 ( 0, CTR2, "Seconds since last zeroed" ),
                 ( 10, CTR2, "Control buffer allocation failed" ),
                 ( 20, CTR2, "Small buffer allocation failed" ),
                 ( 30, CTR2, "Large buffer allocation failed" ),
                 ( 40, CTR2, "Receive buffer allocation failed" )),)
    entity = ""
    
class AIFile (AI):
    # For RSTS file names to remove the embedded spaces that make
    # things look confusing.
    def format (self, tlist = None):
        return super ().format (tlist).replace (" ", "")
    
class NiceRSTSObjReply (NiceReply):
    replydict = ReplyDict
    entity_class = RSTSObjEntity
    _layout = (( RSTSObjEntity, "entity" ),
               ( NICE, True,
                 ( 500, AI, "Name" ),
                 ( 2100, AIFile, "File" ),
                 ( 2101, DU2, "Parameter 1" ),
                 ( 2102, DU2, "Parameter 2" ),
                 ( 2103, C1, "Type" ),
                 ( 2104, C1, "Verification", None,
                         ( "Program", "Off", "On" ))))

    rowheader = ( "Object  Name",
                  None,
                  "Object  Name    File name            Verification  Parameters" )
    rowformat = ( "{0.entity!s:<8s}{0.name:<8s}",
                  None,
                  "{0.entity!s:<8s}{0.name:<8s}{0.file:<21s}{0.verification:<14s}{0.parameter_1:>5s} {0.parameter_2:>5s}" )
    rowfields = ((500,), (), (500, 2100, 2101, 2102, 2104))
    
class NiceRSTSLinkReply (NiceReply):
    replydict = ReplyDict
    entity_class = RSTSLinkEntity
    _layout = (( RSTSLinkEntity, "entity" ),
               ( NICE, True,
                 ( 2131, DU2, "RLA" ),
                 ( 2132, DU1, "User link address" ),
                 ( 2133, C1, "Link state", None,
                          ( "-", "CI Delivered", "CI sent", "CI received",
                            "CC sent", "Run", "DI pending", "DI sent" )),
                 ( 2134, CMNode, "Node" ),
                 ( 2135, AI, "Receiver name" ),
                 ( 2136, DU1, "Receiver job number" ),
                 ( 2137, DU1, "Receiver RIB number" ),
                 ( 2138, C1, "Local flow control", None,
                          ( "None", "Segment", "Message" )),
                 ( 2139, C1, "Remote flow control", None,
                          ( "None", "Segment", "Message" ) ),
                 ( 2140, DU1, "Local data request count" ),
                 ( 2141, DU1, "Remote data request count" ),
                 ( 2142, DU1, "Local interrupt request count" ),
                 ( 2143, DU1, "Remote interrupt request count" )))
    rowheader = " LLA   RLA   State        Node             Name     Job"
    rowformat = "{0.entity!s:>5s} {0.rla:>5s}  {0.link_state:<13s}{0.node:<17s}{0.receiver_name:<7s}{0.receiver_job_number:>3s}"
    rowfields = (2131, 2133, 2134, 2135, 2136)
    
class NiceVMSObjReply (NiceReply):
    replydict = ReplyDict
    entity_class = VMSObjEntity
    _layout = (( VMSObjEntity, "entity" ),
               ( NICE, True,
                 ( 513, DU1, "Number" ),
                 ( 530, AI, "File ID" ),
                 ( 535, H4, "Process ID" ),
                 ( 550, AI, "User ID" ),
                 ( 560, C1, "Proxy access", None,
                        ( "?", "Incoming", "Outgoing" ) ),
                 ( 565, C1, "Alias outgoing", None,
                        ( "Enabled", "Disabled" ) ),
                 ( 566, C1, "Alias incoming", None,
                        ( "Enabled", "Disabled" ) ),))

class NiceVMSLinkReply (NiceReply):
    replydict = ReplyDict
    entity_class = VMSLinkEntity
    _layout = (( VMSLinkEntity, "entity" ),
               ( NICE, True,
                 ( 0, C1, "State", None, { 5 : "Run" } ),
                 ( 101, H4, "PID" ),
                 ( 102, CMNode, "Remote node" ),
                 ( 110, DU2, "Delay" ),
                 ( 120, DU2, "Remote link" ),
                 ( 121, AI, "Remote user" ),
                 ( 130, AIFile, "Username" ),
                 ( 131, AI, "Process name" )))
    rowheader = ( " Link       Node           PID     Process     Remote link  Remote user",
                  " Link       Node           PID     Process     Remote link  State" )
    rowformat = ( "{0.entity!s:>5s}  {0.remote_node:<18s}{0.pid:<10s}{0.process_name:<18s}{0.remote_link:>5s}  {0.remote_user}",
                  "{0.entity!s:>5s}  {0.remote_node:<18s}{0.pid:<10s}{0.process_name:<18s}{0.remote_link:>5s}  {0.state}" )
    rowfields = ((102, 101, 131, 120, 121),
                 (102, 101, 131, 120, 0))

# System-specific requests.
# Base class for NICE Read Information request packets
class NiceSysSpecific (NiceRequestHeader):
    function = 22
    
    classindex = { }
    classindexkey = "os"
        
    _layout = (( packet.B, "os", 1 ),)

    def makereplydict (self, node):
        rc = self.replyclass
        return rc.replydict (rc, node)

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

    def sig (self):
        return self.entity.code == -5

    def sigact (self):
        return self.entity.code == -2 or self.entity.code == -5

    def wild (self):
        return self.entity.code < -5

class NiceRSXSpecific (NiceSysSpecific):
    os = 2

    classindex = { }
    classindexkey = "sfunction"
        
    _layout = (( packet.B, "sfunction", 1 ),)

class NiceRSXShowBase (NiceRSXSpecific):
    sfunction = 20
    
    classindex = { }
    classindexkey = "entity_type"
        
    _layout = (( packet.BM,
                 ( "permanent", 7, 1 ),
                 ( "info", 4, 3 ),
                 ( "entity_type", 0, 3 )),)

class NiceRSXShowObject (NiceRSXShowBase):
    entity_class = RSXObjReqEntity
    entity_type = entity_class.e_type
    replyclass = NiceRSXObjReply

    _layout = (( RSXObjReqEntity, "entity" ),
               packet.Payload )
        
class NiceRSXShowProcess (NiceRSXShowBase):
    entity_class = RSXProcessReqEntity
    entity_type = entity_class.e_type
    replyclass = NiceRSXProcessReply

    _layout = (( RSXProcessReqEntity, "entity" ),
               packet.Payload )

class NiceRSXShowSystem (NiceRSXShowBase):
    entity_class = RSXSysReqEntity
    entity_type = 6
    replyclass = NiceRSXSystemReply
    _addslots = ("entity",)

class NiceRSTSSpecific (NiceSysSpecific):
    os = 1

    classindex = { }
    classindexkey = "sfunction"
        
    _layout = (( packet.B, "sfunction", 1 ),)

class NiceRSTSShowBase (NiceRSTSSpecific):
    sfunction = 20
    
    classindex = { }
    classindexkey = "entity_type"
        
    _layout = (( packet.BM,
                 ( "permanent", 7, 1 ),
                 ( "info", 4, 3 ),
                 ( "entity_type", 0, 3 )),)

class NiceRSTSShowObject (NiceRSTSShowBase):
    entity_class = RSTSObjReqEntity
    entity_type = entity_class.e_type
    replyclass = NiceRSTSObjReply

    _layout = (( RSTSObjReqEntity, "entity" ),
               packet.Payload )
        
class NiceRSTSShowLink (NiceRSTSShowBase):
    entity_class = RSTSLinkReqEntity
    entity_type = entity_class.e_type
    replyclass = NiceRSTSLinkReply

    _layout = (( RSTSLinkReqEntity, "entity" ),
               packet.Payload )
        
class NiceVMSSpecific (NiceSysSpecific):
    os = 4

    classindex = { }
    classindexkey = "sfunction"
        
    _layout = (( packet.B, "sfunction", 1 ),)

class NiceVMSShowBase (NiceVMSSpecific):
    sfunction = 20
    
    classindex = { }
    classindexkey = "entity_type"
        
    _layout = (( packet.BM,
                 ( "permanent", 7, 1 ),
                 ( "info", 4, 3 ),
                 ( "entity_type", 0, 3 )),)

class NiceVMSShowObject (NiceVMSShowBase):
    entity_class = VMSObjReqEntity
    entity_type = entity_class.e_type
    replyclass = NiceVMSObjReply

    _layout = (( VMSObjReqEntity, "entity" ),
               packet.Payload )
        
class NiceVMSShowLink (NiceVMSShowBase):
    entity_class = VMSLinkReqEntity
    entity_type = entity_class.e_type
    replyclass = NiceVMSLinkReply

    _layout = (( VMSLinkReqEntity, "entity" ),
               packet.Payload )
        
# Phase II NICE encoding.  This is quite different from the extensible
# encoding used in Phase III and Phase IV, and the message code
# numbers are distinct.

# Phase II first reply (header of the following sequence)
# Base class for NICE reply packets.  These need to be subclassed for
# each entity code in the reply header.
class P2NiceReply1 (packet.Packet):
    _layout = (( packet.SIGNED, "retcode", 1 ),)

class P2NiceReply3 (P2NiceReply1):
    retcode = 1
    
    _layout = (( packet.B, "count", 2 ),)
    
# Base class for NICE Read Information reply packets
class P2NiceReadInfoReply (packet.Packet):
    replydict = P2ReplyDict

    _layout = (( packet.B, "type", 1 ),)

    # Dummy values for the row formatting machinery
    rowheader = None
    rowformat = None
    rowfields = ()
    
# Line ID in request and response.  Believe it or not, the unit
# numbers are in octal.
_line_re = re.compile (r"([a-z]+)[-_]([0-7]+)(?:[-_]([0-7]+))?$", re.I)

class P2LineEntity (packet.Field, bytes):
    numeric = False
    devnames = {
      0 : "DP",    # DP11-DA
      2 : "DU",    # DU11-DA synchronous line interface
      4 : "DL",    # DL11-C, -E or -WA asynchronous line interface
      6 : "DQ",    # DQ11-DA
      8 : "DA",    # DA11-B or -AL UNIBUS link
      10 : "DUP",  # DUP11-DA synchronous line interface
      12 : "DMC",  # DMC11-DA/AR, -FA/AR, -MA/AL or -MD/AL interprocessor link
      14 : "DLV",  # DLV11, MXV11 asynchronous line interface
      16 : "DL",   # DL11-A
      20 : "DTE",  # DTE20 PDP-11 to KL10 interface
      22 : "DV",   # DV11-AA/BA synchronous line multiplexer
      28 : "KDP",  # KMC11/DUP11-DA synchronous line multiplexer
      30 : "KDZ"   # KMC11/DZ11-A, -B, -C, or -D asynchronous line multiplexer
    }
    devcodes = { v : k for (k, v) in devnames.items () }

    def __new__ (cls, buf, alt = None):
        if isinstance (buf, str):
            if buf == "*":
                return bytes.__new__ (cls, b"\000")
            m = _line_re.match (buf)
            if m:
                dev, ctl, unit = m.groups ()
                try:
                    dev = cls.devcodes[dev.upper ()]
                    ctl = int (ctl, 8)
                    if unit:
                        unit = int (unit, 8)
                    else:
                        unit = 0
                    if ctl <= 255 and unit <= 255:
                        return bytes.__new__ (cls, (1, dev, ctl, unit, 0))
                except Exception:
                    pass
            # Not a device string of the standard TOPS-20 pattern.  If
            # "alt" is supplied, make up a placeholder ID.  If not,
            # encode as a string format ID (which TOPS-20 V4.1 does
            # not support).
            if alt is None:
                dname = packet.A (buf)
                return bytes.__new__ (cls, b"\002" + dname.encode (255))
            # The alternate is DTE_0_n where n is the alternate value.
            # Why DTE?  It makes very little sense, but as input
            # values TOPS-20 only accepts DMC, DTE, DUP, and KDP.
            return bytes.__new__ (cls, (1, cls.devcodes["DTE"], 0, alt, 0))
        return bytes.__new__ (cls, buf)
    
    def __format__ (self, arg):
        return "Line = {!s}".format (self)
        
    def __str__ (self):
        if self[0] == 0:
            return "*"
        if self[0] == 1:
            ret = "{}_{:o}".format (self.devnames[self[1]], self[2])
            if self[3]:
                ret += "_{:o}".format (self[3])
            return ret
        return str (self[2:], "ascii")
    
    def encode (self):
        return makebytes (self)

    def known (self):
        return self[0] == 0
    
    @classmethod
    def decode (cls, buf):
        code = buf[0]
        if not 0 <= code <= 2:
            raise ValueError ("Invalid Line ID code {}", ret.code)
        if code == 1:
            val = buf[:5]
            buf = buf[5:]
        elif code == 2:
            l = buf[1]
            val = buf[:2 + l]
            buf = buf[2 + l:]
        else:
            val = buf[:1]
            buf = buf[1:]
        return cls (val), buf
    
class P2NiceReadExecStatusReply (P2NiceReadInfoReply):
    type = 1
    entity = "Executor"

    _layout = (( packet.A, "name", 6 ),
               ( packet.B, "id", 1 ),
               ( packet.B, "state", 1 ),
               ( packet.RES, 2 ),
               ( packet.A, "defhost", 6 ),
               ( Version, "routing_version" ),
               ( Version, "comm_version" ),
               ( packet.A, "system", 40 ))

# Line CTR2 but with a one-byte ID.
class P2CTR2 (CTR2):
    def encode (self, pnum):
        # Note that pnum comes in with the counter flag set
        return byte (pnum & 0xff) + \
               min (self, self.maxval).to_bytes (self.bytecnt, "little")

    # Don't use the NICE checktype, we want to force values to be this
    # type.
    @classmethod
    def checktype (cls, name, v, tlist = None):
        """If v is not already an instance of cls, make it an
        instance of cls.
        """
        if not isinstance (v, cls):
            v = cls (v)
        return v

class P2NICE (NICE):
    """Layout element for Phase II NICE parameter-number data.  This
    uses a single byte parameter number, the encoding is given by the
    table (not in the packet) and counters and non-counters can't be
    mixed.  The first argument is True for a counters packet, False
    otherwise.
    """
    @classmethod
    def decodepnum (cls, buf, ctr, pdict):
        """Decode the parameter number.  Returns a tuple consisting of
        parameter code, parameter number, parameter class, field name,
        values dict, and remaining buffer.  The parameter code is fixed
        at the one we use in the limited code here (CTR2) because Phase
        II NICE messages are not self-describing, unlike the later
        version of the protocol.
        """
        # For now we only handle counters
        param = buf[0] | 0x8000
        buf = buf[1:]
        try:
            pcls, fn, vals = pdict[param]
        except KeyError:
            raise DecodeError ("Unknown parameter {} in request".format (param))
        return P2CTR2.code, pcls, fn, vals, buf

class P2NiceReadLineCountersReply (P2NiceReadInfoReply):
    type = 4

    _layout = (( P2LineEntity, "entity" ),
               ( P2NICE, True,
                 ( 0, P2CTR2, "Seconds since last zeroed", "time_since_zeroed" ),
                 ( 1, P2CTR2, "Data blocks received", "pkts_recv" ),
                 ( 2, P2CTR2, "Data blocks sent", "pkts_sent" ),
                 ( 3, P2CTR2, "Data errors outbound" ),
                 ( 4, P2CTR2, "Data errors inbound" ),
                 ( 5, P2CTR2, "Remote reply timeouts" ),
                 ( 6, P2CTR2, "Local reply timeouts" ),
                 ( 6, P2CTR2, "Selection errors" ),
                 ( 8, P2CTR2, "Buffer unavailable" )),)

class P2NiceReadLineStatusReply (P2NiceReadInfoReply):
    type = 5
    # This allows attributes to be set that aren't in the layout.
    # Those will be ignored but it simplifies code that sets
    # attributes defined in later versions of NICE.
    _addslots = ( "__dict__", )

    # Information for tabular output
    rowheader = "Line ID         State           Adjacent Node"
    rowformat = "{0.entity!s:<16s}{0.state!s:<16s}{0.adjacent_node}"
    rowfields = (0, 1)
    
    # Status codes:
    ON = 0
    OFF = 1
    MAINT = 4
    ILOOP = 5
    ELOOP = 6

    # Note: these use the same names as in the Phase III/IV circuit
    # status reply.
    _layout = (( P2LineEntity, "entity" ),
               ( packet.B, "state", 1 ),
               ( packet.RES, 2 ),
               ( packet.A, "adjacent_node", 6 ))
    
# Base class for NICE Read Information request packets
class P2NiceReadInfoHdr (NiceRequestHeader):
    function = 8
    
    classindex = { }
    classindexkey = "type"
        
    _layout = (( packet.B, "type", 1 ),)

    def makereplydict (self, node):
        rc = self.replyclass
        return rc.replydict (rc, node)

    def sum (self):
        return True

    stat = sum
    sumstat = sum

    def char (self):
        return False

    counters = char
    events = char

class P2NiceReadExecStatus (P2NiceReadInfoHdr):
    type = 1
    replyclass = P2NiceReadExecStatusReply

class P2NiceReadLineCounters (P2NiceReadInfoHdr):
    type = 4
    replyclass = P2NiceReadLineCountersReply

    _layout = (( P2LineEntity, "entity" ),)

    def sum (self):
        return False

    stat = sum
    sumstat = sum

    def counters (self):
        return True

class P2NiceReadLineStatus (P2NiceReadInfoHdr):
    type = 5
    replyclass = P2NiceReadLineStatusReply

    _layout = (( P2LineEntity, "entity" ),)


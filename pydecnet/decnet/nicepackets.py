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
               ( "b", "detail", 2 ),
               ( "a", "message", 255 ))

    def __init__ (self, *args):
        self.detail = 0xffff
        super ().__init__ (*args)

class NiceReadReply (NiceReply):
    replydict = ReplyDict
    _layout = (( EntityBase, "entity" ),)

rvalues = ( "Routing III", "Non-Routing III", "Phase II", "Area",
            "Routing IV", "Non-Routing IV" )

ed_values = ( "Enabled", "Disabled" )

class NiceLoopReply (NiceReply):
    _layout = (( "nice",
                 (( 10, HI, "Physical Address" ), )),)

class NiceLoopErrorReply (NiceReply):
    _layout = (( "b", "notlooped", 2 ),)
    
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

class C1Fun (C1):
    vlist = ( "Loop", "Dump", "Primary loader",
              "Secondary loader", "Boot", "Console carrier",
              "Counters")

class C1Mon (C1):
    vlist = ( "#0", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    
class ModuleReply (NiceReadReply):
    entity_class = ModuleEntity
    
    _layout = (( "nice",
                 (( 100, AI, "Circuit" ),
                  ( 110, C1, "Surveillance" ),
                  ( 111, CM3, "Elapsed time", None, ( DU2, DU1, DU1 )),
                  ( 120, HI, "Physical address" ),
                  ( 130, CM5, "Last report", None,
                         ( DU1, C1Mon, DU1, DU1, DU1 )),
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
                  ( 1401, DU2, "Data link buffer size", "bufsize" ))),)

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

# Loop node parameters
loop_params = [ ( "nice_req",
                  (( 10, HI, "Physical Address" ),
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
                   # TODO: the next two should be NodeReqEntity, but
                   # that doesn't work at the moment, the NICE packet
                   # format machinery isn't flexible enough.
                   ( 155, AI, "Loop node" ),
                   ( 156, AI, "Loop assistant node" )
                   )) ]

# Base class for NICE Test packets
class NiceTestHeader (NicePacket):
    function = 18

    _layout = (( "b", "function", 1 ),
               ( "bm",
                 ( "test_type", 0, 3 ),
                 ( "access_ctl", 7, 1 )),)

class NiceLoopNodeBase (NiceTestHeader):
    test_type = 0
    
    _layout = (( NodeReqEntity, "node" ),)

class NiceLoopNode (NiceLoopNodeBase):
    username = password = account = b""

    _layout = loop_params
    
class NiceLoopNodeAcc (NiceLoopNodeBase):
    access_ctl = 1

    _layout = [ ( "a", "username", 39 ),
                ( "a", "password", 39 ),
                ( "a", "account", 39 ) ] + loop_params

class NiceLoopCircuit (NiceTestHeader):
    test_type = 3

    _layout = [ ( CircuitReqEntity, "circuit" ) ] + loop_params
                   
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

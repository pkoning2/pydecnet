#!

"""MOP support for DECnet/Python

"""

from .packet import *

class SysId (Packet):
    layout = ( ( "b", "code", 1 ),
               ( "res", 1 ),
               ( "b", "receipt", 2 ),
               ( "tlv", 2, 1, True,
                 { 1 : ( "bs", "version", 3 ),
                   2 : ( "bm",
                         ( "loop", 0, 1 ),
                         ( "dump", 1, 1 ),
                         ( "ploader", 2, 1 ),
                         ( "sloader", 3, 1 ),
                         ( "boot", 4, 1 ),
                         ( "carrier", 5, 1 ),
                         ( "counters", 6, 1 ),
                         ( "carrier_reserved", 7, 1 ),
                         ( "", 8, 8 ) ),
                   3 : ( "bs", "console_user", 6 ),
                   4 : ( "b", "reservation_timer", 2 ),
                   5 : ( "b", "console_cmd_size", 2 ),
                   6 : ( "b", "console_resp_size", 2 ),
                   7 : ( "bs", "hwaddr", 6 ),
                   8 : ( "bs", "time", 10 ),
                   100 : ( "b", "device", 1 ),
                   200 : ( "bs", "software", 17 ),
                   300 : ( "b", "processor", 1 ),
                   400 : ( "b", "datalink", 1 ) } )
               )
    code = 7
    devices = { 0 : ( "DP", "DP11-DA (OBSOLETE)" ),
                1 : ( "UNA", "DEUNA multiaccess communication link" ),
                2 : ( "DU", "DU11-DA synchronous line interface" ),
                3 : ( "CNA", "DECNA Ethernet adapter" ),
                4 : ( "DL", "DL11-C, -E or -WA asynchronous line interface" ),
                5 : ( "QNA", "DEQNA Ethernet adapter" ),
                6 : ( "DQ", "DQ11-DA (OBSOLETE)" ),
                7 : ( "CI", "Computer Interconnect interface" ),
                8 : ( "DA", "DA11-B or -AL UNIBUS link" ),
                9 : ( "PCL", "PCL11-B multiple CPU link" ),
                10 : ( "DUP", "DUP11-DA synchronous line interface" ),
                11 : ( "LUA", "DELUA Ethernet adapter" ),
                12 : ( "DMC", "DMC11-DA/AR, -FA/AR, -MA/AL or -MD/AL interprocessor link" ),
                14 : ( "DN", "DN11-BA or -AA automatic calling unit" ),
                16 : ( "DLV", "DLV11-E, -F, -J, MXV11-A or - B asynchronous line interface" ),
                17 : ( "LQA", "DELQA Ethernet adapter" ),
                18 : ( "DMP", "DMP11 multipoint interprocessor link" ),
                20 : ( "DTE", "DTE20 PDP-11 to KL10 interface" ),
                22 : ( "DV", "DV11-AA/BA synchronous line multiplexer" ),
                24 : ( "DZ", "DZ11-A, -B, -C, or -D asynchronous line multiplexer" ),
                28 : ( "KDP", "KMC11/DUP11-DA synchronous line multiplexer" ),
                30 : ( "KDZ", "KMC11/DZ11-A, -B, -C, or -D asynchronous line multiplexer" ),
                32 : ( "KL", "KL8-J (OBSOLETE)" ),
                34 : ( "DMV", "DMV11 interprocessor link" ),
                36 : ( "DPV", "DPV11 synchronous line interface" ),
                38 : ( "DMF", "DMF-32 synchronous line unit" ),
                40 : ( "DMR", "DMR11-AA, -AB, -AC, or -AE interprocessor link" ),
                42 : ( "KMY", "KMS11-PX synchronous line interface with X.25 level 2 microcode" ),
                44 : ( "KMX", "KMS11-BD/BE synchronous line interface with X.25 level 2 microcode" ),
                75 : ( "LQA-T", "DELQA-T Ethernet adapter" ),
                }
    datalinks = { 1 : "Ethernet",
                  2 : "DDCMP",
                  3 : "LAPB (frame level of X.25)" }
    processors = { 1 : "PDP-11 (UNIBUS)",
                   2 : "Communication Server",
                   3 : "Professional" }
    
class RequestId (Packet):
    layout = ( ( "b", "code", 1 ),
               ( "res", 1 ),
               ( "b", "receipt", 2 ) )
    code = 5

class RequestCounters (Packet):
    layout = ( ( "b", "code", 1 ),
               ( "b", "receipt", 2 ) )
    code = 9

class Counters (Packet):
    layout = ( ( "b", "code", 1 ),
               ( "b", "receipt", 2 ) )
    code = 11

class ConsoleRequest (Packet):
    layout = ( ( "b", "code", 1 ),
               ( "bs", "verification", 8 ) )
    code = 13

class ConsoleRelease (Packet):
    layout = ( ( "b", "code", 1 ), )
    code = 15

class ConsoleCommand (Packet):
    layout = ( ( "b", "code", 1 ),
               ( "bm",
                 ( "seq", 0, 1 ),
                 ( "break", 1, 1 ) ) )
    code = 17

class ConsoleResponse (Packet):
    layout = ( ( "b", "code", 1 ),
               ( "bm",
                 ( "seq", 0, 1 ),
                 ( "cmd_lost", 1, 1 ),
                 ( "resp_lost", 2, 1 ) ) )
    code = 19
    

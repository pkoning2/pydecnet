#!

"""NSP packet layouts

"""

from .common import *
from . import logging
from . import events
from . import modulo
from . import packet

# NSP packet layouts.  These cover the routing layer payload (or the
# datalink layer payload, in the case of Phase II)

# Packet parsing exceptions
class NSPDecodeError (packet.DecodeError): pass
class InvalidAck (NSPDecodeError): "ACK fields in error"
class InvalidLS (NSPDecodeError): "Reserved LSFLAGS value"

# Sequence numbers are modulo 4096
class Seq (Field, modulo.Mod, mod = 4096):
    """Sequence numbers for NSP -- integers modulo 2^12.  Note that
    creating one of these (e.g., from packet decode) ignores high
    order bits rather than complaining about them.
    """
    def __new__ (cls, val):
        return modulo.Mod.__new__ (cls, val & 0o7777)

    @classmethod
    def decode (cls, buf):
        if len (buf) < 2:
            raise MissingData
        v = int.from_bytes (buf[:2], packet.LE)
        return cls (v), buf[2:]

    def encode (self):
        return self.to_bytes (2, packet.LE)

    def __bytes__ (self):
        return self.encode ()
    
class AckNum (Field):
    """Class for the (usually optional) ACK field in an NSP packet.
    """
    # Values for QUAL:
    ACK = 0
    NAK = 1
    XACK = 2
    XNAK = 3
    _labels = ( "ACK", "NAK", "XACK", "XNAK" )
    def __init__ (self, num = 0, qual = ACK):
        if not 0 <= qual <= 3:
            raise ValueError ("Invalid QUAL value {}".format (qual))
        self.qual = qual
        self.num = Seq (num)

    def __str__ (self):
        return "{} {}".format (self._labels[self.qual], self.num)

    def __eq__ (self, other):
        return self.num == other.num and self.qual == other.qual

    def __ne__ (self, other):
        return not self == other
    
    @classmethod
    def decode (cls, buf):
        if len (buf) >= 2:
            v = int.from_bytes (buf[:2], packet.LE)
            if v & 0x8000:
                # ACK field is present.  Always advance past it.
                buf = buf[2:]
                qual = (v >> 12) & 7
                if 0 <= qual <= 3:
                    # Use the field only if QUAL is valid
                    return cls (v, qual), buf
        return None, buf

    @classmethod
    def checktype (cls, name, val):
        # This allows for the field to be optional, which is
        # represented by an attribute value of None.
        if val is None:
            return val
        return super (__class__, cls).checktype (name, val)
    
    def encode (self):
        return (0x8000 + (self.qual << 12) + self.num).to_bytes (2, packet.LE)
    
    def is_nak (self):
        return self.qual == self.NAK or self.qual == self.XNAK

    def is_cross (self):
        return self.qual == self.XACK or self.qual == self.XNAK
    
    def chan (self, this, other):
        if self.is_cross ():
            return other
        return this

class tolerantI (packet.I):
    # A version of the I (image string) field, but coded to be
    # tolerant of messed up input since some implementation such as
    # Cisco send bad values some of the time.
    @classmethod
    def decode (cls, buf, maxlen):
        if not buf:
            logging.trace ("Missing I field, empty field substituted")
            return cls (b""), b""            
        flen = buf[0]
        if flen > maxlen or flen > len (buf) + 1:
            logging.trace ("Invalid I field, empty field substituted")
            return cls (b""), b""
        return super (__class__, cls).decode (buf, maxlen)

# Common header -- just the MSGFLG field, expanded into its subfields.
class NspHdr (packet.IndexedPacket):
    classindex = nlist (128)
    classindexkey = "msgflag"

    def instanceindexkey (buf):
        require (buf, 1)
        return buf[0]

    _layout = (( packet.BM,
                 ( "mbz", 0, 2 ),
                 ( "type", 2, 2 ),
                 ( "subtype", 4, 3 ),
                 ( "int_ls", 4, 1 ),
                 ( "bom", 5, 1 ),    # if int_ls == 0 (data message)
                 ( "eom", 6, 1 ),    # if int_ls == 0 (data message)
                 ( "int", 5, 1 ),    # if int_ls == 1 (other-data message)
                 ( "mbz2", 7, 1 )), )
    mbz = 0
    mbz2 = 0
    # type codes
    DATA = 0
    ACK = 1
    CTL = 2
    # Ack subtype codes
    ACK_DATA = 0
    ACK_OTHER = 1
    ACK_CONN = 2
    # Control subtype codes
    NOP = 0    # NOP (normally only in Phase II, but spec doesn't restrict it)
    CI = 1
    CC = 2
    DI = 3
    DC = 4
    #NI = 5    # Phase 2 node init (handled in routing, doesn't come to NSP)
    RCI = 6    # Retransmitted CI

class AckHdr (NspHdr):
    """The standard packet beginning for packets that have link addresses
    and acknum fields.  Note that the second ACK field is called "acknum2"
    rather than "ackoth" or "ackdat" since those names don't make sense if
    we use this header interchangeably for all packet layouts.  And while
    it is typical to use the first field for "this subchannel" and the 
    second for "the other subchannel", that isn't required.
    """
    _layout = (( packet.B, "dstaddr", 2 ),
               ( packet.B, "srcaddr", 2 ),
               ( AckNum, "acknum" ),
               ( AckNum, "acknum2" ))

    def check (self):
        # Check that the two acknum fields (if both are supplied) point
        # to different subchannels
        if self.acknum and self.acknum2 and \
           self.acknum.is_cross () == self.acknum2.is_cross ():
            logging.debug ("Both acknums refer to the same subchannel")
            raise InvalidAck ("Both acknums refer to the same subchannel")

# Note on classes for packet layouts:
#
# It is tempting at times to make packet type x a subclass of packet
# type y, when x looks just like y but with some extra stuff, or with
# a change in type code only.  IntMsg vs. LinkSvcMsg are an example
# of the former, AckData vs. AckOther or DataSeg vs. IntMsg an example
# of the latter.  This is typically not a good idea, because "isinstance"
# will match an object of a subclass of the supplied class.  To keep
# the actual message classes distinct, in the hierarchy below they are
# almost always derived from a base class that is not in itself an
# actual message class.  However, we can reuse some of the methods of
# other classes (those that we didn't want to use as base class) without
# causing trouble -- consider AckData.check for example.

class AckData (AckHdr):
    type = NspHdr.ACK
    subtype = NspHdr.ACK_DATA
    msgflag = 0x04
    
    def check (self):
        AckHdr.check (self)
        if self.acknum is None:
            logging.debug ("acknum field missing")
            raise InvalidAck ("acknum field missing")
        
class AckOther (AckHdr):
    type = NspHdr.ACK
    subtype = NspHdr.ACK_OTHER
    msgflag = 0x14
    check = AckData.check
        
class AckConn (NspHdr):
    # A Conn Ack doesn't have payload, but VAXELN sends extraneous
    # bytes at the end and pretending that's payload will suppress a
    # parse error.
    _layout = (( packet.B, "dstaddr", 2 ),
               packet.Payload)
    type = NspHdr.ACK
    subtype = NspHdr.ACK_CONN
    msgflag = 0x24

    def __init__ (self, *args, **kwargs):
        super ().__init__ (*args, **kwargs)
        self.payload = b""
        
class DataSeg (AckHdr):
    _layout = (( packet.BM,
                 ( "segnum", 0, 12, Seq ),
                 ( "dly", 12, 1 )),
                packet.Payload)
    type = NspHdr.DATA
    msgflag = 0
    classindexmask = 0x9f
    int_ls = 0
    
class IntMsg (AckHdr):
    _layout = (( Seq, "segnum" ),
               packet.Payload)
    type = NspHdr.DATA
    subtype = 3
    msgflag = 0x30
    int_ls = 1
    int = 1
    # So we can check the "delay" flag for either subchannel
    dly = 0

# Link Service message also uses the interrupt subchannel.
class LinkSvcMsg (AckHdr):
    _layout = (( Seq, "segnum" ),
               ( packet.BM,
                 ( "fcmod", 0, 2 ),
                 ( "fcval_int", 2, 2 )),
               ( packet.SIGNED, "fcval", 1 ))
    type = NspHdr.DATA
    subtype = 1
    msgflag = 0x10
    int_ls = 1
    int = 0
    # fcval_int values:
    DATA_REQ = 0
    INT_REQ = 1
    # fcmod values:
    NO_CHANGE = 0
    XOFF = 1
    XON = 2
    # So we can check the "delay" flag for either subchannel
    dly = 0

    def check (self):
        if self.fcval_int > 1 or self.fcmod == 3:
            logging.debug ("Reserved LSFLAGS value")
            raise InvalidLS

# Control messages.  5 (Node init) is handled in route_ptp since it is
# a datalink dependent routing layer message.  0 (NOP) is here,
# however.

# Common parts of CI, RCI, and CC
class ConnMsg (NspHdr):
    _layout = (( packet.B, "dstaddr", 2 ),
               ( packet.B, "srcaddr", 2 ),
               ( packet.BM,
                 ( "mb1", 0, 2 ),
                 ( "fcopt", 2, 2 ),
                 ( "mbz", 4, 4 )),
               ( packet.EX, "info", 1 ),
               ( packet.B, "segsize", 2 ))
    type = NspHdr.CTL
    mb1 = 1
    mbz = 0
    # Services:
    SVC_NONE = 0
    SVC_SEG = 1         # Segment flow control
    SVC_MSG = 2         # Message flow control
    # Info:
    VER_PH3 = 0         # Phase 3 (NSP 3.2)
    VER_PH2 = 1         # Phase 2 (NSP 3.1)
    VER_PH4 = 2         # Phase 4 (NSP 4.0)
    VER_41 = 3          # Phase 4+ (NSP 4.1)

nspverstrings = ( "3.2", "3.1", "4.0", "4.1" )
nspver3 = ( (3, 2, 0), (3, 1, 0), (4, 0, 0), (4, 1, 0))
nspphase = { ConnMsg.VER_PH2 : 2, ConnMsg.VER_PH3 : 3,
             ConnMsg.VER_PH4 : 4, ConnMsg.VER_41 : 4  }

# This is either Connect Initiate or Retransmitted Connect Initiate
# depending on the subtype value.
class ConnInit (ConnMsg):
    _layout = (packet.Payload,)
    #subtype = NspHdr.CI
    #subtype = NspHdr.RCI
    dstaddr = 0
    classindexkeys = (0x18, 0x68)    # CI and retransmitted CI
    
# Connect Confirm is very similar to Connect Init (the differences are
# mainly in the session layer, which is just payload to us).
# However, the srcaddr is now non-zero.
class ConnConf (ConnMsg):
    _layout = (( tolerantI, "data_ctl", 16 ),)    # CC payload is an I field
    subtype = NspHdr.CC
    msgflag = 0x28
    
class DiscConf (NspHdr):
    _layout = (( packet.B, "dstaddr", 2 ),
               ( packet.B, "srcaddr", 2 ),
               ( packet.B, "reason", 2 ))
    type = NspHdr.CTL
    subtype = NspHdr.DC
    msgflag = 0x48

    # Three reason codes are treated as specific packets in the NSP spec;
    # all others are in effect synonyms for disconnect initiate for Phase II
    # compatibility.
    classindex = dict ()
    classindexkey = "reason"
    
    # Supply a dummy value in the object to allow common handling with
    # DiscInit, which does include a disconnect data field.
    data_ctl = b""

    @classmethod
    def defaultclass (cls, idx):
        return __class__

# Three reason codes are treated as specific packets in the NSP spec;
# all others are in effect synonyms for disconnect initiate for Phase II
# compatibility.  Define subclasses for the three here so we can use
# those later.
class NoRes (DiscConf):
    reason = 1

class DiscComp (DiscConf):
    reason = 42

class NoLink (DiscConf):
    reason = 41

# DI is like DC but it adds session control disconnect data
class DiscInit (NspHdr):
    _layout = (( packet.B, "dstaddr", 2 ),
               ( packet.B, "srcaddr", 2 ),
               ( packet.B, "reason", 2 ),
               ( tolerantI, "data_ctl", 16 ))
    type = NspHdr.CTL
    subtype = NspHdr.DI
    msgflag = 0x38
    
OBJ_FAIL = 38       # Object failed (copied from session.py)
UNREACH = 39        # Destination unreachable (copied from session.py)

# Mapping from packet type code (msgflg field) to packet class
msgmap = { (c.type << 2) + (c.subtype << 4) : c
           for c in ( AckData, AckOther, AckConn, ConnConf,
                      DiscConf, DiscInit, IntMsg, LinkSvcMsg ) }
# Put in Connect Init with its two msgflag values
msgmap[(NspHdr.CTL << 2) + (NspHdr.CI << 4)] = ConnInit
msgmap[(NspHdr.CTL << 2) + (NspHdr.RCI << 4)] = ConnInit
# For data segments we put in all 4 combinations of bom/eom flags so
# we can just do the message map without having to check for those cases
# separately.
for st in range (4):
    msgmap[NspHdr.DATA + (st << 5)] = DataSeg
# Put in an "ignore me" entry for NOP packets
msgmap[(NspHdr.CTL << 2) + (NspHdr.NOP << 4)] = None

# Mapping from reason to specific Disconnect Confirm subclass
dcmap = { c.reason : c for c in ( NoRes, DiscComp, NoLink ) }

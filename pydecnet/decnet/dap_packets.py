#!

"""Packet format definitions for DAP

Reference:

DECnet Digital Network Architecture
Data Access Protocol (DAP) functional specification
Version 5.6, 28-March-1980

Document no. HAL-78.001-03-S

Note that we claim DAP version 7.2.0, for which unfortunately no spec
appears to be available.  The main reason for doing this is to allow
VMS to transfer Stream_LF format files, a record format not defined in
5.6.0.  Some of the logic in the protocol code is guessword, derived
from reverse engineering of the protocol exchanges with other DECnet
implementations.
"""

import time

from .common import *
from . import packet

class DapVersion (Version):
    N = 5

DAPVERSION = DapVersion (7,0,0,0,0)
MYOSTYPE = 192
MYFILESYS = 13        # Ultrix FS, which seems a reasonable fit

DAPDEFAULT = bytes (128)

class IF (packet.FieldGroup):
    """A wrapper to make a field conditional on a flag preceding it in
    the packet layout.
    """
    @classmethod
    def encode (cls, msg, flag, ftype, fname, args):
        if getattr (msg, flag, 0):
            return msg.encode_row (ftype, fname, args)
        return b""

    @classmethod
    def decode (cls, buf, msg, flag, ftype, fname, args):
        if getattr (msg, flag, 0):
            buf = msg.decode_row (buf, ftype, fname, args)
        return buf

    @classmethod
    def makecoderow (cls, flag, cls2, *args):
        cls2, fname, args, names, wild = cls2.makecoderow (*args)
        ret = cls, None, (flag, cls2, fname, args), names, wild
        return ret

class IFELSE (IF):
    """Conditional field, but if the flag is not set parse the default
    string instead of not doing anything.
    """
    @classmethod
    def encode (cls, msg, flag, default, ftype, fname, args):
        return super (__class__, cls).encode (msg, flag, ftype, fname, args)
    
    @classmethod
    def decode (cls, buf, msg, flag, default, ftype, fname, args):
        if getattr (msg, flag, 0):
            buf = msg.decode_row (buf, ftype, fname, args)
        else:
            msg.decode_row (default, ftype, fname, args)
        return buf

    @classmethod
    def makecoderow (cls, flag, default, cls2, *args):
        cls2, fname, args, names, wild = cls2.makecoderow (*args)
        ret = cls, None, (flag, default, cls2, fname, args), names, wild
        return ret

class DEF (packet.FieldGroup):
    @classmethod
    def encode (cls, msg, defval, ftype, fname, args):
        return msg.encode_row (ftype, fname, args)

    @classmethod
    def decode (cls, buf, msg, defval, ftype, fname, args):
        if buf is DAPDEFAULT:
            buf = defval
        return msg.decode_row (buf, ftype, fname, args)

    @classmethod
    def makecoderow (cls, defval, cls2, *args):
        cls2, fname, args, names, wild = cls2.makecoderow (*args)
        ret = cls, None, (defval, cls2, fname, args), names, wild
        return ret
        
class BMEX (packet.BM):
    """Similar to the standard BM collection of bit fields, but the
    encoding of the underlying integer is EX-n rather than B-n.
    """
    @classmethod
    def valtobytes (cls, val, flen):
        val = packet.EX (val)
        return val.encode (flen)

    @classmethod
    def bytestoval (cls, buf, flen):
        return packet.EX.decode (buf, flen)

    @classmethod
    def makecoderow (cls, maxlen, *args):
        # The argument of BM is simply a sequence of fields; for BMEX it
        # is the EX-n max length followed by the fields.  Substitute
        # that value into the code row, replacing the calculated byte
        # count from the base class (which doesn't apply since we're
        # dealing with multiples of 7, not 8, bits here).
        x, x, fe, names, x = super (__class__, cls).makecoderow (*args)
        x, elements = fe
        return cls, None, (maxlen, elements), names, False

class I_int (Field, int):
    "An unsigned integer encoded in I-n form"
    __slots__ = ()

    def encode (self, maxlen):
        flen = (self.bit_length () + 7) // 8
        if flen > maxlen:
            logging.debug ("Value too long for {} byte field", maxlen)
            raise FieldOverflow
        return byte (flen) + self.to_bytes (flen, LE)

    @classmethod
    def decode (cls, buf, maxlen):
        require (buf, 1)
        flen = buf[0]
        if flen > maxlen:
            logging.debug ("Image field length {} longer than max length {}",
                           flen, maxlen)
            raise FieldOverflow
        v = buf[1:flen + 1]
        if len (v) != flen:
            logging.debug ("Not {} bytes left for image field", flen)
            raise MissingData
        return cls (int.from_bytes (v, LE)), buf[flen + 1:]

class AV (Field, str):
    "A fixed length text string"
    __slots__ = ()

    def encode (self, flen):
        retval = bytes (self, encoding = "latin1")
        l = len (retval)
        if l < flen:
            retval += bytes (flen - l)
        elif l > flen:
            logging.debug ("Value too long for {} byte field", flen)
            raise FieldOverflow
        return retval

    @classmethod
    def decode (cls, buf, flen):
        require (buf, flen)
        return cls (str (buf[:flen], encoding = "latin1")), buf[flen:]

    @classmethod
    def length (cls, flen):
        return flen

# Some comment layout parts
BM_FOP = (BMEX, 6,            # FOP
          ( "fb_rwo", 0, 1 ),
          ( "fb_rwc", 1, 1 ),
          ( "fb_pos", 3, 1 ),
          ( "fb_dlk", 4, 1 ),
          ( "fb_locked", 6, 1 ),
          ( "fb_ctg", 7, 1 ),
          ( "fb_sup", 8, 1 ),
          ( "fb_nef", 9, 1 ),
          ( "fb_tmp", 10, 1 ),
          ( "fb_mkd", 11, 1 ),
          ( "fb_dmo", 13, 1 ),
          ( "fb_wck", 14, 1 ),
          ( "fb_rck", 15, 1 ),
          ( "fb_cif", 16, 1 ),
          ( "fb_sqo", 18, 1 ),
          ( "fb_mxv", 19, 1 ),
          ( "fb_spl", 20, 1 ),
          ( "fb_scf", 21, 1 ),
          ( "fb_dlt", 22, 1 ),
          ( "fb_cbt", 23, 1 ),
          ( "fb_dwf", 25, 1 ),
          ( "fb_tef", 26, 1 ),
          ( "fb_opf", 27, 1 ))

class DapBase (packet.IndexedPacket):
    "Basic minimal header, just one byte"
    _layout = (( packet.B, "type", 1 ),)
    classindex = { }
    classindexkey = "type"

    @classmethod
    def decode (cls, buf):
        "Decode the packet data into this (newly constructed) object"
        # This is a modified version of the one in the IndexedPacket
        # base class.  There are two differences.  One is that DAP
        # packets may be truncated, with the omitted fields getting
        # "default" values (usually zero).  The other is that packets
        # can be "blocked" -- assembled more than one to a session
        # control message.  This is done with optional length fields in
        # the header.
        buf = makebytes (buf)
        # Find a suitable decode class via the index
        cls2 = cls.findclassb (buf)
        ret = cls2 ()
        msglen = len (buf)
        bufret = b""
        if msglen > 1:
            flags = buf[1]
            if flags:
                # We only allow these two values, the other bits are
                # unsupported.  Note that the "length" encoded in the
                # header is the length of what follows, not the full
                # length of the whole message.
                if flags == 2:
                    # LENGTH but not LEN256
                    require (buf, 3)
                    msglen = buf[2] + 3
                elif flags == 6:
                    # LENGTH and LEN256
                    require (buf, 4)
                    msglen = buf[2] + (buf[3] << 8) + 4
                bufret = buf[msglen:]
                buf = buf[:msglen]
                assert len (buf) == msglen
        ret.decoded_from = buf
        done = False
        for ftype, fname, args in ret._codetable:
            if done:
                buf = DAPDEFAULT
            buf = ret.decode_row (buf, ftype, fname, args)
            if not buf:
                done = True
        if not done:
            # We didn't parse all the data in the message
            print ("extra data", buf)#raise ExtraData
        return ret, bufret

    # The next two are lifted from inside the encode and decode loops in
    # packet.py.
    def encode_row (self, ftype, fname, args):
        if fname:
            # Simple field, get its value
            val = getattr (self, fname, None)
            # Check type and/or supply default
            val = ftype.checktype (fname, val)
            if val is not None:
                return val.encode (*args)
            return b""
        else:
            # Composite like TLV
            return ftype.encode (self, *args)
        
    def decode_row (self, buf, ftype, fname, args):
        if fname:
            try:
                val, buf = ftype.decode (buf, *args)
                setattr (self, fname, val)
            except Exception:
                raise packet.AtField (fname)
        else:
            buf = ftype.decode (buf, self, *args)
        return buf
        
class DapHeader (DapBase):
    "Header if packet is longer than one byte"
    _layout = (( BMEX, 5,            # FLAGS
                 ( "m_streamid", 0, 1 ),
                 ( "m_length", 1, 1 ),
                 ( "m_len256", 2, 1 ),
                 ( "m_bitcnt", 3, 1 ),
                 ( "m_syspec", 5, 1 ),
                 ( "m_seg", 6, 1 )),
               ( IF, "m_streamid", packet.B, "streamid", 1 ),
               ( IF, "m_length", packet.B, "length", 1 ),
               ( IF, "m_len256", packet.B, "len256", 1 ),
               ( IF, "m_bitcnt", packet.B, "bitcnt", 1 ))
    # We don't support these options
    m_syspec = 0
    m_seg = 0
    
class Config (DapHeader):
    _layout = (( packet.B, "bufsiz", 2 ),
               ( packet.B, "ostype", 1 ),
               ( packet.B, "filesys", 1 ),
               ( DapVersion, "version" ),
               ( BMEX, 12,                   # SYSCAP
                 ( "prealloc", 0, 1 ),
                 ( "fo_seq", 1, 1 ),
                 ( "fo_rel", 2, 1 ),
                 ( "seq_xfer", 5, 1 ),
                 ( "random_rec", 6, 1 ),
                 ( "random_blk", 7, 1 ),
                 ( "random_key", 8, 1 ),
                 ( "random_rfa", 10, 1 ),
                 ( "isam", 11, 1 ),
                 ( "mode_switch", 12, 1 ),
                 ( "append", 13, 1 ),
                 ( "submit", 14, 1 ),
                 ( "streams", 16, 1 ),
                 ( "blocking", 18, 1 ),
                 ( "unres_blocking", 19, 1 ),
                 ( "len2", 20, 1 ),
                 ( "cksum", 21, 1 ),
                 ( "key_xa", 22, 1 ),
                 ( "alloc_xa", 23, 1 ),
                 ( "sum_xa", 24, 1 ),
                 ( "dir", 25, 1 ),
                 ( "dattim_xa", 26, 1 ),
                 ( "fprot_xa", 27, 1 ),
                 ( "spool", 29, 1 ),
                 ( "submit_op", 30, 1 ),
                 ( "delete", 31, 1 ),
                 ( "seq_ra", 33, 1 ),
                 ( "bitcnt", 35, 1 ),
                 ( "warn", 36, 1 ),
                 ( "rename", 37, 1 ),
                 ( "glob", 38, 1 ),
                 ( "name", 40, 1 ),
                 ( "seg", 41, 1 ),
                 # DAP V7 options:
                 ( "close_att", 42, 1 ),
                 ( "close_tim", 43, 1 ),
                 ( "close_pro", 44, 1 ),
                 ( "close_nam", 45, 1 ),
                 ( "cre_retattr", 46, 1 ),
                 ( "name3", 47, 1 ),
                 ( "rename_att", 48, 1 ),
                 ( "rename_tim", 49, 1 ),
                 ( "rename_pro", 50, 1 ),
                 ( "blkcnt", 51, 1 ),
                 ( "octal_versions", 52, 1 )))
    type = 1

class Attrib (DapHeader):
    _layout = (( BMEX, 6,            # ATTMENU
                 # Names here are prefixed by m_ to avoid conflict
                 # with value attributes later on.
                 ( "m_datatype", 0, 1 ),
                 ( "m_org", 1, 1 ),
                 ( "m_rfm", 2, 1 ),
                 ( "m_rat", 3, 1 ),
                 ( "m_bls", 4, 1 ),
                 ( "m_mrs", 5, 1 ),
                 ( "m_alq", 6, 1 ),
                 ( "m_bks", 7, 1 ),
                 ( "m_fsz", 8, 1 ),
                 ( "m_mrn", 9, 1 ),
                 ( "m_runsys", 10, 1 ),
                 ( "m_deq", 11, 1 ),
                 ( "m_fop", 12, 1 ),
                 ( "m_bsz", 13, 1 ),
                 ( "m_dev", 14, 1 ),
                 ( "m_lrl", 16, 1 ),
                 ( "m_hbk", 17, 1 ),
                 ( "m_ebk", 18, 1 ),
                 ( "m_ffb", 19, 1 ),
                 ( "m_sbn", 20, 1 )),
               ( IFELSE, "m_datatype", b"\x02", BMEX, 2,        # DATATYPE
                 ( "ascii", 0, 1 ),
                 ( "image", 1, 1 ),        # This is the default
                 ( "compressed", 3, 1 ),
                 ( "executable", 4, 1 ),
                 ( "privileged", 5, 1 ),
                 ( "sensitive", 7, 1 )),
               ( IF, "m_org", packet.B, "org", 1 ),
               ( IFELSE, "m_rfm", b"\x01", packet.B, "rfm", 1 ),
               ( IF, "m_rat", BMEX, 3,            # RAT
                 ( "fb_ftn", 0, 1 ),
                 ( "fb_cr",  1, 1 ),
                 ( "fb_prn", 2, 1 ),
                 ( "fb_blk", 3, 1 ),
                 ( "fb_emb", 4, 1 ),
                 ( "fb_lsa", 6, 1 ),
                 ( "fb_macy11", 7, 1 )),
               # default for BLS is 512
               ( IFELSE, "m_bls", b"\x00\x02", packet.B, "bls", 2 ),
               ( IF, "m_mrs", packet.B, "mrs", 2 ),
               ( IF, "m_alq", I_int, "alq", 5 ),
               ( IF, "m_bks", packet.B, "bks", 1 ),
               ( IF, "m_fsz", packet.B, "fsz", 1 ),
               ( IF, "m_mrn", I_int, "mrn", 5 ),
               ( IF, "m_runsys", packet.A, "runsys", 40 ),
               ( IF, "m_deq", packet.B, "deq", 2 ),
               ( IF, "m_fop") + BM_FOP,
               # Default for BSZ is 8
               ( IFELSE, "m_bsz", b"\x08", packet.B, "bsz", 1 ),
               ( IF, "m_dev", BMEX, 6,            # DEV
                 ( "fb_rec", 0, 1 ),
                 ( "fb_ccl", 1, 1 ),
                 ( "fb_trm", 2, 1 ),
                 ( "fb_mdi", 3, 1 ),
                 ( "fb_sdi", 4, 1 ),
                 ( "fb_sqd", 5, 1 ),
                 ( "fb_null", 6, 1 ),
                 ( "fb_fod", 7, 1 ),
                 ( "fb_share", 8, 1 ),
                 ( "fb_spl", 9, 1 ),
                 ( "fb_mnt", 10, 1 ),
                 ( "fb_dmt", 11, 1 ),
                 ( "fb_all", 12, 1 ),
                 ( "fb_idv", 13, 1 ),
                 ( "fb_odv", 14, 1 ),
                 ( "fb_swl", 15, 1 ),
                 ( "fb_avl", 16, 1 ),
                 ( "fb_elg", 17, 1 ),
                 ( "fb_mbx", 18, 1 ),
                 ( "fb_rtm", 19, 1 ),
                 ( "fb_rad", 20, 1 ),
                 ( "fb_rdchk", 21, 1 ),
                 ( "fb_wrchk", 22, 1 ),
                 ( "fb_foreign", 23, 1 ),
                 ( "fb_network", 24, 1 ),
                 ( "fb_generic", 25, 1 )),
               ( IF, "m_lrl", packet.B, "lrl", 2 ),
               ( IF, "m_hbk", I_int, "hbk", 5 ),
               ( IF, "m_ebk", I_int, "ebk", 5 ),
               ( IF, "m_ffb", packet.B, "ffb", 2 ),
               ( IF, "m_sbn", I_int, "sbn", 5 ))
    type = 2
    # values of org field
    fb_seq = 0
    fb_rel = 0o20
    fb_idx = 0o40
    # values of rfm field
    fb_udf = 0
    fb_fix = 1        # (default)
    fb_var = 2
    fb_vfc = 3
    fb_stm = 4
    fb_slf = 5        # Stream_LF (DAP 7)
    fb_scr = 6        # Stream_CR (DAP 7)
    
class Access (DapHeader):
    _layout = (( packet.B, "accfunc", 1 ),
               ( BMEX, 5,            # ACCOPT
                 ( "err_nonfatal", 0, 1 ),
                 ( "checksum", 3, 1 ),
                 ( "go_nogo", 4, 1 )),
               ( packet.A, "filespec", 255 ),
               ( DEF, b"\x02", BMEX, 3,            # FAC
                 ( "fb_put", 0, 1 ),
                 ( "fb_get", 1, 1 ),        # default
                 ( "fb_del", 2, 1 ),
                 ( "fb_upd", 3, 1 ),
                 ( "fb_trn", 4, 1 ),
                 ( "fb_bio", 5, 1 ),
                 ( "fb_bro", 6, 1 )),
               ( DEF, b"\x02", BMEX, 3,            # SHR
                 ( "shr_fb_put", 0, 1 ),
                 ( "shr_fb_get", 1, 1 ),        # default
                 ( "shr_fb_del", 2, 1 ),
                 ( "shr_fb_upd", 3, 1 ),
                 ( "fb_mse", 4, 1 ),
                 ( "fb_upi", 5, 1 ),
                 ( "shr_fb_nil", 6, 1 )),
               ( BMEX, 4,            # DISPLAY
                 ( "main", 0, 1 ),
                 ( "keydef", 1, 1 ),
                 ( "alloc", 2, 1 ),
                 ( "summary", 3, 1 ),
                 ( "date", 4, 1 ),
                 ( "fprot", 5, 1 ),
                 ( "name", 8, 1 ),
                 # DAP V7
                 ( "name3", 9, 1 )),
               ) #( packet.A, "password", 40 ))
    type = 3
    # opcodes in ACCFUNC:
    OPEN = 1
    CREATE = 2
    RENAME = 3
    ERASE = 4
    DIR = 6
    SUBMIT = 7
    EXECUTE = 8

class Control (DapHeader):
    _layout = (( DEF, b"\x01", packet.B, "ctlfunc", 1 ),
               ( BMEX, 4,            # CTLMENU
                 ( "m_rac", 0, 1 ),
                 ( "m_key", 1, 1 ),
                 ( "m_krf", 2, 1 ),
                 ( "m_rop", 3, 1 )),
               ( IF, "m_rac", packet.B, "rac", 1 ),
               ( IF, "m_key", packet.I, "key", 255 ),
               ( IF, "m_krf", packet.B, "krf", 1 ),
               ( IF, "m_rop", BMEX, 6,            # ROP
                 ( "rb_eof", 0, 1 ),
                 ( "rb_fdl", 1, 1 ),
                 ( "rb_uif", 2, 1 ),
                 ( "rb_loa", 4, 1 ),
                 ( "rb_ulk", 5, 1 ),
                 ( "rb_tpt", 6, 1 ),
                 ( "rb_rah", 7, 1 ),
                 ( "rb_wbh", 8, 1 ),
                 ( "rb_kge", 9, 1 ),
                 ( "rb_kgt", 10, 1 ),
                 ( "rb_nlk", 11, 1 ),
                 ( "rb_rlk", 12, 1 ),
                 ( "rb_bio", 13, 1 )))
    type = 4
    # opcodes in CTLFUNC:
    GET = 1
    CONNECT = 2
    UPDATE = 3
    PUT = 4
    DELETE = 5
    REWIND = 6
    TRUNCATE = 7
    FREE = 10
    FLUSH = 12
    FIND = 14
    SPACE_FORWARD = 17
    SPACE_BACKWARD = 18
    # RAC values:
    RB_SEQ = 0    # sequential record access.
    RB_KEY = 1    # keyed access.
    RB_RFA = 2    # Access by Record  File  Address
    RB_SEQF = 3   # sequential file access
    RB_BLK = 4    # block mode record access
    RB_BLKF = 5   # block mode file  transfer.

class Continue (DapHeader):
    _layout = (( packet.B, "confunc", 1 ),)
    type = 5
    # opcodes in CONFUNC:
    TRYAGAIN = 1
    SKIP = 2
    ABORT = 3
    RESUME = 4
    
class Ack (DapHeader):
    type = 6

class AccComplete (DapHeader):
    _layout = (( packet.B, "cmpfunc", 1 ),
               BM_FOP,
               ( packet.B, "check", 2 ))
    type = 7
    # Completion functions in CMPFUNC:
    CLOSE = 1
    RESPONSE = 2
    PURGE = 3
    EOS = 4
    SKIP = 5

class Data (DapHeader):
    _layout = (( I_int, "recnum", 8 ),
               ( DEF, b"", packet.PAYLOAD, "payload" ))
    type = 8
    
class Status (DapHeader):
    _layout = (( packet.BM,
                 ( "miccode", 0, 12 ),
                 ( "maccode", 12, 4 )),
               # Payload is here to absorb whatever extra stuff might
               # get sent to us.
               ( DEF, b"", packet.PAYLOAD, "payload" ))
    type = 9
    # MACCODE values:
    maccodes = {
        0o00 : "Pending",
        0o01 : "Success",
        0o02 : "Unsupported",
        0o04 : "Open error",
        0o05 : "Transfer error",
        0o06 : "Transfer warning",
        0o07 : "Close error",
        0o10 : "Message format error",
        0o11 : "Invalid field",
        0o12 : "Out of sync" }
    # MICCODE values for MACCODE 2, 8, 9.  Keys in octal, the spec gives
    # them in two two-digit parts but they are encoded as a single 12
    # bit value.
    miccodes_289 = {
        0o0000 : "Unspecified DAP message error.",
        0o0010 : "DAP message type field (TYPE) error.",
        0o0100 : "Unknown field.",
        0o0110 : "DAP message flags field (FLAGS).",
        0o0111 : "Data stream identification field (STREAMID).",
        0o0112 : "Length field (LENGTH).",
        0o0113 : "Length extension field (LEN256).",
        0o0114 : "BITCNT field (BITCNT).",
        0o0120 : "Buffer size field (BUFSIZ).",
        0o0121 : "Operating system type field (OSTYPE).",
        0o0122 : "File system type field (FILESYS).",
        0o0123 : "DAP version number field (VERNUM).",
        0o0124 : "ECO version number field (ECONUM).",
        0o0125 : "USER protocol version number field (USRNUM).",
        0o0126 : "DEC software release number field (SOFTVER).",
        0o0127 : "User software release number field (USRSOFT).",
        0o0130 : "System capabilities field (SYSCAP).",
        0o0200 : "Unknown field.",
        0o0210 : "DAP message flags field (FLAGS).",
        0o0211 : "Data stream identification field (STREAMID).",
        0o0212 : "Length field (LENGTH).",
        0o0213 : "Length extension field (LEN 256).",
        0o0214 : "Bit count field (BITCNT).",
        0o0215 : "System specific field (SYSPEC).",
        0o0220 : "Attributes menu field (ATTMENU).",
        0o0221 : "Data type field (DATATYPE).",
        0o0222 : "File organization field (ORG).",
        0o0223 : "Record format field (RFM).",
        0o0224 : "Record attributes field (RAT).",
        0o0225 : "Block size field (BLS).",
        0o0226 : "Maximum record size field (MRS).",
        0o0227 : "Allocation quantity field (ALQ).",
        0o0230 : "Bucket size field (BKS).",
        0o0231 : "Fixed control area size field (FSZ).",
        0o0232 : "Maximum record number field (MRN).",
        0o0233 : "Run-time system field (RUNSYS).",
        0o0234 : "Default extension quantity field (DEQ).",
        0o0235 : "File options field (FOP).",
        0o0236 : "Byte size field (BSZ).",
        0o0237 : "Device characteristics field (DEV).",
        0o0240 : "Spooling device characteristics field (SDC).",
        0o0241 : "Longest record length field (LRL).",
        0o0242 : "Highest virtual block allocated field (HBK).",
        0o0243 : "End of file block field (EBK).",
        0o0244 : "First free byte field (FFB).",
        0o0245 : "Starting LBN for contiguous file (SBN).",
        0o0300 : "Unknown field.",
        0o0310 : "DAP message flags field (FLAGS).",
        0o0311 : "Data stream identification field (STREAMID).",
        0o0312 : "Length field (LENGTH).",
        0o0313 : "Length extension field (LEN256).",
        0o0314 : "Bit count field (BITCNT).",
        0o0315 : "System specific field (SYSPEC). .",
        0o0320 : "Access function field (ACCFUNC).",
        0o0321 : "Access options field (ACCOPT).",
        0o0322 : "File specification field (FILESPEC).",
        0o0323 : "File access field (FAC).",
        0o0324 : "File sharing field (SHR).",
        0o0325 : "Display attributes request field (DISPLAY).",
        0o0326 : "File password field (PASSWORD).",
        0o0400 : "Unknown field.",
        0o0410 : "DAP message flags field (FLAGS).",
        0o0411 : "Data stream identification field (STREAMID).",
        0o0412 : "Length field (LENGTH).",
        0o0413 : "Length extension field (LEN256).",
        0o0414 : "Bit count field (BITCNT).",
        0o0415 : "System specific field (SYSPEC). .",
        0o0420 : "Control function field (CTLFUNC).",
        0o0421 : "Control menu field (CTLMENU).",
        0o0422 : "Record access field (RAC).",
        0o0423 : "Key field (KEY).",
        0o0424 : "Key of reference field (KRF).",
        0o0425 : "Record options field (ROP).",
        0o0426 : "Hash code field (HSH).",
        0o0427 : "Display attributes request field (DISPLAY).",
        0o0500 : "Unknown field.",
        0o0510 : "DAP message flags field (FLAGS).",
        0o0511 : "Data stream identification field (STREAMID).",
        0o0512 : "Length field (LENGTH).",
        0o0513 : "Length extension field (LEN256).",
        0o0514 : "Bit count field (BITCNT).",
        0o0515 : "System specific field (SYSPEC).",
        0o0520 : "Continue transfer function field (CONFUNC).",
        0o0600 : "Unknown field.",
        0o0610 : "DAP message flags field (FLAGS).",
        0o0611 : "Data stream identification field (STREAMID).",
        0o0612 : "Length field (LENGTH).",
        0o0613 : "Length extension field (LEN256).",
        0o0614 : "Bit count field (BITCNT).",
        0o0615 : "System specific field (SYSPEC).",
        0o0700 : "Unknown field.",
        0o0710 : "DAP message flags field (FLAGS).",
        0o0711 : "Data stream identification field (STREAMID).",
        0o0712 : "Length field (LENGTH).",
        0o0713 : "Length extension field (LEN256).",
        0o0714 : "Bit count field (BITCNT).",
        0o0715 : "System specific field (SYSPEC).",
        0o0720 : "Access complete function field (CMPFUNC).",
        0o0721 : "File options field (FOP).",
        0o0722 : "Checksum field (CHECK).",
        0o1000 : "Unknown field.",
        0o1010 : "DAP message flags field (FLAGS).",
        0o1011 : "Data stream identification field (STREAMID).",
        0o1012 : "Length field (LENGTH).",
        0o1013 : "Length extension field (LEN256).",
        0o1014 : "Bit count field (BITCNT).",
        0o1015 : "System specific field (SYSPEC).",
        0o1020 : "Record number field (RECNUM).",
        0o1021 : "File data field (FILEDATA).",
        0o1100 : "Unknown field.",
        0o1110 : "DAP message flags field (FLAGS).",
        0o1111 : "Data stream identification field (STREAMID).",
        0o1112 : "Length field (LENGTH).",
        0o1113 : "Length extension field (LEN256).",
        0o1114 : "Bit count field (BITCNT).",
        0o1115 : "System specific field (SYSPEC).",
        0o1120 : "Macro status code field (MACCODE).",
        0o1121 : "Micro status code field (MICCODE).",
        0o1122 : "Record file address field (RFA).",
        0o1123 : "Record number field (RECNUM).",
        0o1124 : "Secondary status field (STV).",
        0o1200 : "Unknown field.",
        0o1210 : "DAP message flags field (FLAGS).",
        0o1211 : "Data stream identification field (STREAMID).",
        0o1212 : "Length field (LENGTH).",
        0o1213 : "Length extension field (LEN256).",
        0o1214 : "Bit count field (BITCNT).",
        0o1215 : "System specific field (SYSPEC).",
        0o1220 : "Key definition menu field (KEYMENU).",
        0o1221 : "Key option flags field (FLG).",
        0o1222 : "Data bucket fill quantity field (DFL).",
        0o1223 : "Index bucket fill quantity field (IFL).",
        0o1224 : "Key segment repeat count field (SEGCNT).",
        0o1225 : "Key segment position field (POS).",
        0o1226 : "Key segment size field (SIZ).",
        0o1227 : "Key of reference field (REF).",
        0o1230 : "Key name field (KNM).",
        0o1231 : "Null key character field (NUL).",
        0o1232 : "Index area number field (IAN).",
        0o1233 : "Lowest level area number field (LAN).",
        0o1234 : "Data level area number field (DAN).",
        0o1235 : "Key data type field (DTP).",
        0o1236 : "Root VBN for this key field (RVB).",
        0o1237 : "Hash algorithm value field (HAL).",
        0o1240 : "First data bucket VBN field (DVB).",
        0o1241 : "Data bucket size field (DBS).",
        0o1242 : "Index bucket size field (IBS).",
        0o1243 : "Level of root bucket field (LVL).",
        0o1244 : "Total key size field (TKS).",
        0o1245 : "Minimum record size field (MRL).",
        0o1300 : "Unknown field.",
        0o1310 : "DAP message flags field (FLAGS).",
        0o1311 : "Data stream identification field (STREAMID).",
        0o1312 : "Length field (LENGTH).",
        0o1313 : "Length extension field (LEN256).",
        0o1314 : "Bit count field (BITCNT).",
        0o1315 : "System specific field (SYSPEC).",
        0o1320 : "Allocation menu field (ALLMENU).",
        0o1321 : "Relative volume number field (VOL).",
        0o1322 : "Alignment options field (ALN).",
        0o1323 : "Allocation options field (AOP).",
        0o1324 : "Starting location field (LOC).",
        0o1325 : "Related file identification field (RFI).",
        0o1326 : "Allocation quantity field (ALQ).",
        0o1327 : "Area identification field (AID).",
        0o1330 : "Bucket size field (BKZ).",
        0o1331 : "Default extension quantity field (DEQ).",
        0o1400 : "Unknown field.",
        0o1410 : "DAP message flags field (FLAGS).",
        0o1411 : "Data stream identification field (STREAMID).",
        0o1412 : "Length field (LENGTH).",
        0o1413 : "Length extension field (LEN256).",
        0o1414 : "Bit count field (BITCNT).",
        0o1415 : "System specific field (SYSPEC).",
        0o1420 : "Summary menu field (SUMENU).",
        0o1421 : "Number of keys field (NOK).",
        0o1422 : "Number of areas field (NOA).",
        0o1423 : "Number of record descriptors field (NOR).",
        0o1424 : "Prologue version number (PVN).",
        0o1500 : "Unknown field.",
        0o1510 : "DAP message flags field (FLAGS).",
        0o1511 : "Data stream identification field (STREAMID).",
        0o1512 : "Length field (LENGTH).",
        0o1513 : "Length extension field (LEN256).",
        0o1514 : "Bit count field (BITCNT).",
        0o1515 : "System specific field (SYSPEC).",
        0o1520 : "Date and time menu field (DATMENU).",
        0o1521 : "Creation date and time field (CDT).",
        0o1522 : "Last update date and time field (RDT).",
        0o1523 : "Deletion date and time field (EDT).",
        0o1524 : "Revision number field (RVN).",
        0o1600 : "Unknown field.",
        0o1610 : "DAP message flags field (FLAGS).",
        0o1611 : "Data stream identification field (STREAMID).",
        0o1612 : "Length field (LENGTH).",
        0o1613 : "Length extension field (LEN256).",
        0o1614 : "Bit count field (BITCNT).",
        0o1615 : "System specific field (SYSPEC).",
        0o1620 : "Protection menu field (PROTMENU).",
        0o1621 : "File owner field (OWNER).",
        0o1622 : "System protection field (PROTSYS).",
        0o1623 : "Owner protection field (PROTOWN).",
        0o1624 : "Group protection field (PROTGRP).",
        0o1625 : "World protection field (PROTWLD).",
        0o1700 : "Unknown field.",
        0o1710 : "DAP message flags field (FLAGS).",
        0o1711 : "Data stream identification field (STREAMID).",
        0o1712 : "Length field (LENGTH).",
        0o1713 : "Length extension field (LEN256).",
        0o1714 : "Bit count field (BITCNT).",
        0o1715 : "System specific field (SYSPEC).",
        0o1720 : "Name type field (NAMETYPE).",
        0o1721 : "Name field (NAMESPEC).",
        0o2000 : "Unknown field.",
        0o2010 : "DAP message flags field (FLAGS).",
        0o2011 : "Data stream identification field (STREAMID).",
        0o2012 : "Length field (LENGTH).",
        0o2013 : "Length extension field (LEN256).",
        0o2014 : "Bit count field (BITCNT).",
        0o2015 : "System specific field (SYSPEC).",
        0o2020 : "Access control list repeat count field (ACLCNT).",
        0o2021 : "Access control list entry field (ACL)."
    }
    # MICCODE values for MACCODE 0, 1, 4, 5, 6, 7.
    miccodes_rms = {
        0o0 : "Unspecified error.",
        0o1 : "operation aborted.",
        0o2 : "F11-ACP could not access file.",
        0o3 : '"FILE" activity precludes operation.',
        0o4 : "bad area ID.",
        0o5 : "alignment options error.",
        0o6 : "allocation quantity too large or 0 value.",
        0o7 : 'not ANSI "D" format.',
        0o10 : "allocation options error.",
        0o11 : "invalid (i.e., synch) operation at AST level.",
        0o12 : "attribute read error.",
        0o13 : "attribute write error.",
        0o14 : "bucket size too large.",
        0o15 : "bucket size too large.",
        0o16 : '"BLN" length error.',
        0o17 : "beginning of file detected.",
        0o20 : "private pool address.",
        0o21 : "private pool size.",
        0o22 : "internal RMS error condition detected.",
        0o23 : "cannot connect RAB.",
        0o24 : "$UPDATE changed a key without having attribute of XB$CHG set.",
        0o25 : "bucket format check-byte failure.",
        0o26 : "RSTS/E close function failed.",
        0o27 : 'invalid or unsupported "COD" field.',
        0o30 : "F11-ACP could not create file (STV=sys err code).",
        0o31 : "no current record (operation not preceded by GET/FIND).",
        0o32 : 'F11-ACP deaccess error during "CLOSE".',
        0o33 : 'data "AREA" number invalid.',
        0o34 : "RFA-Accessed record was deleted.",
        0o35 : "bad device, or inappropriate device type.",
        0o36 : "error in directory name.",
        0o37 : "dynamic memory exhausted.",
        0o40 : "directory not found.",
        0o41 : "device not ready.",
        0o42 : "device has positioning error.",
        0o43 : '"DTP" field invalid.',
        0o44 : "duplicate key detected, XB$DUP not set.",
        0o45 : "RSX-F11ACP enter function failed.",
        0o46 : 'operation not selected in "ORG$" macro.',
        0o47 : "end-of-file.",
        0o50 : "expanded string area too short.",
        0o51 : "file expiration date not yet reached.",
        0o52 : "file extend failure.",
        0o53 : 'not a valid FAB ("BID" NOT = FB$BID).',
        0o54 : 'illegal FAC for REC-OP,0, or FB$PUT not set for "CREATE".',
        0o55 : "file already exists.",
        0o56 : "invalid file I.D.",
        0o57 : "invalid flag-bits combination.",
        0o60 : "file is locked by other user.",
        0o61 : 'RSX-F11ACP "FIND" function failed.',
        0o62 : "file not found.",
        0o63 : "error in file name.",
        0o64 : "invalid file options.",
        0o65 : "DEVICE/FILE full.",
        0o66 : 'index "AREA" number invalid.',
        0o67 : "invalid IFI value or unopened file.",
        0o70 : "maximum NUM(254) areas/key XABS exceeded.",
        0o71 : "$INIT macro never issued.",
        0o72 : "operation illegal or invalid for file organization.",
        0o73 : "illegal record encountered (with sequential files only).",
        0o74 : "invalid ISI value, on unconnected RAB.",
        0o75 : "bad KEY buffer address (KBF=0).",
        0o76 : "invalid KEY field (KEY=0/neg).",
        0o77 : "invalid key-of-reference ($GET/$FIND).",
        0o100 : "KEY size too large.",
        0o101 : 'lowest-level-index "AREA" number invalid.',
        0o102 : "not ANSI labeled tape.",
        0o103 : "logical channel busy.",
        0o104 : "logical channel number too large.",
        0o105 : "logical extend error, prior extend still valid.",
        0o106 : '"LOC" field invalid.',
        0o107 : "buffer mapping error.",
        0o110 : "F11-ACP could not mark file for deletion.",
        0o111 : "MRN value=neg or relative key>MRN.",
        0o112 : "MRS value=0 for fixed length records. Also 0 for relative files.",
        0o113 : '"NAM" block address invalid (NAM=0, or not accessible).',
        0o114 : "not positioned to EOF (sequential files only).",
        0o115 : "cannot allocate internal index descriptor.",
        0o116 : "indexed no primary key defined.",
        0o117 : "RSTS/E open function failed.",
        0o120 : "XAB'S not in correct order.",
        0o121 : "invalid file organization value.",
        0o122 : "error in file's prologue (reconstruct file).",
        0o123 : '"POS" field invalid (POS>MRS,STV=XAB indicator).',
        0o124 : "bad file date field retrieved.",
        0o125 : "privilege violation (OS denies access).",
        0o126 : 'not a valid RAB ("BID" NOT=RB$BID).',
        0o127 : "illegal RAC value.",
        0o130 : "illegal record attributes.",
        0o131 : 'invalid record buffer address ("ODD", or not word-aligned if BLK-IO).',
        0o132 : "file read error.",
        0o133 : "record already exists.",
        0o134 : "bad RFA value (RFA=0).",
        0o135 : "invalid record format.",
        0o136 : "target bucket locked by another stream.",
        0o137 : "RSX-F11 ACP remove function failed.",
        0o140 : "record not found.",
        0o141 : "record not locked.",
        0o142 : "invalid record options.",
        0o143 : "error while reading prologue.",
        0o144 : "invalid RRV record encountered.",
        0o145 : "RAB stream currently active.",
        0o146 : "bad record size (RSZ>MRS, or NOT=MRS if fixed length records).",
        0o147 : "record too big for user's buffer.",
        0o150 : "primary key out of sequence (RAC=RB$SEQ for $PUT).",
        0o151 : '"SHR" field invalid for file (cannot share sequential files).',
        0o152 : '"SIZ field invalid.',
        0o153 : "stack too big for save area.",
        0o154 : "system directive error.",
        0o155 : "index tree error.",
        0o156 : "error in file type extension on FNS too big.",
        0o157 : "invalid user buffer addr (0, odd, or if BLK-IO not word aligned).",
        0o160 : "invalid user buffer size (USZ=0).",
        0o161 : "error in version number.",
        0o162 : "invalid volume number.",
        0o163 : "file write error (STV=sys err code).",
        0o164 : "device is write locked.",
        0o165 : "error while writing prologue.",
        0o166 : "not a valid XAB (@XAB=ODD,STV=XAB indicator).",
        0o167 : "default directory invalid.",
        0o170 : "cannot access argument list.",
        0o171 : "cannot close file.",
        0o172 : "cannot deliver AST.",
        0o173 : "channel assignment failure (STV=sys err code).",
        0o174 : "terminal output ignored due to (CNTRL) O.",
        0o175 : "terminal input aborted due to (CNTRL) Y.",
        0o176 : "default filename string address error.",
        0o177 : "invalid device I.D. field.",
        0o200 : "expanded string address error.",
        0o201 : "filename string address error.",
        0o202 : "FSZ field invalid.",
        0o203 : "invalid argument list.",
        0o204 : "known file found.",
        0o205 : "logical name error.",
        0o206 : "node name error.",
        0o207 : "operation successful.",
        0o210 : "record inserted had duplicate key.",
        0o211 : "index update error occurred-record inserted.",
        0o212 : "record locked but read anyway.",
        0o213 : "record inserted in primary o.k.; may not be accessible by secondary keys or RFA.",
        0o214 : "file was created, but not opened.",
        0o215 : "bad prompt buffer address.",
        0o216 : "async. operation pending completion.",
        0o217 : "quoted string error.",
        0o220 : "record header buffer invalid.",
        0o221 : "invalid related file.",
        0o222 : "invalid resultant string size.",
        0o223 : "invalid resultant string address.",
        0o224 : "operation not sequential.",
        0o225 : "operation successful.",
        0o226 : "created file superseded existing version.",
        0o227 : "filename syntax error.",
        0o230 : "time-out period expired.",
        0o231 : "FB$BLK record attribute not supported.",
        0o232 : "bad byte size.",
        0o233 : "cannot disconnect RAB.",
        0o234 : "cannot get JFN for file.",
        0o235 : "cannot open file.",
        0o236 : "bad JFN value.",
        0o237 : "cannot position to end-of-file.",
        0o240 : "cannot truncate file.",
        0o241 : "file is currently in an undefined access is denied.",
        0o242 : "file must be opened for exclusive access.",
        0o243 : "directory full.",
        0o244 : "handler not in system.",
        0o245 : "fatal hardware error.",
        0o246 : "attempt to write beyond EOF.",
        0o247 : "hardware option not present.",
        0o250 : "device not attached.",
        0o251 : "device already attached.",
        0o252 : "device not attachable.",
        0o253 : "sharable resource in use.",
        0o254 : "illegal overlay request.",
        0o255 : "block check or CRC error.",
        0o256 : "caller's nodes exhausted.",
        0o257 : "index file full.",
        0o260 : "file header full.",
        0o261 : "accessed for write.",
        0o262 : "file header checksum failure.",
        0o263 : "attribute control list error.",
        0o264 : "file already accessed on LUN.",
        0o265 : "bad tape format.",
        0o266 : "illegal operation on file descriptor block.",
        0o267 : "rename; 2 different devices.",
        0o270 : "rename; new filename already in use.",
        0o271 : "cannot rename old file system.",
        0o272 : "file already open.",
        0o273 : "parity error on device.",
        0o274 : "end of volume detected.",
        0o275 : "data over-run.",
        0o276 : "bad block on device.",
        0o277 : "end of tape detected.",
        0o300 : "no buffer space for file.",
        0o301 : "file exceeds allocated space -- no blks.",
        0o302 : "specified task not installed.",
        0o303 : "unlock error.",
        0o304 : "no file accessed on LUN.",
        0o305 : "send/receive failure.",
        0o306 : "spool or submit command file failure.",
        0o307 : "no more files.",
        0o310 : "DAP file transfer Checksum error.",
        0o311 : "Quota exceeded",
        0o312 : "internal network error condition detected.",
        0o313 : "terminal input aborted due to (CNTRL) C.",
        0o314 : "data bucket fill size > bucket size in XAB.",
        0o315 : "invalid expanded string length.",
        0o316 : "illegal bucket format.",
        0o317 : "bucket size of LAN NOT = IAN in XAB.",
        0o320 : "index not initialized.",
        0o321 : "illegal file attributes (corrupt file header).",
        0o322 : "index bucket fill size > bucket size in XAB.",
        0o323 : "key name buffer not readable or writeable in XAB.",
        0o324 : "index bucket will not hold two keys for key of reference.",
        0o325 : "multi-buffer count invalid (negative value).",
        0o326 : "network operation failed at remote node.",
        0o327 : "record is already locked.",
        0o330 : "deleted record successfully accessed.",
        0o331 : "retrieved record exceeds specified key value.",
        0o332 : "key XAB not filled in.",
        0o333 : "nonexistent record successfully accessed.",
        0o334 : "unsupported prologue version.",
        0o335 : "illegal key-of-reference in XAB.",
        0o336 : "invalid resultant string length.",
        0o337 : "error updating rrv's, some paths to data may be lost.",
        0o340 : "data types other than string limited to one segment in XAB.",
        0o341 : "reserved",
        0o342 : "operation not supported over network.",
        0o343 : "error on write behind.",
        0o344 : "invalid wildcard operation.",
        0o345 : "working set full (can not lock buffers in working set.)",
        0o346 : "directory listing -- error in reading volume-set name, directory name, of file name.",
        0o347 : "directory listing -- error in reading file attributes.",
        0o350 : "directory listing -- protection violation in trying to read the volume-set, directory or file name.",
        0o351 : "directory listing -- protection violation in trying to read file attributes.",
        0o352 : "directory listing -- file attributes do not exist.",
        0o353 : "directory listing -- unable to recover directory list after Continue Transfer (Skip).",
        0o354 : "sharing not enabled.",
        0o355 : "sharing page count exceeded.",
        0o356 : "UPI bit not set when sharing with BRO set.",
        0o357 : "error in access control string (poor man's route through error).",
        0o360 : "terminator not seen.",
        0o361 : "bad escape sequence.",
        0o362 : "partial escape sequence.",
        0o363 : "invalid wildcard context value.",
        0o364 : "invalid directory rename operation.",
        0o365 : "user structure (FAB/RAB) became invalid during operation.",
        0o366 : "network file transfer made precludes operation. "
    }
    # MICCODE values for MACCODE 10:
    miccodes_10 = {
        0o0 : "Unknown Message Type",
        0o1 : "Configuration Message",
        0o2 : "Attributes Message",
        0o3 : "Access Message",
        0o4 : "Control Message",
        0o5 : "Continue Transfer Message",
        0o6 : "Acknowledge Message",
        0o7 : "Access Complete Message",
        0o10 : "Data Message",
        0o11 : "Status Message",
        0o12 : "Key Definition Attributes Extension Message",
        0o13 : "Allocation Attributes Extension Message",
        0o14 : "Summary Attributes Extension Message",
        0o15 : "Date and Time Attributes Extension Message",
        0o16 : "Protection Attributes Extension Message",
        0o17 : "Name message",
        0o20 : "Access Control List Extended Attributes Message"
    }
    def __str__ (self):
        mac = self.maccode
        try:
            macstr = self.maccodes[mac]
            try:
                if mac in (2, 8, 9):
                    micstr = self.miccodes_289[self.miccode]
                elif mac in (0, 1, 4, 5, 6, 7):
                    micstr = self.miccodes_rms[self.miccode]
                elif mac == 10:
                    micstr = self.miccodes_10[self.miccode]
                else:
                    micstr = ""
            except KeyError:
                micstr = "Unexpected MICCODE {:0>4o}".format (self.miccode)
        except KeyError:
            macstr = "Unexpected MACCODE {:0>4o}".format (mac)
        return "{}: {}".format (macstr, micstr)
    
# Key attributes message (type 10) not supported, omit its layout
# Allocation attributes message (type 11) not supported, omit its layout
# Summary attributes message (type 12) not supported, omit its layout

class Date (DapHeader):
    _layout = (( BMEX, 6,            # DATMENU
                 ( "m_cdt", 0, 1 ),
                 ( "m_rdt", 1, 1 ),
                 ( "m_edt", 2, 1 ),
                 ( "m_rvn", 3, 1 )),
               ( IF, "m_cdt", AV, "cdt", 18 ),
               ( IF, "m_rdt", AV, "rdt", 18 ),
               ( IF, "m_edt", AV, "edt", 18 ),
               ( IF, "m_rvn", packet.B, "rvn", 2 ))
    type = 13

    @staticmethod
    def fmtdate (s):
        "Convert the date/time field value to a more readable form"
        d = s[:2]
        m = s[3:6]
        y = s[7:9]
        t = s[10:]
        if y < "70":
            y = "20" + y
        else:
            y = "19" + y
        return "{}-{}-{} {}".format (d, m.capitalize (), y, t)

    @staticmethod
    def setdate (t):
        "Convert a Unix time value to a DAP time string"
        t = time.localtime (t)
        return time.strftime ("%d-%b-%y %H:%M:%S", t).upper ()
    
class Prot (DapHeader):
    _layout = (( BMEX, 6,            # PROTMENU
                 ( "m_owner", 0, 1 ),
                 ( "m_protsys", 1, 1 ),
                 ( "m_protown", 2, 1 ),
                 ( "m_protgrp", 3, 1 ),
                 ( "m_protwld", 4, 1 )),
               ( IF, "m_owner", packet.A, "owner", 40 ),
               ( IF, "m_protsys", BMEX, 3,
                 ( "s_noread", 0, 1 ),
                 ( "s_nowrite", 1, 1 ),
                 ( "s_noexec", 2, 1 ),
                 ( "s_nodel", 3, 1 ),
                 ( "s_noappend", 4, 1 ),
                 ( "s_nodir", 5, 1 ),
                 ( "s_noupdate", 6, 1 ),
                 ( "s_nochprot", 7, 1 ),
                 ( "s_noextend", 8, 1 ),
                 # The _rw field is the two protection bits RSTS knows.
                 ( "s_rw", 0, 2 )),
               ( IF, "m_protown", BMEX, 3,
                 ( "o_noread", 0, 1 ),
                 ( "o_nowrite", 1, 1 ),
                 ( "o_noexec", 2, 1 ),
                 ( "o_nodel", 3, 1 ),
                 ( "o_noappend", 4, 1 ),
                 ( "o_nodir", 5, 1 ),
                 ( "o_noupdate", 6, 1 ),
                 ( "o_nochprot", 7, 1 ),
                 ( "o_noextend", 8, 1 ),
                 ( "o_rw", 0, 2 )),
               ( IF, "m_protgrp", BMEX, 3,
                 ( "g_noread", 0, 1 ),
                 ( "g_nowrite", 1, 1 ),
                 ( "g_noexec", 2, 1 ),
                 ( "g_nodel", 3, 1 ),
                 ( "g_noappend", 4, 1 ),
                 ( "g_nodir", 5, 1 ),
                 ( "g_noupdate", 6, 1 ),
                 ( "g_nochprot", 7, 1 ),
                 ( "g_noextend", 8, 1 ),
                 ( "g_rw", 0, 2 )),
               ( IF, "m_protwld", BMEX, 3,
                 ( "w_noread", 0, 1 ),
                 ( "w_nowrite", 1, 1 ),
                 ( "w_noexec", 2, 1 ),
                 ( "w_nodel", 3, 1 ),
                 ( "w_noappend", 4, 1 ),
                 ( "w_nodir", 5, 1 ),
                 ( "w_noupdate", 6, 1 ),
                 ( "w_nochprot", 7, 1 ),
                 ( "w_noextend", 8, 1 ),
                 ( "w_rw", 0, 2 )))
    type = 14

    def rstsprot (self):
        "Convert the protection settings to the RSTS encoded equivalent"
        if not (self.m_protown and self.m_protgrp and self.m_protwld):
            return 0
        return ((not self.o_exec) << 6) + self.o_rw + \
               (self.g_rw << 2) + (self.w_rw << 4)

    def unixmode_s (self):
        "Return the protection settings as a Unix style permission string"
        if not (self.m_protown and self.m_protgrp and self.m_protwld):
            return "---------"
        ret = list ()
        for c, b in \
           ("r", self.o_noread), ("w", self.o_nowrite), ("x", self.o_noexec), \
           ("r", self.g_noread), ("w", self.g_nowrite), ("x", self.g_noexec), \
           ("r", self.w_noread), ("w", self.w_nowrite), ("x", self.w_noexec):
            if b:
                ret.append ("-")
            else:
                ret.append (c)
        return "".join (ret)

    def setmode (self, mode):
        # Set protection flags from a Unix mode value.  Note that the
        # "write" bit in the Unix mode maps to both the write and
        # delete deny bits in DAP.
        for b, f in (0o400, "o_noread"), (0o200, "o_nowrite"), \
                    (0o200, "o_nodel"),  (0o100, "o_noexec"), \
                    (0o040, "g_noread"), (0o020, "g_nowrite"), \
                    (0o020, "g_nodel"),  (0o010, "g_noexec"), \
                    (0o004, "w_noread"), (0o002, "w_nowrite"), \
                    (0o002, "w_nodel"),  (0o001, "w_noexec"):
            if (mode & b) == 0:
                setattr (self, f, 1)
        self.m_protown = self.m_protgrp = self.m_protwld = 1
            
class Name (DapHeader):
    _layout = (( BMEX, 3,            # NAMETYPE
                 ( "filespec", 0, 1 ),
                 ( "filename", 1, 1 ),
                 ( "dirname", 2, 1 ),
                 ( "volname", 3, 1 )),
               ( packet.A, "namespec", 200 ))
    type = 15
                 

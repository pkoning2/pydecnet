#!

"""A subset of pylibpcap, implemented as straight Python using ctype.

"""

from ctypes import *
import ctypes.util
import socket
import sys

from decnet import logging

PCAP_ERRBUF_SIZE = 256
PCAP_MTU = 1518
PCAP_NETMASK_UNKNOWN = 0xffffffff

_pcaplib = None

if sys.platform == "linux":
    AF_LINK = socket.AF_PACKET

    class sockaddr_dl (Structure):
        _fields_ = (("sdl_family", c_ushort), # AF_LINK
                    ("sdl_index", c_ushort),  # if != 0, system given index for intf
                    ("sdl_type", c_ushort),   # interface type 
                    ("sdl_unknown", c_byte * 5), # some stuff I can't figure out
                    ("sdl_alen", c_ubyte),    # link layer selector length
                    ("sdl_data", c_ubyte * 12)) # Name and address

    class sockaddr_in (Structure):
        _fields_ = (("sin_family", c_ushort), # AF_INET
                    ("sin_port", c_ushort),   # port number
                    ("sin_addr", c_ubyte * 4)) # IP address

    class sockaddr_in6 (Structure):
        _fields_ = (("sin6_family", c_ushort), # AF_INET6
                    ("sin6_port", c_ushort),   # port number
                    ("sin6_flowinfo", c_uint32), # Flow information
                    ("sin6_addr", c_ubyte * 16), # IPv6 address
                    ("sin6_scope_id", c_uint32)) # Scope zone index
else:
    AF_LINK = 18

    class sockaddr_dl (Structure):
        _fields_ = (("sdl_len", c_ubyte),
                    ("sdl_family", c_ubyte),  # AF_LINK
                    ("sdl_index", c_ushort),  # if != 0, system given index for intf
                    ("sdl_type", c_ubyte),    # interface type 
                    ("sdl_nlen", c_ubyte),    # interface name length
                    ("sdl_alen", c_ubyte),    # link level address length
                    ("sdl_slen", c_ubyte),    # link layer selector length
                    ("sdl_data", c_ubyte * 12)) # Name and address

    class sockaddr_in (Structure):
        _fields_ = (("sin_len", c_ubyte),
                    ("sin_family", c_ubyte),  # AF_INET
                    ("sin_port", c_ushort),   # port number
                    ("sin_addr", c_ubyte * 4)) # IP address

    class sockaddr_in6 (Structure):
        _fields_ = (("sin6_len", c_ubyte),
                    ("sin6_family", c_ubyte),  # AF_INET6
                    ("sin6_port", c_ushort),   # port number
                    ("sin6_flowinfo", c_uint32), # Flow information
                    ("sin6_addr", c_ubyte * 16), # IPv6 address
                    ("sin6_scope_id", c_uint32)) # Scope zone index

class sockaddr (Union):
    _fields_ = (("inet", sockaddr_in),
                ("inet6", sockaddr_in6),
                ("dl", sockaddr_dl))

def format_sa (s):
    if s:
        s = s.contents
        af = s.inet.sin_family
        if af == socket.AF_INET:
            return socket.inet_ntop (af, s.inet.sin_addr)
        if af == socket.AF_INET6:
            return socket.inet_ntop (af, s.inet6.sin6_addr)
        if af == AF_LINK:
            if sys.platform == "linux":
                nlen = 0
            else:
                nlen = s.dl.sdl_nlen
            alen = s.dl.sdl_alen
            addr = s.dl.sdl_data[nlen:nlen + alen]
            return ':'.join (["{:02x}".format (b) for b in addr])
    return None
    
class pcap_addr (Structure):
    pass
pcap_addr._fields_ = (("next", POINTER (pcap_addr)),
                      ("addr", POINTER (sockaddr)),
                      ("netmask", POINTER (sockaddr)),
                      ("broadaddr", POINTER (sockaddr)),
                      ("dstaddr", POINTER (sockaddr)))

class pcap_if_t (Structure):
    pass
p_pcap_if_t = POINTER (pcap_if_t)
pp_pcap_if_t = POINTER (p_pcap_if_t)
pcap_if_t._fields_ = (("next", p_pcap_if_t),
                      ("name", c_char_p),
                      ("description", c_char_p),
                      ("addresses", POINTER (pcap_addr)),
                      ("flags", c_uint32))

class timeval (Structure):
    _fields_ = (("tv_sec", c_long),
                ("tv_usec", c_int))
    
class pcap_pkthdr (Structure):
    _fields_ = (("ts", timeval),        # Time stamp
                ("caplen", c_int32),    # Length of portion captured
                ("len", c_int32))       # Actual packet length

class bpf_program (Structure):
    _fields_ = (("bf_len", c_uint),
                ("bf_insns", c_void_p))

    def __init__ (self):
        self.bf_len = 0
        self.bf_insns = None 
        
_dispatch_callback_type = CFUNCTYPE (None, c_void_p,
                                     POINTER (pcap_pkthdr),
                                     POINTER (c_ubyte))

def _findlib ():
    global _pcaplib
    if not _pcaplib:
        libfn = ctypes.util.find_library ("pcap")
        _pcaplib = CDLL (libfn)

        # Set up prototype information for functions we use
        _pcaplib.pcap_open_live.argtypes = (c_char_p, c_int, c_int, c_int,
                                            c_char * PCAP_ERRBUF_SIZE)
        _pcaplib.pcap_open_live.restype = c_void_p
        _pcaplib.pcap_close.argtypes = (c_void_p,)
        _pcaplib.pcap_close.restype = None
        _pcaplib.pcap_inject.argtypes = (c_void_p, POINTER (c_ubyte), c_size_t)
        _pcaplib.pcap_inject.restype = c_int
        _pcaplib.pcap_dispatch.argtypes = (c_void_p, c_int,
                                           _dispatch_callback_type, c_void_p)
        _pcaplib.pcap_dispatch.restype = c_int
        _pcaplib.pcap_findalldevs.argtypes = (pp_pcap_if_t,
                                              c_char * PCAP_ERRBUF_SIZE)
        _pcaplib.pcap_findalldevs.restype = c_int
        _pcaplib.pcap_freealldevs.argtypes = (p_pcap_if_t,)
        _pcaplib.pcap_freealldevs.restype = None
        _pcaplib.pcap_fileno.argtypes = (c_void_p,)
        _pcaplib.pcap_fileno.restype = c_int
        _pcaplib.pcap_compile.argtypes = (c_void_p, POINTER (bpf_program),
                                          c_char_p, c_int, c_uint32)
        _pcaplib.pcap_compile.restype = c_int
        _pcaplib.pcap_freecode.argtypes = (POINTER (bpf_program),)
        _pcaplib.pcap_setfilter.argtypes = (c_void_p, POINTER (bpf_program))
        _pcaplib.pcap_setfilter.restype = c_int
        _pcaplib.pcap_geterr.argtypes = (c_void_p,)
        _pcaplib.pcap_geterr.restype = c_char_p
        
class _pcap (object):
    """This class exists simply to match the naming conventions
    for the pcap error exception.
    """
    class error (OSError): pass

def cvterrbuf (errbuf):
    errbuf = b"".join (b for b in errbuf).rstrip (b"\0")
    return errbuf.decode ("latin1", "ignore")
    
def findalldevs ():
    """Return a list of 4-tuples: name, description, addresses, and flags
    for each pcap device found.  Addresses is a list of 4-tuples: individual
    address, netmask, broadcast address, and destination address, or None
    for each of these if not applicable.  Address types recognized are
    datalink address, IPv4 address, and IPv6 address; each is returned as
    a string formatted according to its conventions.
    """
    _findlib ()
    retval = list ()
    listhead = p_pcap_if_t ()
    errbuf = create_string_buffer (PCAP_ERRBUF_SIZE)
    ret = _pcaplib.pcap_findalldevs (byref (listhead), errbuf)
    if ret < 0:
        raise _pcap.error (cvterrbuf (errbuf))
    try:
        lptr = listhead
        while lptr:
            lptr = lptr.contents
            name = lptr.name
            if name:
                name = name.decode ("latin1", "ignore")
            desc = lptr.description
            if desc:
                desc = desc.decode ("latin1", "ignore")
            flags = lptr.flags
            alist = list ()
            aptr = lptr.addresses
            while aptr:
                aptr = aptr.contents
                alist.append ((format_sa (aptr.addr),
                               format_sa (aptr.netmask),
                               format_sa (aptr.broadaddr),
                               format_sa (aptr.dstaddr)))
                aptr = aptr.next
            retval.append ((name, desc, alist, flags))
            lptr = lptr.next
    finally:
        _pcaplib.pcap_freealldevs (listhead)
    return retval

class _pcapCallback (object):
    """A wrapper for the callback for pcap.dispatch, to make it match
    the pylibpcap calling conventions.
    """
    def __init__ (self, fun):
        self.fun = fun

    def __call__ (self, unused, hdr, buf):
        hdr = hdr.contents
        buf = cast (buf, POINTER (c_ubyte * hdr.caplen))
        buf = bytes (buf.contents)
        self.fun (hdr.len, buf, float (hdr.ts.tv_sec) + hdr.ts.tv_usec / 1000000.)
        
class pcapObject (object):
    """Encapsulation of most of the libpcap methods
    """
    def __init__ (self):
        _findlib ()
        self.pcap = None
        self.filterprog = bpf_program ()
        
    def close (self):
        if self.pcap:
            _pcaplib.pcap_close (self.pcap)
            self.pcap = None

    def fileno (self):
        """Return the file descriptor number for this capture, or -1 if none.
        """
        if self.pcap:
            return _pcaplib.pcap_fileno (self.pcap)
        else:
            return -1
        
    def open_live (self, name, mtu = PCAP_MTU, promisc = False, timeout = 0):
        """Open a live data stream.
        """
        _findlib ()
        if isinstance (name, str):
            name = name.encode ("latin1", "ignore")
        errbuf = create_string_buffer (PCAP_ERRBUF_SIZE)
        self.close ()
        self.pcap = _pcaplib.pcap_open_live (name, mtu, promisc,
                                             timeout, errbuf)
        if not self.pcap:
            logging.error ("PCAP open failure, status {}", cvterrbuf (errbuf))
        return self.pcap
    
    def inject (self, buf):
        """Send a buffer.  Returns the number of bytes sent.
        """
        _findlib ()
        if not self.pcap:
            raise _pcap.error ("pcap.inject on closed handle")
        buf = (c_ubyte * len (buf)).from_buffer_copy (buf)
        return _pcaplib.pcap_inject (self.pcap, buf, len (buf))

    def dispatch (self, count, fun):
        """Dispatch "count" packets (or unlimited if 0) to "fun".
        "fun" must be a function with three arguments: packet length,
        the packet buffer, and a timestamp.
        """
        _findlib ()
        if not self.pcap:
            raise _pcap.error ("pcap.dispatch on closed handle")
        cb = _dispatch_callback_type (_pcapCallback (fun))
        _pcaplib.pcap_dispatch (self.pcap, count, cb, None)

    def setfilter (self, s):
        """Compile a PCAP filter expression, then make it the current
        filter.
        """
        _findlib ()
        if not self.pcap:
            raise _pcap.error ("pcap.setfilter on closed handle")
        logging.trace ("Setfilter: '{}'", s)
        if isinstance (s, str):
            s = s.encode ("latin1", "ignore")
        ret = _pcaplib.pcap_compile (self.pcap, self.filterprog,
                                     s, 0, PCAP_NETMASK_UNKNOWN)
        if ret:
            raise _pcap.error ("filter compile failure {}: {}"
                               .format (ret, self.geterr ()))
        ret = _pcaplib.pcap_setfilter (self.pcap, self.filterprog)
        if ret:
            raise _pcap.error ("setfilter failure {}: {}"
                               .format (ret, self.geterr ()))
       # Once the filters have been set, the compiled code buffer is no
        # longer needed, so free it.
        _pcaplib.pcap_freecode (self.filterprog)

    def geterr (self):
        """Get the current error string.
        """
        _findlib ()
        if not self.pcap:
            raise _pcap.error ("pcap.geterr on closed handle")
        s = _pcaplib.pcap_geterr (self.pcap)
        s = s.decode ("latin1", "ignore")
        return s
    

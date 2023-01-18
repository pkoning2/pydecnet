#!

"""Classes for dealing with host addresses and IP communication

"""

import time
import socket
import queue
import os
import re
import subprocess
import errno
import psutil
import random

from .common import *
from . import logging

# Lifted from the Python 3.8 socket.py implementation.  It does not
# depend on 3.8 features so we put it here to allow things to work in
# older releases.

def has_dualstack_ipv6():
    """Return True if the platform supports creating a SOCK_STREAM socket
    which can handle both AF_INET and AF_INET6 (IPv4 / IPv6) connections.
    """
    if not socket.has_ipv6 \
            or not hasattr(socket, 'IPPROTO_IPV6') \
            or not hasattr(socket, 'IPV6_V6ONLY'):
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            return True
    except socket.error:
        return False

dualstack = has_dualstack_ipv6 ()

# Time value way far into the future
NEVER = 1 << 62

class HostAddress (object):
    """A class for handling host addresses, including periodic refreshing
    of name lookup information.  Thanks to Rob Jarratt for the idea, in
    a note on the HECnet list.
    """
    resolver = None
    def __init__ (self, name, port, source, interval = 3600,
                  any = False):
        """Initialize a HostAddress object for the supplied name, which
        will be looked up now and re-checked every "interval" seconds.
        The default check interval is one hour.  If "any" is True, the
        special name "*" or the empty string are permitted and will be
        interpreted by the "valid" method as "any address is considered
        valid".  If "any" is False (the default) then that is an invalid
        name.  

        "source" is either a SourceAddress object for this circuit (if
        we're dealing with a destination address), or the PyDECnet
        configuration object.  It is used to find the ipv4 and ipv6
        enable flags.
        """
        # Make sure we have a resolver (singleton)
        if not self.resolver:
            self.__class__.resolver = NameResolver ()
        # Assume name to be looked up
        self.dolookup = True
        self.allow_ipv4 = source.ipv4
        self.allow_ipv6 = source.ipv6
        if not self.allow_ipv4 and not self.allow_ipv6:
            # Default to IPv4 and, if supported, IPv6 as well.
            self.allow_ipv4 = 1
            self.allow_ipv6 = socket.has_ipv6
        self.sockaddrset = set ()
        self.ipaddrset = set ()
        if name == "*" or not name:
            if any:
                self.any = True
                self.dolookup = False
                self.ipv4 = self.allow_ipv4
                self.ipv6 = self.allow_ipv6
                self.sockaddrset = { ("", port) }
                fam = socket.AF_INET6 if self.ipv6 else socket.AF_INET
                self.ailist = [ (fam, ("", port)) ]
                self.aiiter = iter (self.ailist)
                self._current_ai = next (self.aiiter)
                self.next_check = NEVER
                return
            else:
                raise ValueError ("Wildcard name not permitted")
        else:
            self.any = False
            self.ipv4 = self.ipv6 = False
            try:
                socket.inet_pton (socket.AF_INET, name)
                # Valid IPv4 address
                if not self.allow_ipv4:
                    raise ValueError ("IPv4 address, but IPv4 not enabled")
                self.dolookup = False
                self.ipv4 = True
            except OSError:
                try:
                    socket.inet_pton (socket.AF_INET6, name)
                    # Valid IPv6 address
                    if not self.allow_ipv6:
                        raise ValueError ("IPv6 address, but IPv6 not enabled") from None
                    self.dolookup = False
                    self.ipv6 = True
                except OSError:
                    pass
        self.name = name
        self.port = port
        self.interval = interval
        if self.dolookup:
            self.next_check = time.time () + interval
        else:
            self.next_check = NEVER
        self._current_ai = None
        # Look it up now, to initialize the address info and also to
        # validate the name argument.  Note we do that for the numeric
        # address case too, but of course the answer can't change later
        # so the "dolookup" flag is False for numerics.
        self.resolver.dolookup (self)
        if not self.sockaddrset:
            # Empty result
            raise ValueError ("No useable addresses for {}", name)

    def lookup_done (self, addrinfo):
        # Handle completion of a name lookup, in the constructor or by
        # the NameResolver thread.
        if self.allow_ipv6:
            if self.allow_ipv4:
                fams = { socket.AF_INET, socket.AF_INET6 }
            else:
                fams = { socket.AF_INET6 }
        else:
            fams = { socket.AF_INET }
        aset = set ()
        aiset = set ()
        # We filter address families here, explicitly, because
        # getaddrinfo doesn't do it the way we want.  If we ask for just
        # IPv6, it will still return IPv4-only results, but encode them
        # in IPv6 mapped form.
        #
        # Note that we don't care about type or proto, that's controlled
        # by the caller directly.
        for fam, x, x, x, sockaddr in addrinfo:
            if fam in fams:
                if fam == socket.AF_INET:
                    self.ipv4 = True
                else:
                    self.ipv6 = True
                    if sockaddr[0].startswith ("fe80"):
                        # Skip link local addresses
                        continue
                aiset.add ((fam, sockaddr))
                aset.add (sockaddr)
        self.sockaddrset = aset
        for f, a in aiset:
            self.ipaddrset.add (a[0])
        # It's possible that we get nothing back.  If so, keep the
        # previous answer.
        if not aiset:
            return
        # Apply address family preference, if requested.
        if self.allow_ipv4 == self.allow_ipv6:
            # No preference, deliver a random permutation of what we
            # found.
            aiset = list (aiset)
            random.shuffle (aiset)
        elif self.allow_ipv4 < self.allow_ipv6:
            # Prefer IPv6.  Sort the set with a key function that
            # returns 0 (False) for IPv6 and 1 (True) for IPv4.
            aiset = sorted (aiset, key = lambda x: x[0] == socket.AF_INET)
        else:
            # Prefer IPv4
            aiset = sorted (aiset, key = lambda x: x[0] == socket.AF_INET6)
        self.ailist = aiset
        self.aiiter = iter (aiset)
        # If the currently chosen address isn't in the lookup result any
        # longer, pick a different one.  But don't do that if the lookup
        # produces nothing at all, in that case we hang on to the
        # previous pick for lack of better choices.
        if self._current_ai not in aiset and aiset:
            self._current_ai = next (self)

    def __iter__ (self):
        return self

    def __next__ (self):
        """As an interator, the HostAddr object returns an infinite
        sequence of socket create information values, in the same format
        as the "sockaddr" property.
        """
        try:
            self._current_ai = next (self.aiiter)
        except StopIteration:
            self.aiiter = iter (self.ailist)
            try:
                self._current_ai = next (self.aiiter)
            except StopIteration:
                # This should not happen since we don't set self.ailist
                # to an empty list, but just to be paranoid we don't
                # want an infinite loop.
                self._current_ai = None
        return self._current_ai
    
    def valid (self, addr):
        """Verify that the supplied sockaddr is a valid address for
        the host, i.e., that its IP address part is in the set of IP
        addresses we found at the last lookup.
        """
        self.check_interval ()
        ia = addr[0]
        if ia.startswith ("::ffff:"):
                ia = ia[7:]
        return ia in self.ipaddrset or self.any

    def check_interval (self):
        """Do another check, if needed.  If so, do another DNS lookup
        and select an address from among the set of addresses found.
        If the currently selected address is still valid, keep that one;
        otherwise pick a random one.
        """
        if time.time () > self.next_check:
            if not self.any:
                self.resolver.queue.put (self)
            self.next_check = time.time () + self.interval

    @property
    def sockaddr (self):
        """Return the currently chosen sockaddr to use when sending to
        this host.
        """
        self.check_interval ()
        return self.addrinfo[1]

    def __str__ (self):
        if self.any:
            return "*:{}".format (self.sockaddr[1])
        return "{}:{}".format (*self.sockaddr)
    
    @property
    def addrinfo (self):
        """Return the currently chosen address info for this host.
        The value returned is a pair of family and sockaddr.  If the
        host name cannot be resolved, None is returned.
        """
        self.check_interval ()
        return self._current_ai

    @property
    def use_dualstack (self):
        return self.ipv4 and self.ipv6

    @property
    def conn_family (self):
        return self.addrinfo[0]

    @property
    def listen_family (self):
        return socket.AF_INET6 if self.ipv6 else socket.AF_INET
        
    @property
    def can_connect (self):
        "True if this address is a suitable connect destination"
        return not self.any

    @property
    def can_listen (self):
        "True if this address is useable as a listen source"
        return dualstack or not self.use_dualstack

    def __bool__ (self):
        "False if address and port are both default, True otherwise"
        # The value False means the bind operation for this address (if
        # a local address) should be skipped since it has nothing to do.
        addr, port, *x = self.sockaddr
        return bool (addr or port)

    def create_connection (self, source):
        """Create an outbound TCP connection to this destination.

        *source* is a LocalAddress object specifying the source address
        and/or source port.  Neither is required, they will be defaulted
        if not supplied.
        """
        assert self.can_connect
        logging.trace ("Connecting from {} to {}", source, self)
        sock = source.bind_socket (self.conn_family)
        sock.setblocking (False)
        try:
            sock.connect (self.sockaddr)
        except OSError as e:
            # Annoyingly, a connect on a nonblocking socket raises
            # an exception, which we want to ignore.
            if e.errno != errno.EINPROGRESS:
                sock.close ()
                raise
        return sock
            
    def create_udp (self, source):
        """Create a UDP socket for communicating with this destination.

        *source* is a LocalAddress object specifying the source port
        and optional source address.
        """
        assert self.can_connect
        if not source.can_listen:
            raise ValueError ("Dual stack operation requested or defaulted but not supported on this platform")
        assert source.sockaddr[1]
        assert self.sockaddr[1]
        logging.trace ("Binding UDP at {} to talk to {}", source, self)
        return source.bind_socket (self.conn_family,
                                   socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    def create_raw (self, source, proto):
        """Create a raw socket for communicating with this destination.

        *source* is a LocalAddress object specifying the source port
        and protocol, which must match *proto*.
        *proto* is the IP protocol to use.
        """
        assert self.can_connect
        if not source.can_listen:
            raise ValueError ("Dual stack operation requested or defaulted but not supported on this platform")
        assert proto == source.sockaddr[1]
        logging.trace ("Binding RAW socket at {} to talk to {}",
                       source, self)
        return source.bind_socket (self.conn_family, socket.SOCK_RAW, proto)
    
# Get the local addresses using psutil.  Link scope IPv6 addresses are
# included, with the link name (%ifname part) stripped off.  
LocalAddresses = set ()
for ifname, ifaddr in psutil.net_if_addrs ().items ():
    for addr in ifaddr:
        if addr.family == socket.AF_INET:
            LocalAddresses.add (addr.address)
        elif addr.family == socket.AF_INET6:
            a, *rest = addr.address.split ("%")
            LocalAddresses.add (a)

# Subclass of HostAddress used for this side of connections.
class SourceAddress (HostAddress):
    "A source address, from --source, should be one of our addresses"
    def __init__ (self, config, port = 0):
        super ().__init__ (config.source, port, config, any = True)
        if self.any:
            return
        if len (self.sockaddrset) != 1:
            raise ValueError ("--source does not map to a single address")
        if self.sockaddr[0] not in LocalAddresses:
            raise ValueError ("--source is not an address of this host")

    def bind_socket (self, fam, type = socket.SOCK_STREAM, proto = 0):
        sock = socket.socket (fam, type, proto)
        try:
            if fam == socket.AF_INET6 and type != socket.SOCK_RAW:
                if self.use_dualstack:
                    # We want both IPs, enable that
                    sock.setsockopt (socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                elif dualstack:
                    # We only want IPv6 but dual is possible, turn it off
                    # explicitly in case that was the default.
                    sock.setsockopt (socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            if self:
                # Note about Windows. We don't set SO_REUSEADDR because:
                # 1) It's unnecessary: bind() will succeed even in case of a
                # previous closed socket on the same address and still in
                # TIME_WAIT state.
                # 2) If set, another socket is free to bind() on the same
                # address, effectively preventing this one from accepting
                # connections. Also, it may set the process in a state where
                # it'll no longer respond to any signals or graceful kills.
                # See: msdn2.microsoft.com/en-us/library/ms740621(VS.85).aspx
                if os.name not in ('nt', 'cygwin') and \
                        hasattr (socket, 'SO_REUSEADDR'):
                    try:
                        sock.setsockopt (socket.SOL_SOCKET,
                                         socket.SO_REUSEADDR, 1)
                    except socket.error:
                        # Fail later on bind(), for platforms which may not
                        # support this option.
                        pass
                # Now bind to the sockaddr
                sock.bind (self.sockaddr)
            return sock
        except socket.error:
            sock.close ()
            raise

    # This creates a socket for a server (listener).
    def create_server (self):
        """Method to create a listener socket for this source address."""
        if not self.can_listen:
            raise ValueError ("Dual stack operation requested or defaulted but not supported on this platform")
        logging.trace ("Listening at {}", self)
        sock = self.bind_socket (self.listen_family)
        try:
            # Listen for connections
            sock.listen (1)
            return sock
        except socket.error:
            sock.close()
            raise
        
class NameResolver:
    # Helper class (singleton) to run name lookups in another thread
    # for HostAddress objects.
    def __init__ (self):
        self.queue = queue.Queue ()
        self.rthread = StopThread (name = "NameResolver", target = self.run)
        self.rthread.start ()

    def run (self):
        while True:
            try:
                host = self.queue.get ()
            except KeyboardInterrupt:
                break
            started = time.time ()
            logging.trace ("Starting name lookup for {}", host.name)
            try:
                self.dolookup (host)
            except Exception:
                logging.exception ("Lookup failure for name {}".format (host.name))
            dt = time.time () - started
            logging.trace ("Finished with name lookup for {}", host.name)

    def dolookup (self, host):
        try:
            ai = socket.getaddrinfo (host.name, host.port,
                                     type = socket.SOCK_STREAM)
        except socket.error:
            # Ignore lookup errors, the previous result is remembered.
            logging.trace ("DNS error looking up {}", host.name)
            return
        host.lookup_done (ai)


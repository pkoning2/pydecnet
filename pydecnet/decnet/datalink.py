#!

"""Classes for the datalink layer as used by DECnet routing.

"""

from abc import abstractmethod, ABCMeta
import time
import os
import sys
import struct
import socket
import select
import queue
import re
import subprocess
from collections import defaultdict

from .common import *
from . import logging
from . import nicepackets
from . import statemachine
from . import timers

# Either of these is taken as a socket error:
POLLERRHUP = select.POLLERR | select.POLLHUP
# We'll use select.poll.register with one of these masks:
REGPOLLIN  = select.POLLIN  | POLLERRHUP
REGPOLLOUT = select.POLLOUT | POLLERRHUP

# Poll timeout to use.  Note that it is in milliseconds, rather than
# the normal seconds.
POLLTS = 1000

class DatalinkLayer (Element):
    """The datalink layer.  This is mainly a container for the individual
    datalink circuits.
    """
    def __init__ (self, owner, config):
        """Initialize the Datalink layer.  "config" is the configuration.
        Establish our common state, then create Datalink objects for each
        circuit given in the configuration.
        """
        logging.debug ("Initializing data link layer")
        super ().__init__ (owner)
        self.config = config
        self.circuits = dict ()
        self.p2lines = dict ()
        datalinks = { d.__name__ : d for d in Datalink.leafclasses () }
        for name, c in config.circuit.items ():
            try:
                kind = datalinks[c.type]
            except KeyError:
                logging.error ("Invalid datalink type {!r}", kind)
                continue
            kindname = kind.__name__
            try:
                dl = kind (self, name, c)
                self.circuits[name] = dl
                p2id = nicepackets.P2LineEntity (name, len (self.p2lines))
                self.p2lines[p2id] = dl
                dl.p2id = p2id
                logging.debug ("Initialized {} datalink {}", kindname, name)
            except Exception:
                logging.exception ("Error initializing {} datalink {}",
                                   kindname, name)

    def start (self):
        """Start the datalink layer, which means starting each of
        the circuits that were configured.
        """
        logging.debug ("Starting datalink layer")
        for name, c in self.circuits.items ():
            try:
                c.open ()
                logging.debug ("Started datalink {}", name)
            except Exception:
                logging.exception ("Error starting datalink {}", name)
    
    
    def stop (self):
        """Stop the datalink layer, which means stopping each of
        the circuits that were configured.
        """
        logging.debug ("Stopping datalink layer")
        for name, c in self.circuits.items ():
            try:
                c.close ()
                logging.debug ("Stopped datalink {}", name)
            except Exception:
                logging.exception ("Error stopping datalink {}", name)

    def nice_read (self, req, resp):
        if isinstance (req, nicepackets.NiceReadLine):
            if req.entity.code > 0:
                # read one line
                cn = req.entity.value.upper ()
                try:
                    c = self.circuits[cn]
                except KeyError:
                    return
                c.nice_read_line (req, resp)
            else:
                # Read active or known circuits.  We handle those the
                # same because all our circuits are always on.
                for c in self.circuits.values ():
                    c.nice_read_line (req, resp)
            return resp
        if isinstance (req, nicepackets.P2NiceReadLineCounters):
            if req.entity.known ():
                # Known lines, loop
                for c in self.circuits.values ():
                    c.nice_read_line (req, resp)
            else:
                try:
                    c = self.p2lines[req.entity]
                except KeyError:
                    return
                c.nice_read_line (req, resp)
            return resp

class Datalink (Element, metaclass = ABCMeta):
    """Abstract base class for a DECnet datalink.
    """
    use_mop = False    # True if we want MOP to run on this type of datalink
    port_type = None   # NICE type of ports for this datalink
    
    def __init__ (self, owner, name, config):
        """Initialize a Datalink instance.  "name" is the name of
        the instance; "owner" is its owner; "config" is the configuration
        data for this circuit.
        The owner will receive notifications of received data,
        transmit completions, and other applicable events by work
        items delivered via the node work queue to the "dispatch"
        method of the owner.
        """
        super ().__init__ (owner)
        self.name = name
        self.owner = owner
        self.config = config

    @classmethod
    def leafclasses (cls):
        """Yield the leaf classes of Datalink -- these are the actually
        supported DECnet datalink types.
        """
        scl = cls.__subclasses__ ()
        if scl:
            for sc in scl:
                yield from sc.leafclasses ()
        elif cls.__name__[0] != '_':
            yield cls

    @abstractmethod
    def create_port (self, *args, **kwargs):
        """Create a port.  Returns an instance of the Port subclass
        associated with this datalink.  Depending on the datalink
        type, there may be a limit on the number of ports that can
        exist at one time.
        """
        return self.port_class (self, *args, **kwargs)

    @abstractmethod
    def open (self):
        """Open the datalink.
        """
        pass
    
    @abstractmethod
    def close (self):
        """Close the datalink.
        """
        pass

    def nice_read_line (self, req, resp):
        r = resp[str (self.name)]
        if req.sumstat ():
            # summary or status
            r.state = 0    # on
        elif req.char ():
            r.duplex = 0    # full
            r.protocol = self.nice_protocol
        elif req.counters ():
            # counters
            self.counters.copy (r)
        if isinstance (req, nicepackets.P2NiceReadLineCounters):
            r.entity = req.entity
            
class Port (Element, metaclass = ABCMeta):
    """Abstract base class for a DECnet datalink port
    """
    def __init__ (self, datalink, owner):
        super ().__init__ (datalink)
        self.owner = owner

    @abstractmethod
    def send (self, msg, dest = None):
        """Transmit a message.  
        """
        pass

    def nice_read_port (self, req, r):
        if req.char ():
            # Characteristics
            r.type = self.parent.port_type
        elif req.counters ():
            # Counters
            self.counters.copy (r)

# Work items for point to point datalinks

# This work item is used to report to the layer above that the datalink
# instance (datalink port) has gone up or down.  It is also used
# internal to the datalink layer state machine.
class DlStatus (Work):
    """Notification of some sort of datalink event.  Attribute is
    "status".  The status attribute is one of UP or DOWN.  DOWN means it
    has shut down.  UP means it is operational.
    """
    UP = "Up"
    DOWN = "Down"

    def __str__ (self):
        return "DLStatus: {}".format (self.status)

# The next few work items are used to initiate actions requested by
# other layers.  Work items are used for this to synchronize cleanly
# with the operation of the state machine.
class Start (Work):
    "A work item to request point to point datalink startup"

class Stop (Work):
    "A work item to request point to point datalink shutdown"

class Restart (Work):
    """A work item to request point to point datalink restart.  This
    means protocol restart, to perform "remote restart notification" as
    specified by DNA.  When possible any underlying connections are left
    in place.
    """
        
# Next are work items used to progress through the states, internal to
# the datalink instance.
class Reconnect (Work):
    """A work item to request starting over, beginning with new connections

    The "now" constructor argument indicates whether the restart should
    be immediate or should be done only after a holdoff timeout.  The
    default is hold off (False).
    """
    def __init__ (self, owner, now = False):
        super ().__init__ (owner)
        self.now = now

class Connected (Work):
    "A work item to report a connection has been made"

class ThreadExit (Work):
    "The receive thread has terminated"
    
# Point to point port

class PtpPort (Port):
    """Base class for a point to point datalink port.  A port
    describes an upper layer's use of the datalink.  In the point to
    point case, only one port is allowed at a time, since there is
    no multiplexing support.  (If maintenance mode is ever added,
    that might change.)
    """
    # This attribute is True if the datalink for this port has a start
    # operation that obeys the required semantics, i.e., data link
    # requirement #2 "Detection of remote startup" is implemented.
    start_works = True
    
    def __init__ (self, datalink, owner, proto = None):
        super ().__init__ (datalink, owner)

    @property
    def counters (self):
        return self.parent.counters
    
    def open (self):
        logging.trace ("Datalink {} open port", self.parent.name)
        self.node.addwork (Start (self.parent))

    def close (self):
        logging.trace ("Datalink {} close port", self.parent.name)
        self.node.addwork (Stop (self.parent))
        
    def restart (self):
        logging.trace ("Datalink {} restart port", self.parent.name)
        self.node.addwork (Restart (self.parent))
        
    def send (self, msg, dest = None):
        self.parent.send (msg)

# Point to point datalink (circuit) counters
class PtpCounters (BaseCounters):
    def __init__ (self, owner):
        super ().__init__ (owner)
        # A subset of the counters defined by the architecture
        self.bytes_sent = self.pkts_sent = 0
        self.bytes_recv = self.pkts_recv = 0
        
# Point to point datalink base class
class PtpDatalink (Datalink, statemachine.StateMachine):
    """Base class for point to point datalinks.
    """
    port_class = PtpPort
    counter_class = PtpCounters
    nice_protocol = 0    # DDCMP point

    def __init__ (self, owner, name, config):
        Datalink.__init__ (self, owner, name, config)
        statemachine.StateMachine.__init__ (self)
        self.tname = "{}.{}".format (owner.node.nodename, name)
        self.port = None
        self.rthread = None
        self.counters = self.counter_class (self)
        self.restart_timer = Backoff (2, 120)
        self.is_up = False
        self.restart_now = False
        
    def open (self):
        # Open and close datalink are ignored, control is via the port
        # (the higher layer's handle on the datalink entity)
        pass

    def close (self):
        pass

    def reconnect (self, now = False):
        """Queue a Reconnect request.  The argument indicates whether to
        reconnect immediately or hold off (False, the default).
        """
        self.node.addwork (Reconnect (self, now))
        
    def create_port (self, owner, proto = None, *args, **kwargs):
        if self.port:
            raise RuntimeError ("Creating second port on ptp datalink")
        port = super ().create_port (owner, proto, *args, **kwargs)
        self.port = port
        return port

    def recvall (self, n):
        """Receive a specific number of bytes from self.socket.  

        This function returns when the specified number of bytes has
        been read.  If the socket connection is lost, or a thread stop
        signal is delivered, it raises an IOError exception.
        """
        sock = self.socket
        p = select.poll ()
        p.register (sock, REGPOLLIN)
        ret = b''
        while len (ret) < n:
            # Look for traffic
            try:
                pl = p.poll (POLLTS)
            except select.error:
                logging.trace ("Poll error", exc_info = True)
                raise
            if self.rthread and self.rthread.stopnow:
                raise IOError
            if not pl:
                continue
            fn, mask = pl[0]
            if mask & POLLERRHUP:
                raise IOError
            if mask & select.POLLIN:
                # Receive a packet
                try:
                    m = sock.recv (n - len (ret))
                except (AttributeError, OSError, socket.error):
                    logging.trace ("Receive header error", exc_info = True)
                    m = None
                if not m:
                    raise IOError
                ret += m
        return ret

    def report_up (self):
        "Tell the port owner that this datalink instance is UP"
        if not self.is_up:
            self.is_up = True
            if self.port:
                logging.trace ("Reporting UP to owner of {}", self.name)
                self.node.addwork (DlStatus (self.port.owner,
                                             status = DlStatus.UP))
            
    def report_down (self):
        "Tell the port owner that this datalink instance is DOWN"
        if self.is_up:
            self.is_up = False
            if self.port:
                logging.trace ("Reporting DOWN to owner of {}", self.name)
                self.node.addwork (DlStatus (self.port.owner,
                                             status = DlStatus.DOWN))
            
    def handle_stop (self, item):
        """Common actions for a Stop work item
        """
        # Stop the receive thread, if active
        if self.rthread:
            self.rthread.stop (False)
        # Tell the owner
        self.report_down ()
        # Set the state
        if self.rthread:
            # We still have a thread, wait for it to exit
            return self.shutdown
        return self.s0

    def handle_reconnect (self, item):
        """Common actions for a Reconnect work item
        """
        logging.trace ("in handle_reconnect, {}", item.now)
        self.handle_stop (item)
        self.restart_now = item.now
        self.state = ret = self.reconnecting
        if self.rthread:
            # We still have a thread, wait for it to exit
            return ret
        # Move things along to the next stage by giving the Reconnect
        # item to the reconnecting state handler.
        return self.reconnecting (item)
    
    def validate (self, item):
        # Implement common actions (things to be done in all states).
        if isinstance (item, Received):
            # Optimization, dispose of the common case right away
            return True
        elif isinstance (item, Stop):
            self.set_state (self.handle_stop (item))
            return False
        elif isinstance (item, Reconnect):
            self.set_state (self.handle_reconnect (item))
            return False
        elif isinstance (item, ThreadExit):
            if self.state != self.shutdown:
                self.state = self.reconnecting
            if self.rthread and \
               self.rthread is not threading.current_thread ():
                # The check for current thread is mostly for the unit
                # tests, where work item delivery is done more crudely.
                self.rthread.join (1)
            self.rthread = None
            # Report that this circuit is now down
            self.report_down ()
            # Handle this item in the reconnecting state, unless we
            # were in shutdown state in which case it's handled there.
            return True
        # Any other item is just handled without further ado.
        return True
    
    @setlabel ("Halted")
    def s0 (self, item):
        """Initial state.  All messages are ignored.  A Start item sets
        the data link in motion.
        """
        if isinstance (item, Start):
            self.connect ()
            self.start_thread ()
            return self.connecting
        
    @setlabel ("Shutdown")
    def shutdown (self, item):
        """State for shutting down.  All messages are ignored.  A
        ThreadExit work item indicates the receive thread has exited.
        """
        if isinstance (item, ThreadExit):
            # Free any sockets or file descriptors
            self.disconnect ()
            # Report the DOWN to the owner
            self.report_down ()
            return self.s0

    @setlabel ("Reconnecting")
    def reconnecting (self, item):
        """Like shutdown, but when we get the ThreadExit work item,
        start a timer.  When that timer expires, restart.  This state is
        used for handling cases where we have to start over from the
        beginning.  That happens if the connection is lost, if we use
        connections.  It also applies to Multinet, which isn't a real
        datalink but where we use reinitialization of the TCP connection
        in place of data link protocol restart to deal with routing
        layer restart requests.

        The ThreadExit work item may indicate to skip the holdoff timer.
        This is done if the reason for the reconnect is a timeout -- in
        that case, we already waited and there is no good reason to wait
        twice.
        """
        if isinstance (item, timers.Timeout):
            self.node.addwork (Start (self))
            return self.s0
        elif isinstance (item, (ThreadExit, Reconnect)):
            # Free any sockets or file descriptors
            self.disconnect ()
            if self.restart_now:
                # No holdoff, but hold off next time
                self.restart_now = False
                self.node.addwork (Start (self))
                return self.s0
            else:
                self.node.timers.jstart (self, self.restart_timer.next ())
            return None    # No state change
        
    @setlabel ("Connecting")
    def connecting (self, item):
        if isinstance (item, Connected):
            return self.connected ()
        elif isinstance (item, timers.Timeout):
            # Retry the connection by treating this as a reconnect
            # request.  Make it immediate since we already timed out, no
            # sense in timing out twice for one retry.
            self.reconnect (True)
        
    @abstractmethod
    def connected (self, item):
        """Process a Connected work item which indicates the receive
        thread has finished connecting and is transitioning to the
        receive loop.  Depending on the data link details, the next step
        is either normal running (e.g., Multinet) or the start of the
        datalink initialization protocol (e.g., DDCMP).  This method
        should initiate that next step in the operation.

        The return value is the next state of the state machine.
        """
        pass

    def start_thread (self):
        # Create the receive thread
        if not self.rthread:
            self.rthread = StopThread (name = self.tname, target = self.run)
            self.rthread.start ()
        
    def run (self):
        """The main code for the receive thread.
        """
        try:
            logging.trace ("Receive thread started for {}", self.name)
            conn = self.check_connection ()
            if self.rthread and not self.rthread.stopnow:
                if conn:
                    # Reset the restart holdoff timer since we reached the
                    # point of having a good connection.
                    logging.trace ("Connected on {}", self.name)
                    self.restart_timer.reset ()
                    self.node.addwork (Connected (self))
                    self.receive_loop ()
                else:
                    logging.trace ("Connect failed for {}", self.name)
        except Exception:
            logging.exception ("Exception in receive thread for {}", self.name)
        finally:
            self.node.addwork (ThreadExit (self))
            
    @abstractmethod
    def connect (self):
        """Create any needed sockets or file descriptors and request
        connection(s), if applicable
        """
        pass

    @abstractmethod
    def disconnect (self):
        """Close all sockets and file descriptors that may have been
        opened.
        """
        pass

    @abstractmethod
    def check_connection (self):
        """This method runs in the receive thread, after the call to 
        the connect () method has been done.

        For datalinks that run over a connection, wait for the
        connection to be made.  Return True for good connection, False
        if the connection failed.  While waiting, check
        self.rthread.stopnow and exit if that becomes True.

        For connectionless operation (e.g., UDP) this method simply
        returns True.
        """
        pass

    @abstractmethod
    def receive_loop (self):
        """This method runs in the receive thread, after
        check_connection returned True.  It receives datalink frames and
        sends those to the main thread as Received work items.  It loops
        until either self.rthread.stopnow becomes True, or the
        connection fails.
        """
        pass

# Broadcast datalink counters
class BcCounters (BaseCounters):
    def __init__ (self, owner):
        super ().__init__ (owner)
        # A subset of the counters defined by the architecture
        # The traffic counters are derived from the per-port counters
        #self.bytes_sent = self.pkts_sent = 0
        #self.bytes_recv = seld.pkts_recv = 0
        self.mcbytes_recv = self.mcpkts_recv = 0
        self.unk_dest = 0

    @property
    def bytes_sent (self):
        return self.combine ("bytes_sent")
    
    @property
    def bytes_recv (self):
        return self.combine ("bytes_recv")
    
    @property
    def pkts_sent (self):
        return self.combine ("pkts_sent")
    
    @property
    def pkts_recv (self):
        return self.combine ("pkts_recv")

    def combine (self, attr):
        # Note that a given port can appear more than once in the
        # ports dictionary.  Count it only once here, under its
        # primary port number (the one given at port create time).
        return sum (getattr (v.counters, attr) for k, v in self._owner.ports.items ()
                    if v.proto == k)
    
# Broadcast datalink base class
class BcDatalink (Datalink):
    """Base class for broadcast (LAN) datalinks.
    """
    use_mop = True     # True since we want MOP to run on this type of datalink
    counter_class = BcCounters
    nice_protocol = 6    # Ethernet
    
    def __init__ (self, owner, name, config):
        super ().__init__ (owner, name, config)
        # macaddr is the current MAC address, if in single address mode
        self.hwaddr = self.macaddr = None
        self.single_address = config.single_address
        self.ports = dict ()
        self.counters = self.counter_class (self)

    def create_port (self, owner, *args, **kwargs):
        port = super ().create_port (owner, *args, **kwargs)
        self.newfilter ()
        return port

    def portfilter (self, protos):
        # Return a proto filter string
        ret = list ()
        for p in protos:
            if isinstance (p, DLSAP):
                # There is no elegant way to refer to a DSAP in PCAP
                # filter language, but referring to it as Ethernet
                # packet byte 14 is also correct and just works.  But
                # there is no version-independent way of saying "check
                # for LLC (802.3) format frame".  So ignore that
                # aspect; just checking byte 14 will give a small
                # number of false matches but that's acceptable, it
                # isn't necessary for the PCAP filter to be exact.
                p = "(ether[14]==0x{:x})".format (p)
            else:
                p = "(ether proto {:x})".format (p)
            ret.append (p)
        return " or ".join (ret)
    
    def filter (self):
        "Return PCAP filter string for this datalink"
        # We'll build a string with an element for each enabled address,
        # and for each address the prototypes that are used with it.
        # But if any port is promiscuous then the filter is only a
        # prototype filter.
        protomap = defaultdict (set)
        promisc = False
        for p, port in self.ports.items ():
            if port.promisc:
                promisc = True
                break
            protomap[port.macaddr].add (p)
            for a in port.multicast:
                protomap[a].add (p)
        if promisc:
            return self.portfilter (self.ports.keys ())
        ret = list ()
        for a, ps in protomap.items ():
            if a and a != NULLID:
                pf = self.portfilter (ps)
                ret.append ("((ether dst {::}) and ({}))".format (a, pf))
        return " or ".join (ret)

    def update_filter (self, fs):
        """This method is called whenever the set of enabled addresses
        and/or protocol types and/or promiscuous mode changes.  The
        argument is the new PCAP filter string.  Subclasses can override
        this to enable lower level filtering.  By default, this method
        does nothing.
        """
        pass

    def newfilter (self):
        # Called by port methods whenever something changes that would
        # affect the current filter string.
        self.update_filter (self.filter ())
        
# Broadcast datalink port

class _Any (object):
    """Emulates a container that contains everything -- set this as
    the address filter to be promiscuous.
    """
    def __contains__ (self, other):
        return True

_any = _Any ()

class BcPortCounters (BaseCounters):
    def __init__ (self, owner):
        super ().__init__ (owner)
        # A subset of the counters defined by the architecture (just
        # traffic counters, not error counters because those in
        # general don't make it into here).
        self.bytes_sent = self.pkts_sent = 0
        self.bytes_recv = self.pkts_recv = 0
        self.mcbytes_recv = self.mcpkts_recv = 0
        
class BcPort (Port):
    """Base class for a broadcast (LAN) datalink port.  A port
    describes an upper layer's use of the datalink, specifically
    a particular protocol type, individual address, and set of
    multicast addresses.
    """
    def __init__ (self, datalink, owner, proto = None, sap = None):
        super ().__init__ (datalink, owner)
        self._macaddr = datalink.hwaddr
        self.multicast = set ()
        self.promisc = False
        self._update_filter ()
        self.proto = self.sap = None
        self.protoset = set ()
        self.sapset = set ()
        self.counters = BcPortCounters (self)
        if proto:
            assert not sap, "Exactly one of protocol type or SAP address must be specified"
            self.add_proto (proto)
        else:
            assert sap, "Exactly one of protocol type or SAP address must be specified"
            self.add_sap (sap)

    @property
    def macaddr (self):
        if self.parent.single_address:
            return self.parent.macaddr
        return self._macaddr

    @macaddr.setter
    def macaddr (self, addr):
        addr = Macaddr (addr)
        if addr.ismulti ():
            raise ValueError ("Address {} is not an individual address".format (addr))
        if self.parent.single_address:
            self.parent.macaddr = addr
        else:
            self._macaddr = addr
        self.parent.newfilter ()
        
    def _update_filter (self):
        if self.promisc:
            self.destfilter = _any
        else:
            self.destfilter = self.multicast
        self.parent.newfilter ()
        
    def set_promiscuous (self, promisc = True):
        """Set (default) or clear (promisc = False) promiscuous mode.
        """
        self.promisc = promisc
        logging.trace ("{} promiscuous mode set to {}", self, promisc)
        self._update_filter ()
        
    def add_multicast (self, addr):
        addr = Macaddr (addr)
        if not addr.ismulti ():
            raise ValueError ("Address {} is not a multicast address".format (addr))
        if addr in self.multicast:
            raise KeyError ("Multicast address already enabled")
        self.multicast.add (addr)
        logging.trace ("{} multicast address {} added", self, addr)
        self._update_filter ()
        
    def remove_multicast (self, addr):
        addr = Macaddr (addr)
        self.multicast.remove (addr)
        logging.trace ("{} multicast address {} removed", self, addr)
        self._update_filter ()

    def add_proto (self, proto):
        proto = Ethertype (proto)
        if proto in self.protoset:
            raise KeyError ("Protocol type already enabled")
        if proto in self.parent.ports:
            raise RuntimeError ("Protocol type in use by another port")
        if not self.proto:
            self.proto = proto
        self.parent.ports[proto] = self
        self.protoset.add (proto)
        logging.trace ("{} protocol {} added", self, proto)
        self.parent.newfilter ()
        
    def remove_proto (self, proto):
        proto = Ethertype (proto)
        self.protoset.remove (proto)
        del self.parents.ports[proto]
        logging.trace ("{} protocol {} removed", self, proto)
        self.parent.newfilter ()

    def add_sap (self, sap):
        sap = DLSAP (sap)
        if sap in self.sapset:
            raise KeyError ("SAP address already enabled")
        if sap in self.parent.ports:
            raise RuntimeError ("SAP address in use by another port")
        if not self.sap:
            self.sap = sap
        self.parent.ports[sap] = self
        self.sapset.add (sap)
        logging.trace ("{} SAP address {} added", self, sap)
        self.parent.newfilter ()
        
    def remove_sap (self, sap):
        sap = DLSAP (sap)
        self.sapset.remove (sap)
        del self.parents.ports[sap]
        logging.trace ("{} SAP address {} removed", self, sap)
        self.parent.newfilter ()

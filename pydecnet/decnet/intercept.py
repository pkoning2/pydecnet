#!

"""DECnet Phase II "intercept" feature

Intercept is the term used in the Phase II architecture to describe a
rudimentary routing feature.  Many Phase II implementations only
support communication with neighbor nodes.  But in TOPS-20 systems,
the communication front-end is treated as a separate node, so such a
restriction would make the product useless.  To get around this, the
front end implements "intercept" which lets it forward packets from
the connected TOPS-20 host to adjacent other Phase II nodes.  The host
indicates who to talk to using a routing header; unlike Phase III and
later, this header uses node names, not node numbers.

For the specification of this feature, see the DECnet PHase II NSP
spec, order number AA-D600A-TC, Appendix F.

Intercept is enabled by default, but can be turned off with the
--no-intercept switch on the "routing" statement in the node
configuration.  More precisely, there are four operating modes for a
node, when interacting with Phase II neighbors:

1. No intercept: analogous to most Phase II nodes, which neither
request nor offer intercept (routing) services.  Adjacent Phase II
nodes can only communicate with this node.

2. End-node intercept.  This case applies to Phase II nodes by
default, and to Phase III or IV endnode type.  These will request
intercept if this node or the neighbor is Phase II; if offered, route
headers will be used to attempt to reach non-adjacent nodes.

3. Full intercept, this node is a Phase II router (with multiple
circuits).  This can be requested for Phase II nodes by configuration,
provided the node has multiple circuits, but it is not the default.
The node offers intercept service; if requested, it will process route
headers and forward packets accordingly.  As specified in the
architecture specification, intercept tracks connections mainly so it
can handle packets during the life of the connection that don't have
route headers, since these are optional for most packet types.

4. Intercept, this node is a Phase III or IV router.  Similar to Phase
II full intercept, but since Phase III/IV networks can drop packets,
intercept will save a copy of data packets (anything that is
acknowledged) and will retransmit these if needed (until acknowledged
or timeout).  (TODO: this packet tracking and timeout handling is not
yet implemented.)
"""

from .common import *
from . import events
from .nsp_packets import *
from .routing_packets import RouteHdr, ShortData, LongData

class BaseIntercept (Element):
    def __init__ (self, parent):
        super ().__init__ (parent)
        self.nodename = parent.routing.name
        self.nodeid = parent.routing.nodeid
        
    def start (self):
        # Node startup
        self.routing = self.node.routing
        self.nsp = self.node.nsp
        self.nodename = str (self.node.nodename)
        self.nodeid = self.node.nodeid
        self.nodeinfo_byname = self.node.nodeinfo_byname
        self.nodeinfo_byid = self.node.nodeinfo_byid
        logging.trace ("Intercept started")

    def stop (self):
        # Node shutdown
        pass

    def adjdown (self, adj):
        # Called by routing when a circuit to a Phase II node goes down.
        pass

    def mapsrc (self, adj, pkt):
        # Map the received source node to a node ID, if valid
        if not pkt.srcnode or pkt.srcnode == adj.rnodename:
            return adj.rnodeid
        return None

    def mapdst (self, pkt):
        # Map the received destination node to a node ID, if valid
        if not pkt.dstnode or pkt.dstnode == self.nodename:
            return self.nodeid
        return None

    def noroutehdr (self, pkt, adj):
        "Return dest for packet received without route header"
        return self.nodeid

    def routehdr (self, pkt, adj, dstid):
        "Do any extra processing for a packet received with a route header"
        pass
    
    def recv (self, pkt, adj):
        """Handle arriving packet from a Phase II node.  The return
        value is a pair of True and Phase IV style packet, with a
        ShortData header, if the packet can be sent onwards.  If it is
        not deliverable, return value is a pair of False and a
        Disconnect Confirm message to be reflected back to the sending
        node, with a Phase II style routing header on it.  If the packet
        can't be handled, return a pair of False and None to say
        "discard the packet".
        """
        if isinstance (pkt, RouteHdr):
            # It comes with a route header.  Legal though unusual for
            # the no-interecept case, but normal for the "requested
            # intercept" (endnode intercept) case.  Verify that the
            # source is the neighbor, and destination is this node.
            # Sometimes we see empty names, fill in the default for
            # those.
            srcid = self.mapsrc (adj, pkt)
            dstid = self.mapdst (pkt)
            if not srcid or not dstid:
                # Either source or dest is not acceptable. generate an
                # "unreachable" reply
                logging.debug ("intercept {}: unexpected route header addresses {}",
                               adj, pkt)
                return False, self.makedc (pkt, adj)
            self.routehdr (pkt, adj, dstid)
        else:
            # No route header, so it's from neighbor to us, unless
            # full intercept can look up routing information from NSP
            # connection data.
            srcid = adj.rnodeid
            dstid = self.noroutehdr (pkt, adj)
        logging.trace ("intercept {}: recv from {} to {}: {}", adj, adj.rnodeid, self.nodeid, pkt.payload)
        return True, ShortData (dstnode = dstid, srcnode = srcid,
                                rqr = 1, rts = 0, visit = 0,
                                payload = pkt.payload)

    def send (self, pkt, adj):
        """Handle sending a packet to a Phase II node.  The supplied
        packet has a phase III or IV header (ShortData or LongData).
        Return a pair of True and a Phase II style packet if the packet
        can be delivered, or False and the original packet if it cannot
        (in which case it will be handled as an unreachable
        destination).

        If it can't be sent, return True and None.
        """
        # If it's a return to sender packet, convert it to a disconnect
        # confirm with reason code "destination unreachable".
        logging.trace ("in intercept.send, pkt: {}", pkt)
        if pkt.rts:
            pkt = self.makedc (pkt, adj)
            return True, pkt
        # Can't send it unless it's from this node to the neighbor
        if pkt.dstnode != adj.id or pkt.srcnode != self.nodeid:
            return False, pkt
        # Don't supply a routing header.
        return True, pkt.payload

    def adjdown (self, adj):
        """Handle an adjacency down where the neighbor is a Phase II node.

        For the no intercept case, no action is needed.  
        """
        pass
    
    def makedc (self, pkt, adj):
        """Generate an NSP Disconnect Confirm message with reason code
        "Destination Unreachable", as a response to the supplied
        message.  The supplied message may or may not have a route
        header; the reply message always has a route header.
        
        If it makes no sense to reply to this message, return None.
        This happens if the supplied message is a Disconnect
        Confirm.
        
        If the supplied message has a Phase III/IV header and RTS is set
        in that header, the node addresses are used as-is.  Otherwise
        the message is assumed to be an outbound message, and the
        generated DC response has source and destination node addresses
        interchanged.  Note that the link addresses are always swapped,
        because those are always as sent by the original source whether
        the packet is being returned or not.
        """
        rts = False
        if isinstance (pkt, (ShortData, LongData)):
            # Phase IV (or III) header
            buf = pkt.payload
            try:
                src = self.nodeinfo_byid[pkt.srcnode].nodename
                dst = self.nodeinfo_byid[pkt.dstnode].nodename
            except KeyError:
                return None
            rts = pkt.rts
        elif isinstance (pkt, RouteHdr):
            buf = pkt.payload
            src = pkt.srcnode
            dst = pkt.dstnode
        else:
            buf = pkt
            src = self.nodename
            dst = adj.rnodename
        buf = makebytes (buf)
        try:
            buf = NspHdr (buf)
        except packet.DecodeError:
            logging.trace ("Ill formatted NSP packet received from {}: {}",
                           src, buf)
            # FIXME: this needs to log the message in the right format
            self.node.logevent (events.inv_msg, message = buf,
                                source_node = src)
            return None
        if isinstance (buf, DiscConf):
            logging.trace ("Discarding disconnect confirm from {}", src)
            return None
        # Not a Disconnect Confirm, we can reply to it
        ret = DiscConf (dstaddr = buf.srcaddr,
                        srcaddr = buf.dstaddr,
                        reason = UNREACH)
        if adj.rint:
            # Add a route header only if the node asked for intercept
            if rts:
                ret = RouteHdr (dstnode = dst, srcnode = src, payload = ret)
            else:
                ret = RouteHdr (dstnode = src, srcnode = dst, payload = ret)
        return ret
        
class FullIntercept (BaseIntercept):
    """Full intercept base class
    """
    def __init__ (self, parent):
        super ().__init__ (parent)
        self.conndb = dict ()
        
    def mapdst (self, pkt):
        # Map the received destination node to a node ID, if valid
        if not pkt.dstnode:
            return self.nodeid
        try:
            return self.node.nodeinfo_byname[pkt.dstnode].get_dest ()
        except KeyError:
            # Unknown destination node nanme
            logging.debug ("intercept {}: unknown destination node {}",
                           self.parent, pkt.dstnode)
        return None

    def noroutehdr (self, pkt, adj):
        "Return dest for packet received without route header"
        # For the full intercept case, we need to check the NSP
        # message type.  If it is data, interrupt, link service, or
        # some type of ack, we have to look it up in the logical link
        # database.  If found, the routing information in that entry
        # is used.  Otherwise, this is a packet for the local node
        # (one hop).
        try:
            nsppkt = NspHdr (pkt.payload)
        except packet.DecodeError:
            logging.trace ("Ill formatted NSP packet received from {}: {}",
                           adj, pkt.payload)
            # FIXME: this needs to log the message in the right format
            self.node.logevent (events.inv_msg, message = pkt.payload,
                                source_node = adj.rnodeid)
            # Default to "one hop message" to this node
            return self.nodeid
        if isinstance (nsppkt, AckHdr):
            # All the packets that can be routed from connection
            # database information have an ACK header, with connection
            # address fields in them.  We use the Phase II node's
            # logical link address to find the connection.
            try:
                return self.conndb[(adj.rnodeid, nsppkt.srcaddr)]
            except KeyError:
                pass
        # Other packets are local if no route header
        return self.nodeid

    def routehdr (self, pkt, adj, dstid):
        "Do any extra processing for a packet received with a route header"
        try:
            nsppkt = NspHdr (pkt.payload)
        except packet.DecodeError:
            logging.trace ("Ill formatted NSP packet received from {}: {}",
                           adj, pkt.payload)
            # FIXME: this needs to log the message in the right format
            self.node.logevent (events.inv_msg, message = pkt.payload,
                                source_node = adj.rnodeid)
            return
        if isinstance (nsppkt, (ConnInit, ConnConf)):
            # New connection, make a connection database entry
            logging.trace ("Adding conn {} for adj {}", nsppkt.srcaddr, adj)
            self.conndb[(adj.rnodeid, nsppkt.srcaddr)] = dstid
        elif isinstance (nsppkt, (DiscInit, DiscConf)):
            # Phase II node is terminating this connection, delete it
            # from the database if present
            logging.trace ("Removing conn {} for adj {}", nsppkt.srcaddr, adj)
            self.conndb.pop ((adj.rnodeid, nsppkt.srcaddr), None)

    def send (self, pkt, adj):
        """Handle sending a packet to a Phase II node.  The supplied
        packet has a phase III or IV header (ShortData or LongData).
        Return a pair of True and a Phase II style packet if the packet
        can be delivered, or False and the original packet if it cannot
        (in which case it will be handled as an unreachable
        destination).

        If it can't be sent, return True and None.
        """
        # If it's a return to sender packet, convert it to a disconnect
        # confirm with reason code "destination unreachable".
        if pkt.rts:
            pkt = self.makedc (pkt, adj)
            return True, pkt
        # Can't send it unless it's to the neighbor
        if pkt.dstnode != adj.id:
            return False, pkt
        # Parse the payload to see if we need to do anything special
        try:
            nsppkt = NspHdr (pkt.payload)
        except packet.DecodeError:
            logging.trace ("Ill formatted NSP packet received from {}: {}",
                           pkt.srcnode, pkt.payload)
            # FIXME: this needs to log the message in the right format
            self.node.logevent (events.inv_msg, message = pkt.payload,
                                source_node = pkt.srcnode)
            # Discard it ?
            return False, None
        if isinstance (nsppkt, (DiscInit, DiscConf)):
            # Remote end is terminating this connection, delete it
            # from the database if present
            logging.trace ("Removing conn {} for adj {}", nsppkt.dstaddr, adj)
            self.conndb.pop ((adj.rnodeid, nsppkt.srcaddr), None)
            self.conndb.pop ((adj.rnodeid, nsppkt.dstaddr), None)
        if pkt.srcnode != self.nodeid and not isinstance (nsppkt, AckHdr):
            # It didn't come from this node, so supply a routing
            # header if it is the kind that requires one.
            src = self.node.nodeinfo_byid[pkt.srcnode].nodename
            dst = self.node.nodeinfo_byid[pkt.dstnode].nodename
            pkt = RouteHdr (srcnode = src, dstnode = dst,
                            payload = pkt.payload)
        else:
            # Send without a routing header
            pkt = pkt.payload
        return True, pkt

class P4Intercept (FullIntercept):
    def __init__ (self, parent):
        super ().__init__ (parent)
        logging.debug ("Initialized full Phase III/IV intercept for {}", parent)

    # TODO: more stuff needed for the Phase III/IV case
    
class P2Intercept (FullIntercept):
    def __init__ (self, parent):
        super ().__init__ (parent)
        logging.debug ("Initialized full Phase II intercept for {}", parent)

class EndnodeIntercept (BaseIntercept):
    """Intercept requestor handling.

    This is used by default on Phase II nodes, and unconditionally for
    Phase III and IV endnodes.  The node will then request but not offer
    intercept services.  If this is a Phase II node, or the neighbor is
    Phase II, and the neighbor offers intercept services ("full
    intercept") we will use route headers to talk to non-neighbor
    destinations.
    """
    def __init__ (self, parent):
        super ().__init__ (parent)
        logging.debug ("Initialized intercept requestor for {}", parent)

    def mapsrc (self, adj, pkt):
        # Map the received source node to a node ID, if valid
        if not pkt.srcnode:
            return adj.rnodeid
        try:
            return self.node.nodeinfo_byname[pkt.srcnode].get_dest ()
        except KeyError:
            # Unknown destination node nanme
            logging.debug ("intercept {}: unknown source node {}",
                           adj, pkt.srcnode)
        return None
    
    def send (self, pkt, adj):
        """Handle sending a packet to a Phase II node.  The supplied
        packet has a phase III or IV header (ShortData or LongData).
        Return a pair of True and a Phase II style packet if the packet
        can be delivered, or False and the original packet if it cannot
        (in which case it will be handled as an unreachable
        destination).

        If it can't be sent, return True and None.
        """
        # If it's a return to sender packet, convert it to a disconnect
        # confirm with reason code "destination unreachable".
        if pkt.rts:
            pkt = self.makedc (pkt, adj)
            return True, pkt
        # Can't send it unless it's from here
        if pkt.srcnode != self.nodeid:
            return False, pkt
        if pkt.dstnode != adj.id:
            # It isn't going to the neighbor, so supply a route header
            src = self.node.nodeinfo_byid[pkt.srcnode].nodename
            dst = self.node.nodeinfo_byid[pkt.dstnode].nodename
            pkt = RouteHdr (srcnode = src, dstnode = dst,
                            payload = pkt.payload)
        else:
            # Send without a routing header
            pkt = pkt.payload
        return True, pkt

class NoIntercept (BaseIntercept):
    """No-intercept handling.

    This is used when --no-intercept is specified on the routing config.
    The node will then not request and not offer intercept services.  If
    connected to a Phase II neighbor, it will not use route headers and
    only be able to connect to that neighbor.
    """
    def __init__ (self, parent):
        super ().__init__ (parent)
        logging.debug ("Initialized no-intercept for {}", parent)

# Factory function.  This creates the type of intercept to use (for a
# given circuit belonging to the caller) given the local intercept
# function and intercept request flags, and the received Node Init
# message.
def Intercept (parent, phase, intfun, intreq, pkt):
    # Combine local flags with what the other end offered/requested.
    intfun = intfun and pkt.rint
    intreq = intreq and pkt.int
    if intreq:
        # We requested intercept and neighbor offered it
        return EndnodeIntercept (parent)
    if intfun:
        # We offered intercept and neighbor requested it
        if phase == 2:
            return P2Intercept (parent)
        return P4Intercept (parent)
    # For all other cases intercept is not available
    return NoIntercept (parent)

def intflags (config):
    "Return a pair of offered and requested intercept flags"
    # Offered flag is either 0 or 7, requested is 0 or 3
    #  Intercept function: 0: none supplied, 7: intercept available
    #  Intercept request:  0: none wanted,   3: requesting intecept service
    if config.routing.intercept == 0:
        return 0, 0
    if config.routing.type == "phase2":
        if config.routing.intercept is None:
            # Default Phase II to requesting intercept
            config.routing.intercept = 1
        if config.routing.intercept == 2:
            if len (config.routing.circuits) == 1:
                raise ValueError ("Full intercept not valid with single circuit")
            return 7, 0
    elif config.routing.type in ("endnode", "phase3endnode"):
        if config.routing.intercept == 2:
            raise ValueError ("Full intercept not valid on end nodes")
        # Set to request intercept if Phase II neighbor
        config.routing.intercept = 1
    elif config.routing.intercept is None:
        # Routers default to offering intercept
        if config.routing.intercept == 1:
            raise ValueError ("Request intercept not valid for Phase III or IV router")
        config.routing.intercept = 2
    if config.routing.intercept == 2:
        return 7, 0
    return 0, 3

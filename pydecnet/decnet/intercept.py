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

2. Intercept, this node is a Phase II router (with multiple circuits).
The node offers intercept service; if requested, it will process route
headers and forward packets accordingly.  As specified in the
architecture specification, intercept tracks connections mainly so it
can handle packets during the life of the connection that don't have
route headers, since these are optional for most packet types.

3. Intercept, this node is a Phase III or IF router.  Similar to Phase
II full intercept, but since Phase III/IV networks can drop packets,
intercept will save a copy of data packets (anything that is
acknowledged) and will retransmit these if needed (until acknowledged
or timeout).

4. End-node intercept.  This case applies to Phase II nodes with one
circuit, and to Phase III or IV endnode type.  These will request
intercept if the neighbor is Phase II; if offered (case 2 above),
route headers will be used to attempt to reach non-adjacent nodes.
"""

from .common import *
from . import events
from .nsp_packets import *
from .routing_packets import RouteHdr, ShortData, LongData

class BaseIntercept (Element):
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        # TODO: anything else?
        
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
    
    def intfun (self):
        # Node Init "functions" field for "intercept offered"
        return 7

    def intreq (self):
        # Node Init "requests" field for "no intercept requested"
        return 0

    def recv (self, pkt, adj):
        """Handle arriving packet from a Phase II node.  The return
        value is a pair of True and Phase IV style packet, with a
        ShortData header, if the packet can be sent onwards.  If it is
        not deliverable, return value is a pair of False and a
        Disconnect Confirm message to be reflected back to the sending
        node, with a Phase II style routing header on it.  If the packet
        can't be handled, return a pair of False and None to say
        "discard the packet".
         
        The base case handled here allows only terminating packets.
        """
        if isinstance (pkt, RouteHdr):
            # It comes with a route header.  Odd but technically legal.
            # It must come from the neighbor (that's true for all
            # intercept cases) and be addressed to this node.  Sometimes
            # we see empty names, fill in the default for those.
            if not pkt.srcnode:
                pkt.srcnode = adj.rnodename
            if not pkt.dstnode:
                pkt.dstnode = self.nodename
            if pkt.dstnode != self.nodename or pkt.srcnode != adj.rnodename:
                # Generate an "unreachable" reply
                logging.trace ("intercept {}: unexpected route header addresses {}",
                               adj, pkt)
                return False, self.makedc (pkt, adj)
            pkt = pkt.payload
        return True, ShortData (dstnode = self.nodeid,
                                srcnode = adj.rnodeid,
                                rqr = 1, rts = 0, visit = 0,
                                payload = pkt)

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
        msgflg = buf[0]
        try:
            t = msgmap[msgflg]
        except KeyError:
            # TYPE or SUBTYPE invalid, or MSGFLG is extended (step 1)
            logging.trace ("Ill formatted NSP packet received from {}: {}",
                           src, buf)
            # FIXME: this needs to log the message in the right format
            self.node.logevent (events.inv_msg, message = buf,
                                source_node = src)
            return None
        try:
            buf = t (buf)
        except Exception:
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
        
class P2Intercept (BaseIntercept):
    """Full intercept for Phase III and IV routers.
    """
    def __init__ (self, parent, config):
        super ().__init__ (parent, config)
        logging.debug ("Initialized full Phase III/IV intercept")
        
    def recv (self, pkt, adj):
        """Handle arriving packet from a Phase II node.  The return
        value is a pair of True and Phase IV style packet, with a
        ShortData header, if the packet can be sent onwards.  If it is
        not deliverable, return value is a pair of False and a
        Disconnect Confirm message to be reflected back to the sending
        node, with a Phase II style routing header on it.  If the packet
        can't be handled, return a pair of False and None to say
        "discard the packet".
         
        The base case handled here allows only terminating packets.
        """
        if not adj.rint:
            # Neighbor didn't ask for intercept service, handle it in
            # the base class.
            return super ().recv (pkt, adj)
        if isinstance (pkt, RouteHdr):
            # It comes with a route header.  It must come from the
            # neighbor.  Sometimes we see empty names, fill in the
            # default for those.
            if not pkt.srcnode:
                pkt.srcnode = adj.rnodename
            if not pkt.dstnode:
                pkt.dstnode = self.nodename
            if pkt.srcnode != adj.rnodename:
                # Generate an "unreachable" reply
                logging.trace ("intercept {}: unexpected route header fields {}",
                               adj, pkt)
                return False, self.makedc (pkt, adj)
            try:
                dst =  self.nodeinfo_byname[pkt.dstnode].get_dest ()
            except KeyError:
                # Unknown destination node nanme
                logging.trace ("intercept {}: unknown destination node {}",
                               adj, pkt.dstnode)
                return False, self.makedc (pkt, adj)                
            pkt = pkt.payload
        else:
            dst = self.nodeid
        return True, ShortData (dstnode = dst,
                                srcnode = adj.rnodeid,
                                rqr = 1, rts = 0, visit = 1,
                                payload = pkt)

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
        if pkt.srcnode != self.nodeid:
            # It didn't come from this node, so supply a routing header.
            # But first check if the neighbor understands those.
            if adj.rint:
                src = self.nodeinfo_byid[pkt.srcnode].nodename
                dst = self.nodeinfo_byid[pkt.dstnode].nodename
                pkt = RouteHdr (srcnode = src, dstnode = dst,
                                payload = pkt.payload)
            else:
                # Neighbor didn't ask for intercept, so unreachable
                return False, pkt
        else:
            # Send without a routing header
            pkt = pkt.payload
        return True, pkt

class P4Intercept (P2Intercept):
    pass

class NoIntercept (BaseIntercept):
    """No-intercept handling.

    This is used when --no-intercept is specified on the routing config.
    The node will then not request and not offer intercept services.  If
    connected to a Phase II neighbor, it will not use route headers and
    only be able to connect to that neighbor.
    """
    def __init__ (self, parent, config):
        super ().__init__ (parent, config)
        logging.debug ("Initialized no-intercept")
        
    def intfun (self):
        return 0

# Factory function
def Intercept (parent, config):
    if config.routing.no_intercept:
        return NoIntercept (parent, config)
    if config.routing.type == "phase2":
        return P2Intercept (parent, config)
    return P4Intercept (parent, config)
#!

"""Phase II network topology server implementation.

Implementation of the DECnet Phase II (TOPS-20) topology server.

This is an undocumented (by Digital) facility.  For a protocol 
description, see doc/protocols/topol.txt.

If the node has intercept disabled, this server always reports an just
the local node..  If intercept is enabled, it reports the nodes seen
as reachable ("active"), i.e., roughly the reachable nodes in the area
plus any adjacent nodes.  If --argument is supplied on the object
definition, it is interpreted as a list of node names separated by
commas; those nodes are also reported whether reachable or not.

The list is trimmed to a maximum of 50 entries to accommodate a limit
in TOPS-20 NETCON.
"""

from decnet.common import Element, Version
from decnet import packet
from decnet import session
from decnet import logging
from decnet.nicepackets import NiceReadNode, NodeReqEntity, NodeEntity

SvnFileRev = "$LastChangedRevision: 480 $"

TOPO_VERSION = Version (1, 0, 0)

# Opcodes
TOPO_REQ = 1
TOPO_RSP = 2

# Field codes
NODENAME = 1
NODENUM  = 2
NODESTAT = 3
LINEID   = 4
LINESTAT = 5
VERSION  = 6
NODELIST = 7

class TopoHdr (packet.Packet):
    _layout = (( packet.B, "opcode", 1 ),
               ( packet.B, "f_version", 1 ),
               ( Version, "version" ))
    f_version = VERSION
    version = TOPO_VERSION

class TopoReq (TopoHdr):
    opcode = TOPO_REQ

class TopoResp (TopoHdr):
    _layout = (( packet.B, "f_nodes", 1 ),
               ( packet.B, "node_count", 1 ),
               packet.Payload )
    opcode = TOPO_RSP
    f_nodes = NODELIST

class NodeEntry (packet.Packet):
    _layout = (( packet.B, "f_nodename", 1 ),
               ( packet.A, "node", 6 ))
    f_nodename = NODENAME
    
class Application (Element):
    def __init__ (self, parent, obj):
        super ().__init__ (parent)
        # If we're not doing intercept, report an empty list since
        # only nodes seen as adjacent on working circuits are
        # reachable in that case.
        if not self.node.intercept.intfun ():
            logging.trace ("Topology server: no intercept, report self")
            self.names = [ str (self.node.nodename) ]
        else:
            # obj.argument is the list of names to report unconditionally
            if obj.argument:
                self.names = { n.upper ()
                               for n in obj.argument[0].split (",") }
            else:
                self.names = set ()
            # Get the visible nodes ("active nodes").  Note, not
            # "significant nodes" because on a mapper node that is just
            # about everyone since it tries to contact everyone.
            req = NiceReadNode ()
            req.entity = NodeReqEntity (-2)  # Active Nodes
            req.info = 1                     # Status
            resp = self.node.nice_read (req)
            # Add any of those that have names
            for r in resp.values ():
                e = r.entity
                name = e.nodename
                if name:
                    self.names.add (name.upper ())
            self.names = list (self.names)
            if len (self.names) > 50:
                # TOPS-20 NETCON can handle up to 50 (see NETPAR.MAC)
                logging.trace ("Topology server: too many names ({}), truncating to 50", len (self.names))
                self.names = self.names[:50]
        logging.trace ("Topology server: names are {}", self.names)
        
    def dispatch (self, item):
        # Process work sent up from the Session Control layer. 
        conn = item.connection
        msg = item.message
        logging.tracepkt ("TOPOL message", pkt = msg)
        if isinstance (item, session.Data):
            # The client is expected to send a 5-byte message with a
            # request code and a version number.  Don't bother
            # checking, just send back our reply.
            rep = TopoResp ()
            payload = [ bytes (NodeEntry (node = n)) for n in self.names ]
            rep.payload = b"".join (payload)
            conn.send_data (rep)
            logging.trace ("TOPOL: {} node records sent to {}",
                           len (self.names), conn.remotenode)
        elif isinstance (item, session.ConnectInit):
            # There is no connect data in either direction
            conn.accept ()
        elif item.name == "disconnect":
            # No action needed
            pass
        

#!

"""DECnet/Python bridge

This implements the DECnet and LAT bridge created by Johnny Bilquist,
but in Python.  It supports connecting bridge ports directly
(internally) to DECnet/Python Ethernet ports, as well as regular
Ethernet ports and Ethernet packets over UDP.
"""

from .common import *
from . import ethernet
from . import events
from . import timers
from . import datalink

def protostr (proto):
    return "{0[0]:02x}-{0[1]:02x}".format (proto)

class BridgeCircuit (Element):
    def __init__ (self, parent, name, datalink, config):
        super ().__init__ (parent)
        self.name = name
        self.datalink = datalink.create_port (self, ROUTINGPROTO,
                                              pad = False)
        # Check that it's a good one
        if not isinstance (self.datalink, ethernet.EthPort):
            raise TypeError ("Circuit must be Ethernet type")
        # Remember whether MOP and friends are allowed on this circuit
        self.mop = config.mop
        if self.mop:
            self.datalink.add_proto (MOPDLPROTO)
            self.datalink.add_proto (MOPCONSPROTO)
            self.datalink.add_proto (LATPROTO)
            self.datalink.add_proto (LOOPPROTO)
        self.datalink.set_promiscuous (True)

    def start (self):
        pass

    def stop (self):
        pass
    
    def __str__ (self):
        return "{0.name}".format (self)

    def dispatch (self, item):
        item.src = self
        self.parent.dispatch (item)

    def send_frame (self, pdu, skip = None):
        logging.trace ("Sending %d bytes to %s: %s", len (pdu), self, pdu)
        self.datalink.parent.send_frame (pdu, skip)
        
class Bridge (Element):
    """A bridge.  This is roughly a "simple bridge" (no spanning tree
    protocol).  But more precisely, it's a Python version of Johnny
    Billquist's bridge program for HECnet.
    """
    
    def __init__ (self, node, config):
        super ().__init__ (node)
        self.name = config.bridge.name
        logging.debug ("Initializing bridge %s", self.name)
        self.config = config.bridge
        # Counters?  TBD
        # Dictionary of known destination addresses
        self.dest = dict ()
        # Find our circuits
        self.circuits = dict ()
        dlcirc = self.node.datalink.circuits
        for name, c in config.circuit.items ():
            dl = dlcirc[name]
            try:
                self.circuits[name] = BridgeCircuit (self, name, dl, c)
                logging.debug ("Initialized bridge circuit %s", name)
            except Exception:
                logging.exception ("Error initializing bridge circuit %s", name)
                del dlcirc[name]
        
    def __str__ (self):
        return "{0.name}".format (self)

    def restart (self):
        self.start ()

    def start (self):
        logging.debug ("Starting Bridge layer")
        for name, c in self.circuits.items ():
            try:
                c.start ()
                logging.debug ("Started Bridge circuit %s", name)
            except Exception:
                logging.exception ("Error starting Bridge circuit %s", name)

    def stop (self):
        logging.debug ("Stopping Bridge layer")
        for name, c in self.circuits.items ():
            try:
                c.stop ()
                logging.debug ("Stopped Bridge circuit %s", name)
            except Exception:
                logging.exception ("Error stopping Bridge circuit %s", name)

    def dispatch (self, work):
        if isinstance (work, datalink.Received):
            circ = work.src
            packet = work.pdu
            dest = Macaddr (packet[:6])
            src = Macaddr (packet[6:12])
            if dest == src:
                return
            proto = packet[12:14]
            # TODO: address database entry expiration
            self.dest[src] = circ
            logging.trace ("Received packet from %s on %s", src, circ)
            if dest in self.dest:
                out = self.dest[dest]
                if out is not circ:
                    logging.trace ("Forwarding to %s", out)
                    out.send_frame (packet, work.extra)
            else:
                for c in self.circuits.values ():
                    if c is not circ:
                        logging.trace ("Flooding packet to %s", c)
                        c.send_frame (packet, work.extra)

    def html (self, what):
        hdr = """<table border=1 cellspacing=0 cellpadding=4 rules=none><tr>
        <td width=180 align=center><a href="/bridge">Summary</td>
        <td width=180 align=center><a href="/bridge/status">Status</td>
        <td width=180 align=center><a href="/bridge/counters">Counters</td>
        <td width=180 align=center><a href="/bridge/internals">Internals</td></table>
        <h3>Bridge {}</h3>""".format (self.name)
        ctab = """<h3>Circuits</h3>
        <table border=1 cellspacing=0 cellpadding=4>
        <tr><th>Name</th><th>Protocols</th></tr>\n"""
        clist = list ()
        for cnam, c in sorted (self.circuits.items ()):
            p = list ()
            for proto in sorted (c.datalink.protoset):
                p.append (protostr (proto))
            p = ", ".join (p)
            clist.append ("<tr><td>{0}</td><td>{1}</td></tr>".format (cnam, p))
        clist = ''.join (clist) + "</table>"
        ftab = """<h3>Forwarding table</h3>
        <table border=1 cellspacing=0 cellpadding=4>
        <tr><th>Address</th><th>Circuit</th></tr>\n"""
        f = list ()
        for addr, circ in sorted (self.dest.items (),
                                  key = lambda x: str (x[1])):
            f.append ("<tr><td>{0}</td><td>{1}</td></tr>\n".format (addr, circ))
        f = ''.join (f) + "</table>"
        return hdr + ctab + clist + ftab + f
    

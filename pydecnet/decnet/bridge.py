#!

"""DECnet/Python bridge

This implements the DECnet and LAT bridge created by Johnny Bilquist,
but in Python.  It supports connecting bridge ports directly
(internally) to DECnet/Python Ethernet ports, as well as regular
Ethernet ports and Ethernet packets over UDP.
"""

from .common import *
from . import logging
from . import ethernet
from . import events
from . import timers
from . import datalink
from . import pktlogging

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

    def get_api (self):
        protos = [ p for p in self.datalink.protoset ]
        return { "name" : self.name,
                 "protocols" : protos }
    
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
        pktlogging.tracepkt ("Sending {} bytes to {}: ".format (len (pdu), self), pdu)
        #logging.trace ("Sending {} bytes to {}: {}", len (pdu), self, pdu)
        self.datalink.parent.send_frame (pdu, skip)

class AddrEnt (timers.Timer):
    """An entry in the bridge address database.  This is basically a
    combination of a MAC address (the database key), a circuit (what
    that Mac address points to) and a timer that will remove the entry
    from the database on expiration.
    """
    Timeout = 60
    
    def __init__ (self, db, addr, circ):
        """Add an entry for address "addr", pointing to circuit "circ".
        It will be entered in address database "db".  Timer expiration
        will remove it from "db".
        """
        super ().__init__ ()
        self.addr = addr
        self.owner = db
        self.circuit = circ
        self.alive()
        logging.debug ("New MAC address {} on circuit {}", addr, circ)

    def alive (self):
        self.owner.timers.start (self, self.Timeout)

    def update (self, circ):
        logging.debug ("MAC address {} moved from circuit {} to {}",
                       addr, self.circuit, circ)
        self.circuit = circ
        self.alive ()

    def dispatch (self, item):
        # Timer expiration
        logging.debug ("MAC address {} timed out on circuit {}",
                       self.addr, self.circuit)
        del self.owner[self.addr]

    def get_api (self):
        return self.circuit.name
        
class AddrDb (dict):
    """The address database.  This contains AddrEnt elements, keyed
    by MAC address.
    """
    def __init__ (self, node):
        super ().__init__ ()
        self.node = node
        self.timers = node.timers

    def learn (self, addr, circ):
        try:
            ent = self[addr]
            if ent.circuit is circ:
                ent.alive ()
            else:
                ent.update (circ)
        except KeyError:
            self[addr] = AddrEnt (self, addr, circ)

    def get_api (self):
        return { str (k) : v.get_api () for (k, v) in self.items () }
    
class Bridge (Element):
    """A bridge.  This is roughly a "simple bridge" (no spanning tree
    protocol).  But more precisely, it's a Python version of Johnny
    Billquist's bridge program for HECnet.
    """
    
    def __init__ (self, node, config):
        super ().__init__ (node)
        self.name = config.bridge.name
        logging.debug ("Initializing bridge {}", self.name)
        self.config = config.bridge
        # Counters?  TBD
        # Database of known destination addresses
        self.addrdb = AddrDb (node)
        # Find our circuits
        self.circuits = dict ()
        dlcirc = self.node.datalink.circuits
        for name, c in config.circuit.items ():
            dl = dlcirc[name]
            try:
                self.circuits[name] = BridgeCircuit (self, name, dl, c)
                logging.debug ("Initialized bridge circuit {}", name)
            except Exception:
                logging.exception ("Error initializing bridge circuit {}", name)
        
    def __str__ (self):
        return "{0.name}".format (self)

    def restart (self):
        self.start ()

    def start (self):
        logging.debug ("Starting Bridge layer")
        for name, c in self.circuits.items ():
            try:
                c.start ()
                logging.debug ("Started Bridge circuit {}", name)
            except Exception:
                logging.exception ("Error starting Bridge circuit {}", name)

    def stop (self):
        logging.debug ("Stopping Bridge layer")
        for name, c in self.circuits.items ():
            try:
                c.stop ()
                logging.debug ("Stopped Bridge circuit {}", name)
            except Exception:
                logging.exception ("Error stopping Bridge circuit {}", name)

    def dispatch (self, work):
        if isinstance (work, datalink.Received):
            circ = work.src
            packet = work.pdu
            dest = Macaddr (packet[:6])
            src = Macaddr (packet[6:12])
            if dest == src:
                return
            proto = packet[12:14]
            self.addrdb.learn (src, circ)
            logging.trace ("Received packet from {} on {}", src, circ)
            if dest in self.addrdb:
                out = self.addrdb[dest].circuit
                if out is not circ:
                    logging.trace ("Forwarding to {}", out)
                    out.send_frame (packet, work.extra)
            else:
                for c in self.circuits.values ():
                    if c is not circ:
                        logging.trace ("Flooding packet to {}", c)
                        c.send_frame (packet, work.extra)

    def http_get (self, parts, qs):
        ret = [ """<table border=1 cellspacing=0 cellpadding=4 rules=none><tr>
        <td width=180 align=center><a href="/bridge{1}">Summary</td>
        <td width=180 align=center><a href="/bridge/status{1}">Status</td>
        <td width=180 align=center><a href="/bridge/counters{1}">Counters</td>
        <td width=180 align=center><a href="/bridge/internals{1}">Internals</td></table>
        <h3>Bridge {0}</h3>""".format (self.name, qs) ]
        ret.append ("""<h3>Circuits</h3>
        <table border=1 cellspacing=0 cellpadding=4>
        <tr><th>Name</th><th>Protocols</th></tr>\n""")
        clist = list ()
        for cnam, c in sorted (self.circuits.items ()):
            p = list ()
            for proto in sorted (c.datalink.protoset):
                p.append (protostr (proto))
            p = ", ".join (p)
            clist.append ("<tr><td>{0}</td><td>{1}</td></tr>".format (cnam, p))
        ret.append (''.join (clist) + "</table>")
        if parts and parts[0] == "internals":
            ftab = """<h3>Forwarding table</h3>
            <table border=1 cellspacing=0 cellpadding=4>
            <tr><th>Address</th><th>Circuit</th></tr>\n"""
            ret.append (ftab)
            f = list ()
            for circ, addr in sorted ([ (str (ent.circuit), addr) for
                                        addr, ent in self.addrdb.items () ]):
                f.append ("<tr><td>{0}</td><td>{1}</td></tr>\n".format (addr, circ))
            ret.extend (f)
            ret.append ("</table>")
        return '\n'.join (ret)

    def description (self):
        return "<a href=\"/bridge?system={0.name}\">Bridge {0.name}</a>".format (self)

    def json_description (self):
        return { self.name : "Bridge" }
    
    def get_api (self):
        return { "circuits" : [ c.name for c in self.circuits.values () ],
                 "name" : self.name }

    def getentity (self, ent):
        try:
            return self.circuits[ent.upper ()]
        except KeyError:
            pass
        return super ().getentity (ent)

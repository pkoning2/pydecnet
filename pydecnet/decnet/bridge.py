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
from . import html

SvnFileRev = "$LastChangedRevision$"

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
        self.ip = config.ip
        if self.ip:
            self.datalink.add_proto (0x0800)            # IP
            self.datalink.add_proto (0x0806)            # ARP
        self.phase_5 = config.phase_5
        if self.phase_5:
            self.datalink.add_sap (OSISAP)
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
        logging.trace ("New MAC address {} on circuit {}", addr, circ)

    def alive (self):
        self.owner.timers.start (self, self.Timeout)

    def update (self, circ):
        logging.trace ("MAC address {} moved from circuit {} to {}",
                       self.addr, self.circuit, circ)
        self.circuit = circ
        self.alive ()

    def dispatch (self, item):
        # Timer expiration
        logging.trace ("MAC address {} timed out on circuit {}",
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
    
infos = (( "", "Summary" ),
         ( "/status", "Status" ),
         ( "/counters", "Counters" ),
         ( "/internals", "Internals" ))
    
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
        node.register_api ("bridge", self.api)
        
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
            self.addrdb.learn (src, circ)
            logging.trace ("Received packet from {} on {}", src, circ)
            if dest in self.addrdb:
                out = self.addrdb[dest].circuit
                if out is circ:
                    logging.trace ("Dropping frame, output == input")
                else:
                    logging.trace ("Forwarding to {}", out)
                    out.send_frame (packet, work.extra)
            else:
                for c in self.circuits.values ():
                    if c is not circ:
                        logging.trace ("Flooding packet to {}", c)
                        c.send_frame (packet, work.extra)
    
    def http_get (self, mobile, parts, qs):
        if parts:
            what = parts[0]
        else:
            what = "summary"
        sb = html.sbelement (html.sblabel ("Information"),
                             html.sbbutton (mobile, "bridge", "Summary", qs),
                             html.sbbutton (mobile, "bridge/internals", "Internals", qs))
        if what == "internals":
            active = 2
        else:
            active = 1
        sb.contents[active].__class__ = html.sbbutton_active
        ret = [ """<h2>Bridge {0}</h2>""".format (self.name, qs) ]
        clist = list ()
        for cnam, c in sorted (self.circuits.items ()):
            p = list ()
            for proto in sorted (c.datalink.protoset):
                p.append (protostr (proto))
            p = ", ".join (p)
            clist.append ((cnam, p))
        ret.append (html.tbsection ("Circuits",
                                    ("Name", "Protocols"),
                                    clist))
        if what == "internals":
            ret.append (html.tbsection ("Forwarding table",
                                        ("Address", "Circuit"),
                                        ((addr, circ) for circ, addr in sorted ([ (str (ent.circuit), addr) for
                                        addr, ent in self.addrdb.items () ]))))
        return sb, html.main (*ret)

    def description (self, mobile):
        return html.makelink (mobile, "bridge",
                              "Bridge {0.name}".format (self),
                              "?system={0.name}".format (self))

    def api (self, client, reqtype, tag, args):
        if reqtype == "get":
            return self.get_api ()
        return dict (error = "Unsupported operation", type = reqtype)

    def get_api (self):
        return { "circuits" : list (self.circuits.keys ()),
                 "name" : self.name }

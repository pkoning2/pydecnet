#!

"""MOP support for DECnet/Python

"""

import time
import socket
import os
import threading
import queue

from .common import *
from . import events
from . import packet
from . import datalink
from . import timers
from . import statemachine
from . import logging
from . import html
from . import nicepackets

if not WIN:
    from fcntl import *

SvnFileRev = "$LastChangedRevision$"

class ReceiptGen (object):
    """Generates MOP message receipt numbers, which are integers in the
    range 1..0xffff.  Note that 0 is not produced, it is used to indicate
    periodic messages as opposed to request/response exchanges.
    """
    def __init__ (self):
        self.receipt = random.randint (1, 0xffff)
        self.lock = threading.Lock ()

    def next (self):
        with self.lock:
            ret = self.receipt
            if ret == 0xffff:
                self.receipt = 1
            else:
                self.receipt = ret + 1
        return ret

# The receipt generator is global, so we don't produce conflicting
# receipt numbers if we're running a multi-node config.
receipt = ReceiptGen ()

# Some well known Ethernet addresses
CONSMC = Macaddr ("AB-00-00-02-00-00")
LOOPMC = Macaddr ("CF-00-00-00-00-00")

class C (packet.FieldGroup):
    """A MOP software identification field.  This is either a counted
    string, or a single byte integer in the range -2..0.
    """
    # We have to do this as a FieldGroup to get access to the owning
    # Packet object, which is where the "tolerant" flag is found.
    @classmethod
    def encode (cls, pkt, fname, maxlen):
        val = getattr (pkt, fname, None)
        if val is None:
            return b""
        if isinstance (val, int):
            if not -2 <= val <= 0:
                logging.debug ("MOP C-n field integer not in -2..0")
                raise DecodeError ("Value {} not valid for C field".format (val))
            return val.to_bytes (1, "little", signed = True)
        if isinstance (val, str):
            val = bytes (val, encoding = "latin1")
        else:
            val = makebytes (val)
        return byte (len (val)) + val
    
    @classmethod
    def decode (cls, buf, pkt, fname, maxlen):
        """Decode the next field in the buffer according to the rules
        for the "software" protocol field.  Basically this is like an
        A-n field, but special values 0, -1, and -2 are accepted in the
        first byte, and string values are taken to be text strings.

        If the packet attribute "tolerant" is True, the decoder accepts
        certain non-conforming forms that are found in the wild.
        """
        if not buf:
            if pkt.tolerant:
                return buf
            logging.debug ("No data left for C field")
            raise MissingData
        flen = int.from_bytes (buf[:1], "little", signed = True)
        if flen < -2:
            logging.debug ("C field with negative length {}", flen)
            raise DecodeError
        if flen <= 0:
            setattr (pkt, fname, flen)
            return buf[1:]
        if (flen > maxlen or flen > len (buf)) and pkt.tolerant:
            setattr (pkt, fname, str (buf, encoding = "latin1"))
            return b""
        val, buf = packet.A.decode (buf, maxlen)
        setattr (pkt, fname, val)
        return buf

    @classmethod
    def checktype (cls, name, val):
        if isinstance (val, __class__):
            return val
        if isinstance (val, int):
            return cls (val)
        return packet.A.checktype (name, val)
    
    @classmethod
    def makecoderow (cls, name, maxlen):
        return cls, None, (name, maxlen), { name }, False
    
class TIME (Field):
    __slots__ = ("tm",)
    
    def encode (self):
        """Encode a time.struct_time value into a 10 byte MOP encoding
        of time.
        """
        try:
            tzoff = tm.tm_gmtoff // 60
        except AttributeError:
            tzoff = 0
        if tzoff < 0:
            hoff, moff = divmod (-tzoff, 60)
            hoff = (256 - hoff) & 0xff
            moff = (256 - moff) & 0xff
        else:
            hoff, moff = divmod (tzoff, 60)
        cent, yr = divmod (self.tm.tm_year, 100)
        eval = ( cent, yr, self.tm.tm_mon, self.tm.tm_mday, self.tm.tm_hour,
                 self.tm.tm_min, self.tm.tm_sec, 0, hoff, moff )
        return bytes (eval)

    @classmethod
    def decode (cls, buf):
        """Decode a MOP time value, which is a 10 byte value vaguely
        like what's found in a "struct tm" in Unix, or Python
        time.struct_time.
        """
        require (buf, 10)
        t = buf[:10]
        if t[0]:
            yr = t[0] * 100 + t[1]
        else:
            # Not sure if is needed
            yr = 1900 + t[1]
        hoff = t[8]
        if hoff >= 128:
            hoff -= 256
        moff = t[9]
        if moff >= 128:
            moff -= 256
        tzoff = (hoff * 60 + moff) * 60
        ret = cls ()
        ret.tm = time.struct_time ((yr, t[2], t[3], t[4], t[5], t[6],
                                    0, 0, -1, "", tzoff))
        return ret, buf[10:]
    
class MopHdr (packet.IndexedPacket):
    classindex = { }
    classindexkey = "code"
    _layout = ( ( packet.B, "code", 1 ), )

class SysId (MopHdr):
    tolerant = True
    _addslots = ( "last_ts", )
    
    _layout = ( ( packet.RES, 1 ),
                ( packet.B, "receipt", 2 ),
                ( packet.TLV, 2, 1, True,
                  ( 1, Version, "version" ),
                  ( 2, packet.BM,
                        ( "loop", 0, 1 ),
                        ( "dump", 1, 1 ),
                        ( "ploader", 2, 1 ),
                        ( "sloader", 3, 1 ),
                        ( "boot", 4, 1 ),
                        ( "carrier", 5, 1 ),
                        ( "counters", 6, 1 ),
                        ( "carrier_reserved", 7, 1 ) ),
                  ( 3, Macaddr, "console_user" ),
                  ( 4, packet.B, "reservation_timer", 2 ),
                  ( 5, packet.B, "console_cmd_size", 2 ),
                  ( 6, packet.B, "console_resp_size", 2 ),
                  ( 7, Macaddr, "hwaddr" ),
                  ( 8, TIME, "time" ),
                  ( 100, packet.B, "device", 1 ),
                  # Spec says max is 17 but sometimes longer values are seen
                  ( 200, C, "software", 127 ),
                  ( 300, packet.B, "processor", 1 ),
                  ( 400, packet.B, "datalink", 1 ),
                  ( 401, packet.B, "bufsize", 2 ))
                )
    
    code = 7
    def_version = Version (3, 0, 0)
    def services (self):
        srv = list ()
        for s in ( "loop", "dump", "ploader", "sloader",
                   "boot", "carrier", "counters" ):
            if getattr (self, s):
                srv.append (s)
        return srv
        
class RequestId (MopHdr):
    _layout = ( ( packet.RES, 1 ),
                ( packet.B, "receipt", 2 ), )
    code = 5

class RequestCounters (MopHdr):
    _layout = ( ( packet.B, "receipt", 2 ), )
    code = 9

class Counters (MopHdr):
    # Note that most of the error counts don't apply to DECnet/Python,
    # but we define them so that we can parse and report them in
    # messages from other systems where they do have meaning.
    _layout = ( ( packet.B, "receipt", 2 ),
                ( Timestamp, "time_since_zeroed", 2 ),
                ( packet.CTR, "bytes_recv", 4 ),
                ( packet.CTR, "bytes_sent", 4 ),
                ( packet.CTR, "pkts_recv", 4 ),
                ( packet.CTR, "pkts_sent", 4 ),
                ( packet.CTR, "mcbytes_recv", 4 ),
                ( packet.CTR, "mcpkts_recv", 4 ),
                ( packet.CTR, "pkts_deferred", 4),
                ( packet.CTR, "pkts_1_collision", 4),
                ( packet.CTR, "pkts_mult_collision", 4),
                ( packet.CTR, "send_fail", 2),
                ( packet.B, "send_reasons", 2),
                ( packet.CTR, "recv_fail", 2),
                ( packet.B, "recv_reasons", 2),
                ( packet.CTR, "unk_dest", 2 ),
                ( packet.CTR, "data_overrun", 2),
                ( packet.CTR, "no_sys_buf", 2),
                ( packet.CTR, "no_user_buf", 2) )
    code = 11
    # Bit definitions for send_fail field
    SEND_FAIL_EXC_COLL = 1
    SEND_FAIL_CARR_CHECK_FAIL = 2
    SEND_FAIL_SHORT = 4
    SEND_FAIL_OPEN = 8
    SEND_FAIL_LONG = 16
    SEND_FAIL_DEFERFAIL = 32
    # Bit definitions for recv_fail field
    RECV_FAIL_BCC = 1
    RECV_FAIL_FRAMING = 2
    RECV_FAIL_LONG = 4

class ConsoleRequest (MopHdr):
    _layout = ( ( packet.BV, "verification", 8 ), )
    code = 13

class ConsoleRelease (MopHdr):
    code = 15

class ConsoleCommand (MopHdr):
    _layout = ( ( packet.BM,
                  ( "seq", 0, 1 ),
                  ( "break", 1, 1 )),
                 packet.Payload)
    code = 17

class ConsoleResponse (MopHdr):
    _layout = ( ( packet.BM,
                  ( "seq", 0, 1 ),
                  ( "cmd_lost", 1, 1 ),
                  ( "resp_lost", 2, 1 ) ),
                packet.Payload )
    code = 19

class LoopSkip (packet.Packet):
    _layout = ( ( packet.B, "skip", 2 ),
                packet.Payload )
    
class LoopFwd (packet.Packet):
    _layout = ( ( packet.B, "function", 2 ),
                ( Macaddr, "dest" ),
                packet.Payload )
    function = 2

class LoopReply (packet.Packet):
    _layout = ( ( packet.B, "function", 2 ),
                ( packet.B, "receipt", 2 ),
                packet.Payload )
    function = 1

class Mop (Element):
    """The MOP layer.  It doesn't do much, other than being the
    parent of the per-datalink MOP objects.
    """
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        self.node.mop = self
        logging.debug ("Initializing MOP layer")
        self.config = config
        self.circuits = dict ()
        dlcirc = self.node.datalink.circuits
        self.console_config = False
        self.connections = dict ()
        for name, c in config.circuit.items ():
            dl = dlcirc[name]
            if dl.use_mop:
                try:
                    self.circuits[name] = MopCircuit (self, name, dl, c)
                    logging.debug ("Initialized MOP circuit {}", name)
                    if c.console:
                        self.console_config = True
                except Exception:
                    logging.exception ("Error initializing MOP circuit {}", name)
        parent.register_api ("mop", self.api, self.end_api)
        
    def start (self):
        logging.debug ("Starting MOP layer")
        for name, c in self.circuits.items ():
            try:
                c.start ()
                logging.debug ("Started MOP circuit {}", name)
            except Exception:
                logging.exception ("Error starting MOP circuit {}", name)
    
    def stop (self):
        logging.debug ("Stopping MOP layer")
        for name, c in self.circuits.items ():
            try:
                c.stop ()
                logging.debug ("Stopped MOP circuit {}", name)
            except Exception:
                logging.exception ("Error stopping MOP circuit {}", name)
    
    def http_get (self, mobile, parts, qs):
        infos = ( "summary", "status", "details" )
        if not parts or parts == ['']:
            what = "summary"
        elif parts[0] in infos:
            what = parts[0]
        else:
            return None, None
        active = infos.index (what) + 1
        sb = html.sbelement (html.sblabel ("Information"),
                             html.sbbutton (mobile, "mop", "Summary", qs),
                             html.sbbutton (mobile, "mop/status", "Status", qs),
                             html.sbbutton (mobile, "mop/details",
                                            "Details", qs))
        sb.contents[active].__class__ = html.sbbutton_active
        ret = [ "<h3>MOP {0}</h3>".format (what) ]
        first = True
        if self.console_config:
            hdr = ( "Name", "MAC address", "HW address",
                    "Console user", "Services" )
        else:
            hdr = ( "Name", "MAC address", "HW address", "Services" )
        data = [ c.html (what, self.console_config)
                 for c in self.circuits.values () ]
        ret.append (html.tbsection ("Circuits", hdr, data))
        if what in ("status", "details"):
            for c in self.circuits.values ():
                if c.sysid:
                    ret.append (c.sysid.html (what))
        return sb, html.main (*ret)

    def api (self, client, reqtype, tag, args):
        if reqtype == "get":
            return { "circuits" : [ c.api () for c in self.circuits.values () ] }
        c = args.get ("circuit", None)
        h = args.get ("handle", None)
        if c is None and h is None:
            return dict (error = "neither circuit nor handle specified")
        if h is not None:
            conn = self.connections.get (h, None)
            if conn is None:
                return dict (error = "unknown handle")
            return conn.api (client, tag, reqtype, args)
        c = self.circuits.get (c.upper (), None)
        if c is None:
            return dict (error = "invalid circuit argument")
        if reqtype == "sysid":
            return c.sysid.api ()
        if reqtype == "loop":
            return c.loop.api (client, tag, args)
        if reqtype == "counters":
            return c.request_counters.api (client, tag, args)
        if reqtype == "connect":
            # Only "connect" comes here; the other console client
            # requests are relative to an open connection and have a
            # "handle" argument, so they are taken care of above.
            return c.console.api (client, tag, reqtype, args)
        return dict (error = "Unsupported operation", type = reqtype)

    def end_api (self, client):
        for conn in list (self.connections.values ()):
            conn.end_api (client)

    def nice_read (self, req, resp):
        if not isinstance (req, nicepackets.NiceReadModule) or \
           not req.sumstat ():
            return
        # We handle either known/active modules, or the specific
        # module name "configurator"
        if req.one () and req.entity.value.upper () != "CONFIGURATOR":
            return
        # See if there is a circuit qualifier
        try:
            c = req.circuit
            if c.code < 0:
                # Plural entity
                if c.code == -1:
                    # Known
                    clist = self.circuits.values ()
                else:
                    return
            else:
                clist = [ self.circuits[c.value] ]
        except AttributeError:
            clist = self.circuits.values ()
        except KeyError:
            # Circuit not in self.circuits, error
            return
        # Looks ok, start collecting data
        ret = [ ]
        for c in clist:
            first = True
            r1 = None
            if req.stat ():
                for k, v in sorted (c.sysid.heard.items ()):
                    r = resp.makeitem ("CONFIGURATOR")
                    if first:
                        r1 = r
                        first = False
                    r.circuit = c.name
                    r.physical_address = k
                    ts = time.localtime (v.last_ts)
                    r.last_report = (ts.tm_mday, ts.tm_mon, 
                                     ts.tm_hour,ts.tm_min, ts.tm_sec)
                    fl = [ ]
                    for i, fn in enumerate (("loop", "dump", "ploader",
                                             "sloader", "boot", "carrier",
                                             "counters")):
                        if getattr (v, fn, False):
                            fl.append (i)
                    if fl:
                        r.functions = fl
                    for fn in ( "version", "console_user",
                                "reservation_timer", "console_cmd_size",
                                "console_resp_size", "hwaddr",
                                "device", "processor", "datalink",
                                "bufsize" ):
                        setattr (r, fn, getattr (v, fn, None))
                    s = getattr (v, "software", None)
                    if s:
                        if isinstance (s, int):
                            r.software = ( s, )
                        else:
                            r.software = ( 0, s )
                    ret.append (r)
            if not r1:
                r1 = resp.makeitem ("CONFIGURATOR")
                r1.circuit = c.name
                ret.append (r1)
            r1.surveillance = 0
            dt = time.time () - c.sysid.start_ts
            dh, dt = divmod (dt, 3600)
            dm, ds = divmod (dt, 60)
            r1.elapsed_time = ( dh, dm, ds )
        resp["CONFIGURATOR"] = ret
                
class MopConnection (Element, timers.Timer):
    def __init__ (self, parent, circuit, client, tag):
        Element.__init__ (self, parent)
        timers.Timer.__init__ (self)
        self.mop = parent.mop
        self.circuit = circuit
        self.client = client
        self.tag = tag
        self.rnum = None
        self.mop.connections[id (self)] = self
        
    def request (self, pkt, dest, port, receipt = None, timeout = 3):
        self.rnum = self.circuit.request (self, pkt, dest, port, receipt)
        self.node.timers.start (self, timeout)

    def cancel (self):
        try:
            del self.mop.connections[id (self)]
        except KeyError:
            pass
        if self.rnum:
            self.circuit.done (self.rnum)
            self.node.timers.stop (self)
            self.rnum = None

    def end_api (self, client):
        if client == self.client:
            self.cancel ()
            
class CounterConnection (MopConnection):
    def start (self, req):
        dest = Macaddr (req["dest"])
        timeout = int (req.get ("timeout", 3))
        if timeout < 1:
            return { "status" : "invalid timeout" }
        pkt = RequestCounters ()
        self.request (pkt, dest, self.parent.port, timeout = timeout)
        # Request successfully initiated; the reply is asynchronous
        return None
    
    def dispatch (self, work):
        self.cancel ()
        ret = dict (system = self.node.nodename,
                    api = "mop", tag = self.tag)
        if isinstance (work, timers.Timeout):
            ret["status"] = "timeout"
        else:
            ret["status"] = "ok"
            for t, n, *x in Counters._layout:
                if t == packet.CTR:
                    ret[n] = getattr (work, n)
            ret["time_since_zeroed"] = int (work.time_since_zeroed)
        self.client.send_dict (ret)
        
class MopCircuit (Element):
    """The parent of the protocol handlers for the various protocols
    and services enabled on a particular circuit (datalink instance).
    """
    def __init__ (self, parent, name, datalink, config):
        super ().__init__ (parent)
        self.mop = parent
        self.config = config
        self.name = name
        self.datalink = datalink
        self.mop = parent
        self.loop = self.sysid = None
        self.carrier_client_dest = dict ()
        self.carrier_server = None
        self.console_verification = config.console
        self.console = None
        
    def getentity (self, name):
        if name == "counters":
            return self.request_counters
        return super ().getentity (name)
    
    def start (self):
        if self.datalink.use_mop:
            # Do this only on datalinks where we want MOP (Ethernet, basically)
            logging.debug ("Starting mop for {} {}",
                           self.datalink.__class__.__name__, self.name)
            # Dictionary of pending requests, indexed by receipt number
            self.requests = dict ()
            self.loop = LoopHandler (self, self.datalink)
            # The various MOP console handlers share a port, so we'll
            # own it and dispatch received traffic.
            consport = self.datalink.create_port (self, MOPCONSPROTO)
            self.consport = consport
            consport.add_multicast (CONSMC)
            self.sysid = SysIdHandler (self, consport)
            self.request_counters = CounterHandler (self, consport)
            self.console = CarrierClient (self, consport)
            # No console carrier server just now
            self.carrier_server = None
            services = list ()
            if self.loop:
                services.append ("loop")
            if self.sysid:
                services.append ("counters")
            if self.console_verification:
                services.append ("console")
            self.services = services

    def stop (self):
        logging.debug ("Stopping mop for {} {}",
                       self.datalink.__class__.__name__, self.name)
        if self.carrier_server:
            self.carrier_server.release ()

    def request (self, element, pkt, dest, port, receipt = None):
        """Start a request/response exchange.  "element" is the Element
        instance that will receive the response.  "pkt" is the request
        to send.  The receipt number will be filled in.  "dest" is the
        packet destination address. "port" is the datalink port to send
        the packet to.  

        If "receipt" is supplied, that is the receipt number to assume
        for this exchange (it must be set in the outgoing packet by the
        caller). This is for retransmitting requests in the Console
        Carrier protocol where reuse of a receipt number has a specific
        meaning, and for loopback where the receipt position in the
        packet depends on the request.

        The assigned receipt number is returned.
        """
        if receipt is None:
            rnum = receipt.next ()
            pkt.receipt = rnum
        else:
            rnum = receipt
        self.requests[rnum] = element
        port.send (pkt, dest)
        return rnum

    def deliver (self, item):
        """Deliver a response.
        """
        rnum = item.receipt
        if rnum:
            e = self.requests.pop (rnum, None)
            if e:
                e.dispatch (item)

    def done (self, rnum):
        """Indicate that we're done with the request whose receipt
        number is rnum.
        """
        self.requests.pop (rnum, None)
        
    def dispatch (self, work):
        if isinstance (work, datalink.Received):
            buf = work.packet
            if not buf:
                logging.debug ("Null MOP packet received on {}", self.name)
                return
            logging.trace ("MOP packet received on {}: {}",
                           self.name, bytes (buf))
            try:
                parsed = MopHdr (buf)
            except KeyError:
                logging.debug ("MOP packet with unknown message code {} on {}",
                               buf[0], self.name)
                return
            except DNAException:
                logging.exception ("MOP packet parse error\n {}", bytes (buf))
                return
            parsed.src = work.src
        else:
            # Unknown request
            return
        if isinstance (parsed, (SysId, Counters, LoopReply)):
            # A response packet with a receipt number.
            if isinstance (parsed, SysId):
                # Always look at SysId for the stations-heard table
                self.sysid.dispatch (parsed)
            # Pick up the receipt number, and dispatch the packet to whoever
            # is waiting for it.
            self.deliver (parsed)
        elif isinstance (parsed, ConsoleResponse):
            logging.trace ("Mop consoleresponse {} from {}", parsed, parsed.src)
            try:
                self.carrier_client_dest[parsed.src].dispatch (parsed)
            except KeyError:
                logging.trace ("no address match, {}", repr (self.carrier_client_dest))
                pass
        elif isinstance (parsed, ConsoleRequest):
            if self.console_verification and not self.carrier_server:
                if self.console_verification ==  parsed.verification:
                    self.carrier_server = CarrierServer (self, self.consport, parsed)
                else:
                    logging.debug ("Console request ignored, wrong verification from {}",
                                   parsed.src)
        else:
            # Not a response.  Give it to the console carrier server, if
            # one is active, then to the Sysid handler which deals with
            # other requests.
            if self.carrier_server:
                self.carrier_server.dispatch (parsed)
            self.sysid.dispatch (parsed)
            
    def html (self, what, console):
        services = ", ".join (self.services)
        if console:
            cu = (self.carrier_server and self.carrier_server.remote) or ""
            return [ self.name, self.consport.macaddr, self.datalink.hwaddr,
                     cu, services ]
        else:
            return [ self.name, self.consport.macaddr, self.datalink.hwaddr,
                     services ]

    def api (self):
        return { "name" : self.name,
                 "hwaddr" : self.datalink.hwaddr,
                 "macaddr" : self.consport.macaddr,
                 "services" : self.services }

class CounterHandler (Element):
    """This class defines the API interface for requesting counters.
    """
    def __init__ (self, parent, port):
        super ().__init__ (parent)
        self.port = port
        self.mop = parent.mop

    def api (self, client, tag, req):
        """Get counters.
        Input: dest (MAC address), optional timeout in seconds (default: 3)
        Output: status (a string: timeout or ok).  If ok, the counters.
        """
        logging.trace ("processing API call, counter request")
        conn = CounterConnection (self, self.parent, client, tag)
        return conn.start (req)

SYSID_STARTRATIO = 30

class SysIdHandler (Element, timers.Timer):
    """This class defines processing for SysId messages, both sending
    them (periodically and on request) and receiving them (multicast
    and directed).  We track received ones in a dictionary.
    """
    def __init__ (self, parent, port):
        Element.__init__ (self, parent)
        timers.Timer.__init__ (self)
        self.mop = parent.mop
        # Send the initial ID fairly soon after startup
        self.node.timers.start (self, self.id_self_delay () / SYSID_STARTRATIO)
        self.port = port
        self.mop = parent.parent
        self.heard = dict ()
        self.start_ts = time.time ()
        logging.debug ("Initialized sysid handler for {}", parent.name)

    def id_self_delay (self):
        return random.uniform (8 * 60, 12 * 60)
    
    def dispatch (self, pkt):
        if isinstance (pkt, packet.Packet):
            src = pkt.src
            if isinstance (pkt, SysId):
                if src in self.heard:
                    logging.trace ("Sysid update on {} from {}",
                                   self.parent.name, src)
                else:
                    logging.trace ("Sysid on {} from new node {}",
                                   self.parent.name, src)
                pkt.last_ts = time.time ()
                self.heard[src] = pkt
            elif isinstance (pkt, RequestId):
                self.send_id (src, pkt.receipt)
            elif isinstance (pkt, RequestCounters):
                self.send_ctrs (src, pkt.receipt)
        elif isinstance (pkt, timers.Timeout):
            logging.trace ("Sending periodic sysid on {}", self.parent.name)
            self.send_id (CONSMC, 0)
            self.node.timers.start (self, self.id_self_delay ())

    def send_id (self, dest, receipt):
        sysid = SysId (receipt = receipt,
                       version = SysId.def_version,
                       hwaddr = self.port.parent.hwaddr,
                       loop = True,
                       counters = True,
                       # I want to use a defined code, but one that is
                       # obviously not real.  PCL-11 is real but is
                       # not Ethernet, so it's a nice choice.
                       device = 9,    # PCL-11
                       datalink = 1,  # Ethernet
                       processor = 2, # Comm server
                       software = "DECnet/Python"  # Note: 16 chars max
                       )
        if self.parent.console_verification:
            sysid.carrier = True
            sysid.reservation_timer = CarrierServer.reservation_timer
            sysid.console_cmd_size = sysid.console_resp_size = CarrierServer.msgsize
            if self.parent.carrier_server:
                sysid.carrier_reserved = True
                sysid.console_user = self.parent.carrier_server.remote
        self.port.send (sysid, dest)

    def send_ctrs (self, dest, receipt):
        reply = Counters (receipt = receipt)
        self.port.parent.counters.copy (reply)
        # Make sure this is an integer
        reply.time_since_zeroed = int (reply.time_since_zeroed)
        self.port.send (reply, dest)

    def html (self, what):
        title = "Sysid data for {}".format (self.parent.name)
        if not self.heard:
            return html.textsection (title, [ "<em>Nothing heard yet</em>" ])
        else:
            header = [ "Source addr", "Services", "HW Address",
                       "Device", "Last heard" ]
            rows = list ()
            for k, v in sorted (self.heard.items ()):
                srcaddr = getattr (v, "src", "") or k
                services = ', '.join (v.services ())
                hwaddr = getattr (v, "hwaddr", "")
                device = getattr (v, "device", "")
                device = nicepackets.MOPdevices.get (device, device)
                ts = time.localtime (v.last_ts)
                last = time.strftime ("%d-%b-%Y %H:%M:%S", ts)
                row = [ srcaddr, services, hwaddr, device, last ]
                if what == "details":
                    details = list ()
                    for fn in [ "console_user", "reservation_timer",
                                "time", "processor", "datalink",
                                "blocksize", "software" ] + v.xfields (True):
                        val = getattr (v, fn, "")
                        if val:
                            if fn == "time":
                                val = time.strftime ("%d-%b-%Y %H:%M:%S", val)
                            elif fn == "processor":
                                val = nicepackets.MOPCPUs.get (val, val)
                            elif fn == "datalink":
                                val = nicepackets.MOPdatalinks.get (val, val)
                            elif fn == "software":
                                if isinstance (val, int):
                                    val = ("Not specified", "Standard OS",
                                           "Maintenance system")[-val] 
                            elif isinstance (val, bytes):
                                # A byte string, see if it looks printable
                                v1 = "-".join ("{:02x}".format (b) for b in val)
                                try:
                                    v2 = str (val, "ascii")
                                    if v2.isprintable ():
                                        v1 = v2
                                except UnicodeDecodeError:
                                    pass
                                val = v1
                            fn = v.fieldlabel (fn)
                            details.append (("{} =".format (fn), val))
                    row.append (details)
                rows.append (row)
            if what == "details":
                return html.detail_section (title, header, rows)
            return html.tbsection (title, header, rows)
        
    def api (self):
        logging.trace ("processing API call on sysid listener")
        ret = list ()
        for k, v in self.heard.items ():
            item = dict ()
            item["srcaddr"] = getattr (v, "src", "") or k
            item["console_user"] = getattr (v, "console_user", "")
            item["reservation_timer"] = getattr (v, "reservation_timer", 0)
            item["hwaddr"] = getattr (v, "hwaddr", "")
            systime = getattr (v, "time", None)
            if systime:
                systime = systime.tm
                tzoff = systime.tm_gmtoff
                systime = time.strftime ("%d-%b-%Y %H:%M:%S", systime)
                if tzoff:
                    systime += " {:+03d}{:02d}".format (*divmod (tzoff // 60, 60))
                item["time"] = systime
            device = getattr (v, "device", "")
            item["device"] = nicepackets.MOPdevices.get (device, device)
            processor = getattr (v, "processor", "")
            item["processor"] = nicepackets.MOPCPUs.get (processor, processor)
            datalink = getattr (v, "datalink", "")
            item["datalink"] = nicepackets.MOPdatalinks.get (datalink, datalink)
            bs = getattr (v, "bufsize", None)
            if bs:
                item["bufsize"] = bs
            item["software"] = getattr (v, "software", "")
            item["services"] = v.services ()
            # Add in any implementation dependent fields
            for k in v.xfields ():
                item[k] = getattr (v, k)
            ret.append (item)
        return { "sysid" : ret }

class ConsolePost (Work):
    pass

class CarrierClientConnection (MopConnection, statemachine.StateMachine):
    """A MOP connection object for the client side of the console
    carrier protocol.
    """
    CONNPOLLINTERVAL = 0.2
    DATAPOLLMIN = 0.1
    DATAPOLLMAX = 2
    
    def __init__ (self, parent, circuit, client, tag):
        MopConnection.__init__ (self, parent, circuit, client, tag)
        statemachine.StateMachine.__init__ (self)
        self.port = circuit.consport
        logging.trace ("Created console carrier client connection, handle {}", id (self))
        self.dtime = Backoff (self.DATAPOLLMIN, self.DATAPOLLMAX)

    def start (self, data):
        logging.trace ("Starting connection {}", id (self))
        try:
            dest = Macaddr (data["dest"])
            self.verification = scan_ver (data["verification"])
        except KeyError:
            return { "error" : "missing arguments" }
        except ValueError:
            return { "error" : "Invalid argument value" }
        dest = Macaddr (data["dest"])
        if dest in self.circuit.carrier_client_dest:
            return { "error" : "destination busy" }
        self.dest = dest
        self.circuit.carrier_client_dest[dest] = self
        self.msg = RequestId ()
        self.sendmsg ()
        logging.trace ("Initialized console carrier client for {}, handle {}",
                       self.circuit.name, id (self))
        return dict (handle = id (self), type = "connecting")

    def sendmsg (self, tries = 5, receipt = None, timeout = CONNPOLLINTERVAL):
        self.retries = tries
        if isinstance (self.msg, ConsoleCommand):
            self.port.send (self.msg, self.dest)
        else:
            self.node.timers.start (self, timeout)
            self.circuit.request (self, self.msg, self.dest, self.port, receipt = receipt)

    def close (self):
        """End this console carrier session.  Stop any timer and remove
        its entries in the lookup dictionaries.
        """
        self.node.timers.stop (self)
        self.msg = self.msg2 = self.listener = None
        try:
            del self.circuit.carrier_client_dest[self.dest]
        except KeyError:
            pass
        # Do the base class cleanup
        super ().cancel ()

    def cancel (self):
        # API client went away, clean up
        work = ConsolePost (self, type = "disconnect")
        self.node.addwork (work)
        
    def sendreply (self, msg):
        msg["system"] = self.node.nodename
        msg["api"] = "mop"
        msg["handle"] = id (self)
        self.client.send_dict (msg)
        
    def s0 (self, item):
        """Initial state: await SysId response, make sure console
        carrier is available.
        """
        if isinstance (item, SysId):
            self.node.timers.stop (self)
            if item.carrier and not item.carrier_reserved:
                # Looks good, proceed
                self.cmdsize = item.console_cmd_size
                self.respsize = item.console_resp_size
                self.restimer = item.reservation_timer
                # Now we send a reservation request followed by another
                # RequestId to see if it worked.
                self.msg2 = ConsoleRequest (verification = self.verification)
                self.port.send (self.msg2, self.dest)
                self.sendmsg ()
                return self.reserve
            if not item.carrier:
                self.sendreply ({ "type" : "reject",
                                  "status" : "no console carrier support" })
            else:
                self.sendreply ({ "type" : "reject",
                                  "status" : "console carrier reserved",
                                  "client" : str (item.console_user) })
            self.close ()
        elif isinstance (item, timers.Timeout):
            # Timeout, try again if not at the limit
            self.retries -= 1
            if self.retries:
                self.sendmsg (self.retries)
            else:
                self.sendreply ({ "type" : "reject", "status" : "no reply" })
                self.close ()
            
    def reserve (self, item):
        """Verify that reservation was successful.
        """
        if isinstance (item, SysId):
            # If the reservation succeeded, switch to active state to
            # run the two-way console data stream.
            if item.carrier_reserved:
                if item.console_user != self.port.macaddr:
                    self.sendreply ({ "type" : "reject",
                                      "status" : "console carrier reserved",
                                      "client" : str (item.console_user) })
                    self.node.timers.stop (self)
                    self.listener = None
                    return self.close ()
                self.seq = 0
                self.msg = None      # No poll message yet
                self.pendinginput = b""
                self.sendpoll ()
                self.sendreply ({ "type" : "accept" })
                self.listener = None
                return self.active
        elif isinstance (item, timers.Timeout):
            # Timeout, try again if not at the limit
            self.retries -= 1
            if self.retries:
                # Resend a reservation request followed by another
                # RequestId to see if it worked.
                self.port.send (self.msg2, self.dest)
                self.sendmsg (self.retries)
            else:
                self.sendreply ({ "type" : "reject", "status" : "no reply" })
                self.close ()

    def sendpoll (self):
        """Send a new poll, or retransmit the previous one.
        """
        tries = self.retries
        if not self.msg:
            tries = 5
            self.seq ^= 1
            if self.pendinginput:
                # There's keyboard input to send, make the poll go fast.
                self.dtime.reset ()
            indata = self.pendinginput[:self.cmdsize]
            self.pendinginput = self.pendinginput[self.cmdsize:]
            self.msg = ConsoleCommand (seq = self.seq, payload = indata)
        self.node.timers.start (self, self.dtime.next ())
        self.sendmsg (tries)

    def sendrelease (self):
        self.msg2 = ConsoleRelease ()
        self.port.send (self.msg2, self.dest)
        self.msg = RequestId ()
        self.sendmsg ()
    
    def active (self, item):
        """Active (connected) state of the console carrier.
        """
        if isinstance (item, ConsoleResponse) and item.seq == self.seq:
            # Response packet from our peer, and next in sequence
            self.retries = 5
            data = item.payload
            if data:
                # Reset the poll timer to minimum
                self.dtime.reset ()
                self.node.timers.start (self, self.dtime.next ())
                data = str (data, encoding = "latin1")
                self.sendreply ({ "type" : "data", "data" : data })
            self.msg = None
            # If there is more data to send, do so now
            if self.pendinginput:
                self.sendpoll ()
                return
        elif isinstance (item, (ConsoleResponse, timers.Timeout)):
            # Console response but not in sequence, or timeout: for
            # both, retransmit if it isn't time to give up.  If there is
            # no currently pending message, send the next one.
            self.retries -= 1
            if self.retries:
                self.sendpoll ()
            else:
                self.sendreply ({ "type" : "disconnect",
                                  "status" : "no response" })
                self.close ()
        elif isinstance (item, ConsolePost):
            if item.type in ("disconnect", "abort", "close"):
                # Close request -- release the console
                self.sendrelease ()
                return self.release
            # Input request, post it and say ok
            newinput = item.data
            if self.pendinginput or self.msg:
                self.pendinginput += newinput
            else:
                self.pendinginput = newinput
                self.sendpoll ()

    def release (self, item):
        """Verify that release was successful.
        """
        if isinstance (item, SysId) and item.receipt == self.msg.receipt:
            # If the reservation succeeded, switch to active state to
            # run the two-way console data stream.  
            if not (item.carrier_reserved and item.console_user == self.dest):
                logging.trace ("Console client closed for {}", self.dest)
                self.close ()
        elif isinstance (item, timers.Timeout):
            # Timeout, try again if not at the limit
            self.retries -= 1
            if self.retries:
                # Resend a release request followed by another
                # RequestId to see if it worked.
                self.port.send (self.msg2, self.dest)
                self.sendmsg (self.retries)
            else:
                logging.debug ("Release request timed out for node {}", self.dest)
                self.close ()
            
    def api (self, client, tag, reqtype, req):
        try:
            conn = self.mop.connections[req.get ("handle", None)]
        except KeyError:
            return { "error" : "no such console connection" }
        if reqtype == "data":
            data = req.get ("data", "")
            data = data.encode ("latin1")
            work = ConsolePost (conn, type = reqtype, data = data)
        elif reqtype == "disconnect" or reqtype == "abort":
            work = ConsolePost (conn, type = reqtype)
        else:
            return { "error" : "invalid request" }
        self.node.addwork (work)

class CarrierClient (Element):
    """The owner of all the console carrier client connections.
    """
    def __init__ (self, parent, port):
        super ().__init__ (parent)
        self.port = port
        self.mop = parent.mop

    def api (self, client, tag, reqtype, req):
        """Open a console carrier client connection
        Input: dest (MAC address), optional timeout in seconds (default: 3)
        """
        conn = CarrierClientConnection (self, self.parent, client, tag)
        ret = conn.start (req)
        return ret

class CarrierServer (Element, timers.Timer):
    """The server side of the console carrier protocol.
    """
    reservation_timer = 15
    msgsize = 512
    
    def __init__ (self, parent, port, reserve):
        Element.__init__ (self, parent)
        timers.Timer.__init__ (self)
        self.port = port
        self.mop = parent.mop
        self.remote = reserve.src
        self.seq = self.pty = 0
        self.pendinginput = b""
        self.response = None
        self.pendingoutput = None
        self.node.timers.start (self, self.reservation_timer)
        try:
            pid, fd = os.forkpty () #pty.fork ()
            if pid:
                # Parent process.  Save the pty fd and set it
                # to non-blocking mode
                logging.trace ("Started console server for {} {} process {}",
                               parent.name, self.remote, pid)
                self.pendingoutput = b""
                self.pty = fd
                oldflags = fcntl (fd, F_GETFL, 0)
                fcntl (fd, F_SETFL, oldflags | os.O_NONBLOCK)
            else:
                # Child process, send it off to login.
                os.execlp ("login", "login")
                sys._exit (1)
        except Exception:
            logging.exception ("Exception starting console client session")
            self.release ()

    def release (self):
        self.node.timers.stop (self)
        logging.trace ("Closed console server for {} {}",
                       self.parent.name, self.remote)
        if self.pty:
            try:
                os.close (self.pty)
            except Exception:
                pass
        self.parent.carrier_server = None

    def dispatch (self, item):
        if isinstance (item, timers.Timeout):
            # Reservation timeout, clear any reservation
            if self.pty:
                self.release ()
            self.parent.carrier_server = None
        elif isinstance (item, packet.Packet):
            # Some received packet.
            res = self.remote
            # Ignore any packets from others
            if item.src != res:
                return
            if isinstance (item, ConsoleRelease):
                # Session ended
                self.release ()
            elif isinstance (item, ConsoleCommand):
                # Command/poll message.
                self.node.timers.start (self, self.reservation_timer)
                if item.seq == self.seq:
                    # Retransmit, so resend the previous message
                    if self.response:
                        self.port.send (self.response, res)
                else:
                    # New packet.  Save any input, check for output,
                    # build a response packet with pending output.
                    self.pendinginput += item.payload
                    try:
                        accepted = os.write (self.pty, self.pendinginput)
                    except Exception:
                        accepted = len (self.pendinginput)
                    self.pendinginput = self.pendinginput[accepted:]
                    self.seq ^= 1
                    lp = len (self.pendingoutput)
                    if lp < self.msgsize:
                        try:
                            self.pendingoutput += os.read (self.pty,
                                                           self.msgsize - lp)
                        except Exception:
                            pass
                    self.response = ConsoleResponse (seq = self.seq,
                                                     payload = self.pendingoutput)
                    self.pendingoutput = b""
                    self.port.send (self.response, res)
    
class LoopConnection (MopConnection):
    def dispatch (self, work):
        self.cancel ()
        ret = dict (system = self.node.nodename,
                    api = "mop", tag = self.tag)
        if isinstance (work, timers.Timeout):
            if not self.waiting:
                if self.nml:
                    # NML quits on timeout; send it the number not looped
                    self.client.mop_loop_done (self.packets - len (self.delays))
                    return
                # Record a timeout
                self.delays.append (-1)
                if len (self.delays) == self.packets:
                    return self.finished ()
        else:
            # Got a reply, record the time it took
            self.delays.append (time.time () - self.sent)
            if self.multidest:
                self.firsthop = work.src
            if len (self.delays) == self.packets:
                return self.finished ()
            if not self.fast:
                self.waiting = True
                self.node.timers.start (self, 1)
                return
        # Finished with a message, and we're not done yet.
        self.send_req ()

    def start (self, data, nml):
        if not data:
            # In case request data was omitted entirely, substitute an
            # empty dictionary, which will do the right thing (all
            # defaults apply).
            data = { }
        dest = data.get ("dest", LOOPMC)
        if not isinstance (dest, list):
            dest = [ dest ]
        if not dest:
            dest = [ LOOPMC ]
        dest = [ Macaddr (d) for d in dest ]
        self.multidest = dest == [ LOOPMC ]
        if not self.multidest:
            for d in dest:
                if d.ismulti ():
                    return { "status" : "invalid address" }
        if len (dest) > 3:
            return  { "status" : "too many addresses" }
        # Add self as the last hop
        dest.append (self.parent.port.macaddr)
        self.timeout = int (data.get ("timeout", 3))
        self.packets = int (data.get ("packets", 1))
        if nml:
            self.fast = True
            self.payload = data["payload"]
        else:
            self.payload = b"Python! " * 12
            self.fast = data.get ("fast", False)
        if self.timeout < 1 or self.packets < 1:
            return { "status" : "invalid arguments" }
        ret = { "status" : "ok" }
        self.delays = list ()
        self.firsthop, *self.destlist = dest
        self.nml = nml
        # Build the message and make sure it's valid length
        loopmsg, rnum = self.buildloop (self.destlist, self.payload)
        if len (loopmsg) > 1500:
            # Supply the upper limit, for the case of one hop (no assist)
            return { "status" : "payload too long", "limit" : 1500 - 8 - 10 }
        # Send the first request
        self.send_req ()
        
    def send_req (self):
        loopmsg, rnum = self.buildloop (self.destlist, self.payload)
        self.waiting = False
        self.sent = time.time ()
        self.request (loopmsg, self.firsthop, self.parent.port, rnum,
                      timeout = self.timeout)

    def finished (self):
        if self.nml:
            self.client.mop_loop_done (self.firsthop)
        else:
            ret = dict (system = self.node.nodename,
                        api = "mop", tag = self.tag, status = "ok",
                        dest = self.firsthop, delays = self.delays)
            self.client.send_dict (ret)

    def buildloop (self, destlist, payload):
        rnum = receipt.next ()
        ret = LoopReply (receipt = rnum, payload = payload)
        for dest in reversed (destlist):
            ret = LoopFwd (dest = dest, payload = ret)
        ret = LoopSkip (payload = ret)
        return ret, rnum

class LoopHandler (Element):
    """Handler for loopback protocol
    """
    def __init__ (self, parent, datalink):
        super ().__init__ (parent)
        self.mop = parent.mop
        self.port = port = datalink.create_port (self, LOOPPROTO, pad = False)
        port.add_multicast (LOOPMC)
        self.pendingreq = None
        logging.debug ("Initialized loop handler for {}", parent.name)
        
    def dispatch (self, item):
        """Work item handler
        """
        if isinstance (item, datalink.Received):
            buf = item.packet
            top = LoopSkip (buf)
            skip = top.skip
            if (skip & 1) or skip > len (buf) - 4:
                # Invalid skip count, ignore
                return
            # Get the function code
            fun = int.from_bytes (buf[skip + 2:skip + 4], packet.LE)
            if fun == LoopFwd.function:
                f = LoopFwd (buf[skip + 2:])
                if f.dest[0] & 1:
                    # Forward to multicast, invalid, ignore
                    return
                top.skip += 8
                self.port.send (top, f.dest)
            elif fun == LoopReply.function:
                f = LoopReply (buf[skip + 2:])
                f.src = item.src
                self.parent.deliver (f)
                
    def api (self, client, tag, data, nml = False):
        """Perform a loop operation.
        Input: dest (MAC addresses), optional "timeout" in seconds (default: 3),
               optional "packets" -- count of packets (default: 1).
               By default there is a 1 second delay after a successful loop;
               optional "fast":True suppresses that delay.
               "nml" is True if the call is from NML rather than from the
               REST API.  In that case, the operation stops on failure.
               Also, for NML the additional argument "payload" is 
               expected (the data to be sent), and "fast" is implicitly True.
        Output: a dictionary containing two keys: "status" whose value is
                a message "ok" for success or an error message string, and
                "delays", a list of results for each packet: the round 
                trip time in seconds, or -1 to indicate that packet timed out.
                If "nml" is True, output is the MAC address of the
                station that replied (a Macaddr) or the count of messages
                not looped if there was a timeout (an int).
                If there is something wrong with the inputs, the return
                value is a dict with element "status" containing
                an error message.
                Error results are delivered as the return value of this 
                call, but success results are sent asynchronously via
                send_dict to the API client, or mop_loop_done to NML.
        """
        conn = LoopConnection (self, self.parent, client, tag)
        return conn.start (data, nml)

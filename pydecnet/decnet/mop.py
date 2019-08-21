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

# Some well known Ethernet addresses
CONSMC = Macaddr ("AB-00-00-02-00-00")
LOOPMC = Macaddr ("CF-00-00-00-00-00")

class MopHdr (packet.Packet):
    _layout = ( ( "b", "code", 1 ), )

class SysId (MopHdr):
    tolerant = True
    _addslots = ( "last_ts", )
    
    _layout = ( ( "res", 1 ),
                ( "b", "receipt", 2 ),
                ( "tlv", 2, 1, True,
                  { 1 : ( Version, "version" ),
                    2 : ( "bm",
                          ( "loop", 0, 1 ),
                          ( "dump", 1, 1 ),
                          ( "ploader", 2, 1 ),
                          ( "sloader", 3, 1 ),
                          ( "boot", 4, 1 ),
                          ( "carrier", 5, 1 ),
                          ( "counters", 6, 1 ),
                          ( "carrier_reserved", 7, 1 ),
                          ( None, 8, 8 ) ),    # Reserved
                    3 : ( Macaddr, "console_user" ),
                    4 : ( "b", "reservation_timer", 2 ),
                    5 : ( "b", "console_cmd_size", 2 ),
                    6 : ( "b", "console_resp_size", 2 ),
                    7 : ( Macaddr, "hwaddr" ),
                    8 : ( "time", "time", 10 ),
                    100 : ( "b", "device", 1 ),
                    # Spec says max is 17 but sometimes longer values are seen
                    200 : ( "c", "software", 127 ),
                    300 : ( "b", "processor", 1 ),
                    400 : ( "b", "datalink", 1 ),
                    401 : ( "b", "bufsize", 2 ) } )
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
        
    def encode_c (self, field, maxlen):
        """Encode "field" according to the rules for the "software"
        protocol field.  If "field" is a string, encode it as for the
        "I" type. If it is an integer, it has to be in -2..0, and the
        encoding is just that one byte.
        """
        val = getattr (self, field)
        if isinstance (val, int):
            if val not in (0, -1, -2):
                logging.debug ("MOP C-n field integer not in -2..0")
                raise DecodeError
            val = byte (val)
        else:
            if isinstance (val, str):
                val = bytes (val, "latin-1", "ignore")
            vl = len (val)
            if vl > maxlen:
                logging.debug ("Value too long for {} byte field", maxlen)
                raise DecodeError
            val = byte (vl) + val
        return val

    def decode_c (self, buf, field, maxlen):
        """Decode "field" according to the rules for the "software"
        protocol field.  Basically this is like an I-n field, but
        special values 0, -1, and -2 are accepted in the first byte,
        and string values are taken to be text strings.

        If "tolerant" is True, the decoder accepts certain non-conforming
        forms that are found in the wild.
        """
        if not buf:
            if tolerant:
                return buf
            logging.debug ("No data left for C field")
            raise MissingData
        flen = buf[0]
        # Convert to a signed byte value
        if flen >= 128:
            flen -= 256
        if flen < -2:
            logging.debug ("C field with negative length {}", flen)
            raise DecodeError
        elif flen <= 0:
            v = flen
            flen = 1
        else:
            if flen > maxlen:
                if self.tolerant:
                    flen = maxlen
                    v = buf
                else:
                    logging.debug ("C field length {} longer than max length {}",
                                   flen, maxlen)
                    raise DecodeError
            else:
                v = buf[1:flen + 1]
            v = bytes (v).decode ()
        setattr (self, field, v)
        return buf[flen + 1:]

    def encode_time (self, field, flen):
        """Encode a time.struct_time value into a 10 byte MOP encoding
        of time.
        """
        assert flen == 10
        val = getattr (self, field)
        try:
            tzoff = val.tm_gmtoff // 60
        except AttributeError:
            tzoff = 0
        if tzoff < 0:
            hoff, moff = divmod (-tzoff, 60)
            hoff = (256 - hoff) & 0xff
            moff = (256 - moff) & 0xff
        else:
            hoff, moff = divmod (tzoff, 60)
        cent, yr = divmod (val.tm_year, 100)
        eval = ( cent, yr, val.tm_mon, val.tm_mday, val.tm_hour,
                 val.tm_min, val.tm_sec, 0, hoff, moff )
        return bytes (eval)
    
    def decode_time (self, buf, field, flen):
        """Decode a MOP time value, which is a 10 byte value vaguely
        like what's found in a "struct tm" in Unix, or Python
        time.struct_time.
        """
        assert flen == 10
        if len (buf) < flen:
            logging.debug ("Not {} bytes left for time field", flen)
            raise MissingData
        t = buf[:flen]
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
        tm = time.struct_time ((yr, t[2], t[3], t[4], t[5], t[6],
                                0, 0, -1, "", tzoff))
        setattr (self, field, tm)
        return buf[flen:]

class RequestId (MopHdr):
    _layout = ( ( "res", 1 ),
                ( "b", "receipt", 2 ), )
    code = 5

class RequestCounters (MopHdr):
    _layout = ( ( "b", "receipt", 2 ), )
    code = 9

class Counters (MopHdr):
    # Note that most of the error counts don't apply to DECnet/Python,
    # but we define them so that we can parse and report them in
    # messages from other systems where they do have meaning.
    _layout = ( ( "b", "receipt", 2 ),
                ( "b", "time_since_zeroed", 2 ),
                ( "ctr", "bytes_recv", 4 ),
                ( "ctr", "bytes_sent", 4 ),
                ( "ctr", "pkts_recv", 4 ),
                ( "ctr", "pkts_sent", 4 ),
                ( "ctr", "mcbytes_recv", 4 ),
                ( "ctr", "mcpkts_recv", 4 ),
                ( "ctr", "pkts_deferred", 4),
                ( "ctr", "pkts_1_collision", 4),
                ( "ctr", "pkts_mult_collision", 4),
                ( "ctr", "send_fail", 2),
                ( "b", "send_reasons", 2),
                ( "ctr", "recv_fail", 2),
                ( "b", "recv_reasons", 2),
                ( "ctr", "unk_dest", 2 ),
                ( "ctr", "data_overrun", 2),
                ( "ctr", "no_sys_buf", 2),
                ( "ctr", "no_user_buf", 2) )
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
    _layout = ( ( "bv", "verification", 8 ), )
    code = 13

class ConsoleRelease (MopHdr):
    code = 15

class ConsoleCommand (MopHdr):
    _addslots = { "payload" }
    _layout = ( ( "bm",
                  ( "seq", 0, 1 ),
                  ( "break", 1, 1 ) ), )
    code = 17

class ConsoleResponse (MopHdr):
    _addslots = { "payload" }
    _layout = ( ( "bm",
                  ( "seq", 0, 1 ),
                  ( "cmd_lost", 1, 1 ),
                  ( "resp_lost", 2, 1 ) ), )
    code = 19

class LoopSkip (packet.Packet):
    _addslots = { "payload" }
    _layout = ( ( "b", "skip", 2 ), )
    
class LoopFwd (packet.Packet):
    _addslots = { "payload" }
    _layout = ( ( "b", "function", 2 ),
                ( Macaddr, "dest" ) )
    function = 2

class LoopReply (packet.Packet):
    _addslots = { "payload" }
    _layout = ( ( "b", "function", 2 ),
                ( "b", "receipt", 2 ) )
    function = 1

# Dictionary of packet codes to packet layout classes
packetformats = { c.code : c for c in globals ().values ()
                  if type (c) is packet.packet_encoding_meta
                  and hasattr (c, "code") }

class Mop (Element):
    """The MOP layer.  It doesn't do much, other than being the
    parent of the per-datalink MOP objects.
    """
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        self.node.mop = self
        logging.debug ("Initializing MOP layer")
        self.config = config
        self.circuits = EntityDict ()
        dlcirc = self.node.datalink.circuits
        self.console_config = False
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

    def get_api (self):
        return { "circuits" : self.circuits.get_api () }

    def nice_read (self, req, resp):
        if not isinstance (req, nicepackets.NiceReadModule) or \
           not req.sumstat ():
            return
        # We handle either known/active modules, or the specific
        # module name "configurator"
        if req.one () and req.entity.value.upper () != "CONFIGURATOR":
            return
        # We expect payload carrying a circuit qualifier.  The spec
        # makes it look like this is encoded in NICE data item
        # encoding but that is not actually accurate.  If there is no
        # payload we treat that as "known circuits".
        ce = nicepackets.CircuitReqEntity (-1)
        if req.payload:
            p = req.payload
            require (p, 3)
            c = int.from_bytes (p[:2], "little")
            if c != 100:
                return -6    # Unrecognized parameter
            c = p[2]
            if c >= 128:
                c -= 256
            ce.code = c
            if c > 0:
                # Specific string
                require (p, 3 + c)
                ce.value = str (p[3:3 + c], "latin1")
        # Parsed the circuit(s) to return, check
        if ce.code > 0:
            try:
                c = self.circuits[ce.value]
                clist = [ c ]
            except KeyError:
                return
        else:
            clist = self.circuits.values ()
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
                
        
class MopCircuit (Element):
    """The parent of the protocol handlers for the various protocols
    and services enabled on a particular circuit (datalink instance).
    """
    def __init__ (self, parent, name, datalink, config):
        super ().__init__ (parent)
        self.config = config
        self.name = name
        self.datalink = datalink
        self.mop = parent
        self.loop = self.sysid = None
        self.conn_clients = dict ()
        self.carrier_client_dest = dict ()
        self.carrier_server = None
        self.console_verification = config.console
        self.console = ConnApiHelper (self, CarrierClient)
        
    def getentity (self, name):
        if name == "counters":
            return self.datalink.counters
        return super ().getentity (name)
    
    def start (self):
        if self.datalink.use_mop:
            # Do this only on datalinks where we want MOP (Ethernet, basically)
            logging.debug ("Starting mop for {} {}",
                           self.datalink.__class__.__name__, self.name)
            # Dictionary of pending requests, indexed by receipt number
            self.requests = dict ()
            self.receipt = ReceiptGen ()
            self.loop = LoopHandler (self, self.datalink)
            # The various MOP console handlers share a port, so we'll
            # own it and dispatch received traffic.
            consport = self.datalink.create_port (self, MOPCONSPROTO)
            self.consport = consport
            consport.add_multicast (CONSMC)
            self.sysid = SysIdHandler (self, consport)
            self.request_counters = CounterHandler (self, consport)
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
            rnum = self.receipt.next ()
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
            try:
                self.requests[rnum].dispatch (item)
                del self.requests[rnum]
            except KeyError:
                pass

    def done (self, rnum):
        """Indicate that we're done with the request whose receipt
        number is rnum.
        """
        try:
            del self.requests[rnum]
        except KeyError:
            pass
        
    def exchange (self, pkt, dest, port, timeout = 3, receipt = None):
        """Perform a request/response exchange.  "pkt" is the request to
        send.  The receipt number will be filled in.  "dest" is the
        packet destination address. "port" is the datalink port to send
        to.

        This method must not be called from the main node thread, only 
        from worker threads such as the HTTPS API threads.

        The response packet is returned, or None to indicate timeout.
        """
        listener = WorkHandler ()
        try:
            rnum = self.request (listener, pkt, dest, port, receipt = receipt)
            ret = listener.wait ()
        finally:
            self.done (rnum)
        return ret
    
    def dispatch (self, work):
        if isinstance (work, datalink.Received):
            buf = work.packet
            if not buf:
                logging.debug ("Null MOP packet received on {}", self.name)
                return
            logging.trace ("MOP packet received on {}: {}",
                           self.name, bytes (buf))
            header = MopHdr (buf[:1])
            msgcode = header.code
            try:
                parsed = packetformats[msgcode] (buf)
            except KeyError:
                logging.debug ("MOP packet with unknown message code {} on {}",
                               msgcode, self.name)
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

    def get_api (self):
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
        
    def post_api (self, data):
        """Get counters.
        Input: dest (MAC address), optional timeout in seconds (default: 3)
        Output: status (a string: timeout or ok).  If ok, the counters.
        """
        logging.trace ("processing POST API call, counter request")
        dest = Macaddr (data["dest"])
        timeout = int (data.get ("timeout", 3))
        if timeout < 1:
            return { "status" : "invalid timeout" }
        pkt = RequestCounters ()
        reply = self.parent.exchange (pkt, dest, self.port, timeout)
        if reply is None:
            return { "status" : "timeout" }
        ret = { "status" : "ok" }
        for t, n, *x in Counters._layout:
            if t == "ctr":
                ret[n] = getattr (reply, n)
        ret["time_since_zeroed"] = reply.time_since_zeroed
        return ret
        
class SysIdHandler (Element, timers.Timer):
    """This class defines processing for SysId messages, both sending
    them (periodically and on request) and receiving them (multicast
    and directed).  We track received ones in a dictionary.
    """
    def __init__ (self, parent, port):
        Element.__init__ (self, parent)
        timers.Timer.__init__ (self)
        # Send the initial ID fairly soon after startup
        self.node.timers.start (self, self.id_self_delay () // 30)
        self.port = port
        self.mop = parent.parent
        self.heard = dict ()
        self.start_ts = time.time ()
        logging.debug ("Initialized sysid handler for {}", parent.name)

    def id_self_delay (self):
        return random.randint (8 * 60, 12 * 60)
    
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
        
    def get_api (self):
        logging.trace ("processing GET API call on sysid listener")
        ret = list ()
        for k, v in self.heard.items ():
            item = dict ()
            item["srcaddr"] = getattr (v, "src", "") or k
            item["console_user"] = getattr (v, "console_user", "")
            item["reservation_timer"] = getattr (v, "reservation_timer", 0)
            item["hwaddr"] = getattr (v, "hwaddr", "")
            systime = getattr (v, "time", "")
            if systime:
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
        return ret

class ConsolePost (Work):
    pass

class CarrierClient (Element, statemachine.StateMachine):
    """The client side of the console carrier protocol.
    """
    API_TIMEOUT = 120
    
    def __init__ (self, parent, data, listener):
        Element.__init__ (self, parent)
        statemachine.StateMachine.__init__ (self)
        self.listener = listener
        self.last_post = time.time ()
        self.port = parent.consport
        self.handle = random.getrandbits (64)
        self.outputq = queue.Queue ()
        try:
            dest = Macaddr (data["dest"])
            self.verification = scan_ver (data["verification"])
        except KeyError:
            self.listener.dispatch ({ "status" : "missing arguments" })
            return
        except ValueError:
            self.listener.dispatch ({ "status" : "Invalid argument value" })
            return
        dest = Macaddr (data["dest"])
        if dest in self.parent.carrier_client_dest:
            self.listener.dispatch ({ "status" : "destination busy" })
            return
        self.dest = dest
        self.parent.conn_clients[self.handle] = self
        self.parent.carrier_client_dest[dest] = self
        self.msg = RequestId ()
        self.sendmsg ()
        logging.debug ("Initialized console carrier client for {}, handle {}",
                       parent.name, self.handle)

    def post_api (self, data):
        if not data.get ("data", None) and not data.get ("close", False):
            # Not close and no data, so it's read
            if self.state == self.active:
                try:
                    ret = self.outputq.get (timeout = 60)
                except queue.Empty:
                    ret = { "status" : "ok", "data" : "" }
            else:
                try:
                    ret = self.outputq.get_nowait ()
                except Queue.Empty:
                    ret = { "status" : "closed" }
            return ret
        listen = WorkHandler ()
        w = ConsolePost (self, data = data, listener = listen)
        self.node.addwork (w)
        ret = listen.wait (timeout = 60)
        return ret
    
    def sendmsg (self, tries = 5, receipt = None):
        self.retries = tries
        self.node.timers.stop (self)
        self.node.timers.start (self, 1)
        if isinstance (self.msg, ConsoleCommand):
            self.port.send (self.msg, self.dest)
        else:
            self.parent.request (self, self.msg, self.dest, self.port, receipt = receipt)

    def close (self):
        """End this console carrier session.  Stop any timer and remove
        its entries in the lookup dictionaries.
        """
        self.node.timers.stop (self)
        self.msg = self.msg2 = self.listener = None
        try:
            del self.parent.conn_clients[self.handle]
        except KeyError:
            pass
        try:
            del self.parent.carrier_client_dest[self.dest]
        except KeyError:
            pass
        
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
                self.listener.dispatch ({ "status" : "no console carrier support" })
            else:
                self.listener.dispatch ({ "status" : "console carrier reserved",
                                          "client" : str (item.console_user) })
            self.close ()
        elif isinstance (item, timers.Timeout):
            # Timeout, try again if not at the limit
            self.retries -= 1
            if self.retries:
                self.sendmsg (self.retries)
            else:
                self.listener.dispatch ({ "status" : "no reply" })
                self.close ()
            
    def reserve (self, item):
        """Verify that reservation was successful.
        """
        if isinstance (item, SysId):
            # If the reservation succeeded, switch to active state to
            # run the two-way console data stream.
            if item.carrier_reserved:
                if item.console_user != self.port.macaddr:
                    self.listener.dispatch ({ "status" : "console carrier reserved",
                                              "client" : str (item.console_user) })
                    self.node.timers.stop (self)
                    self.listener = None
                    return self.s0
                self.seq = 0
                self.msg = None      # No poll message yet
                self.pendinginput = b""
                self.sendpoll ()
                self.listener.dispatch ({ "status" : "ok",
                                          "handle" : self.handle })
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
                self.listener.dispatch ({ "status" : "no reply" })
                self.close ()

    def sendpoll (self):
        """Send a new poll, or retransmit the previous one.
        """
        tries = self.retries
        if not self.msg:
            tries = 5
            self.seq ^= 1
            indata = self.pendinginput[:self.cmdsize]
            self.pendinginput = self.pendinginput[self.cmdsize:]
            self.msg = ConsoleCommand (seq = self.seq, payload = indata)
        self.node.timers.stop (self)
        self.node.timers.start (self, 1)
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
                data = str (data, encoding = "latin1")
                self.outputq.put ({ "status" : "ok", "data" : data })
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
            if time.time () - self.last_post > self.API_TIMEOUT:
                logging.debug ("Closing console client {} due to API timeout", self.dest)
                self.outputq.put ({ "status" : "api timeout" })
                self.sendrelease ()
                return self.release
            if self.retries:
                self.sendpoll ()
            else:
                self.outputq.put ({ "status" : "no response" })
                self.close ()
        elif isinstance (item, ConsolePost):
            data = item.data
            listener = item.listener
            if data.get ("close", False):
                # Close request -- release the console
                self.sendrelease ()
                listener.dispatch ({ "status" : "ok" })
                self.outputq.put ({ "status" : "closed", "data" : "" })
                return self.release
            # Input request, post it and say ok
            newinput = bytes (data["data"], encoding = "latin1")
            if self.pendinginput or self.msg:
                self.pendinginput += newinput
            else:
                self.pendinginput = newinput
                self.sendpoll ()
                listener.dispatch ({ "status" : "ok" })

    def release (self, item):
        """Verify that release was successful.
        """
        if isinstance (item, SysId) and item.receipt == self.msg.receipt:
            # If the reservation succeeded, switch to active state to
            # run the two-way console data stream.  
            if not (item.carrier_reserved and item.console_user == self.dest):
                logging.debug ("Console client closed for {}", self.dest)
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
        elif isinstance (item, ConsolePost):
            # data read or redundant close request when already closing,
            # say so.
            item.listener.dispatch ({ "status" : "closed" })
            

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
                logging.debug ("Started console server for {} {} process {}",
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
        logging.debug ("Closed console server for {} {}",
                       self.parent.name, self.remote)
        if self.pty:
            try:
                os.close (self.pty)
            except Exception:
                pass
        self.parent.carrier_server = None

    def dispatch (self, item):
        if isinstance (item, timers.Timer):
            # Reservation timeout, clear any reservation
            if self.pty:
                self.release ()
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
                self.node.timers.stop (self)
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
    
class LoopHandler (Element, timers.Timer):
    """Handler for loopback protocol
    """
    def __init__ (self, parent, datalink):
        Element.__init__ (self, parent)
        timers.Timer.__init__ (self)
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
                
    def post_api (self, data):
        """Perform a loop operation.
        Input: dest (MAC addresses), optional "timeout" in seconds (default: 3),
               optional "packets" -- count of packets (default: 1).
               By default there is a 1 second delay after a successful loop;
               optional "fast":true suppresses that delay.
        Output: a list of results for each packet: the round trip time in 
                seconds, or -1 to indicate that packet timed out.
        """
        logging.trace ("processing POST API call, counter request")
        dest = data.get ("dest", LOOPMC)
        if not isinstance (dest, list):
            dest = [ dest ]
        dest = [ Macaddr (d) for d in dest ]
        multidest = dest == [ LOOPMC ]
        if not multidest:
            for d in dest:
                if d.ismulti ():
                    return { "status" : "invalid address" }
        if len (dest) > 3:
            return  { "status" : "too many addresses" }
        # Add self as the last hop
        dest.append (self.port.macaddr)
        timeout = int (data.get ("timeout", 3))
        packets = int (data.get ("packets", 1))
        fast = data.get ("fast", False)
        if timeout < 1 or packets < 1:
            return { "status" : "invalid arguments" }
        ret = { "status" : "ok" }
        delays = list ()
        for i in range (packets):
            loopmsg, rnum = self.buildloop (dest[1:])
            sent = time.time ()
            reply = self.parent.exchange (loopmsg, dest[0],
                                          self.port, timeout, receipt = rnum)
            if reply is None:
                delays.append (-1)
            else:
                delays.append (time.time () - sent)
                if multidest:
                    dest[0] = reply.src
                    ret["dest"] = str (dest[0])
                if not fast:
                    if i < packets - 1:
                        time.sleep (1)
        ret["delays"] = delays
        return ret

    def buildloop (self, destlist):
        rnum = self.parent.receipt.next ()
        ret = LoopReply (receipt = rnum, payload = b"Python! " * 12)
        for dest in reversed (destlist):
            ret = LoopFwd (dest = dest, payload = ret)
        ret = LoopSkip (payload = ret)
        return ret, rnum

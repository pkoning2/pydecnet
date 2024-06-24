#!

"""Network management listener implementation.

Implementation of the DECnet network management (NICE) protocol.
Refer to the specification:
    DECnet Digital Network Architecture Phase IV
    Network Management Functional Specification
    Order no. AA-X437A-TK (December 1983)

This is the listener end of the protocol, i.e., it handles incoming 
event messages from another node to process requests from NCP.
"""

from decnet.common import *
from decnet import logging
from decnet import session
from decnet import nicepackets
from decnet.nsp import UnknownNode, WrongState

MYVERSION = ( 4, 0, 0 )

# Map Connect Reject codes from session control into mirror connect
# failure detail codes.
ses2mirror = {
    session.APPLICATION : 5,
    session.NO_OBJ : 7,
    session.BAD_FMT : 6,
    session.BAD_AUTH: 8,
    session.BAD_ACCT: 8,
    session.OBJ_FAIL: 12,
    session.UNREACH: 3,
    session.AUTH_LONG: 8
}

class LoopWork (Work):
    name = "Loop circuit work thread response"
    connection = message = False
    
class Application (Element):
    def __init__ (self, parent, obj):
        self.loop_conn = None
        self.apiclient = None
        self.mult = False
        # TODO: "zero" support is only just started
        self.readonly = True
        super ().__init__ (parent)

    def api (self, client, reqtype, tag, args):
        # Entry point for internal NICE requests (from a local NCP via
        # the general API).
        if reqtype != "nice":
            return dict (error = "invalid operation type")
        self.apiclient = client
        self.tag = tag
        self.phase2 = False
        self.replies = list ()
        try:
            req = args["data"]
        except KeyError:
            return dict (error = "missing 'data' argument")
        req = bytes (req, "latin1")
        item = session.Data (self, message = req, connection = self)
        self.dispatch (item)

    def sendreply (self, resp):
        resp = makebytes (resp)
        if self.apiclient:
            code = resp[0]
            if code > 127:
                code -= 256
            if code == 2:
                self.mult = True
                return
            elif code != -128:
                self.replies.append (resp)
                if self.mult:
                    return
            d = dict (tag = self.tag, api = "ncp",
                      system = self.node.nodename,
                      data = self.replies)
            self.apiclient.send_dict (d)
        else:
            self.niceconnection.send_data (resp)
            
    def dispatch (self, item):
        # Process work sent up from the Session Control layer. 
        conn = item.connection
        if conn is self.loop_conn:
            return self.loop_work (item)
        msg = item.message
        logging.tracepkt ("NICE {} message", item.name, pkt = msg)
        if isinstance (item, session.Data):
            try:
                req = nicepackets.NiceRequestHeader (msg)
            except DecodeError:
                logging.tracepkt ("Invalid NICE request packet",
                                  pkt = msg, level = logging.DEBUG)
                resp = nicepackets.NiceReply ()
                resp.retcode = -1   # Unrecognized function
                self.sendreply (resp)
                return
            if isinstance (req, nicepackets.NiceTestHeader) \
               and not self.phase2:
                return self.loop_request (req)
            elif not isinstance (req, (nicepackets.NiceReadInfoHdr,
                                       nicepackets.P2NiceReadInfoHdr)):
                # Load/dump, or some flavor of modify, or system
                # dependent.  Do further checking.
                # Right now, the only other thing we support is
                # zero counters
                if isinstance (req, nicepackets.NiceZeroCtrHdr):
                    if self.readonly:
                        logging.trace ("Read-only NICE violation")
                        resp = nicepackets.NiceReply ()
                        resp.retcode = -3   # Privilege violation
                        self.sendreply (resp)
                        return
                else:
                    logging.trace ("Unsupported NICE request")
                    resp = nicepackets.NiceReply ()
                    resp.retcode = -1   # Unrecognized function
                    self.sendreply (resp)
                    return
            # At this point, we have a read info message (phase 2 or
            # phase 3/4).
            resp = 0
            detail = 0xffff
            # Check protocol
            if isinstance (req, nicepackets.P2NiceReadInfoHdr) != self.phase2:
                # Phase 2 but new read info, or old read info but not phase 2
                if isinstance (req, nicepackets.P2NiceReadInfoHdr):
                    # Unexpected request was Phase 2 format, reply
                    # that way (rather than replying using the
                    # negotiated protocol level, since clearly
                    # something was lost in the exchange).  A case
                    # where this can happen is when sending NICE
                    # through PMR, which (in the standard version)
                    # does not return the responsing side accept data
                    # where NICE keeps the protocol version number.
                    # So NCP would mistake the far end for a Phase 2
                    # NICE.
                    resp = nicepackets.P2NiceReply1 ()
                else:
                    resp = nicepackets.NiceReply ()
                    resp.detail = 0xffff
                resp.retcode = -1    # Unrecognized function
                self.sendreply (resp)
                return
            if isinstance (req, nicepackets.NiceReadInfoHdr) \
               and req.permanent:
                logging.trace ("Read permanent data not supported")
                resp = -1   # Unrecognized function
            else:
                resp = self.node.nice_read (req)
            if not resp:     # Reply is None or empty
                if not req.mult ():
                    # Request was for a specific entity, so if we
                    # don't get information back that means
                    # "unrecognized component"
                    resp = -8    # Unrecognized component
            if isinstance (resp, int):
                # Error code returned
                logging.trace ("Read data error code {}", resp)
                if self.phase2:
                    resp2 = nicepackets.P2NiceReply1 ()
                else:
                    resp2 = nicepackets.NiceReply ()
                    resp2.detail = detail
                resp2.retcode = resp
                self.sendreply (resp2)
                return
            resp = [ v for k, v in resp.sorted (req) ]
            if self.phase2:
                resp2 = nicepackets.P2NiceReply3 ()
                resp2.count = len (resp)
                self.sendreply (resp2)
                for r in resp:
                    logging.trace ("Sending reply {}", r)
                    self.sendreply (r)
            else:
                if len (resp) == 1 and (not isinstance (resp[0], list) or
                                        len (resp[0]) == 1):
                    resp = resp[0]
                    if isinstance (resp, list):
                        resp = resp[0]
                    resp.retcode = 1   # success
                    logging.trace ("Sending reply {}", resp)
                    self.sendreply (resp)
                else:
                    resp0 = nicepackets.NiceReply ()
                    resp0.retcode = 2   # multiple items
                    self.sendreply (resp0)
                    logging.trace ("Sending reply {}", resp0)
                    for r in resp:
                        if not r:
                            continue
                        if isinstance (r, list):
                            for r2 in r[:-1]:
                                r2.retcode = 3  # more for this entity
                                logging.trace ("Sending reply {}", r2)
                                self.sendreply (r2)
                            r = r[-1]
                        r.retcode = 1  # success
                        logging.trace ("Sending reply {}", r)
                        self.sendreply (r)
                    resp = nicepackets.NiceReply ()
                    resp.retcode = -128   # end of multiple items
                    logging.trace ("Sending reply {}", resp)
                    self.sendreply (resp)
        elif isinstance (item, session.ConnectInit):
            # Check the connect data (in "msg") which carries the
            # protocol version number. 
            self.rversion = msg[:3]
            # If no version number is sent, it's a Phase II NCP, which
            # is a rather different protocol.
            self.phase2 = not self.rversion
            if self.rversion:
                vstr = "version " + ".".join (str (i) for i in self.rversion)
                # Accept the connection; our version number is 4.0.0.
                conn.accept (MYVERSION)
            else:
                vstr = "Phase II"
                # Accept the connection Phase II style
                conn.accept ()
            logging.trace ("Network management listener connection from {}, {}",
                           conn.remotenode, vstr)
            # Remember the connection
            self.niceconnection = conn
        elif isinstance (item, session.Disconnect):
            logging.trace ("Network management listener disconnect from {}",
                           conn.remotenode)
        elif isinstance (item, LoopWork):
            return self.loop_circuit_work (item)

    def loop_request (self, req):
        """Process a NICE "loop" request.
        """
        logging.trace ("Loop request: {}", req)
        if isinstance (req, nicepackets.NiceLoopCircuit):
            return self.loop_circuit (req)
        elif not isinstance (req, nicepackets.NiceLoopNodeBase):
            logging.trace ("Unsupported NICE loop request")
            resp = nicepackets.NiceLoopErrorReply ()
            resp.retcode = -1
            resp.notlooped = 0
            self.sendreply (resp)
            return
        # Set up state for the loop operation to be done
        w = getattr (req, "loop_with", 2)       # default type MIXED
        l = getattr (req, "loop_length", 128)   # default length 128
        self.loop_count = getattr (req, "loop_count", 1)  # default 1 msg
        # Argument validation
        badarg = None
        if w == 0:
            payload = b'\x00'
        elif w == 1:
            payload = b'\xff'
        elif w == 2:
            payload = b'\x55'
        else:
            badarg = 152
        if l < 1 or l > 65535:
            badarg = 151
        if self.loop_count < 1:
            badarg = 150
        if badarg:
            logging.trace ("Invalid argument in NICE loop request")
            resp = nicepackets.NiceLoopErrorReply ()
            resp.retcode = -16
            resp.detail = badarg
            resp.notlooped = self.loop_count
            self.sendreply (resp)
            return
        self.loop_data = payload * l
        # Send off a connect request to the specified node.  When the
        # response arrives we'll handle that in loop_work.
        try:
            self.loop_conn = self.parent.connect (req.entity.value, 25, b"",
                                                  req.username, req.password,
                                                  req.account)
        except UnknownNode:
            resp = nicepackets.NiceLoopErrorReply ()
            resp.retcode = -21   # Mirror connect request failed
            resp.detail = 2      # Unknown node name
            resp.notlooped = self.loop_count
            self.sendreply (resp)
            
    def loop_work (self, item):
        # Work item handler for LOOP NODE (for the traffic relating to
        # the connection to the mirror object).
        msg = item.message
        logging.tracepkt ("LOOP {} message", item.name, pkt = msg)
        if isinstance (item, session.Data):
            f = msg[0]
            if f == 1:
                # Mirror says success
                if msg[1:] == self.loop_data:
                    # We're happy.  Count down and stop if we're done,
                    # else send another request.
                    self.loop_count -= 1
                    if self.loop_count < 1:
                        self.loop_conn.disconnect ()
                        self.loop_conn = None
                        resp = nicepackets.NiceLoopReply ()
                        resp.retcode = 1
                        self.sendreply (resp)
                        return
                    self.loop_conn.send_data (b'\x00' + self.loop_data)
                    return
            self.loop_conn.abort()
            self.loop_conn = None
            resp = nicepackets.NiceLoopErrorReply ()
            resp.retcode = -28
            resp.notlooped = self.loop_count
            self.sendreply (resp)
        elif isinstance (item, session.Accept):
            maxlen = int.from_bytes (msg[:2], "little")
            logging.trace ("Loop: server max length is {}", maxlen)
            if maxlen < len (self.loop_data) + 1:
                self.loop_conn.abort()
                self.loop_conn = None
                resp = nicepackets.NiceLoopErrorReply ()
                resp.retcode = -16   # Invalid parameter value
                resp.detail = 151    # Loop length
                resp.notlooped = self.loop_count
                self.sendreply (resp)
                return
            # We're happy, send the first loop data message.
            self.loop_conn.send_data (b'\x00' + self.loop_data)
        elif isinstance (item, session.Reject):
            self.loop_conn = None
            resp = nicepackets.NiceLoopErrorReply ()
            resp.retcode = -21   # Mirror connect request failed
            try:
                reason = ses2mirror[item.reason]
            except KeyError:
                reason = 0
            resp.detail = reason
            resp.notlooped = self.loop_count            
            self.sendreply (resp)
        else:
            # Something else went wrong, call it a disconnect
            try:
                self.loop_conn.abort()
            except DNAException:
                pass
            self.loop_conn = None
            resp = nicepackets.NiceLoopErrorReply ()
            resp.retcode = -19   # Mirror connection failed
            resp.detail = 0      # TODO
            resp.notlooped = self.loop_count
            self.sendreply (resp)

    def loop_circuit (self, req):
        """Process a NICE "loop circuit" request.
        """
        circname = req.entity.value
        try:
            looper = self.node.mop.circuits[circname.upper ()].loop
        except Exception:
            resp = nicepackets.NiceLoopErrorReply ()
            resp.retcode = -8
            resp.detail = nicepackets.CircuitReqEntity.e_type
            resp.notlooped = 0
            self.sendreply (resp)
            return
        # Set up state for the loop operation to be done
        badarg = None
        msg = None
        w = getattr (req, "loop_with", 2)       # default type MIXED
        l = getattr (req, "loop_length", 128)   # default length 128
        self.loop_count = getattr (req, "loop_count", 1)  # default 1 msg
        to = getattr (req, "physical_address", None)
        if to:
            to = Macaddr (to)
        else:
            to = getattr (req, "loop_node", None)
            if to:
                to = Macaddr (self.node.nodeinfo (to))
        assist = getattr (req, "loop_help", -1)
        if assist != -1:
            if not to:
                badarg = 10
                msg = "Either Physical Address or Node must be specified"
            helper = getattr (req, "assistant_pa", None)
            if helper:
                helper = Macaddr (helper)
                if helper.ismulti ():
                    badarg = 153
                    msg = "Assistant address must not be multicast"
            else:
                helper = getattr (req, "assistant_node", None)
                if not helper:
                    badarg = 153
                    msg = "Either Loop Assistant Physical Address or "\
                          "Loop Node must be specified"
                else:
                    helper = Macaddr (self.node.nodeinfo (helper))
            if assist > 2:
                badarg = 154
        if w == 0:
            payload = b'\x00'
        elif w == 1:
            payload = b'\xff'
        elif w == 2:
            payload = b'\x55'
        else:
            badarg = 152
        if l < 1 or l > 1490:
            badarg = 151
        if self.loop_count < 1:
            badarg = 150
        if badarg:
            logging.trace ("Invalid argument in NICE loop request")
            resp = nicepackets.NiceLoopErrorReply ()
            resp.retcode = -16
            resp.detail = badarg
            if msg:
                resp.message = msg
            resp.notlooped = self.loop_count
            self.sendreply (resp)
            return
        dest = [ ]
        payload *= l
        if assist == 0 or assist == 2:
            dest = [ helper ]
        if to:
            dest.append (to)
        if assist == 1 or assist == 2:
            dest.append (helper)
        mopreq = dict (dest = dest, packets = self.loop_count,
                       payload = payload)
        ret = looper.api (self, 0, mopreq, True)
        if ret:
            # Some error response.  Payload too long can happen
            # because we don't do detailed validation of the length
            # (MOP owns those rules, we don't).  Others should not.
            logging.trace ("Reply from API: {}", repr (ret))
            resp = nicepackets.NiceLoopErrorReply ()
            resp.notlooped = self.loop_count
            msg = ret["status"]
            if msg == "payload too long":
                resp.retcode = -16   # Invalid parameter value
                resp.detail = 151    # loop length
                resp.notlooped = ret["limit"]
            else:
                resp.retcode = -25   # operation failure
                resp.message = msg
            self.sendreply (resp)
            return
        # No return value, so the reply will be asynchronous via
        # mop_loop_done.

    def mop_loop_done (self, ret):
        # This is how the MOP circuit loop server returns its results
        logging.trace ("Async reply from API: {}", repr (ret))
        if isinstance (ret, int):
            # ret is the number of messages not looped
            resp = nicepackets.NiceLoopErrorReply ()
            resp.notlooped = ret
            resp.retcode = -25       # operation failure
        else:
            # Success, ret is the address of the replying station.
            assert isinstance (ret, Macaddr)
            resp = nicepackets.NiceLoopReply ()
            resp.retcode = 1
            resp.physical_address = ret
        try:
            self.sendreply (resp)
        except WrongState:
            pass

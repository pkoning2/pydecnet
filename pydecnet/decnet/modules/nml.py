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
from decnet import session
from decnet import pktlogging
from decnet import nicepackets
from decnet.nsp import UnknownNode, WrongState

SvnFileRev = "$LastChangedRevision$"

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
        # TODO: "zero" support is only just started
        self.readonly = True
        super ().__init__ (parent)

    def dispatch (self, item):
        # Process work sent up from the Session Control layer. 
        conn = item.connection
        if conn is self.loop_conn:
            return self.loop_work (item)
        msg = item.message
        pktlogging.tracepkt ("NICE {} message".format (item.name), msg)
        if isinstance (item, session.Data):
            try:
                fun = msg[0]
                if fun == nicepackets.NiceTestHeader.function:
                    return self.loop_request (conn, msg)
                elif fun != nicepackets.NiceReadInfoHdr.function:
                    # Load/dump, or some flavor of modify, or system
                    # dependent.  Do further checking.
                    # Right now, the only other thing we support is
                    # zero counters
                    if fun == nicepackets.NiceZeroCtrHdr.function:
                        if self.readonly:
                            logging.trace ("Read-only NICE violation")
                            resp = nicepackets.NiceReply ()
                            resp.retcode = -3   # Privilege violation
                            conn.send_data (resp)
                            return
                        baseclass = nicepackets.NiceZeroCtrHdr
                    else:
                        logging.trace ("Unsupported NICE request")
                        resp = nicepackets.NiceReply ()
                        resp.retcode = -1   # Unrecognized function
                        conn.send_data (resp)
                        return
                else:
                    baseclass = nicepackets.NiceReadInfoHdr
                ent = msg[1] & 0x07
                cls = baseclass.findclass (ent)
                resp = 0
                detail = 0xffff
                try:
                    req = cls (msg)
                    detail = req.entity_class.e_type
                except DecodeError:
                    pktlogging.tracepkt ("Invalid NICE request packet", msg,
                                         logging.DEBUG)
                    resp = -1
                if not resp:
                    if isinstance (req, nicepackets.NiceReadInfoHdr) \
                       and req.permanent:
                        logging.trace ("Read permanent data not supported")
                        resp = -1   # Unrecognized function
                    else:
                        resp = self.node.nice_read (req)
                if not resp:     # Reply is None or empty
                    if resp is None or \
                       not isinstance (resp, nicepackets.NiceZeroCtrHdr):
                        # Rejected, or empty data for read info   
                        resp = -8    # Unrecognized component
                if isinstance (resp, int):
                    # Error code returned
                    logging.trace ("Read data error code {}", resp)
                    resp2 = nicepackets.NiceReply ()
                    resp2.retcode = resp
                    resp2.detail = detail
                    conn.send_data (resp2)
                    return
                resp = [ v for k, v in resp.sorted (req) ]
                if len (resp) == 1 and (not isinstance (resp[0], list) or
                                        len (resp[0]) == 1):
                    resp = resp[0]
                    if isinstance (resp, list):
                        resp = resp[0]
                    resp.retcode = 1   # success
                    conn.send_data (resp)
                else:
                    resp0 = nicepackets.NiceReply ()
                    resp0.retcode = 2   # multiple items
                    conn.send_data (resp0)
                    for r in resp:
                        if not r:
                            continue
                        if isinstance (r, list):
                            for r2 in r[:-1]:
                                r2.retcode = 3  # more for this entity
                                conn.send_data (r2)
                            r = r[-1]
                        r.retcode = 1  # success
                        conn.send_data (r)
                    resp = nicepackets.NiceReply ()
                    resp.retcode = -128   # end of multiple items
                    conn.send_data (resp)
            except DecodeError:
                pktlogging.tracepkt ("Error parsing NICE request", msg,
                                     logging.DEBUG)
        elif isinstance (item, session.ConnectInit):
            # Check the connect data (in "msg") which carries the
            # protocol version number.  Here we save it in case it's
            # needed but take no action on it; it doesn't seem that
            # there are any version dependent algorithms in this
            # protocol.
            self.rversion = msg[:3]
            logging.trace ("Network management listener connection from {}, version {}",
                           conn.remotenode,
                           ".".join (str (i) for i in self.rversion))
            # Accept the connection; our version number is 4.0.0.
            conn.accept (MYVERSION)
            # Remember the connection
            self.niceconnection = conn
        elif isinstance (item, session.Disconnect):
            logging.trace ("Network management listener disconnect from {}",
                           conn.remotenode)
        elif isinstance (item, LoopWork):
            return self.loop_circuit_work (item)

    def loop_request (self, conn, msg):
        """Process a NICE "loop" request.
        """
        req, x = nicepackets.NiceTestHeader.decode (msg)
        logging.trace ("Loop request: {}", req)
        if req.test_type == nicepackets.NiceLoopCircuit.test_type:
            return self.loop_circuit (conn, msg)
        elif req.test_type != nicepackets.NiceLoopNode.test_type:
            logging.trace ("Unsupported NICE loop request")
            resp = nicepackets.NiceLoopErrorReply ()
            resp.retcode = -1
            resp.notlooped = 0
            conn.send_data (resp)
            return
        if req.access_ctl:
            req = nicepackets.NiceLoopNodeAcc (msg)
        else:
            req = nicepackets.NiceLoopNode (msg)
        logging.trace ("Loop Node request: {}", req)
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
            conn.send_data (resp)
            return

        self.loop_data = payload * l
        self.loop_req_conn = conn
        # Send off a connect request to the specified node.  When the
        # response arrives we'll handle that in loop_work.
        try:
            self.loop_conn = self.parent.connect (req.node.value, 25, b"",
                                                  req.username, req.password,
                                                  req.account)
        except UnknownNode:
            resp = nicepackets.NiceLoopErrorReply ()
            resp.retcode = -21   # Mirror connect request failed
            resp.detail = 2      # Unknown node name
            resp.notlooped = self.loop_count
            conn.send_data (resp)
            
    def loop_work (self, item):
        # Work item handler for LOOP NODE (for the traffic relating to
        # the connection to the mirror object).
        msg = item.message
        pktlogging.tracepkt ("LOOP {} message".format (item.name), msg)
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
                        self.loop_req_conn.send_data (resp)
                        return
                    self.loop_conn.send_data (b'\x00' + self.loop_data)
                    return
            self.loop_conn.abort()
            self.loop_conn = None
            resp = nicepackets.NiceLoopErrorReply ()
            resp.retcode = -28
            resp.notlooped = self.loop_count
            self.loop_req_conn.send_data (resp)
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
                self.loop_req_conn.send_data (resp)
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
            self.loop_req_conn.send_data (resp)
        else:
            # Something else went wrong, call it a disconnect
            self.loop_conn.abort()
            self.loop_conn = None
            resp = nicepackets.NiceReply ()
            resp.retcode = -19   # Mirror connection failed
            resp.detail = 0      # TODO
            resp.notlooped = self.loop_count
            self.loop_req_conn.send_data (resp)

    def loop_circuit (self, conn, msg):
        """Process a NICE "loop circuit" request.
        """
        req = nicepackets.NiceLoopCircuit (msg)
        logging.trace ("Loop circuit request: {}", req)
        circname = req.circuit.value
        try:
            looper = self.node.mop.circuits[circname.upper ()].loop
        except Exception:
            resp = nicepackets.NiceLoopErrorReply ()
            resp.retcode = -8
            resp.detail = nicepackets.CircuitReqEntity.e_type
            resp.not_looped = 0
            conn.send_data (resp)
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
            helper = getattr (req, "loop_assistant_physical_address", None)
            if helper:
                helper = Macaddr (helper)
                if helper.ismulti ():
                    badarg = 153
                    msg = "Assistant address must not be multicast"
            else:
                helper = getattr (req, "loop_assistant_node", None)
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
            conn.send_data (resp)
            return
        dest = [ ]
        payload *= l
        if assist == 0 or assist == 2:
            dest = [ helper ]
        if to:
            dest.append (to)
        if assist == 1 or assist == 2:
            dest.append (helper)
        self.mopreq = dict (dest = dest,
                            packets = self.loop_count,
                            payload = payload)
        t = StopThread (target = self.loopthread, name = "loop circuit",
                        args = (self, looper))
        t.start ()

    def loopthread (self, owner, looper):
        # The actual I/O for loop circuit is done in this thread,
        # which calls MOP just as if it were processing a REST API
        # request.
        logging.trace ("Loop thread, issuing request {}",
                       repr (owner.mopreq))
        ret = looper.post_api (owner.mopreq, True)
        logging.trace ("Reply from API: {}", repr (ret))
        w = LoopWork (owner = owner, result = ret)
        owner.node.addwork (w)
        
    def loop_circuit_work (self, w):
        ret = w.result
        if isinstance (ret, dict):
            # Some error response.  Payload too long can happen
            # because we don't do detailed validation of the length
            # (MOP owns those rules, we don't).  Others should not.
            resp = nicepackets.NiceLoopErrorReply ()
            resp.notlooped = self.loop_count
            msg = ret["status"]
            if msg == "payload too long":
                resp.retcode = -16   # Invalid parameter value
                resp.detail = 151    # loop length
            else:
                resp.retcode = -25   # operation failure
                resp.message = msg
        elif isinstance (ret, int):
            # No reply, ret is the number of messages not looped
            resp = nicepackets.NiceLoopErrorReply ()
            resp.notlooped = ret
            resp.retcode = -25       # operation failure
        else:
            # Success
            assert isinstance (ret, Macaddr)
            resp = nicepackets.NiceLoopReply ()
            resp.physical_address = ret
        try:
            self.niceconnection.send_data (resp)
        except WrongState:
            pass
        

#!

"""NSP (End Communications and Session Control layers) for DECnet/Python

"""

from collections import deque
import random
import importlib
import shutil

from .common import *
from . import logging
from . import events
from . import packet
from . import timers
from . import statemachine
from . import nsp
from . import application_process
from . import html

# General errors for this layer
class SessException (DNAException): pass
class UnexpectedPkt (SessException): "Unexpected NSP packet"

# Packet parse errors
class BadEndUser (DecodeError): "Invalid value in EndUser field"

# Reason codes for connect reject
APPLICATION = 0     # Application reject (or disconnect)
NO_OBJ = 4          # Destination end user does not exist
BAD_FMT = 5         # Connect Init format error
BAD_AUTH = 34       # Authorization data not valid (username/password)
BAD_ACCT = 36       # Account not valid
OBJ_FAIL = 38       # Object failed
UNREACH = 39        # Destination unreachable
AUTH_LONG = 43      # Authorization data fields too long

# Reason codes for disconnect
ABORT = 9           # Connection aborted

# Work items sent up to the application.  All have fields "connection"
# (the SessionConnection) and "message" (the application data).
# Disconnect and reject also have a "reason" field.
class ApplicationWork (Work): pass

class Data (ApplicationWork):
    "Normal data message"
    name = "data"
class Interrupt (ApplicationWork):
    "Interrupt message"
    name = "interrupt"
class Disconnect (ApplicationWork):
    "Disconnect message"
    name = "disconnect"
class Accept (ApplicationWork):
    "Connect accept message"
    name = "accept"
class Reject (ApplicationWork):
    "Connect reject message"
    name = "reject"
class ConnectInit (ApplicationWork):
    "Connect Initialize message"
    name = "connect"
class ConnectConfirm (ApplicationWork):
    "Connect confirm message"
    name = "confirm"
    
class EndUser (object):
    """Class for the "End user" field in Connect Initiate data.
    """
    def __init__ (self, num = 0, name = "", group = None, user = None):
        if num not in range (256) or len (name) > 16:
            raise ValueError ("Invalid num and/or name")
        self.num = num
        self.name = name
        self.group = group
        self.user = user
        if num:
            self.fmt = 0
        elif self.group is not None:
            self.fmt = 2
        else:
            self.fmt = 1
            
    @classmethod
    def decode (cls, buf):
        if len (buf) < 2:
            raise MissingData
        fmt = buf[0]
        num = buf[1]
        if fmt > 2:
            raise BadEndUser ("Invalid end user format {}", fmt)
        if fmt == 0:
            if num == 0:
                raise BadEndUser ("Format 0 with zero number")
            return cls (num), buf[2:]
        if fmt == 1:
            if num != 0:
                raise BadEndUser ("Format 1 with non-zero number {}", num)
            flen, name = packet.decode_a_value (buf[2:], 16)
            if not name:
                raise BadEndUser ("Format 1 with no name")
            return cls (name = name), buf[3 + flen:]
        if num != 0:
            raise BadEndUser ("Format 2 with non-zero number {}", num)
        group = int.from_bytes (buf[2:4], packet.LE)
        user = int.from_bytes (buf[4:6], packet.LE)
        flen, name = packet.decode_a_value (buf[6:], 16)
        if not name:
            raise BadEndUser ("Format 2 with no name")
        return cls (0, name, group, user), buf[7 + flen:]

    def __bytes__ (self):
        if self.num:
            self.fmt = 0
            if self.name:
                raise ValueError ("Can't specify both num and name")
        else:
            self.fmt = 1
            if not self.name:
                raise ValueError ("Must specify one of num or name")
        start = byte (self.fmt) + byte (self.num)
        if self.fmt:
            return start + packet.encode_i_value (self.name, 16)
        return start

    def __str__ (self):
        if self.fmt == 0:
            return "{}".format (self.num)
        if self.fmt == 1:
            return "{}".format (self.name)
        return "[{0.group},{0.user}]{0.name}".format (self)

LocalUser = EndUser (name = "PyDecnet")

class SessionConnInit (packet.Packet):
    _addslots = { "rqstrid", "passwrd", "account", "connectdata", "payload" }
    _layout = (( EndUser, "dstname" ),
               ( EndUser, "srcname" ),
               ( "bm",
                 ( "auth", 0, 1 ),
                 ( "userdata", 1, 1 ),
                 ( "proxy", 2, 1 ),
                 ( "proxy_uic", 3, 1 ),
                 ( "reserved", 4, 1 ),
                 ( "scver", 5, 2 ),
                 ( "mbz2", 7, 1 )))
    mbz2 = 0
    SCVER1 = 0   # Session Control 1.0
    SCVER2 = 1   # Session Control 2.0

    def encode (self):
        self.auth = self.userdata = 0
        payload = list ()
        if self.rqstrid or self.passwrd or self.account:
            payload.append (packet.encode_i_value (self.rqstrid, 39))
            payload.append (packet.encode_i_value (self.passwrd, 39))
            payload.append (packet.encode_i_value (self.account, 39))
            self.auth = 1
        if self.connectdata:
            payload.append (packet.encode_i_value (self.connectdata, 16))
            self.userdata = 1
        self.payload = b''.join (payload)
        return super ().encode ()
        
    def check (self):
        # Post-processing: pick up optional fields, which land in
        # "payload" during base parse.
        buf = self.payload
        # Set fields to their default value
        self.rqstrid = self.passwrd = self.account = ""
        self.connectdata = b""
        if buf:
            if self.auth:
                # Authentication fields are present.
                flen, self.rqstrid = packet.decode_a_value (buf, 39)
                buf = buf[flen + 1:]
                flen, self.passwrd = packet.decode_a_value (buf, 39)
                buf = buf[flen + 1:]
                flen, self.account = packet.decode_a_value (buf, 39)
                buf = buf[flen + 1:]
            if self.userdata:
                flen, self.connectdata = packet.decode_i_value (buf, 16)
                buf = buf[flen + 1:]
            if buf:
                logging.debug ("Extra data in session control CI packet")
        else:
            if self.auth or self.userdata:
                raise MissingData
            
class SessionObject (Element):
    def __init__ (self, parent, number, name = "", module = "", file = ""):
        super ().__init__ (parent)
        self.argument = ""
        self.number = number
        self.name = name
        self.module = module
        self.file = file
        if not self.number and not self.name:
            raise ArgumentError ("At least one of name and number must be specified")
        if len (self.name) > 16:
            raise ValueError ("Name too long")
        self.name = self.name.upper ()
        if self.file:
            f = shutil.which (self.file)
            if not f:
                raise ValueError ("File {} not found or not executable".format (self.file))
            self.file = f
            self.app_class = application_process.Application
        elif self.module:
            mod = importlib.import_module (self.module)
            self.app_class = mod.Application
        else:
            raise ArgumentError ("Either file or module must be specified")
        if name:
            parent.obj_name[name] = self
        if number:
            parent.obj_num[number] = self

class DefObj (dict):
    def __init__ (self, name, num, module):
        self.name = name.upper ()
        self.number = num
        self.module = module
        self.file = None
        
defobj = ( DefObj ("MIRROR", 25, "decnet.applications.mirror"),
         )

class SessionConnection (Element):
    def __init__ (self, parent, nspconn, localuser, remuser):
        super ().__init__ (parent)
        self.nspconn = nspconn
        self.localuser = localuser
        self.remuser = remuser

    def accept (self, data = b""):
        return self.nspconn.accept (data)

    def reject (self, data = b""):
        self.nspconn.reject (APPLICATION, data)
        del self.parent.conns[self.nspconn]
    
    def disconnect (self, data = b""):
        self.nspconn.disconnect (APPLICATION, data)
        del self.parent.conns[self.nspconn]

    def abort (self, data = b""):
        self.nspconn.abort (ABORT, data)
        del self.parent.conns[self.nspconn]

    def interrupt (self, data):
        return self.nspconn.interrupt (data)

    def send_data (self, data):
        return self.nspconn.send_data (data)
    
class Session (Element):
    """The session control layer.  This owns all session control
    components.  It talks to NSP for service, to built-in applications,
    and to the session control API for external applications.
    """
    def __init__ (self, parent, config):
        super ().__init__ (parent)
        self.config = config.session
        self.obj_num = dict ()
        self.obj_name = dict ()
        self.conns = dict ()
        for d in defobj:
            # Add default (built-in) objects
            obj = SessionObject (self, d.number, d.name, d.module)
        # Add objects from the config
        for obj in config.object:
            if obj.disable:
                try:
                    o2 = self.obj_num[obj.number]
                    del self.obj_num[o2.number]
                    del self.obj_name[o2.name]
                except KeyError:
                    logging.debug ("Disabling object {} which is not a built-in object",
                                   obj.number)
            else:
                obj = SessionObject (self, obj.number, obj.name,
                                     obj.module, obj.file)
        for k, v in sorted (self.obj_num.items ()):
            if v.module:
                logging.debug ("Session control object {0.number} ({0.name}) module {0.module}", v)
            else:
                logging.debug ("Session control object {0.number} ({0.name}) file {0.file}",
                               v)
        for k, v in sorted (self.obj_name.items ()):
            if not v.number:
                logging.debug ("Session control object {0.name} file {0.file}", v)

    def start (self):
        logging.debug ("Starting Session Control")
        self.nsp = self.parent.nsp

    def stop (self):
        logging.debug ("Stopping Session Control")

    def get_api (self):
        return { "version" : "2.0.0" }    # ?

    def connect (self, dest, payload):
        # FIXME: this needs to be given meaningful SC type arguments,
        # like destination object description, then the NSP payload is
        # constructed from that.  The generated dest user field then
        # goes into the fourth argument of SessionConnection.
        nspconn = self.node.nsp.connect (dest, payload)
        self.conns[nspconn] = ret = SessionConnection (self, nspconn,
                                                       LocalUser, None)
        return ret

    def html_objects (self):
        # Return an HTML item for the object database
        title = "Session control object database"
        hdr = ("Object", "Name", "Type", "Destination")
        items = [ (0, o.name, o) for o in self.obj_name.values () if not o.number ]
        items.extend ([ (o.number, o.name, o) for o in self.obj_num.values () ])
        items.sort ()
        items = [ (n if n else "", m,
                   "Module" if o.module else "File",
                   o.module if o.module else o.file) for n, m, o in items ]
        return html.tbsection (title, hdr, items)

    def html_localuser (self, nspconn):
        try:
            return self.conns[nspconn].localuser
        except KeyError:
            return ""
        
    def html_remuser (self, nspconn):
        try:
            return self.conns[nspconn].remuser
        except KeyError:
            return ""
        
    def dispatch (self, item):
        if isinstance (item, Received):
            nspconn = item.connection
            pkt = item.packet
            if logging.tracing:
                logging.trace ("Received from NSP: {} conn {} reject {}",
                               pkt, nspconn, item.reject)
            if nspconn not in self.conns:
                if not isinstance (pkt, nsp.ConnInit):
                    # Complain and then ignore this.
                    logging.debug ("NSP packet but no connection: {}", pkt)
                    return
                # Parse the connect data
                try:
                    spkt = SessionConnInit (pkt.payload)
                    logging.trace ("Connect Init data {}", spkt)
                except packet.DecodeError:
                    logging.debug ("Invalid Connect Init data {}",
                                   bytes (pkt.payload))
                    nspconn.reject (BAD_FMT, b"")
                    return
                # Look up the object
                try:
                    if spkt.dstname.num:
                        sesobj = self.obj_num[spkt.dstname.num]
                    else:
                        sesobj = self.obj_name[spkt.dstname.name.upper ()]
                except KeyError:
                    logging.debug ("Replying with connect reject, no such object {0.num} ({0.name})",
                                   spkt.dstname)
                    nspconn.reject (NO_OBJ)
                    return
                conn = SessionConnection (self, nspconn,
                                          spkt.dstname, spkt.srcname)
                self.conns[nspconn] = conn
                data = spkt.connectdata
                awork = ConnectInit (self, message = data, connection = conn)
                # TODO: find api user in "listen" mode
                try:
                    logging.trace ("starting object {0.num} ({0.name})",
                                   spkt.dstname)
                    conn.client = sesobj.app_class (self, sesobj)
                    conn.client.dispatch (awork)
                except Exception:
                    logging.debug ("Object application (module) exception at startup")
                    nspconn.reject (OBJ_FAIL)
                    del self.conns[nspconn]
                    return
            else:
                conn = self.conns[nspconn]
                if isinstance (pkt, nsp.DataSeg):
                    awork = Data (self, message = pkt.payload,
                                  connection = conn)
                elif isinstance (pkt, nsp.IntMsg):
                    awork = Interrupt (self, message = pkt.payload,
                                       connection = conn)
                elif isinstance (pkt, nsp.ConnConf):
                    awork = Accept (self, message = pkt.data_ctl,
                                    connection = conn)
                elif isinstance (pkt, (nsp.DiscInit, nsp.DiscConf)):
                    if item.reject:
                        awork = Reject (self, message = pkt.data_ctl,
                                        connection = conn,
                                        reason = pkt.reason)
                    else:
                        awork = Disconnect (self, message = pkt.data_ctl,
                                            connection = conn,
                                            reason = pkt.reason)
                    del self.conns[nspconn]
                else:
                    logging.debug ("Unexpected work item {}", item)
                    return
                try:
                    conn.client.dispatch (awork)
                except Exception:
                    logging.debug ("Object application (module) exception")
                    try:
                        nspconn.abort (OBJ_FAIL)
                    except Exception:
                        logging.exception ("abort failed")
                    del self.conns[nspconn]
                    return

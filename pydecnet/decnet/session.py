#!

"""Session Control layer for DECnet/Python

"""

import subprocess
import os
import sys
import signal
import importlib
import shutil
import pwd
import functools
try:
    import pam
    pamobj = pam.pam ()
except ImportError:
    pam = None

from .common import *
from . import logging
from . import events
from . import packet
from . import timers
from . import statemachine
from . import nsp
from . import html
from . import nice_coding

SvnFileRev = "$LastChangedRevision$"

# General errors for this layer
class SessException (DNAException): pass
class UnexpectedPkt (SessException): "Unexpected NSP packet"
class InUse (SessException): "Object number or name already registered"
    
# Packet parse errors
class BadEndUser (DecodeError): "Invalid value in EndUser field"

# Reason codes for connect reject
APPLICATION = 0     # Application reject (or disconnect)
UNK_NODE = 2        # Unrecognized node name
NO_OBJ = 4          # Destination end user does not exist
BAD_FMT = 5         # Connect Init format error
BAD_NODE = 10       # Invalid node name format
BAD_AUTH = 34       # Authorization data not valid (username/password)
BAD_ACCT = 36       # Account not valid
OBJ_FAIL = 38       # Object failed
UNREACH = 39        # Destination unreachable
AUTH_LONG = 43      # Authorization data fields too long

# Reason codes for disconnect
ABORT = 9           # Connection aborted

reject_text = {
    BAD_NODE :  "Invalid node name format",
    UNK_NODE :  "Unrecognized node name",
    UNREACH :  "Node unreachable",
    1 :  "Network resources",
    APPLICATION :  "Rejected by object",
    BAD_FMT :  "Invalid object name format",
    NO_OBJ :  "Unrecognized object",
    BAD_AUTH :  "Access control rejected",
    AUTH_LONG :  "Access control data too long",
    BAD_ACCT :  "Account not valid",
    OBJ_FAIL :  "Node or object failed",
    ABORT :  "Abort by object",
}

# Helper function to run in the subprocess used for a "file" type
# object, just before the executable file is run.
def setuser (u, g):
    if g:
        os.setgid (g)
    if u:
        os.setuid (u)

# Work items sent up to the application.  All have fields "connection"
# (the SessionConnection) and "message" (the application data).
# Disconnect and reject also have a "reason" field.
class ApplicationWork (Work):
    closes = False

class ApplicationExited (Exception): pass
    
class Data (ApplicationWork):
    "Normal data message"
    name = "data"
class Interrupt (ApplicationWork):
    "Interrupt message"
    name = "interrupt"
class Disconnect (ApplicationWork):
    "Disconnect message"
    name = "disconnect"
    closes = True
class Accept (ApplicationWork):
    "Connect accept message"
    name = "accept"
class Reject (ApplicationWork):
    "Connect reject message"
    name = "reject"
    closes = True
class ConnectInit (ApplicationWork):
    "Connect Initialize message"
    name = "connect"
class Exited (ApplicationWork):
    "Application process has exited"
    name = "exited"

class EndUser (packet.IndexedPacket):
    classindex = nlist (3)
    classindexkey = "fmt"
    _layout = (( packet.B, "fmt", 1 ),
               ( packet.B, "num", 1 ))

class EndUser0 (EndUser):
    fmt = 0
    name = ""
    group = user = 0
    
    def check (self):
        if not self.num:
            raise BadEndUser ("Format 0 with zero number")

    def __format__ (self, format):
        return "{}".format (self.num)
    
    def nicedata (self):
        return nice_coding.CMProc ((self.num,))
    
class EndUser1 (EndUser):
    fmt = 1
    num = 0
    group = user = 0
    _layout = (( packet.A, "name", 16 ),)

    def check (self):
        if not self.name:
            raise BadEndUser ("Format 1 with no name")
        
    def __format__ (self, format):
        return "{}".format (self.name)

    def nicedata (self):
        return nice_coding.CMProc ((0, self.name))
    
class EndUser2 (EndUser):
    fmt = 2
    num = 0
    _layout = (( packet.B, "group", 2),
               ( packet.B, "user", 2),
               ( packet.A, "name", 16 ))

    def check (self):
        if not self.name:
            raise BadEndUser ("Format 2 with no name")
    
    def __format__ (self, format):
        return "[{},{}]{}".format (self.group, self.user, self.name)

    def nicedata (self):
        return nice_coding.CMProc ((0, self.group, self.user, self.name))
    
LocalUser = EndUser1 (name = "PyDECnet")

class SessionConnInit (packet.Packet):
    _addslots = { "rqstrid", "passwrd", "account", "connectdata" }
    _layout = (( EndUser, "dstname" ),
               ( EndUser, "srcname" ),
               ( packet.BM,
                 ( "auth", 0, 1 ),
                 ( "userdata", 1, 1 ),
                 ( "proxy", 2, 1 ),
                 ( "proxy_uic", 3, 1 ),
                 ( "reserved", 4, 1 ),
                 ( "scver", 5, 2 ),
                 ( "mbz2", 7, 1 )),
                packet.Payload )
    mbz2 = 0
    SCVER1 = 0   # Session Control 1.0
    SCVER2 = 1   # Session Control 2.0

    def encode (self):
        self.auth = self.userdata = 0
        payload = list ()
        r = self.rqstrid
        p = self.passwrd
        a = self.account
        if r or p or a:
            for f in (r, p, a):
                f = packet.A.checktype ("session", f)
                payload.append (f.encode (39))
            self.auth = 1
        if self.connectdata:
            data = packet.I.checktype ("data", self.connectdata)
            payload.append (data.encode (16))
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
                self.rqstrid, buf = packet.A.decode (buf, 39)
                self.passwrd, buf = packet.A.decode (buf, 39)
                self.account, buf = packet.A.decode (buf, 39)
            if self.userdata:
                self.connectdata, buf = packet.I.decode (buf, 16)
            if buf:
                logging.debug ("Extra data in session control CI packet")
        else:
            if self.auth or self.userdata:
                raise MissingData
            
class ObjectListener (Element):
    def __init__ (self, parent, number, name = "", auth = "off"):
        super ().__init__ (parent)
        auth = auth.lower ()
        if auth != "off" and not pam:
            raise ArgumentError ("authentication requested but python-pam is not installed")
        self.number = number
        name = name.upper ()
        self.name = name
        self.auth = auth
        self.uid = None
        self.gid = 0
        if not self.number and not self.name:
            raise ArgumentError ("At least one of name and number must be specified")
        if len (self.name) > 16:
            raise ValueError ("Name too long")
        if name:
            parent.obj_name[name] = self
        if number:
            parent.obj_num[number] = self

    def disconnect (self):
        # Used for listeners, i.e., object name and/or number entries
        # allocated dynamically by applications.  They call
        # "disconnect" to remove that registration.  --disable also
        # calls this.
        if self.number:
            del self.parent.obj_num[self.number]
        if self.name:
            del self.parent.obj_name[self.name]

    def __str__ (self):
        return "object {}".format (self.name or self.number)

class ApiListener (ObjectListener):
    uid = None
    gid = 0
    root = None
    def __init__ (self, parent, apiconnector, number, name = "", auth = "off"):
        if name in parent.obj_name or number in parent.obj_num:
            raise InUse
        super ().__init__ (parent, number, name, auth)
        self.apiconnector = apiconnector
        apiconnector.conns[id (self)] = self

    @property
    def what (self):
        return "Application h={}".format (id (self.apiconnector))

    def connector (self, x):
        return self.apiconnector

class SessionObject (ObjectListener):
    def __init__ (self, parent, number, name = "", auth = "off", arg = [ ]):
        super ().__init__ (parent, number, name, auth)
        self.argument = arg

class ModuleObject (SessionObject):
    uid = None
    gid = 0
    root = None
    def __init__ (self, parent, module, number, name = "",
                  auth = "off", arg = [ ], uid = None, gid = 0):
        super ().__init__ (parent, number, name, auth, arg)
        self.module = module
        mod = importlib.import_module (self.module)
        self.app_class = mod.Application
        if auth == "login":
            raise ValueError ("--authentication login not valid for modules")
        if uid is not None or gid:
            raise ValueError ("--uid or --gid not valid for modules")
            
    @property
    def what (self):
        return "Module {}".format (self.module)
    
    def connector (self, pw):
        logging.trace ("starting object {} ({})", self.number, self.name)
        return ModuleConnector (self.parent, self, self.app_class)

class FileObject (SessionObject):
    def __init__ (self, parent, file, number, name = "",
                  auth = "off", arg = [ ], uid = None, gid = 0):
        super ().__init__ (parent, number, name, auth, arg)
        self.root = None
        if uid is not None:
            if uid.isnumeric ():
                uid = int (uid)
            else:
                # User name, look it up
                try:
                    pw = pwd.getpwnam (uid)
                except KeyError:
                    raise ValueError ("Unknown uid {}".format (uid)) from None
                uid = pw.pw_uid
                gid = pw.pw_gid
                self.root = pw.pw_dir
        self.uid = uid
        self.gid = gid
        # Remember the supplied file name for display purposes
        self.shortfile = file
        # If the "file" argument is just a bare name, do a PATH lookup
        # on it to find the full path
        if not os.path.dirname (file):
            f = shutil.which (file)
        else:
            f = os.path.normpath (os.path.join (DECNETROOT, file))
        if f.endswith (".py"):
            # Python file, it needs to exist but it doesn't have to be
            # executable, because we'll pass it to the current Python
            # as a script file name argument.
            if not os.path.exists (f):
                f = None
        else:
            # Not a Python file, we'll execute it.  Check that it is
            # executable.  
            f = shutil.which (f)
        if not f:
            raise ValueError ("File {} not found or not executable".format (file))
        self.file = f
    
    @property
    def what (self):
        return "File {}".format (self.shortfile)
    
    def connector (self, pw):
        logging.trace ("starting object {} ({})", self.number, self.name)
        return ProcessConnector (self.parent, self, pw)

class DefObj (dict):
    def __init__ (self, name, num, module = None, file = None, auth = "off"):
        self.name = name.upper ()
        self.number = num
        self.module = module
        self.file = file
        self.auth = auth
        
defobj = ( DefObj ("NML", 19, "decnet.modules.nml"),
           DefObj ("MIRROR", 25, "decnet.modules.mirror"),
           DefObj ("EVTLOG", 26, "decnet.modules.evl"),
           DefObj ("TOPOL", 0, "decnet.modules.topol")
         )
# pmr requires 3.7 or later (it uses asyncio)
if sys.version_info >= (3, 7):
    # File name given here is relative to the location of this module.
    defobj += (DefObj ("PSTHRU", 123, file = "applications/pmr.py"),)

class SessionConnection (Element):
    def __init__ (self, parent, nspconn, **kw):
        super ().__init__ (parent)
        self.nspconn = nspconn
        self.remotenode = nspconn.destnode
        self.__dict__.update (kw)
        
    def accept (self, data = b""):
        data = makebytes (data)
        return self.nspconn.accept (data)

    def reject (self, data = b""):
        data = makebytes (data)
        self.nspconn.reject (APPLICATION, data)
        del self.parent.conns[self.nspconn]
    
    def disconnect (self, data = b""):
        self.nspconn.disconnect (APPLICATION, data)
        del self.parent.conns[self.nspconn]

    def abort (self, data = b""):
        self.nspconn.abort (ABORT, data)
        del self.parent.conns[self.nspconn]

    def interrupt (self, data):
        data = makebytes (data)
        return self.nspconn.interrupt (data)

    def send_data (self, data):
        data = makebytes (data)
        return self.nspconn.send_data (data)

    def setsockopt (self, **kwds):
        return self.nspconn.setsockopt (**kwds)

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
        self.apiconnectors = dict ()
        for d in defobj:
            # Add default (built-in) objects
            if d.module:
                ModuleObject (self, d.module, d.number, d.name, auth = d.auth)
            else:
                FileObject (self, d.file, d.number, d.name, auth = d.auth)
        # Add objects from the config
        for obj in config.object:
            if obj.disable:
                try:
                    if obj.number:
                        o2 = self.obj_num[obj.number]
                    else:
                        o2 = self.obj_name[obj.name]
                    o2.disconnect ()
                except KeyError:
                    logging.debug ("Disabling object {} which is not a built-in object",
                                   obj.number or obj.name)
            else:
                if obj.file:
                    if obj.module:
                        raise ValueError ("Only one of --file and --module is allowed")
                    obj = FileObject (self, obj.file, obj.number, obj.name,
                                      obj.authentication, obj.argument,
                                      obj.uid, obj.gid)
                elif obj.module:
                    obj = ModuleObject (self, obj.module, obj.number, obj.name,
                                        obj.authentication, obj.argument,
                                        obj.uid, obj.gid)
                else:
                    raise ValueError ("Object needs one of --file, --module, or --disable")
        for k, v in sorted (self.obj_num.items ()):
            logging.debug ("Session control object {0.number} ({0.name}) module {0.what}", v)
        for k, v in sorted (self.obj_name.items ()):
            if not v.number:
                logging.debug ("Session control object {0.name} module {0.what}", v)
        parent.register_api ("session", self.api, self.end_api)
        # Special one for internal interface to NML.  This goes via
        # here because we have to hook NML to a ModuleConnector so it
        # can do session control calls.
        global nml
        from .modules import nml    # to avoid import loops
        # TODO: end_api for NICE?
        parent.register_api ("ncp", self.nice_api)
        
    def start (self):
        logging.debug ("Starting Session Control")
        self.nsp = self.parent.nsp

    def stop (self):
        logging.debug ("Stopping Session Control")

    def api (self, client, reqtype, tag, args):
        cc = self.apiconnectors.get (client, None)
        if not cc:
            cc = self.apiconnectors[client] = ApiConnector (self, client)
        return cc.api (reqtype, tag, args)

    def end_api (self, client):
        try:
            cc = self.apiconnectors[client]
            cc.close ()
        except Exception:
            pass

    def nice_api (self, client, reqtype, tag, args):
        c = ModuleConnector (self, None, nml.Application)
        return c.app.api (client, reqtype, tag, args)
    
    def connect (self, client, dest, remuser, conndata = b"",
                 username = "", password = "", account = "",
                 localuser = LocalUser, proxy = False):
        if isinstance (localuser, EndUser):
            pass
        elif isinstance (localuser, int):
            localuser = EndUser0 (num = localuser)
        elif isinstance (localuser, str):
            localuser = EndUser1 (name = localuser)
        elif isinstance (localuser, (list, tuple)) and len (localuser) == 3:
            g, u, n = localuser
            localuser = EndUser2 (group = g, user = u, name = n)
        else:
            raise BadEndUser
        if isinstance (remuser, int):
            remuser = EndUser0 (num = remuser)
        else:
            remuser = EndUser1 (name = remuser)
        sc = SessionConnInit (srcname = localuser, dstname = remuser,
                              connectdata = conndata, rqstrid = username,
                              passwrd = password, account = account)
        if proxy:
            sc.scver = sc.SCVER2
            sc.proxy = 1
            sc.proxy_uic = 0
        nspconn = self.node.nsp.connect (dest, sc)
        self.conns[nspconn] = ret = SessionConnection (self, nspconn,
                                                       localuser = localuser,
                                                       remuser = remuser)
        ret.client = client
        return ret

    def html_objects (self):
        # Return an HTML item for the object database
        title = "Session control object database"
        hdr = ("Object", "Name", "Type", "Destination", "Authentication", "Uid")
        items = [ (0, o.name, o) for o in self.obj_name.values () if not o.number ]
        items.extend ([ (o.number, o.name, o) for o in self.obj_num.values () ])
        items.sort ()
        items = [ (n if n else "", m, *o.what.split (" ", 1),
                   o.auth.capitalize (), o.uid or "") for n, m, o in items ]
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
                    # Trace and then ignore this.  This happens due to a
                    # timing window between disconnect and when we see
                    # packets from NSP that were queued up in the
                    # meantime.
                    logging.trace ("NSP packet but no connection: {}", pkt)
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
                # Give the remote node address and, if known, name to
                # the application.
                dest = nspconn.destnode
                if dest.nodename:
                    pw = { "destination" : [ int (dest), dest.nodename ] }
                else:
                    pw = { "destination" : int (dest) }
                # Supply the source descriptor
                if spkt.srcname.fmt == 0:
                    pw["srcuser"] = spkt.srcname.num
                elif spkt.srcname.fmt == 1:
                    pw["srcuser"] = spkt.srcname.name
                else:
                    # Format 2
                    pw["srcuser"] = [ spkt.srcname.group,
                                      spkt.srcname.user,
                                      spkt.srcname.name ]
                # Ditto for destination descriptor
                if spkt.dstname.fmt == 0:
                    pw["dstuser"] = spkt.dstname.num
                elif spkt.dstname.fmt == 1:
                    pw["dstuser"] = spkt.dstname.name
                else:
                    # Format 2
                    pw["dstuser"] = [ spkt.dstname.group,
                                      spkt.dstname.user,
                                      spkt.dstname.name ]
                if isinstance (sesobj, ApiListener):
                    pw["listenhandle"] = id (sesobj)
                pw["uid"] = sesobj.uid
                pw["gid"] = sesobj.gid
                pw["root"] = sesobj.root
                pw["auth"] = sesobj.auth
                if sesobj.auth != "off":
                    # Authentication required.  We don't look at
                    # Account, but the other two fields must be
                    # present and they must be the correct value to
                    # pass PAM authentication on this host.
                    if not spkt.rqstrid or not spkt.passwrd:
                        if sesobj.auth == "login" and sesobj.uid:
                            # If "login" authentication is specified,
                            # the optional "uid" argument is the
                            # default user ID to use if authentication
                            # data is not supplied.
                            logging.trace ("Using default uid {}", sesobj.uid)
                            ok = True
                        else:
                            logging.debug ("Authentication reject, not supplied")
                            ok = False
                    else:
                        if sesobj.auth == "login":
                            try:
                                pwinfo = pwd.getpwnam (spkt.rqstrid.lower ())
                                ok = True
                                pw["uid"] = pwinfo.pw_uid
                                pw["gid"] = pwinfo.pw_gid
                                pw["root"] = pwinfo.pw_dir
                            except KeyError:
                                logging.debug ("Authentication reject, unknown user {}", spkt.rqstrid)
                                ok = False
                        else:
                            ok = True
                        if ok:
                            user = str (spkt.rqstrid).lower ()
                            passwd = str (spkt.passwrd)
                            if not pamobj.authenticate (user, passwd):
                                logging.debug ("Authentication reject for username {}", user)
                                ok = False
                    if spkt.rqstrid:
                        pw["username"] = spkt.rqstrid
                    if spkt.passwrd:
                        pw["password"] = 0
                    if spkt.account:
                        pw["account"] = spkt.account
                    if not ok:
                        s = spkt.srcname
                        d = spkt.dstname
                        self.node.logevent (events.acc_rej, 
                                            source_process = s.nicedata (),
                                            destination_process = d.nicedata (),
                                            **pw)
                        nspconn.reject (BAD_AUTH)
                        return
                # Pass up authentication parameters (without the
                # actual password) if authentication was requested and
                # acceptable.
                conn = SessionConnection (self, nspconn, 
                                          localuser = spkt.dstname,
                                          remuser = spkt.srcname, **pw)
                self.conns[nspconn] = conn
                data = spkt.connectdata
                awork = ConnectInit (self, message = data, connection = conn, **pw)
                # Have the object deliver a suitable connector
                try:
                    c = sesobj.connector (pw)
                    conn.client = c
                    conn.client.dispatch (awork)
                except FileNotFoundError:
                    logging.trace ("File not found for object")
                    nspconn.reject (NO_OBJ)
                    return
                except Exception:
                    # Something went wrong trying to start that
                    logging.exception ("Error starting object")
                    nspconn.reject (OBJ_FAIL)
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
                    payload = b""
                    if isinstance (pkt, nsp.DiscInit):
                        # Disconnect Init has a data field, but
                        # Disconnect Confirm does not.
                        payload = pkt.data_ctl
                    if item.reject:
                        awork = Reject (self, message = payload,
                                        connection = conn,
                                        reason = pkt.reason)
                    else:
                        awork = Disconnect (self, message = payload,
                                            connection = conn,
                                            reason = pkt.reason)
                    del self.conns[nspconn]
                else:
                    logging.debug ("Unexpected work item {}", item)
                    return
                conn.client.dispatch (awork)

    def nice_read (self, req, resp):
        pass

# Below we have the machinery that connection the session control core
# to applications, whether implemented as a module or as a separate
# process.  This is architecturally part of session control.
class FromApplicationWork (Work):
    name = "Request from application"

def api (fun):
    fun.is_api = True
    return fun

class BaseConnector (Element):
    """Base class for the interface between Session Control and an
    application.  It defines a small object which mainly is used to
    track the connections owned by a particular application.  Subclasses
    take care of the different types: module, process, and HTTP API
    client.
    """
    def __init__ (self, parent, obj):
        """Initialize an application.  

        "parent" is the Session object.  "obj" is the object definition
        (the DECnet object attributes) which are saved but not otherwise
        used.  Individual applications may need to refer to this, in
        particular obj.argument (the --argument value from the object
        definition in the config file).
        """
        super ().__init__ (parent)
        self.conns = dict ()
        self.object = obj

    def dispatch (self, item):
        try:
            conn = item.connection
            handle = id (conn)
            if item.closes:
                # This is a closing work item (disconnect or reject), so
                # forget the connection.
                del self.conns[handle]
            else:
                # Add the connection if not known yet, otherwise check
                # that it still matches.
                assert self.conns.setdefault (handle, conn) == conn
        except AttributeError:
            pass
        try:
            self.dispatch2 (item)
        except Exception as e:
            if not isinstance (e, ApplicationExited):
                logging.exception ("Unhandled exception in {}".format (self.object))
            for conn in list (self.conns.values ()):
                if isinstance (conn, ApiListener):
                    # Not an actual connection but "bind" state -- an
                    # object number and/or name registered at run time
                    # by the application.  Just free it.
                    conn.disconnect ()
                    continue
                try:
                        conn.nspconn.abort (OBJ_FAIL)
                except nsp.WrongState:
                    try:
                        conn.nspconn.reject (OBJ_FAIL)
                    except nsp.WrongState:
                        pass
                del self.parent.conns[conn.nspconn]

    def connect (self, dest, remuser, data = b"",
                 username = "", password = "", account = "",
                 localuser = LocalUser, proxy = False):
        conn = self.parent.connect (self, dest, remuser, data,
                                    username, password, account,
                                    localuser, proxy)
        self.conns[id (conn)] = conn
        return conn

class ModuleConnector (BaseConnector):
    """A connector for applications implemented as Python modules and
    run within the pydecnet process ("module" type DECnet objects). 
    """
    def __init__ (self, parent, obj, appcls):
        super ().__init__ (parent, obj)
        self.app = appcls (self, obj)

    def dispatch2 (self, item):
        self.app.dispatch (item)
            
class InternalConnector (BaseConnector):
    """A connector for session control users internal to PyDECnet, not
    covered by the ModuleConnector case.  Examples include components
    that initiate connections rather than respond to them, such as the
    network mapper.
    """
    def __init__ (self, sc, owner, name = None):
        super ().__init__ (sc, name)
        self.app = owner

    def dispatch2 (self, item):
        self.app.dispatch (item)

class DictConnector (BaseConnector):
    """This class has an interface like that of a "module" type
    application object, but instead of implementing an application
    itself, it converts that interface to a stream of dict objects going
    in each direction.  It is a base class used by the ProcessConnector
    (for "file" type objects) and as a helper class for the PyDECnet API
    server.
    """
    # The methods below are called via JSON-encoded requests, so they
    # refer to connections via handles, and data arrives at latin-1
    # encoded strings (which are basically bytes, but not the same
    # type).
    @api
    def accept (self, handle, data = ""):
        conn = self.conns[handle]
        conn.accept (bytes (data, "latin1"))

    @api
    def reject (self, handle, data = ""):
        conn = self.conns[handle]
        conn.reject (bytes (data, "latin1"))
        del self.conns[handle]
    
    @api
    def disconnect (self, handle, data = ""):
        conn = self.conns[handle]
        conn.disconnect (bytes (data, "latin1"))
        del self.conns[handle]

    @api
    def abort (self, handle, data = ""):
        conn = self.conns[handle]
        conn.abort (bytes (data, "latin1"))
        del self.conns[handle]

    @api
    def interrupt (self, handle, data):
        conn = self.conns[handle]
        conn.interrupt (bytes (data, "latin1"))

    @api
    def data (self, handle, data):
        conn = self.conns[handle]
        conn.send_data (bytes (data, "latin1"))

    @api
    def setsockopt (self, handle, **kwds):
        conn = self.conns[handle]
        conn.setsockopt (**kwds)

    @api
    def connect (self, dest, remuser, data = "",
                 username = "", password = "", account = "",
                 localuser = None, proxy = False, tag = None):
        # tag does nothing but the async_connector uses it and the
        # easiest way to handle it is to have it be an ignored
        # argument on the method.
        data = bytes (data, "latin1")
        if localuser is None:
            localuser = LocalUser
        elif isinstance (localuser, int):
            localuser = EndUser0 (num = localuser)
        else:
            localuser = EndUser1 (name = localuser)
        try:
            conn = super ().connect (dest, remuser, data,
                                     username, password, account,
                                     localuser, proxy)
        except nsp.UnknownNode:
            return dict (type = "reject", reason = UNK_NODE)
        handle = id (conn)
        return dict (handle = handle, type = "connecting")

    @api
    def bind (self, num = 0, name = "", auth = "off"):
        try:
            obj = ApiListener (self.parent, self, num, name, auth)
        except Exception as e:
            return dict (error = str (e))
        return dict (handle = id (obj), type = "bind")

    def dispatch2 (self, item):
        if isinstance (item, Exited):
            raise ApplicationExited
        elif isinstance (item, FromApplicationWork):
            # Process work from the process, a request to Session
            # Control.
            args = item.args
            try:
                action = getattr (self, args.pop ("type"))
                assert action.is_api
            except (AssertionError, KeyError, AttributeError):
                raise AttributeError ("Invalid API request", args) from None
            logging.trace ("Application SC {} request:\n{}",
                           action.__name__, repr (args))
            try:
                ret = action (**args)
            except DNAException as e:
                ret = dict (error = str (e))
            if ret is not None:
                logging.trace ("action returns {}", repr (ret))
                tag = getattr (item, "tag", None)
                if tag is not None:
                    ret["tag"] = tag
                self.send_dict (ret)
        else:
            # Process work sent up from the Session Control layer. 
            handle = id (item.connection)
            msg = bytes (item.message)
            mtype = item.name
            jdict = dict (handle = handle, data = msg, type = mtype)
            if mtype == "connect":
                # Put in additional items, if present
                jdict["destination"] = item.destination
                jdict["srcuser"] = item.srcuser
                jdict["dstuser"] = item.dstuser
                if hasattr (item, "listenhandle"):
                    jdict["listenhandle"] = item.listenhandle
                if hasattr (item, "username"):
                    jdict["username"] = item.username
                if hasattr (item, "password"):
                    jdict["password"] = item.password
                if hasattr (item, "account"):
                    jdict["account"] = item.account
            try:
                jdict["reason"] = item.reason
            except AttributeError:
                pass
            self.send_dict (jdict)
        
class ProcessConnector (DictConnector):
    """This class has an interface like that of a "module" type
    application object, but instead of implementing an application
    itself, it converts that interface to a full duplex JSON stream, via
    pipes to a process.  This is the mechanism used to run "file"
    (separate process) applications.

    The JSON streams are connected via pipes to the process stdin
    (messages from session control) and stdout (requests to session
    control).  In addition, there is a pipe to the process stderr, which
    takes error messages and other logging information to the PyDECnet
    logging facility.
    """
    def __init__ (self, parent, obj, pw):
        super ().__init__ (parent, obj)
        self.sp = None
        self.othread = self.ethread = None
        self.enc = DNJsonEncoder ().encode
        self.dec = DNJsonDecoder ().decode
        # Build the minimal environment we want to pass down
        env = dict ()
        for k in "HOME", "PATH", "USER", "LOGNAME":
            try:
                env[k] = os.environ[k]
            except KeyError:
                pass
        args = [ obj.file ] + obj.argument
        if obj.file.endswith (".py"):
            # It's a Python file, run it under whichever Python we're
            # running.  This ensures that an entire PyDECnet run,
            # including any file based objects, use the same Python
            # version.
            args = [ sys.executable ] + args
        logging.trace ("Starting file, args {}, environment {}", args, env)
        # Start the requested program file in a new process.  We ask for
        # line mode on the pipes, but note that only works at this end
        # -- the subprocess is still likely to get full buffering on
        # them and if so has to be sure to flush after pretty much every
        # write.
        uid = pw["uid"]
        gid = pw["gid"]
        if uid is not None or gid:
            userfun = functools.partial (setuser, uid, gid)
        else:
            userfun = None
        self.sp = subprocess.Popen (args,
                                    bufsize = 1,
                                    stdin = subprocess.PIPE,
                                    stdout = subprocess.PIPE,
                                    stderr = subprocess.PIPE,
                                    universal_newlines = True,
                                    start_new_session = True,
                                    env = env,
                                    preexec_fn = userfun,
                                    cwd = pw["root"],
                                    restore_signals = True,
                                    shell = False)
        logging.trace ("object subprocess started")
        tname = str (obj)
        self.othread = StopThread (target = self.ohandler,
                                   name = tname,
                                   args = (self, self.sp.stdout))
        self.ethread = StopThread (target = self.ehandler,
                                   name = tname + " log",
                                   args = (self, self.sp.stderr))
        self.othread.start ()
        self.ethread.start ()
        logging.trace ("obj returncode {}", self.sp.returncode)

    def send_dict (self, jdict):
        jdict = self.enc (jdict)
        logging.trace ("sc json data to {}: {}", self.object, jdict)
        print (jdict, file = self.sp.stdin)
        
    def dispatch2 (self, item):
        if isinstance (item, Exited):
            self.sp.stdin.close ()
        super ().dispatch2 (item)
        
    def ohandler (self, parent, opipe):
        """Read JSON requests from stdout and turn them into
        FromApplicationWork items.
        """
        logging.trace ("object stdout thread started")
        while not self.othread.stopnow:
            req = opipe.readline ().rstrip ("\n")
            if not req:
                opipe.close ()
                stat = parent.sp.wait (timeout = 5)
                if stat < 0:
                    try:
                        sname = signal.Signals (-stat).name
                    except Exception:
                        sname = "unknown signal"
                    logging.debug ("Subprocess for {} exited with signal {} ({})",
                                   str (parent.object), -stat, sname)
                else:
                    logging.trace ("Subprocess for {} exited with status {}",
                                   str (parent.object), stat)
                work = Exited (parent)
                parent.node.addwork (work)
                break
            logging.trace ("json request to sc: {}", req)
            req = self.dec (req)
            tag = req.pop ("tag", None)
            work = FromApplicationWork (parent, args = req, tag = tag)
            parent.node.addwork (work)
        logging.trace ("object stdout thread done")
            
    def ehandler (self, parent, epipe):
        """Read input from stderr.  If it looks like a JSON encoded
        object, use that to invoke logging.log.  If not, log it as a
        plain text DEBUG message.
        """
        logging.trace ("object stderr thread started")
        while not self.ethread.stopnow:
            req = epipe.readline ()
            if not req:
                epipe.close ()
                break
            req = req.rstrip ("\n")
            # Don't log the raw request because we'll log the resulting
            # processed log request below.
            try:
                reqd = self.dec (req)
                lv = reqd["level"]
                msg = reqd["message"]
                args = reqd.get ("args", [ ])
                kwargs = reqd.get ("kwargs", { })
                try:
                    pkt = kwargs["extra"]["packetdata"]
                    kwargs["extra"]["packetdata"] = bytes (pkt, "latin1")
                except KeyError:
                    pass
                logging.log (lv, msg, *args, **kwargs)
            except Exception:
                logging.debug ("Application {} debug message: {}",
                               parent.object, req)
        logging.trace ("object stderr thread done")

class ApiConnector (DictConnector):
    """This class is similar to ProcessConnector but it connects to the
    general PyDECnet API, implementing the "session" subsystem API.
    """
    def __init__ (self, parent, client):
        super ().__init__ (parent, "API connector")
        self.apiclient = client
        self.parent.apiconnectors[client] = self

    def close (self):
        work = Exited (self)
        self.node.addwork (work)
        del self.parent.apiconnectors[self.apiclient]
        
    def api (self, reqtype, tag, args):
        args["type"] = reqtype
        work = FromApplicationWork (self, args = args, tag = tag)
        self.node.addwork (work)

    def send_dict (self, jdict):
        jdict["api"] = "session"
        jdict["system"] = self.parent.node.nodename
        self.apiclient.send_dict (jdict)

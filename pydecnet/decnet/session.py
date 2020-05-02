#!

"""Session Control layer for DECnet/Python

"""

import subprocess
import os
import signal
import importlib
import shutil
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
from . import http

SvnFileRev = "$LastChangedRevision$"

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
class ConnectConfirm (ApplicationWork):
    "Connect confirm message"
    name = "confirm"
class Exited (ApplicationWork):
    "Application process has exited"
    name = "exited"

class EndUser (packet.Packet):
    classindex = { }
    classindexkey = "fmt"
    _layout = (( packet.B, "fmt", 1 ),
               ( packet.B, "num", 1 ))

    @classmethod
    def defaultclass (cls, idx):
        raise BadEndUser ("Invalid EndUser format code {}".format (idx))

class EndUser0 (EndUser):
    fmt = 0
    name = ""
    group = user = 0
    
    def check (self):
        if not self.num:
            raise BadEndUser ("Format 0 with zero number")

    def __format__ (self, format):
        return "{}".format (self.num)
    
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
            
class SessionObject (Element):
    def __init__ (self, parent, number, name = "", module = "", file = "",
                  auth = "off", arg = [ ]):
        super ().__init__ (parent)
        if auth != "off" and not pam:
            raise ArgumentError ("authentication requested but python-pam is not installed")
        self.argument = arg
        self.number = number
        self.name = name
        self.module = module
        self.file = file
        self.auth = auth.lower () != "off"
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
            # None here means we're dealing with a process to be run.
            self.app_class = None
        elif self.module:
            mod = importlib.import_module (self.module)
            self.app_class = mod.Application
        else:
            raise ArgumentError ("Either file or module must be specified")
        if name:
            parent.obj_name[name] = self
        if number:
            parent.obj_num[number] = self

    def __str__ (self):
        return "object {}".format (self.name or self.number)
    
class DefObj (dict):
    def __init__ (self, name, num, module, auth = "off"):
        self.name = name.upper ()
        self.number = num
        self.module = module
        self.file = None
        self.auth = auth
        
defobj = ( DefObj ("NML", 19, "decnet.modules.nml"),
           DefObj ("MIRROR", 25, "decnet.modules.mirror"),
           DefObj ("EVTLOG", 26, "decnet.modules.evl"),
         )

class SessionConnection (Element):
    def __init__ (self, parent, nspconn, localuser, remuser):
        super ().__init__ (parent)
        self.nspconn = nspconn
        self.localuser = localuser
        self.remuser = remuser
        self.remotenode = nspconn.destnode
        
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
        for d in defobj:
            # Add default (built-in) objects
            obj = SessionObject (self, d.number, d.name, d.module,
                                 auth = d.auth)
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
                                     obj.module, obj.file, obj.authentication,
                                     obj.argument)
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

    def connect (self, client, dest, remuser, conndata = b"",
                 username = b"", password = b"", account = b"",
                 srcname = LocalUser, proxy = False):
        if isinstance (remuser, int):
            remuser = EndUser (num = remuser)
        else:
            remuser = EndUser (name = remuser)
        sc = SessionConnInit (srcname = srcname, dstname = remuser,
                              connectdata = conndata, rqstrid = username,
                              passwrd = password, account = account)
        if proxy:
            sc.scver = sc.SCVER2
            sc.proxy = 1
            sc.proxy_uic = 0
        nspconn = self.node.nsp.connect (dest, sc)
        self.conns[nspconn] = ret = SessionConnection (self, nspconn,
                                                       srcname, remuser)
        ret.client = client
        return ret

    def html_objects (self):
        # Return an HTML item for the object database
        title = "Session control object database"
        hdr = ("Object", "Name", "Type", "Destination", "Authentication")
        items = [ (0, o.name, o) for o in self.obj_name.values () if not o.number ]
        items.extend ([ (o.number, o.name, o) for o in self.obj_num.values () ])
        items.sort ()
        items = [ (n if n else "", m,
                   "Module" if o.module else "File",
                   o.module if o.module else o.file,
                   "On" if o.auth else "Off") for n, m, o in items ]
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
                if sesobj.auth:
                    # Authentication required.  We don't look at
                    # Account, but the other two fields must be
                    # present and they must be the correct value to
                    # pass PAM authentication on this host.
                    if not spkt.rqstrid or not spkt.passwrd or \
                       not pamobj.authenticate (spkt.rqstrid, spkt.passwrd):
                        logging.debug ("Authentication reject for username {}",
                                       spkt.rqstrid)
                        pw = dict ()
                        if spkt.passwrd:
                            pw["password"] = 0
                        if spkt.account:
                            pw["account"] = spkt.account
                        s = spkt.srcname
                        d = spkt.dstname
                        so = (s.num, s.group, s.user, s.name)
                        do = (d.num, d.group, d.user, d.name)
                        self.node.logevent (events.acc_rej, 
                                            source_process = so,
                                            destination_process = do,
                                            user = spkt.rqstrid, **pw)
                        nspconn.reject (BAD_AUTH)
                        return
                conn = SessionConnection (self, nspconn,
                                          spkt.dstname, spkt.srcname)
                self.conns[nspconn] = conn
                data = spkt.connectdata
                awork = ConnectInit (self, message = data, connection = conn)
                # TODO: find api user in "listen" mode
                logging.trace ("starting object {0.num} ({0.name})",
                               spkt.dstname)
                cls = sesobj.app_class
                try:
                    if cls:
                        c = ModuleConnector (self, sesobj, cls)
                    else:
                        c = ProcessConnector (self, sesobj)
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
class ApplicationWork (Work):
    name = "Outgoing request"

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
            for conn in self.conns.values ():
                try:
                    conn.nspconn.abort (OBJ_FAIL)
                except nsp.WrongState:
                    try:
                        conn.nspconn.reject (OBJ_FAIL)
                    except nsp.WrongState:
                        pass
                del self.parent.conns[conn.nspconn]
            del self.conns

    # The methods below are called by the file based (JSON encoded)
    # applications, so they refer to connections via handles, and data
    # arrives at latin-1 encoded strings (which are basically bytes, but
    # not the same type).
    def accept (self, handle, data = ""):
        conn = self.conns[handle]
        return conn.accept (bytes (data, "latin1"))

    def reject (self, handle, data = ""):
        conn = self.conns[handle]
        conn.reject (bytes (data, "latin1"))
        del self.conns[handle]
    
    def disconnect (self, handle, data = ""):
        conn = self.conns[handle]
        conn.disconnect (bytes (data, "latin1"))
        del self.conns[handle]

    def abort (self, handle, data = ""):
        conn = self.conns[handle]
        conn.abort (bytes (data, "latin1"))
        del self.conns[handle]

    def interrupt (self, handle, data):
        conn = self.conns[handle]
        return conn.interrupt (bytes (data, "latin1"))

    def data (self, handle, data):
        conn = self.conns[handle]
        return conn.send_data (bytes (data, "latin1"))

    def setsockopt (self, handle, **kwds):
        conn = self.conns[handle]
        return conn.setsockopt (**kwds)

    def connect (self, dest, remuser, data = b"",
                 username = b"", password = b"", account = b"",
                 srcname = LocalUser, proxy = False):
        conn = self.parent.connect (self, dest, remuser, data,
                                    username, password, account,
                                    srcname, proxy)
        self.conns[id (conn)] = conn
        return conn

# The application API into Session Control consists of all the callable
# items in the ApplicationConnector class, except for the internal ones
# (the ones starting with _).
BaseConnector.api = frozenset (k for (k, v) in BaseConnector.__dict__.items ()
                               if k[0] != '_' and k != "dispatch"
                               and callable (v))

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
            
class ProcessConnector (BaseConnector):
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
    def __init__ (self, parent, obj):
        self.conns = dict ()
        super ().__init__ (parent,obj)
        self.sp = None
        self.othread = self.ethread = None
        self.enc = http.DNJsonEncoder ().encode
        self.dec = http.DNJsonDecoder ().decode
        # Build the minimal environment we want to pass down
        env = dict ()
        for k in "HOME", "PATH", "USER", "LOGNAME":
            try:
                env[k] = os.environ[k]
            except KeyError:
                pass
        args = [ obj.file ] + obj.argument
        logging.trace ("Starting file, args {}, environment {}", args, env)
        # Start the requested program file in a new process.  We ask for
        # line mode on the pipes, but note that only works at this end
        # -- the subprocess is still likely to get full buffering on
        # them and if so has to be sure to flush after pretty much every
        # write.
        #
        # TODO: support for logging in to the username supplied in the
        # connect request.
        self.sp = subprocess.Popen (args,
                                    bufsize = 1,
                                    stdin = subprocess.PIPE,
                                    stdout = subprocess.PIPE,
                                    stderr = subprocess.PIPE,
                                    universal_newlines = True,
                                    start_new_session = True,
                                    env = env,
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

    def connect (self, dest, remuser, data = b"",
                 username = b"", password = b"", account = b""):
        # Override "connect" so we can return the result to the
        # subprocess.  The other API calls don't have any interesting
        # return value so for those we don't bother.
        conn = super ().connect (dest, remuser, data,
                                 username, password, account)
        handle = id (conn)
        jdict = dict (handle = handle, type = "connecting")
        jdict = self.enc (jdict)
        logging.trace ("sc json data to {}: {}", self.object, jdict)
        print (jdict, file = self.sp.stdin)

    def dispatch2 (self, item):
        if isinstance (item, Exited):
            self.sp.stdin.close ()
            raise ApplicationExited
        elif isinstance (item, ApplicationWork):
            # Process work from the process, a request to Session
            # Control.
            args = item.args
            action = args["mtype"]
            if action not in self.api:
                raise AttributeError ("Invalid API request")
            del args["mtype"]
            logging.trace ("Application SC {} request:\n{}",
                           action, repr (args))
            action = getattr (self, action)
            action (**args)
        else:
            # Process work sent up from the Session Control layer. 
            handle = id (item.connection)
            msg = bytes (item.message)
            mtype = item.name
            jdict = dict (handle = handle, data = msg, type = mtype)
            try:
                jdict["reason"] = item.reason
            except AttributeError:
                pass
            jdict = self.enc (jdict)
            logging.trace ("sc json data to {}: {}", self.object, jdict)
            print (jdict, file = self.sp.stdin)
        
    def ohandler (self, parent, opipe):
        """Read JSON requests from stdout and turn them into
        ApplicationWork items.
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
            work = ApplicationWork (parent, args = req)
            parent.node.addwork (work)
        logging.trace ("object stdout thread done")
            
    def ehandler (self, parent, epipe):
        """Read input from stderr.  If it looks like a JSON encoded
        object, use that to invoke logging.log.  If not, log it as a
        plain text DEBUG message.
        """
        logging.trace ("object stderr thread started")
        while not self.ethread.stopnow:
            req = epipe.readline ().rstrip ("\n")
            if not req:
                epipe.close ()
                break
            logging.trace ("app stderr data: {}", req)
            try:
                reqd = self.dec (req)
                lv = reqd["level"]
                msg = reqd["message"]
                args = reqd.get ("args", [ ])
                logging.log (lv, msg, *args)
            except Exception:
                logging.debug ("Application {} debug message: {}",
                               parent.object, req)
        logging.trace ("object stderr thread done")
    

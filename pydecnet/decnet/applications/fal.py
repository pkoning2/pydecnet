#!/usr/bin/env python3

"""Simple file access listener for DECnet/Python

Copyright (C) 2022 by Paul Koning

This is a basic but useable implementation of a DAP server in Python,
using the DECnet API in the DECnet/Python stack.  It supports a basic
set of DAP 5.6.0 capabilities.

"""

import sys
import os
import glob
import pwd
import argparse

from decnet.common import *
from decnet.dap_packets import *
from decnet import connectors
from decnet.logging import dump_packet, DEBUG
from decnet import dap

dnparser = argparse.ArgumentParser ()
dnparser.add_argument ("root", nargs = "?")

class NFTError (Exception):
    "General NFT error"

    def __str__ (self):
        return self.__doc__.format (*self.args)

root = None
def applyroot (s):
    s = os.path.normpath (s)
    if root:
        while s.startswith (".."):
            s = s[3:]
        s = os.path.normpath (root + "/" + s)
    return os.path.abspath (s)

def striproot (s):
    s = os.path.normpath (s)
    if root:
        if s.startswith (root):
            s = s[len (root):]
    return s

def files (v7, req, attr = None):
    """Iterator that returns, for each file matched, the path name and a
    sequence of DAP messages describing the file.  For errors, None is
    returned instead of teh path name, and the sequence contains the
    error message.
    """
    # "req" is an Access message, attr the preceding Attrib message if
    # any (none for a DIR operation).
    dirop = req.accfunc == Access.DIR
    pn = applyroot (getattr (req, "filespec", ""))
    if pn.endswith (";*"):
        pn = pn[:-2]
    if pn.endswith ("*.*"):
        pn = pn[:-3]
    if dirop:
        # For Directory request, supply default name of *
        if os.path.isdir (pn):
            pn = os.path.join (pn, "*")
    wild = "*" in pn or "?" in pn
    sendmain = req.main or not dirop
    sendname = dirop or req.name or wild
    ret = list ()
    curdn = None
    files = glob.glob (pn, include_hidden = False)
    if not files:
        # Nothing found, see what we should say about that
        dn, bn = os.path.split (pn)
        err = None
        if not os.access (dn, os.X_OK):
            err = (4, 0o40)    # Directory not found
        if err:
            msg = Status ()
            msg.maccode, msg.miccode = err
            yield None, [ msg ]
            return
    files.sort ()
    fcount = 0
    # Begin with an empty volume name, since RSTS doesn't work without that
    if dirop or wild:
        ret.append (Name (volname = 1, namespec = ""))
    for fn in files:
        dn, bn = os.path.split (fn)
        try:
            s = os.stat (fn)
        except OSError:
            continue
        isdir = os.path.isdir (fn)
        if isdir and not dirop:
            # I/O operation (not DIRECTORY), we can't do I/O to
            # directories so skip those.
            continue
        if not os.access (fn, os.R_OK):
            # DEC rule: if you can't read it, you can't see it
            continue
        fcount += 1
        if dn != curdn:
            curdn = dn
            if dirop or wild:
                ret.append (Name (dirname = 1, namespec = striproot (dn) + "/"))
        # Clean the filename -- non-Latin1 characters are replaced by
        # \unnnn escapes.  Also trim the string to 127 bytes max; the
        # spec says 200 but RSTS NFT crashes if a length of 128 or
        # more appears, most likely a sign extend bug.  127 is fine
        # anyway; DEC file systems don't use such long names and
        # applications tend to look pretty ugly with very long file
        # names.
        bn = str (bytes (bn, "latin1", "backslashreplace")[:127], "latin1")
        if isdir:
            # It's a directory.  DAP has no way to say that as far as I
            # can tell, so do it by appending a / to the name.
            bn = bn[:126] + "/"
        if dirop or wild:
            ret.append (Name (filename = 1, namespec = bn))
        if sendmain:
            # Build an Attrib message
            blk, byt = divmod (s.st_size, 512)
            msg = Attrib (m_bls = 1, bls = 512,
                          m_rfm = 1, rfm = Attrib.fb_fix,
                          m_alq = 1, alq = s.st_blocks,
                          m_hbk = 1, hbk = blk + 1,
                          m_ebk = 1, ebk = blk + 1,
                          m_ffb = 1, ffb = byt)
            if v7:
                # Set stream-lf format
                msg.rfm = Attrib.fb_slf
            if attr:
                # requester included attributes, pick up some of those
                if attr.m_rfm and (attr.rfm != Attrib.fb_stm or not v7):
                    # Apply requested record format, unless it's
                    # stream and requester is V7 (because then we
                    # prefer stream_lf which appeared in V7).
                    msg.rfm = attr.rfm
                if attr.m_bls:
                    msg.bls = attr.bls
                if attr.m_rat:
                    msg.m_rat = 1
                    msg.fb_cr = attr.fb_cr
            if msg.rfm == Attrib.fb_fix:
                msg.m_mrs = 1
                msg.mrs = 512
            ret.append (msg)
        if req.date:
            # Build a Date message
            msg = Date (m_cdt = 1, cdt = Date.setdate (s.st_ctime),
                        m_rdt = 1, rdt = Date.setdate (s.st_mtime))
            ret.append (msg)
        if req.fprot:
            # Build a Prot message
            try:
                owner = pwd.getpwuid (s.st_uid).pw_name
            except KeyError:
                owner = str (s.st_uid)
            msg = Prot (m_owner = 1, owner = owner)
            msg.setmode (s.st_mode)
            ret.append (msg)
        if sendname and not (dirop or wild):
            # For non-wild operations the name message is expected to go
            # at the end.  VMS cares about this.
            msg = Name (filespec = 1, namespec = striproot (dn) + "/" + bn)
            ret.append (msg)
        # We now have everything we want to say about the file.  Yield
        # that result.
        yield fn, ret
        # Reset for next time around
        ret = list ()
    if not fcount:
        # We didn't report anything.  Complain if a specific file was
        # requested.
        if "*" not in bn:
            err = (4, 0o62)    # File not found
            msg = Status ()
            msg.maccode, msg.miccode = err
            yield None, [ msg ]
            return
    
def doget (conn, req, attr):
    if attr and attr.m_bls and attr.bls != 512:
        # Block size requested but not 512
        resp = status (maccode = 2, miccode = 0o0225)
        conn.send (resp)
        conn.flush ()
        return
    for fn, resp in files (conn.v7, req, attr):
        # Send the appropriate messages
        for r in resp:
            conn.send (r)
        if not fn:
            # That was an error, quit (TBD: options?)
            return
        conn.send (Ack ())
        conn.flush ()
        # Wait for the requesting side to connect (to get data) or
        # close (to skip the file)
        msg = conn.recv ()
        if not msg:
            return
        if isinstance (msg, AccComplete) and msg.cmpfunc == AccComplete.CLOSE:
            # Close seen, skip this file
            continue
        if not isinstance (msg, Control):
            # Out of sync
            resp = Status (maccode = 10, miccode = msg.type)
            conn.send (resp)
            conn.flush ()
            return
        if msg.ctlfunc != Control.CONNECT:
            # Unsupported, CTLFUNC field
            resp = Status (maccode = 2, miccode = 0o420)
            conn.send (resp)
            conn.flush ()
            return
        conn.send (Ack ())
        conn.flush ()
        # Wait for start of transfer
        msg = conn.recv ()
        if not msg:
            return
        if not isinstance (msg, Control):
            # Out of sync
            resp = Status (maccode = 10, miccode = msg.type)
            conn.send (resp)
            conn.flush ()
            return
        if msg.ctlfunc != Control.GET:
            # Unsupported, CTLFUNC field
            resp = Status (maccode = 2, miccode = 0o420)
            conn.send (resp)
            conn.flush ()
            return
        if not msg.m_rac or msg.rac != Control.RB_SEQF:
            # Unsupported, RAC field
            resp = Status (maccode = 2, miccode = 0o422)
            conn.send (resp)
            conn.flush ()
            return
        # See what copy mode we want.  Go line mode if variable, or
        # stream (which means not V7 because there we set stream_lf)
        if attr and attr.m_rfm and attr.rfm in (Attrib.fb_var, Attrib.fb_stm):
            # variable length records, i.e., text transfer mode.  See if
            # line endings are implied or explicit.
            exp = not (attr.m_rat and attr.fb_cr)
            with open (fn, "rt") as f:
                for l in f:
                    l = l.rstrip ("\n")
                    if exp:
                        # Explicit line endings, add DEC end of line
                        l += "\r\n"
                    conn.send (Data (payload = bytes (l, "latin1")))
        else:
            # Fixed length records, transfer binary blocks
            with open (fn, "rb") as f:
                while True:
                    d = f.read (512)
                    if not d:
                        break
                    # Pad to 512 bytes
                    if len (d) != 512:
                        d += bytes (512 - len (d))
                    conn.send (Data (payload = d))
        # All done, send end-of-file status
        conn.send (Status (maccode = 5, miccode = 0o47))
        conn.flush ()
        # Await access complete
        msg = conn.recv ()
        if not msg:
            return
        if not isinstance (msg, AccComplete):
            # Out of sync
            resp = Status (maccode = 10, miccode = msg.type)
            conn.send (resp)
            conn.flush ()
            return
        if msg.cmpfunc == AccComplete.EOS:
            # Some clients send EOS (DISCONNECT) before CLOSE.
            conn.send (AccComplete (cmpfunc = AccComplete.RESPONSE))
            conn.flush ()
            msg = conn.recv ()
            if not msg:
                return
            if not isinstance (msg, AccComplete):
                # Out of sync
                resp = Status (maccode = 10, miccode = msg.type)
                conn.send (resp)
                conn.flush ()
                return
        if msg.cmpfunc != AccComplete.CLOSE:
            # Unsupported, CMPFUNC field
            resp = Status (maccode = 2, miccode = 0o720)
            conn.send (resp)
            conn.flush ()
            return
        # Try this:
        #conn.send (Ack ())
        #conn.flush ()
    # When entirely finished, with access complete response
    conn.send (AccComplete (cmpfunc = AccComplete.RESPONSE))
    conn.flush ()
    
def dodir (conn, req):
    for fn, resp in files (conn.v7, req):
        for r in resp:
            conn.send (r)
        if conn.v7:
            # V7 has an Ack after each entry.  VMS cares (RSX does not).
            conn.send (Ack ())
    msg = AccComplete (cmpfunc = AccComplete.RESPONSE)
    conn.send (msg)
    conn.flush ()
    
def main ():
    """The main program for this process-level object.  It is started as
    a subprocess by pydecnet, with pipes for the three standard file
    descriptors.
    """
    global connector, root
    connector = connectors.SimplePipeConnector ()
    # Get the first message, which should be a "connect"
    conn, msg = connector.recv ()
    assert conn and msg.type == "connect"
    conn.accept ()
    # If we're using the default login, set the root directory if one
    # was given.
    if not hasattr (msg, "username"):
        p = dnparser.parse_args ()
        root = p.root
        if root:
            root = os.path.abspath (os.path.expanduser (root))
            os.chdir (root)
    conn = dap.DapSession (conn, False)#, True)
    attr = stream = None
    while True:
        msg = conn.recv ()
        if not msg:
            # Disconnect, leave
            break
        if isinstance (msg, Attrib):
            attr = msg
            continue
        elif isinstance (msg, (Date, Prot)):
            # Extended attributes, ignore those
            continue
        elif isinstance (msg, Access):
            fun = msg.accfunc
            if fun == msg.DIR:
                dodir (conn, msg)
            elif fun == msg.OPEN:
                doget (conn, msg, attr)
            else:
                # Unsupported, ACCFUNC field
                resp = Status (maccode = 2, miccode = 0o320)
                conn.send (resp)
                conn.flush ()
        else:
                # Out of sync
                resp = Status (maccode = 10, miccode = msg.type)
                conn.send (resp)
                conn.flush ()
    return 0

if __name__ == "__main__":
    sys.exit (main ())

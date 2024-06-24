#!/usr/bin/env python3

"""Poor Man's Router implementation

This implements the Poor Man's Routing service, also known as
Passthrough, an application layer connection relay.  This was used in
various DECnet scenarios to reach nodes that are not reachable by
routing layer mechanism: non-adjacent Phase II nodes, out of area
nodes from Phase III nodes, or "hidden area" destinations in large
networks such as DEC's Engineering Network.

"""

import sys
import asyncio

from decnet.async_connectors import AsyncPipeConnector, DEBUG, Nodeid, makestr

def closeconn (conn, abort = False):
    try:
        if not conn.closed:
            if abort:
                conn.abort ()
            else:
                conn.disconnect ()
    except Exception:
        pass

async def forward (conn1, conn2):
    """Forward traffic from conn1 to conn2.  Data, interrupts, and
    disconnects/aborts are passed along; the task exits on error or
    disconnect.
    """
    while True:
        msg = await conn1.recv ()
        msgtype = msg.type
        if msgtype == "data":
            conn2.data (msg)
        elif msgtype == "interrupt":
            conn2.interrupt (msg)
        elif msgtype == "disconnect":
            conn2.disconnect (msg)
            break
        else:
            connector.log (DEBUG, "PMR: unexpected message type {}: {}",
                           msgtype, msg)
            break
        
async def route (conn):
    """Handle a new incoming connection, starting with processing the
    connect data (if needed), accepting the connection, then processing
    all the data.
    """
    connmsg = await conn.recv ()
    assert connmsg.type == "connect"
    num, *name = connmsg.destination
    num = str (Nodeid (num))
    # Accept the connection, no accept data
    conn.accept ()
    # We now expect the PMR request string
    msg = await conn.recv ()
    if msg.type != "data":
        # Something strange.
        closeconn (conn, True)
        return 2
    # The message is a hop count followed by a string specifying what to
    # connect to.  In PyDECnet, the "connect" method of the simple and
    # async connectors understands that string including more PMR
    # requests, so all we have to do here is connect using that string.
    hopcount = msg[0] + 1
    connpath = makestr (msg[1:])
    # In the outbound connection, we give as source user descriptor
    # the one we received on the inbound connection, and similarly we
    # pass along the connect data.  This appears to be how some
    # (though not all) DEC implementations do things.
    conn2, resp = await connector.connect (dest = connpath,
                                           hopcount = hopcount,
                                           localuser = connmsg.srcuser,
                                           data = connmsg)
    if not conn2:
        if resp and resp.type == "reject":
            msg = "\x02Connect failure: {}".format (resp.text)
        else:
            msg = "\x02Connect failure"
        # Send the failure reply
        conn.data (msg)
        closeconn (conn)
        return 2
    # We have the opened outbound connection but we haven't received
    # the accept yet.  Wait for that now.  If more hops were needed
    # (the received PMR request had more than one node name) the
    # connector will handle that handshake.
    resp = await conn2.recv ()
    if resp.type == "reject":
        conn.reject (resp)
        return 1
    elif resp.type != "accept":
        # Something strange.
        closeconn (conn, True)
        closeconn (conn2, True)
        return 2
    # We got an accept.  Build the reply.
    pmrresponse = getattr (resp, "pmrresponse", None)
    hop1 = connpath.split (":", 1)[0]
    if pmrresponse:
        # There was another PMR in the path, insert the first hop name
        # in the response string.
        pmrresponse = makestr (pmrresponse)
        pmrresponse = "{}{}::{}".format (pmrresponse[0], hop1, pmrresponse[1:])
    elif False:
        # Possible PyDECnet extension: include the accept data in the
        # reply.  Disable this for now.
        pmrresponse = "\x01{}::{}".format (hop1, makestr (resp))
    else:
        pmrresponse = "\x01{}::".format (hop1)
    conn.data (pmrresponse)
    # We have two good connections.  Start two relaying tasks
    fwd12 = asyncio.create_task (forward (conn, conn2))
    fwd21 = asyncio.create_task (forward (conn2, conn))
    done, pending = await asyncio.wait ((fwd12, fwd21),
                                        return_when = asyncio.FIRST_COMPLETED)
    if pending:
        for t in pending:
            t.cancel ()
            for t in done:
                t.result ()
    for t in done:
        try:
            t.result ()
        except Exception as e:
            connector.log (DEBUG, "PMR forwarding task exception {}", e)
    closeconn (conn)
    closeconn (conn2)
    return 0

async def main (argv):
    """The main program for this process-level object.  It is started as
    a subprocess by pydecnet, with pipes for the three standard file
    descriptors.
    """
    # Create the connector and start it
    global connector
    connector = AsyncPipeConnector ()
    await connector.start ()
    # Get the inbound connection request that created this object
    # instance.
    conn = await connector.listen ()
    # We have the connection, start a task to handle it. 
    mtask = asyncio.create_task (route (conn))
    # In this DECnet object we are expected to deal with one
    # connection and then exit.
    ret = await mtask
    await connector.close ()
    return ret

if __name__ == "__main__":
    sys.exit (asyncio.run (main (sys.argv)))

****************************************************************

This is a work in progress.  The current version is fairly complete
and solid enough for production use.

If you use this software, I'd be interested in hearing your
observations.  Bug reports in particular are of course welcome, but
"it works fine" is also appreciated!

		Paul Koning, paulkoning@comcast.net

****************************************************************

PyDECnet is a pure Python implementation of the DECnet protocol
stack.  It can be used to implement a DECnet router or end node, and
provides a number of application protocols as well as an API that can
be used to allow applications written as separate processes to use
DECnet communication services.

Note that Digital and its successors have no involvement in this
implementation (other than by virtue of having published the protocol
specifications, which are available to the general public).

PyDECnet allows communication over Ethernet LANs (virtual or real),
GRE, SIMH emulated DDCMP connections over TCP or UDP, asynchronous
DDCMP connections via a supported UART, synchronous DDCMP connections
using my DDCMP framer, and Multinet connections over TCP (or, very
much not recommended, over UDP).  It was initially developed using
Python 3.3 on Mac OS 10.6 and 10.10; it should work with Python 3.3 or
later (but not with any earlier version of Python) on any Unix-like
operating system.  The current version was tested with Python 3.6 and
later since versions earlier than that are no longer supported (as of
2022).  PyDECnet may or may not work on Windows; if you try that, I
would be interested in hearing the results.  A few features require
Python 3.7.

The implementation is written to conform to the Digital Network
Architecture, Phase II, III, and IV, as published by Digital Equipment
Corporation.  "Written to conform" means (a) it can be configured to
acts as a Phase II, Phase III, or Phase IV node, and (b) it should
interoperate with other DECnet Phase II, III, or IV implementations
subject to their version interoperability rules.  The normal rule is
that each version interoperates with others of the same phase, or one
away.  This implementation also interoperates with any phase,
something not described by the specifications but not prohibited, and
not difficult to extrapolate from the specifications.

PyDECnet is licensed under the BSD 3-part license.

"DECnet" may be a trademark.  "PyDECnet" is not, to the best of my
knowledge. 

Dependencies: Async DDCMP support, over an actual serial port (as
opposed to a Telnet connection) requires the "pyserial" package.
Ethernet support (over real Ethernet, as opposed to Ethernet-style
bridging via Johnny Billquist's bridge program) requires libpcap or TAP
support.  To run as a daemon, you need the python-daemon package.  To
use YAML files in the --log-config option, you need the PyYAML
package.  To do password authentication for incoming DECnet
connections, you need the python-pam package.

****************************************************************

Project status:

As of 3/9/2022, the following are implemented and at least somewhat
tested:

- Data links: LAN and point to point frameworks, Ethernet (via the
Johnny Billquist bridge; via pcap; or via TAP); GRE encapsulation of
Ethernet; DDCMP (point to point only, over TCP, UDP, an actual UART,
or my synchronous framer USB device); Multinet over UDP (not
recommended due to the fact that this protocol grossly violates the
DECnet specifications) and over TCP.

- MOP on Ethernet, including console carrier and counters request, but
not load/dump service.

- Routing layer: endnode, level 1, level 2 (area router).  Phase II,
Phase III, and Phase IV are all implemented.  Phase II includes
partial "intercept node" support (the routing part but not the
connection tracking part).  All have received at least cursory
testing. 

- NSP and Session Control layer, with support for applications
(implemented as Python modules or as files which are run in a
subprocess).  There are several applications available, most of
which are enabled by default: "mirror" (for NCP LOOP NODE support),
"nml" (NICE protocol implementation for read operations only) and
"evl" (logging sink, accepts DECnet event messages from other nodes
and send them to the logging machinery), "pmr" (poor man's routing
"Passthrough" object) and "fal" (DAP file access listener, not enabled
by default).

- Fairly complete monitoring via HTTP or HTTPS, with CSS support.
Also monitoring via the NICE protocol.

- An API framework accessed via JSON.  This supports status queries
(similar to the data shown by the HTTP monitoring), a MOP Circuit Loop
requester, Console Carrier client and MOP Counters Request client, all
these for Ethernet circuits.  Also access to the Session Control
services, allowing external programs to request connections outbound,
receive inbound connections, and communicate over those connections.

- Other infrastructure: event logging tied into the Python logging
module, with event filtering, as well as support for the standard
three types of sinks to remote sink nodes.  Configuration file
handling somewhat like the DECnet "permanent database" but with syntax
similar to Unix commands.

- An implementation in Python of Johnny Billquist's bridge, ported from
his C program.  While this is not actually DECnet it is supporting
infrastructure and handy for testing.

To do:

- More documentation.

- Control (not just monitoring) via HTTP and NICE.

****************************************************************

Notes on the network mapper

PyDECnet includes a network map server, which operates by collecting
information about nodes from the HECnet node database, and then
scanning the network status to find reachable nodes and operational
circuits.  The resulting data is then mapped using the Leaflet map
display tools.

The HECnet map server is node 28NH, the map it generates is accessible
at http://akdesign.dyndns.org:8080/map .

A network needs only one or two map servers, and on HECnet those are
provided already.  For this reason, PLEASE DO NOT enable the map
server in PyDECnet unless you first coordinate with Johnny Billquist
and Paul Koning.

The Leaflet and Leaflet.Arc packages used by the mapper are included
with the PyDECnet sources; their licenses can be found in
Leaflet-LICENSE and Leaflet-arc-LICENSE.md respectively.

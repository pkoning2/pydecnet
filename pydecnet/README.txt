****************************************************************

This is a work in progress, somewhat incomplete at present.

Please feel free to use it.  Don't be surprised about problems.  If
you use this, please let me know; in particular bug reports would be
appreciated, but if works well for you, I'd like to hear about that as
well.

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
SIMH emulated DMC connections, and asynchronous DDCMP connections via
a supported UART.  It was developed using Python 3.3 on Mac OS 10.6
and 10.10; it should work with Python 3.3 or later (but not with any
earlier version of Python) on any Unix-like operating system.  It may
or may not work on Windows; if you try that, I would be interested in
hearing the results.  Note, however, that some strange behavior has
been seen in Python 3.3 and 3.5 testing -- but not in Python 3.7 --
when configuring multiple systems in a single invocation.  (The
symptom is that some of the sockets used get bind failures.)

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
opposed to a Telnet connection) requires the "serial" package.
Ethernet support (over real Ethernet, as opposed to Ethernet-style
bridging via Johnny Bilquist's bridge program) requires libpcap or TAP
support.  TAP support has only been done for Mac OS X at this time; it
depends on the "tuntaposx" package by Mattias Nissler (see
http://tuntaposx.sourceforge.net/ for details). To run as a daemon,
you need the python-daemon package.  To use YAML files in the
--log-config option, you need the PyYAML package.

A note on pcap: The original implementation used a modified version of
the pylibpcap package (changed for Python 3 support and to add the
"inject" method).  Later on, that dependency was removed and the
decnet.pcap pure Python wrapper is used instead.

****************************************************************

Project status:

As of 4/29/2020, the following are implemented and at least somewhat
tested:

- Data links: LAN and point to point frameworks, Ethernet (via the
Johnny Bilquist bridge; via pcap; on Mac OS, via TAP); GRE
encapsulation of Ethernet; DDCMP (point to point only, over TCP, UDP,
or an actual UART); Multinet over UDP (not recommended due to the fact
that this protocol grossly violates the DECnet specifications) and
over TCP.

- MOP on Ethernet, including console carrier and counters request.

- Routing layer: endnode, level 1, level 2 (area router).  Phase II,
Phase III, and Phase IV are all implemented.  Phase II includes
partial "intercept node" support (the routing part but not the
connection tracking part).  All have received at least cursory
testing. 

- NSP and Session Control layer, with support for internal
applications (implemented as Python modules).  There are several
application modules available, all of which are enabled by default:
"mirror" (for NCP LOOP NODE support), "nml" (NICE protocol
implementation for read operations only) and "evl" (logging sink,
accepts DECnet event messages from other nodes and send them to the
logging machinery).

- Fairly complete monitoring via HTTP or HTTPS, with CSS support.
Also monitoring via the NICE protocol.

- An API framework accessed via JSON.  At the moment this supports
status queries (accessing about the same data as the HTTP monitoring
does) as well as a MOP Console Carrier client and MOP Counters Request
client. 

- Other infrastructure: event logging tied into the Python logging
module, with event filtering, as well as support for the standard
three types of sinks to remote sink nodes.  Configuration file
handling somewhat like the DECnet "permanent database" but with syntax
similar to Unix commands.

- An implementation in Python of Johnny Bilquist's bridge, ported from
his C program.  While this is not actually DECnet it is supporting
infrastructure and handy for testing.

To do:

- More documentation.

- Also support for external applications via additional JSON API
mechanisms.

- Control (not just monitoring) via HTTP and NICE.

****************************************************************

Notes on the network mapper

PyDECnet includes a network map server, which operates by collecting
information about nodes from the HECnet node database, and then
scanning the network status to find reachable nodes and operational
circuits.  The resulting data is then mapped using the Leaflet map
display tools.

A network needs only one or two map servers, and on HECnet those are
provided already.  For this reason, PLEASE DO NOT enable the map
server in PyDECnet unless you first coordinate with Johnny Billquist
and Paul Koning.

The Leaflet and Leaflet.Arc packages used by the mapper are included
with the PyDECnet sources; their licenses can be found in
Leaflet-LICENSE and Leaflet-arc-LICENSE.md respectively.

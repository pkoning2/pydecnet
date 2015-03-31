****************************************************************

This is a work in progress, rather imcomplete at present.

Please feel free to use it.  Don't be surprised about problems.  If
you use this, please let me know; in particular bug reports would be
appreciated, but if it happens to work well I'd like to hear about
that as well.

		Paul Koning, paulkoning@comcast.net

****************************************************************

PyDECnet is a pure Python implementation of the DECnet protocol
stack.  It can be used to implement a DECnet router or end node, and
provides a number of application protocols as well as an API that can
be used to allow applications written as separate processes to use
DECnet communication services.  

PyDECnet allows communication over Ethernet LANs (virtual or real),
SIMH emulated DMC connections, and asynchronous DDCMP connections via
a supported UART.  It was developed using Python 3.3 on Mac OS 10.6
and 10.10; it should work with Python 3.3 or later (but not with any
earlier version of Python) on any Unix-like operating system.  It may
or may not work on Windows; if you try that, I would be interested in
hearing the results.

The implementation is written to conform to the Digital Network
Architecture, Phase IV, as published by Digital Equipment
Corporation.  Note that Digital and its successors have no involvement
in this implementation (other than by virtue of having published the
protocol specifications, which are available to the general public).

PyDECnet is licensed under a license analogous to the Python license.
See file LICENSE for details.

"DECnet" may be a trademark.  "PyDECnet" is not, to the best of my
knowledge. 

Dependencies: Async DDCMP support, over an actual serial port (as
opposed to a Telnet connection) requires the "serial" package.
Ethernet support requires libpcap or TAP support.  TAP support has
only been done for Mac OS X at this time; it depends on the
"tuntaposx" package by Mattias Nissler (see
http://tuntaposx.sourceforge.net/ for details).  The sample program
"rcexpect" depends on the "pexpect" package, modified for Python 3
support.

A note on pcap: The original implementation used a modified version of
the pylibpcap package (changed for Python 3 support and to add the
"inject" method).  Later on, that dependency was removed and the
decnet.pcap pure Python wrapper is used instead.

****************************************************************

Project status:

As of 6/18/2013, the following are implemented and at least somewhat
tested: 
- Data links: LAN and point to point frameworks, Ethernet (via pcap
and, on Mac OS, via TAP); GRE encapsulation of Ethernet; SIMH DMC-11
emulation; Multinet over UDP (not recommended due to the fact that
this protocol grossly violates the DECnet specifications).
- MOP on Ethernet, including console carrier (but not counters
request)
- Routing layer: endnode, level 1, level 2 (area router).  Phase IV
has been tested; Phase III is implemented but not tested.  Phase II is
partially implemented.
- NSP: just the first few bits of packet parsing.
- Simple monitoring via HTTP.
- An API framework accessed via a Unix domain socket.  At the moment
the only facility available this way is a MOP Console Carrier client.
- Other infrastructure: simple event logging tied into the Python
logging module.  Configuration file handling somewhat like the DECnet
"permanent database" but with syntax similar to Unix commands.

To do:
- Documentation.
- NSP, Session layer, selected application protocols.
- DECnet socket API.
- Control (not just monitoring) via HTTP.

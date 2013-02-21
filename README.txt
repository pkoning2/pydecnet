PyDECnet is a pure Python implementation of the DECnet protocol
stack.  It can be used to implement a DECnet router or end node, and
provides a number of application protocols as well as an API that can
be used to allow applications written as separate processes to use
DECnet communication services.  

PyDECnet allows communication over Ethernet LANs (virtual or real),
SIMH emulated DMC connections, and asynchronous DDCMP connections via
a supported UART.  It was developed using Python 3.2 on Mac OS 10.6;
it should work with Python 3.2 or later (but not with any earlier
version of Python) on any Unix-like operating system.  It may or may
not work on Windows.

The implementation is written to conform to the Digital Network
Architecture, Phase IV, as published by Digital Equipment
Corporation.  Note that Digital and its successors have no involvement
in this implementation (other than by virtue of having published the
protocol specifications, which are available to the general public).

PyDECnet is licensed under a license analogous to the Python license.
See file LICENSE for details.

"DECnet" may be a trademark.  "PyDECnet" is not, to the best of my
knowledge. 

Dependencies: Async DDCMP support requires the "serial" package.
Ethernet support requires libpcap or TAP support.  TAP support has
only been done for Mac OS X at this time; it depends on the "tuntaposx"
package by Mattias Nissler (see http://tuntaposx.sourceforge.net/ for
details).  The sample program "rcexpect" depends on the "pexpect"
package, modified for Python 3 support.

A note on pcap: The original implementation used a modified version of
the pylibpcap package (changed for Python 3 support and to add the
"inject" method).  Later on, that dependency was removed and the
decnet.pcap pure Python wrapper is used instead.

****************************************************************

Project status:

As of 2/21/2013, datalink and MOP support are in place, as well as a
lot of foundation work for the remainder.  The first small bits of
routing layer are appearing.  Apart from sending and receiving MOP and
Ethernet loopback protocol, nothing else works yet.

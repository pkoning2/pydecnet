from .common import *
from .routing_packets import *
from . import logging
from . import nsp

def tracepkt (msg, pkt, layer = 2):
    """Create a TRACE level log entry with given message and the supplied
    packet.  The packet is analyzed if possible to produce a formatted
    dump.  If that doesn't work, it's just dumped as a bytes value.
    "layer" is the protocol layer of the first header; it defaults to
    2 (datalink layer).
    """
    # TODO: datalinks other than Ethernet
    pkt = bytes (pkt)
    proto = rp = None
    parse = list ()
    if layer == 2:
        # Parse Ethernet header
        edst = Macaddr (pkt[:6])
        esrc = Macaddr (pkt[6:12])
        proto = pkt[12:14]
        parse.append ("{} {} {:0>2x}-{:0>2x}".format (edst, esrc,
                                                      proto[0], proto[1]))
        proto = int.from_bytes (proto, "big")
        if proto in { MOPDLPROTO, MOPCONSPROTO, ROUTINGPROTO}:
            plen = int.from_bytes (pkt[14:16], "little")
            parse[0] += " length {}".format (plen)
            pkt = pkt[16:16 + plen]
            if proto == ROUTINGPROTO:
                layer = 3
        else:
            pkt = pkt[14:]
    if layer == 3:
        # Parse DECnet routing packet
        c = pkt[0]
        if c & 0x80:
            # Padding, skip it
            c &= 0x7f
            parse.append ("routing layer padding {}".format (c))
            pkt = pkt[c:]
            c = pkt[0]
        if c & 1:
            code = (c >> 1) & 7
            rp = bccontrolpackets[code] (pkt)
            pkt = b''
        else:
            c &= 7
            if c == 6:
                rp = LongData (pkt)
                layer = 4
                pkt = rp.payload
            elif c == 2:
                rp = ShortData (pkt)
                layer = 4
                pkt = rp.payload
        if rp:
            parse.append (rp.format ({ "decoded_from", "testdata", "payload" }))
    if layer == 4:
        # Parse DECnet NSP packet
        c = pkt[0]
        np = nsp.msgmap[c] (pkt)
        parse.append ("  " + np.format ({ "decoded_from", "payload" }))
        try:
            pkt = np.payload
        except AttributeError:
            pkt = b''
    if pkt:
        parse.append (str (pkt))
    logging.trace ("{}{}", msg, "\n  ".join (parse))
    

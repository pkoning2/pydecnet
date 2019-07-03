from .common import *
from .routing_packets import *
from . import logging
from . import nsp

def tracepkt (msg, pkt):
    """Create a TRACE level log entry with given message and the supplied
    packet. 
    """
    pkt = bytes (pkt)
    parse = list ()
    if pkt:
        for ln in range (0, len (pkt), 16):
            n = list ()
            c = list ()
            for o in range (16):
                try:
                    b = pkt[ln + o]
                    n.append ("{:02x}".format (b))
                    ch = chr (b)
                    if ch.isprintable ():
                        c.append (ch)
                    else:
                        c.append (".")
                except IndexError:
                    n.append ("  ")
                if o == 8:
                    n.append ("")
            parse.append ("{:04x}/ {} {}".format (ln,
                                                  " ".join (n),
                                                  "".join (c)))
    logging.trace ("{}:\n  {}", msg, "\n  ".join (parse))
    

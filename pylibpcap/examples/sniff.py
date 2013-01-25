#! /usr/bin/env python
"""
Example to sniff all HTTP traffic on eth0 interface:
    sudo ./sniff.py eth0 "port 80"
"""

import sys
import pcap
import time
import socket
import struct

if sys.version_info[0] > 2:
    IPPROTO = bytes ((0x08, 0x00))
    bord = int
else:
    IPPROTO = '\x08\x00'
    bord = ord
    
protocols={socket.IPPROTO_TCP:'tcp',
            socket.IPPROTO_UDP:'udp',
            socket.IPPROTO_ICMP:'icmp'}

def decode_ip_packet(s):
    d={}
    d['version']=(bord(s[0]) & 0xf0) >> 4
    d['header_len']=bord(s[0]) & 0x0f
    d['tos']=bord(s[1])
    d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags']=(bord(s[6]) & 0xe0) >> 5
    d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['ttl']=bord(s[8])
    d['protocol']=bord(s[9])
    d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
    d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
    if d['header_len']>5:
        d['options']=s[20:4*(d['header_len']-5)]
    else:
        d['options']=None
    d['data']=s[4*d['header_len']:]
    return d


def dumphex(s):
    bytes = map(lambda x: '%.2x' % x, map(bord, s))
    if sys.version_info[0] > 2:
        bytes = list (bytes)
    for i in range(0,len(bytes)//16):
        print ('        %s' % ' '.join(bytes[i*16:(i+1)*16]))
    print ('        %s' % ' '.join(bytes[(i+1)*16:]))
        
def print_packet(pktlen, data, timestamp):
    if not data:
        return

    if data[12:14]==IPPROTO:
        decoded=decode_ip_packet(data[14:])
        print ('\n%s.%f %s > %s' % (time.strftime('%H:%M',
                                time.localtime(timestamp)),
                                timestamp % 60,
                                decoded['source_address'],
                                decoded['destination_address']))
        for key in ['version', 'header_len', 'tos', 'total_len', 'id',
                                'flags', 'fragment_offset', 'ttl']:
            print ('    %s: %d' % (key, decoded[key]))
        print ('    protocol: %s' % protocols[decoded['protocol']])
        print ('    header checksum: %d' % decoded['checksum'])
        print ('    data:')
        dumphex(decoded['data'])
    else:
        dumphex(data)
 

if __name__=='__main__':

    if len(sys.argv) < 3:
        print ('usage: sniff.py <interface> <expr>')
        sys.exit(0)
    p = pcap.pcapObject()
    #dev = pcap.lookupdev()
    dev = sys.argv[1]
    try:
        net, mask = pcap.lookupnet(dev)
    except Exception:
        net, mask = 0, 0
    # note:    to_ms does nothing on linux
    p.open_live(dev, 1600, 0, 100)
    #p.dump_open('dumpfile')
    p.setfilter(' '.join(sys.argv[2:]), 0, 0)

    # try-except block to catch keyboard interrupt.    Failure to shut
    # down cleanly can result in the interface not being taken out of promisc.
    # mode
    #p.setnonblock(1)
    try:
        while 1:
            p.dispatch(1, print_packet)

        # specify 'None' to dump to dumpfile, assuming you have called
        # the dump_open method
        #    p.dispatch(0, None)

        # the loop method is another way of doing things
        #    p.loop(1, print_packet)

        # as is the next() method
        # p.next() returns a (pktlen, data, timestamp) tuple 
        #    apply(print_packet,p.next())
    except KeyboardInterrupt:
        print ('%s' % sys.exc_type)
        print ('shutting down')
        print ('%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats())
    


# vim:set ts=4 sw=4 et:

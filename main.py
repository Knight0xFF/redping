#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pcap
import dpkt
import socket
import struct
from scapy.all import sniff
import curses

#
# pc = pcap.pcap("en0")
# # pc.setfilter("en0")
# decode = { pcap.DLT_LOOP: dpkt.loopback.Loopback,
#            pcap.DLT_NULL: dpkt.loopback.Loopback,
#            pcap.DLT_EN10MB: dpkt.ethernet.Ethernet }[pc.datalink()]
# try:
#     print 'listening on %s: %s' % (pc.name, pc.filter)
#     for ts, pkt in pc:
#         print ts, `decode(pkt)`
# except KeyboardInterrupt:
#     nrecv, ndrop, nifdrop = pc.stats()
#     print '\n%d packets received by filter' % nrecv
#     print '%d packets dropped by kernel' % ndrop

sniff(filter="", iface="en0", prn=lambda x: x.show())

print "hello world"
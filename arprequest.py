#!/usr/bin/python

import struct
import socket

rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
rawSocket.bind(("enp0s8", socket.htons(0x0800)))

source_mac = "08:00:27:d4:a2:5e"        # sender mac address
source_ip  = "10.0.0.11"           # sender ip address
dest_mac = "\xbb\xbb\xbb\xbb\xbb\xbb"   # target mac address
dest_ip  = "10.0.0.12"             # target ip address

# Ethernet Header
protocol = 0x0806                       # 0x0806 for ARP
eth_hdr = struct.pack("!6s6sH", dest_mac, source_mac, protocol)

# ARP header
htype = 1                               # Hardware_type ethernet
ptype = 0x0800                          # Protocol type IP
hlen = 6                                # Hardware address Len
plen = 4                                # Protocol addr. len
operation = 1                           # 1=request/2=reply
src_ip = socket.inet_aton(source_ip)
dst_ip = socket.inet_aton(dest_ip)
arp_hdr = struct.pack("!HHBBH6s4s6s4s", htype, ptype, hlen, plen, operation, source_mac, src_ip, dest_mac, dst_ip)

packet = eth_hdr + arp_hdr
rawSocket.send(packet)
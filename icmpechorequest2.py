#!/usr/bin/python

import struct
import socket

# From http://www.bitforestinfo.com/2018/01/code-icmp-raw-packet-in-python.html
def checksum(msg):
  s = 0       # Binary Sum
  # loop taking 2 characters at a time
  for i in range(0, len(msg), 2):
    a = ord(msg[i])
    b = ord(msg[i+1])
    s = s + (a+(b << 8))
  # One's Complement
  s = s + (s >> 16)
  s = ~s & 0xffff
  return socket.ntohs(s)

# Get ICMP code
icmp = socket.getprotobyname("icmp")

# Create a raw socket
try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
except socket.error , msg:
  print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
  sys.exit()

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# IP header fields
ip_ver = 4
ip_ihl = 5
ip_tos = 0
ip_tot_len = 0  # kernel will fill the correct total length
ip_id = 54321   #Id of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_ICMP
ip_check = 0    # kernel will fill the correct checksum
ip_saddr = socket.inet_aton("10.32.143.155")
ip_daddr = socket.inet_aton("10.32.143.224")

ip_ihl_ver = (ip_ver << 4) + ip_ihl

ip_header = struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

# ICMP header fields
type = 8
code = 0
mychecksum = 0
identifier = 12345
seqnumber = 0
payload = '123456'

icmp_packet = struct.pack("!BBHHH6s", type, code, mychecksum, identifier, seqnumber, payload)

# Recalculate checksum based on whole packet
mychecksum = checksum(icmp_packet)

icmp_packet = struct.pack("!BBHHH6s", type, code, mychecksum, identifier, seqnumber, payload)

# Get destination address
dest_ip = "10.32.143.224"
dest_addr = socket.gethostbyname(dest_ip)

# Send echo request
s.sendto(ip_header+icmp_packet, (dest_addr,0))

# (packet,addr) = s.recvfrom(65565)

# print hex(ord(packet[0])), hex(ord(packet[1])), hex(ord(packet[2]))



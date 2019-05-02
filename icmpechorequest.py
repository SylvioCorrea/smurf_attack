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
dest_ip = "10.0.0.12"
dest_addr = socket.gethostbyname(dest_ip)

# Send echo request
s.sendto(icmp_packet, (dest_addr,0))
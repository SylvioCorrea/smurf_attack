#Sends ARP requests e replys baseados no input do usuario
#Python 2

#exemplo request:
#sudo python arpsend.py a4:1f:72:f5:90:b7 10.32.143.65 00:00:00:00:00:00 10.32.143.66 1
#exemplo reply:
#sudo python arpsend.py a4:1f:72:f5:90:b7 10.32.143.65 a4:1f:72:f5:90:80 10.32.143.66 2

# strvalue.decode('hex'): transforma o valor em strvalue
# em uma sequencia de bytes


import struct
import socket
import sys

def mac2bytes(mac):
  bytes = ''
  for c in mac.split(':'):
    bytes = bytes + c.decode('hex')
  return bytes

def string2hexip(sip):
  ns = sip.split('.')
  ns2 = []
  for n in ns:
    ns2.append(int(n))
  return struct.pack('!BBBB', ns2[0], ns2[1], ns2[2], ns2[3])
  
  
if len(sys.argv) < 6:
  print 'Uso: sudo python arpsend.py <source mac> <source ip> <dest mac> <dest ip> <arp opcode>'
  exit()

eth_prot = 0x0806
source_mac = mac2bytes(sys.argv[1])
source_ip = string2hexip(sys.argv[2])

arp_opcode = int(sys.argv[5])
if arp_opcode == 1: #ARP request
  target_mac = mac2bytes('ff:ff:ff:ff:ff:ff') #broadcast mac
  target_mac_arp = mac2bytes('00:00:00:00:00:00')
  #campo vai zerado pois eh um request: origem desconhece
  #o endereço MAC associado ao IP
else:
  target_mac = mac2bytes(sys.argv[3])
  target_mac_arp = target_mac

target_ip = string2hexip(sys.argv[4])

#ethernet header
eth_header = struct.pack("!6s6sH", target_mac, source_mac, eth_prot)

hw_type = 1
prot_ipv4 = 0x0800
hw_add_len = 6
prot_add_len = 4

arp_header = struct.pack("!HHBBH6s4s6s4s", hw_type, prot_ipv4, hw_add_len, prot_add_len, arp_opcode, source_mac, source_ip, target_mac_arp, target_ip)

packet = eth_header+arp_header

rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
rawSocket.bind(("enp4s0", socket.htons(0x0800)))
rawSocket.send(packet)

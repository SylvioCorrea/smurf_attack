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
  shorts = struct.unpack('!HHHHHH', header)
  sum = 0
  for n in shorts:
    sum = sum + n
  sum = sum + sum>>16 #se houver carry, soma-o como se fosse um novo numero
  return (~sum) & 0xffff

if len(sys.argv) < 2:
	print "Uso: python ping.py <IP alvo>"
  exit()

target_ip = socket.gethostbyname(sys.argv[1])

#icmp header
type = 8
code = 0
checksum_zero = 0
identifier = 0xffff
sequence = 0x0123
payload = 'asdf'

true_checksum = checksum(struct.pack('!BBHHH4s', type, code, checksum_zero, identifier, sequence, payload))
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

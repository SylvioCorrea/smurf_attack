#Exercicio 1 feito sobre o modelo de autoria de Silver Moon
#Adicionado codigo que le e interpreta o header ARP, funcao ip_from_string

#Packet sniffer in python
#For Linux - Sniffs all incoming and outgoing packets :)
#Silver Moon (m00n.silv3r@gmail.com)

import socket, sys
from struct import *
import time

class Ping_Counter:
    #n = numero de pings de um mesmo host
    #t = momento do ultimo ping
    def __init__(self, n, t):
        self.n = n
        self.t = t

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

#Converte uma string de 4 caracteres para o formato ip  
def ip_from_string(s) :
    ip = "%d.%d.%d.%d" % (ord(s[0]), ord(s[1]), ord(s[2]), ord(s[3]))
    return ip
    
def get_arp_opcode(opc):
    if opc==1: return 'request'
    elif opc==2: return 'reply'
    else: return 'unlisted opcode ' + str(opc)









def main():

    if len(sys.argv) < 2:
        print('Uso: sudo python3 smurf_sniffer.py <interface>')
        print('Exemplo: sudo python3 smurf_sniffer.py enp0s3')
        exit()

    #create a AF_PACKET type raw socket (thats basically packet level)
    #define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
    try:
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
    except(socket.error , msg):
        print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

    # Dicionario de pings que guarda quantos pings um determinado
    # endereco fez em rapida sequencia
    ping_map = {}

    # receive a packet
    while True:
        (packet,addr) = s.recvfrom(65565) # bufsize - 64kbytes

        #parse ethernet header
        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        eth_dstaddr = eth[0]
        eth_srcaddr = eth[1]
        eth_type = eth[2]

        #print('Destination MAC : ' + eth_addr(eth_dstaddr) + ' Source MAC : ' + eth_addr(eth_srcaddr) + ' Protocol : ' + ("%.4x"%eth_type))

        #Parse IP packets, IP Protocol number = 0x0800
        if eth_type == 0x0800 :
            #Parse IP header
            #take first 20 characters for the ip header
            ip_header = packet[eth_length:20+eth_length]

            #now unpack them :)
            iph = unpack('!BBHHHBBH4s4s' , ip_header)
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);

            #print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))

            #ICMP Packets
            if protocol == 0x01 :
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u+4]

                icmph = unpack('!BBH' , icmp_header)

                icmp_type = icmph[0]
                '''
                code = icmph[1]
                checksum = icmph[2]
                '''
                
                if icmp_type==8:
                    print('ICMP: Echo request')
                    print('Source: ', s_addr)
                    '''
                    print('Destination', d_addr)
                    print('Code : ' + str(code) + ' Checksum : ' + str(checksum))

                    h_size = eth_length + iph_length + icmph_length
                    data_size = len(packet) - h_size

                    #get data from the packet
                    data = packet[h_size:]

                    print('Data size: %d' % (len(data)))
                    print('Data : ' + str(data))
                    '''

                    # Verificando quantidade de pings disparados por este endereco IP
                    t = time.time()
                    ping_c = ping_map.get(s_addr)
                    if ping_c is None: # Primeiro ping endereco
                        ping_c = Ping_Counter(1, t)
                        ping_map[s_addr] = ping_c
                    elif ping_c.t - t > 0.05: 
                        ping_c.n = 1 # Reseta o numero de pings guardados para o endereco
                        ping_c.t = t # Guarda o tempo do ultimo ping
                    else:
                        # Tempo entre o ping atual e o ultimo ping do mesmo
                        # endereco eh menor do que 0.05s
                        ping_c.n += 1 #Incrementa a quantidade de pings em sequencia do endereco
                        ping_c.t = t
                        if ping_c.n > 20: # Criterio de caracterizacao de ataque
                            print('Ataque detectado!\nMAC do provavel atacante: ', eth_srcaddr)
          
                print('----------------------------------------')
      
if __name__ == '__main__':
    main()

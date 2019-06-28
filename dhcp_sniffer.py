#Exercicio 1 feito sobre o modelo de autoria de Silver Moon
#Adicionado codigo que le e interpreta o header ARP, funcao ip_from_string

#Exemplo: sudo python3 smurf_sniffer.py enp4s0


#Packet sniffer in python
#For Linux - Sniffs all incoming and outgoing packets :)
#Silver Moon (m00n.silv3r@gmail.com)

import socket, sys
from struct import *
import time

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

    #create a AF_PACKET type raw socket (thats basically packet level)
    #define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
    try:
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
    except(socket.error , msg):
        print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()


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

            #UDP Packets
            if protocol == 0x11 and s_addr == '0.0.0.0' and d_addr == '255.255.255.255':
                
                udp_length = 8;
                udp_start = eth_length+20 #20 from ip packet
                udp_header = packet[udp_start: udp_start+udp_length]
                udph = unpack('!HHHH' , udp_header)
                source_port = udph[0]
                dest_port = udph[1]
                total_udp_length = udph[2]
                
                if source_port == 68 and dest_port == 67 :
                    next_start = udp_start + udp_length
                    next_size = total_udp_length - udp_length
                    rem_packet = packet[next_start : next_start+next_size]
                    
                    dhcp_option = rem_packet[59:64]
                    
                    
                    print(total_udp_length)
                    i = 0
                    while(i<len(rem_packet)):
                        print(i, rem_packet[i:i+4])
                        i+=4
                    print(i, rem_packet[i:i+len(rem_packet)%4])
                    print('======================================\n\n')
                    
                
                
                
      
if __name__ == '__main__':
    main()

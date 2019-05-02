#Exercicio 1 feito sobre o modelo de autoria de Silver Moon
#Adicionado codigo que le e interpreta o header ARP, funcao ip_from_string

#Packet sniffer in python
#For Linux - Sniffs all incoming and outgoing packets :)
#Silver Moon (m00n.silv3r@gmail.com)

import socket, sys
from struct import *

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

#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
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
    print('Destination MAC : ' + eth_addr(eth_dstaddr) + ' Source MAC : ' + eth_addr(eth_srcaddr) + ' Protocol : ' + ("%.4x"%eth_type))

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

        print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

        #TCP protocol
        if protocol == 0x06 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]

            #now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)

            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size

            #get data from the packet
            # data = packet[h_size:]

            # print 'Data : ' + data

        #ICMP Packets
        elif protocol == 0x01 :
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]

            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
            
            print 'ICMP'
            if icmp_type==0: print 'Echo reply'
            elif icmp_type==8: print 'Echo request'
            else: print '\nType : ' + str(icmp_type)
            print 'Code : ' + str(code) + ' Checksum : ' + str(checksum)

            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]
            
            print 'Data size: %d' % (len(data))
            print 'Data : ' + data

        #UDP packets
        elif protocol == 0x11 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)

            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size

            #get data from the packet
            # data = packet[h_size:]

            # print 'Data : ' + data

        #some other IP packet like IGMP
        else :
            print 'Protocol other than TCP/UDP/ICMP'
    
    elif eth_type == 0x0806 :
        print "Protocol ARP"
        arp_length = 28 #tamanho do arp header
        arp_header = packet[eth_length : eth_length + arp_length] #pega todo o header do pacote
        """
        Especificacao de cada componente do header
        0. HW Addr. Type = 2B 			(H)
        1. Protocol Addr Type = 2B 		(H)
        2. HW Addr len. = 1B 			(B)
        3. Protocol Addr len = 1B 		(B)
        4. Opcode = 2B					(H)
        5. Source HW addr(mac) = 6B		(6s)
        6. Source Prot addr = 4B		(4s)
        7. Tgt HW addr(mac) = 6B		(6s)
        8. Tgt Prot addr = 4B			(4s)
        """
        arp_unpacked = unpack('!HHBBH6s4s6s4s', arp_header)
        
        #Estes valores do header nao sao impressos no terminal
        hw_addr_type = arp_unpacked[0]
        prot_addr_type = arp_unpacked[1]
        hw_addr_len = arp_unpacked[2]
        prot_addr_len = arp_unpacked[3]
        #=====================================================
        #Valores que sao impressos no terminal
        opcode = arp_unpacked[4]
        source_hw_addr = arp_unpacked[5]
        source_prot_addr = arp_unpacked[6]
        tgt_hw_addr = arp_unpacked[7]
        tgt_prot_addr = arp_unpacked[8]
        print '\tHardware address type: '+ str(hw_addr_type) + '\n\tProtocol address type: '+ str(prot_addr_type) + '\n\tHardware address length: ' + str(hw_addr_len) + '\n\tProtocol adress length: ' + str(prot_addr_len)
        print '\tOpcode: '+ get_arp_opcode(opcode) + '\n\tSource MAC: '+ eth_addr(source_hw_addr) +"\n\tSource IP: "+ip_from_string(source_prot_addr) + '\n\tTarget MAC: '+ eth_addr(tgt_hw_addr)+'\n\tTarget IP: ' + ip_from_string(tgt_prot_addr)
        
    print '----------------------------------------'	

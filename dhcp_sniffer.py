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

def mac2bytes(mac):
  mac = mac.replace(':', '')
  return bytes.fromhex(mac)

def string2hexip(sip):
  ns = sip.split('.')
  ns2 = []
  for n in ns:
    ns2.append(int(n))
  return pack('!BBBB', ns2[0], ns2[1], ns2[2], ns2[3])

def checksum(msg):
  s = 0       # Binary Sum
  # loop taking 2 characters at a time
  for i in range(0, len(msg), 2):
    a = msg[i]
    b = msg[i+1]
    s = s + (a+(b << 8))
  # One's Complement
  s = s + (s >> 16)
  s = ~s & 0xffff
  return socket.ntohs(s)

ip_offer = string2hexip('10.32.143.150')
ip_a = string2hexip('10.32.143.66')
mac_a = mac2bytes('a4:1f:72:f5:90:80')
subnet_mask = string2hexip('255.255.255.0')
broadcast_ip = string2hexip('255.255.255.255')
zero_ip = string2hexip('0.0.0.0')
zero_192 = bytes(192)

ip_ver_send = 4
ip_ihl_send = 5
ip_ihl_ver = (ip_ver_send << 4) + ip_ihl_send
ip_tos_send = 0
ip_tot_len_send = 0  # kernel will fill the correct total length
ip_id_send = 54321   #Id of this packet
ip_frag_off_send = 0
ip_ttl_send = 255
ip_proto_send = socket.IPPROTO_ICMP
ip_check_send = 0    # kernel will fill the correct checksum

ip_check = 0


def main():

    #create a AF_PACKET type raw socket (thats basically packet level)
    #define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
    try:
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
    except(socket.error , msg):
        print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    
    try:
        s_sender = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        s_sender.bind(('enp4s0', 67))
    except(socket.error , msg):
        print('Sender socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
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
            s_addr = iph[8];
            d_addr = iph[9];

            #print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))

            #UDP Packets
            if protocol == 0x11 and s_addr == zero_ip and d_addr == broadcast_ip:
                
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
                    dhcp_xid = rem_packet[4:8]
                    dhcp_option = rem_packet[240:243]
                    
                    
                    
                    # Discover recebido
                    if dhcp_option[0] == 0x35 and dhcp_option[2] == 0x1:
                        print('Discover received. Sending Offer')
                        
                        #===========================
                        total_ip_len = 302 #atualizar sempre que trocar o tamanho do pacote
                        eth_send = pack("!6s6sH", eth_srcaddr, mac_a, eth_type)
                        ip_send = pack('!BBHHHBBH4s4s',
                                              version_ihl,
                                              0, #TOS
                                              total_ip_len, #total len
                                              0, #identification
                                              0, #flags
                                              255, #ttl
                                              protocol,
                                              0, 
                                              ip_a,
                                              d_addr)
                        ip_check = checksum(ip_send)
                        #ip packet atualizado com checksum correto
                        ip_send = pack('!BBHHHBBH4s4s',
                                              version_ihl,
                                              0, #TOS
                                              total_ip_len, #total len
                                              0, #identification
                                              0, #flags
                                              255, #ttl
                                              protocol,
                                              ip_check, 
                                              ip_a,
                                              d_addr)
                        ip_header_size = len(ip_send)
                        
                        udp_send = pack('!HHHH', dest_port, source_port, 282, 0) # 308
                        udp_header_size = len(udp_send)
                        
                        rem_packet_send = pack('!4s4sHH4s4s4s4s6sH4s4s192s4sBBBBB4sBB4sBB4sBB4sBB4sB',
                                                      bytes.fromhex('02010600'), #4B
                                                      dhcp_xid, # 4B
                                                      0, #secs 2B
                                                      0, #flag 2B
                                                      zero_ip, #ciaddr 4B
                                                      ip_offer, #yiaddr 4B
                                                      ip_a, #siaddr 4B
                                                      ip_a, #giaddr 4B
                                                      eth_srcaddr, #chaddr 6B
                                                      0, #2B
                                                      bytes.fromhex('00000000'), #4B
                                                      bytes.fromhex('00000000'), #4B
                                                      bytes(192), #192B
                                                      bytes.fromhex('63825363'), #magic cookie 4B
                                                      53, #dhcp msg #1B
                                                      1, #length 1B
                                                      2, #msg offer data 1B
                                                      
                                                      1, #opt mask 1B
                                                      4, #length 1B
                                                      subnet_mask, #4B
                                                      
                                                      3, #default gw 1B
                                                      4, #len 1B
                                                      ip_a, # gw 4B
                                                      
                                                      51, #lease ip time 1B
                                                      4, #len 1B
                                                      bytes.fromhex('00000078'), #2 minutos 4B
                                                      
                                                      54, #dhcp server #1B
                                                      4, #len 1B
                                                      ip_a, #dhcp server ip 4B
                                                      
                                                      6, #dns 1B
                                                      4, #len 1B
                                                      ip_a, #dns add 4B
                                                      255
                                                      )
                                                      
                        rem_size = len(rem_packet_send)
                        print('ip len', ip_header_size)
                        print('udp len', udp_header_size)
                        print('rem len', rem_size)
                        print('total udp len', udp_header_size + rem_size)
                        print('total ip len', ip_header_size + udp_header_size + rem_size)
                        mega_packet = eth_send + ip_send + udp_send + rem_packet_send
                        s_sender.send(mega_packet)
                        
                        
                        
                        
                        
                        #===========================
                        
                    # Request recebido
                    if dhcp_option[0] == 0x35 and dhcp_option[2] == 0x3:
                        print(dhcp_option)
                        print('Request received. Sending ack.')
                        
                        print(eth_srcaddr)
                        
                        #===========================
                        total_ip_len = 302 #atualizar sempre que trocar o tamanho do pacote
                        eth_send = pack("!6s6sH", eth_srcaddr, mac_a, eth_type)
                        ip_send = pack('!BBHHHBBH4s4s',
                                              version_ihl,
                                              0, #TOS
                                              total_ip_len, #total len
                                              0, #identification
                                              0, #flags
                                              255, #ttl
                                              protocol,
                                              0, 
                                              ip_a,
                                              d_addr)
                        ip_check = checksum(ip_send)
                        #ip packet atualizado com checksum correto
                        ip_send = pack('!BBHHHBBH4s4s',
                                              version_ihl,
                                              0, #TOS
                                              total_ip_len, #total len
                                              0, #identification
                                              0, #flags
                                              255, #ttl
                                              protocol,
                                              ip_check, 
                                              ip_a,
                                              d_addr)
                        ip_header_size = len(ip_send)
                        
                        udp_send = pack('!HHHH', dest_port, source_port, 282, 0) # 308
                        udp_header_size = len(udp_send)
                        
                        rem_packet_send = pack('!4s4sHH4s4s4s4s6sH4s4s192s4sBBBBB4sBB4sBB4sBB4sBB4sB',
                                                      bytes.fromhex('02010600'), #4B
                                                      dhcp_xid, # 4B
                                                      0, #secs 2B
                                                      0, #flag 2B
                                                      zero_ip, #ciaddr 4B
                                                      ip_offer, #yiaddr 4B
                                                      ip_a, #siaddr 4B
                                                      ip_a, #giaddr 4B
                                                      eth_srcaddr, #chaddr 6B
                                                      0, #2B
                                                      bytes.fromhex('00000000'), #4B
                                                      bytes.fromhex('00000000'), #4B
                                                      bytes(192), #192B
                                                      bytes.fromhex('63825363'), #magic cookie 4B
                                                      53, #dhcp msg #1B
                                                      1, #length 1B
                                                      5, #msg ack data 1B
                                                      
                                                      1, #opt mask 1B
                                                      4, #length 1B
                                                      subnet_mask, #4B
                                                      
                                                      3, #default gw 1B
                                                      4, #len 1B
                                                      ip_a, # gw 4B
                                                      
                                                      51, #lease ip time 1B
                                                      4, #len 1B
                                                      bytes.fromhex('00000078'), #2 minutos 4B
                                                      
                                                      54, #dhcp server #1B
                                                      4, #len 1B
                                                      ip_a, #dhcp server ip 4B
                                                      
                                                      6, #dns 1B
                                                      4, #len 1B
                                                      ip_a, #dns add 4B
                                                      255
                                                      )
                                                      
                        rem_size = len(rem_packet_send)
                        #print('ip len', ip_header_size)
                        #print('udp len', udp_header_size)
                        #print('rem len', rem_size)
                        #print('total udp len', udp_header_size + rem_size)
                        #print('total ip len', ip_header_size + udp_header_size + rem_size)
                        mega_packet = eth_send + ip_send + udp_send + rem_packet_send
                        s_sender.send(mega_packet)
                        
                    # NAK
                    if dhcp_option[0] == 0x35 and dhcp_option[2] == 0x6:
                        print(dhcp_option)
                        
                    print('======================================\n\n')
                    
                
                
                
      
if __name__ == '__main__':
    main()

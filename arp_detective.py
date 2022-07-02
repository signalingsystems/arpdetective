'''
'''
from itertools import count
from scapy.all import sniff 
'''

'''
ip_mac_map ={}

#
#
#
#
def process_packet(packet):
   src_ip = packet['ARP'].psrc
   src_mac=packet['Ether'].src
   old_ip=''
   if src_mac in ip_mac_map.keys():
      if ip_mac_map[src_mac]!=src_ip:
         try:
            old_ip = ip_mac_map[src_mac]
         except:
            old_ip ='unknown'
         msg='possible arp attack detected\n machine with ip {old_ip}'
         +'is pretending to be {src_ip}'
         return msg
   else:
      ip_mac_map[src_mac]=src_ip

sniff(count=0,filter='arp',store=0,prn=process_packet)


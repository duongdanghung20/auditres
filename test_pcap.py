#!/usr/bin/python3

from scapy.all import *

client, server = ("192.168.1.1", "192.168.1.75")
clport, servport = (12346, 80)

cl_isn, serv_isn = (2207, 2008)

eth_servcl, eth_clserv = (Ether()/IP(src=server, dst=client), Ether()/IP(src=client, dst=server))

syn_p = eth_clserv/TCP(flags="S", sport=clport, dport=servport, seq=cl_isn)

synack_p = eth_servcl/TCP(flags="SA", sport=servport, dport=clport, seq=serv_isn, ack=syn_p.ack+1)

ack_p = eth_clserv/TCP(flags="A", sport=clport, dport=servport, seq=syn_p.seq+1, ack=synack_p.seq+1)

data = "GET / HTTP/1.1\r\nHost: www.unilim.fr\r\n\r\n"

get_p = eth_clserv/TCP(flags="PA", sport=clport, dport=servport, seq=ack_p.seq, ack=ack_p.ack)/data

p_list = [syn_p, synack_p, ack_p, get_p]

#print(p_list)

wrpcap("handshake.pcap", p_list)

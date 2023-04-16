#!/usr/bin/python3

from scapy.all import *
from netfilterqueue import NetfilterQueue
import subprocess

IPV6_PREFIX = "2001:2:3:4501:"

## Find the MAC and IPv6 address of the netns h1
p1 = subprocess.Popen("ip netns exec h1 ip address show eth0".split(" "), stdout=subprocess.PIPE)
p2 = subprocess.Popen(["grep", "-E", "link/ether|{}".format(IPV6_PREFIX)], stdin=p1.stdout, stdout=subprocess.PIPE)
CLIENT_MAC, CLIENT_IPV6  = [line.strip().split()[1] for line in p2.communicate()[0].decode().splitlines()]
p1.stdout.close()
CLIENT_IPV6 = CLIENT_IPV6[:-3]


## Find the IPv4 and IPv6 addresses of the server by sending DNS Request using dig command, mode A (to find IPv4) and AAAA (to find IPv6)
SERVER_IPV4, SERVER_IPV6 = [subprocess.run(["dig", "+short", "google.com", dig_type], capture_output=True).stdout.decode().strip("\n") for dig_type in ["A", "AAAA"]]

INTERNET_IFACE = "wlo1"
LOCAL_IPV6_IFACE = "bridge_ipv6"

def process_outgoing_packets(p):
    data = p.get_payload()
    
    ipv6_packet = IPv6(data)
    tc = ipv6_packet.tc
    hlim = ipv6_packet.hlim

    p_tcp = ipv6_packet[TCP]
    del p_tcp.chksum # If not do this, receive no SYN/ACK

    ipv4_header = IP(tos=tc, ttl=hlim, proto='tcp', dst=SERVER_IPV4)

    ipv4_packet = Ether() / ipv4_header / p_tcp

    sendp(ipv4_packet, iface=INTERNET_IFACE)

def process_incoming_packets(p):
    data = p.get_payload()
    
    ipv4_packet = IP(data)

    p_tcp = ipv4_packet[TCP]
    tos = ipv4_packet.tos
    ttl = ipv4_packet.ttl
    proto = ipv4_packet.proto
    del p_tcp.chksum

    ipv6_header = IPv6(tc=tos, hlim=ttl, nh=proto, src=SERVER_IPV6, dst=CLIENT_IPV6)

    ipv6_packet = Ether(dst=CLIENT_MAC) / ipv6_header / p_tcp

    sendp(ipv6_packet, iface=LOCAL_IPV6_IFACE)

q1 = NetfilterQueue()
q1.bind(1, process_outgoing_packets)

q2 = NetfilterQueue()
q2.bind(2, process_incoming_packets)

t1 = threading.Thread(target=q1.run)
t2 = threading.Thread(target=q2.run)
t1.start()
t2.start()
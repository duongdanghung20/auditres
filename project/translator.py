#!/usr/bin/python3

from scapy.all import *
from netfilterqueue import NetfilterQueue
import threading

class Translator:
    def __init__(self, server_ipv4, server_ipv6, client_mac, client_ipv6, internet_iface, local_ipv6_iface) -> None:
        self.__server_ipv4 = server_ipv4
        self.__server_ipv6 = server_ipv6
        self.__client_mac = client_mac
        self.__client_ipv6 = client_ipv6
        self.__internet_iface = internet_iface
        self.__local_ipv6_iface = local_ipv6_iface

    def process_outgoing_packets(self, p):
        data = p.get_payload()
        
        ipv6_packet = IPv6(data)
        tc = ipv6_packet.tc
        hlim = ipv6_packet.hlim

        p_tcp = ipv6_packet[TCP]
        del p_tcp.chksum # If not do this, receive no SYN/ACK

        ipv4_header = IP(tos=tc, ttl=hlim, proto='tcp', dst=self.__server_ipv4)

        ipv4_packet = Ether() / ipv4_header / p_tcp

        sendp(ipv4_packet, iface=self.__internet_iface)

    def process_incoming_packets(self, p):
        data = p.get_payload()
        
        ipv4_packet = IP(data)

        p_tcp = ipv4_packet[TCP]
        tos = ipv4_packet.tos
        ttl = ipv4_packet.ttl
        proto = ipv4_packet.proto
        del p_tcp.chksum

        ipv6_header = IPv6(tc=tos, hlim=ttl, nh=proto, src=self.__server_ipv6, dst=self.__client_ipv6)

        ipv6_packet = Ether(dst=self.__client_mac) / ipv6_header / p_tcp

        sendp(ipv6_packet, iface=self.__local_ipv6_iface)

    def run(self):
        q1 = NetfilterQueue()
        q1.bind(1, self.process_outgoing_packets)

        q2 = NetfilterQueue()
        q2.bind(2, self.process_incoming_packets)

        t1 = threading.Thread(target=q1.run)
        t2 = threading.Thread(target=q2.run)
        t1.start()
        t2.start()
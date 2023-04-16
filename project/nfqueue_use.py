#!/usr/bin/python3
from scapy.all import *
from netfilterqueue import NetfilterQueue
import socket

def traiter_paquet(p):
# le paquet est fourni sous forme d'une séquence d'octet, il faut l'importer
    data = p.get_payload()
    print(data)
    p_scapy = IP(data)
    p_scapy.show()
    p_scapy[IP].id = 42
    del p_scapy[IP].chksum
    p_scapy.show2()
    print(bytes(p_scapy))
    p.set_payload(bytes(p_scapy))
    p.accept()

    
q = NetfilterQueue()
q.bind(2, traiter_paquet)

try:
    q.run()
except KeyboardInterrupt:
    print ("interruption")
    q.unbind()

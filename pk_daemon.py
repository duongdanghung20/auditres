#!/usr/bin/python3

from scapy.all import *
import subprocess

port_knock_sequence = [2027, 3230, 2001, 17377]
knock_dict = {}

def check_knock(packet):
    print(packet.summary())
    ip_src = packet["IP"].src
    dest_port = packet["TCP"].dport
    if ip_src not in list(knock_dict.keys()):
        knock_dict[ip_src] = []
    knock_dict[ip_src].append(dest_port)
    if dest_port == 17377 and len(knock_dict[ip_src]) >= len(port_knock_sequence):
        if knock_dict[ip_src][-4:] == port_knock_sequence:
            subprocess.run("iptables -t filter -I INPUT 2 -p tcp -m state --state NEW --dport 16400 -s {} -j ACCEPT".format(ip_src).split())
            print("New connection allowed: {}".format(ip_src))

if __name__ == "__main__":
    cmd_policy = "iptables -t filter -P INPUT DROP"
    cmd_maintain_conn = "iptables -t filter -A INPUT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT"
    cmd_reject_syn = "iptables -t filter -A INPUT -p tcp -m state --state NEW -j REJECT --reject-with tcp-reset"
    for cmd in [cmd_policy, cmd_maintain_conn, cmd_reject_syn]:
        subprocess.run(cmd.split())

    sniff(filter="tcp", prn=lambda p: check_knock(p))

    subprocess.run("iptables -t filter -F")
    

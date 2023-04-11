#!/usr/bin/python3

from scapy.all import *
import time
import os
import json
import subprocess

sniffs = {}
list_interfaces = ['lo', 'wlo1']
TIME_INTERVAL = 10 
MAX_NUMPORT = 5

def check_scan(pack):
    print(json.dumps(sniffs, indent=2))
    ip_src = pack["IP"].src
    port_conn = pack["TCP"].dport
    sniff_time = pack.time
    flag = pack["TCP"].flags
    if flag == 'S':
        if ip_src not in list(sniffs.keys()):
            sniffs[ip_src] = {}
        sniffs[ip_src][port_conn] = sniff_time
        if len(sniffs[ip_src].keys()) >= MAX_NUMPORT:
            conn_timestamps = sorted(list(sniffs[ip_src].values()))
            if conn_timestamps[-1] - conn_timestamps[-5] <= TIME_INTERVAL:
                time_readable_format = subprocess.run("date -d @{}".format(conn_timestamps[-5]).split(), capture_output=True).stdout.decode('utf-8')
                scan_log_msg = "Port scanned by {} at {}".format(ip_src, time_readable_format)
                print(scan_log_msg)
                if not os.path.isfile('./log_port_scan.txt'):
                    with open("log_port_scan.txt", "w") as wf:
                                wf.write(scan_log_msg)
                else:
                    with open("log_port_scan.txt", "r") as rf:
                        if rf.readlines()[-1] != scan_log_msg:
                            with open("log_port_scan.txt", "a") as af:
                                af.write(scan_log_msg)

if __name__ == "__main__":
    sniff(iface=list_interfaces, filter='tcp', prn=lambda p: check_scan(p))
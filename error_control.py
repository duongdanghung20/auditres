#!/usr/bin/python3

from scapy.all import *

SRC, DST = ("164.81.50.10", "164.81.50.20")
SPORT = 6578
DPORT = 7869

data_packet_1 = b'\x00\x00'
data_packet_2 = b'\xFF\xFF'

packet_1 = Ether()/IP(src = SRC, dst = DST) / UDP(sport = SPORT, dport = DPORT)/data_packet_1
packet_2 = Ether()/IP(src = SRC, dst = DST) / UDP(sport = SPORT, dport = DPORT)/data_packet_2

if __name__ == "__main__":
    print("Packet 1:")
    print(packet_1.show2())
    print("Packet 2:")
    print(packet_2.show2())
    print("same header => same checksum\n")

    print("CRC32 value of packet 1:")
    print(crc32(bytes(packet_1)))
    print("CRC32 value of packet 2:")
    print(crc32(bytes(packet_2)))
    print("CRC32 takes into account MAC dest, MAC source, type but also data. The packets are the same for the first 3 fields but contain different data => different values")
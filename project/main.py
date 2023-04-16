#!/usr/bin/python3

import subprocess
import sys
from translator import Translator

INTERNET_IFACE = "wlo1"
LOCAL_IPV6_IFACE = "bridge_ipv6"
IPV6_PREFIX = "2001:2:3:4501:"

## Find the MAC and IPv6 address of the netns h1
p1 = subprocess.Popen("ip netns exec h1 ip address show eth0".split(" "), stdout=subprocess.PIPE)
p2 = subprocess.Popen(["grep", "-E", "link/ether|{}".format(IPV6_PREFIX)], stdin=p1.stdout, stdout=subprocess.PIPE)
CLIENT_MAC, CLIENT_IPV6  = [line.strip().split()[1] for line in p2.communicate()[0].decode().splitlines()]
p1.stdout.close()
CLIENT_IPV6 = CLIENT_IPV6[:-3]

if __name__ == "__main__":
    ## Find the IPv4 and IPv6 addresses of the server by sending DNS Request using dig command, mode A (to find IPv4) and AAAA (to find IPv6)
    SERVER_DOMAIN_NAME = sys.argv[1]
    SERVER_IPV4, SERVER_IPV6 = [subprocess.run(["dig", "+short", SERVER_DOMAIN_NAME, dig_type], capture_output=True).stdout.decode().strip("\n") for dig_type in ["A", "AAAA"]]
    if len(SERVER_IPV4) == 0 or SERVER_IPV4 is None:
        raise Exception("This domain has no IPv4 address")
    if len(SERVER_IPV6) == 0 or SERVER_IPV6 is None:
        raise Exception("This domain has no IPv6 address")
    t = Translator(SERVER_IPV4, SERVER_IPV6, CLIENT_MAC, CLIENT_IPV6, INTERNET_IFACE, LOCAL_IPV6_IFACE)
    t.run()


#!/usr/bin/env python3
import random
import socket
import sys

from scapy.all import IP, UDP, Ether, get_if_hwaddr, get_if_list, sendp, Raw, sr, sniff


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def handle_pkt(pkt):
    print("get packet")
    exit(0);

def main():

    if len(sys.argv)<5:
        print('pass 4 arguments: <destination> <read/write> <key> <value>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print("sending on interface %s to %s" % (iface, str(addr)))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst=addr)
    pkt = pkt / UDP(dport=1234, sport=random.randint(49152,65535))

    if sys.argv[2] == 'read':
        pkt = pkt / Raw("R")
    else:
        pkt = pkt / Raw("W")

    pkt = pkt / Raw("I")

    pkt = pkt / int(sys.argv[3]).to_bytes(length=4, byteorder="big")
    pkt = pkt / int(sys.argv[4]).to_bytes(length=4, byteorder="big")
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()

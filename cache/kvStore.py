#!/usr/bin/env python3
import os
import sys
import socket

from scapy.all import (
    Ether,
    IP,
    UDP,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff,
    Raw,
    get_if_hwaddr,
    get_if_list,
    sendp
)
from scapy.layers.inet import _IPOption_HDR

kvStore = dict();


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt):
    if UDP in pkt and pkt[UDP].dport == 1234:
        print("got a packet")
        pkt.show2()
    #    hexdump(pkt)
        sys.stdout.flush()
        data = pkt[Raw].load
        key = data[2:6]
        value = data[6:10]
        rw = data[0:1]
        io = data[1:2]
        if io == b'O':
            return
        if rw == b'W':
            kvStore.update({key: value})
        elif rw == b'R':
            if key in kvStore.keys():
                value = kvStore[key]
            else:
                value = b'\xff\xff\xff\xff'

        iface = get_if()
        res = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        res = res / IP(dst=pkt[IP].src)
        res = res / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)

        res = res / rw
        res = res / Raw("O")
        res = res / key
        res = res / value
        sendp(res, iface=iface, verbose=False)

def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()

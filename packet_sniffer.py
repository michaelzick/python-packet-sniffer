#!/usr/bin/env python3

import scapy.all as scapy


def process_sniffed_packet(packet):
    packet.show()


def sniffer(interface):
    scapy.sniff(iface=interface, store=False,
                prn=process_sniffed_packet, filter='tcp')


sniffer('eth0')

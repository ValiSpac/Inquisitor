import ipaddress
import argparse
import re
import os
import scapy.all as scapy
import netifaces

def packet_callback(pkt):
    if pkt.haslayer('TCP') and pkt.haslayer('IP'):
        if pkt['TCP'].dport == 21 or pkt['TCP'].sport == 21:
            print(f"Packet captured: {pkt.summary()}")

def sniff_for_packets(args):
    capture = scapy.sniff(iface=args.interf, count=5, prn=packet_callback)
    capture.summary()

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

    try:
        if not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", args.MAC_src.lower()):
            raise Exception(f'{args.MAC_src} is an invalid mac address')
        if not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", args.MAC_target.lower()):
            raise Exception(f'{args.MAC_target} is an invalid mac address')
        s_ip = ipaddress.IPv4Address(args.IP_src)
        t_ip=ipaddress.IPv4Address(args.IP_target)
        if args.interf not in netifaces.interfaces():
            raise Exception(f'{args.interf} is not an available interface')
        sniff_for_packets(args)
    except Exception as e:
        parser.error(e)
    except KeyboardInterrupt as e:
        print(e)
        return (0)

if __name__=='__main__':
    main()

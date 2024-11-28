#!/bin/bash

echo "IP address of the ftp_server is:"
ifconfig eth0 | grep 'inet ' | awk '{print $2}'

echo "MAC address of the ftp_server is:"
ifconfig eth0 | grep 'ether' | awk '{print $2}'

/usr/sbin/vsftpd /etc/vsftpd.conf

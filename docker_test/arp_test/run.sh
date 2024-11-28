#!/bin/sh

sleep 10

echo "IP address of the docker is:"
ifconfig eth0 | grep 'inet ' | awk '{print $2}'

echo "MAC address of the docker is:"
ifconfig eth0 | grep 'ether' | awk '{print $2}'

echo "test file" > testfile.txt

ftp -n <<EOF
open 172.18.0.2 21
user ftpuser password
put testfile.txt
ls
bye
EOF

sleep infinity

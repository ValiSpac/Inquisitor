#!/bin/sh

echo "IP address of the docker is:"
ifconfig eth0 | grep 'inet ' | awk '{print $2}'

echo "MAC address of the docker is:"
ifconfig eth0 | grep 'ether' | awk '{print $2}'

sleep 10

echo "test file" > testfile.txt

ftp -n <<EOF
open 172.18.0.2 2121
user ftpuser password
put testfile.txt
ls
bye
EOF

sleep infinity

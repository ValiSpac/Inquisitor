#!/bin/sh

echo "IP address of the docker is:"
ifconfig eth0 | grep 'inet ' | awk '{print $2}'

echo "MAC address of the docker is:"
ifconfig eth0 | grep 'ether' | awk '{print $2}'

echo "test file" > testfile.txt

sleep infinity

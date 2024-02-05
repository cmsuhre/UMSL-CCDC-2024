#!/bin/bash

#This script shows listening ports

#Show listening ports with name, user, protocol, PID ,IP
#lsof
lsof -i -P -n | grep -i LISTEN | tr -s ' ' | cut -d ' ' -f 1,2,3,5,6,9

#netstat
netstat -tulpn | grep -i LISTEN


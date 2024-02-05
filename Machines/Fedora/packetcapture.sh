#!/bin/bash

#Run this script in background to capture packets

while true
do
 tcpdump -w packetcapture.txt
 sleep 300
done

#TO READ PACKETCAPTURE.TXT, use [ tcpdump -r packetcapture.txt ]

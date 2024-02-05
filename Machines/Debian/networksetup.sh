#!/bin/bash

#This script instructs on how to set a static DNS and ip on debian or edit


echo "-----------------------------------------------------------------"
echo "YOUR NETWORK INTERFACES: "
echo "-----------------------------------------------------------------"
echo $(ip -o -4 route get 8.8.8.8 | sed -nr 's/.*dev ([^\ ]+).*/\1/p')
echo "-----------------------------------------------------------------"
echo "Follow the directions below to set up DNS, GATEWAY, and IP"
echo " OPEN A SEPRATE TEMRINAL AND FOLLOW INSTRUCTIONS IN THIS SCRIPT "
echo " OPEN A SEPRATE TEMRINAL AND FOLLOW INSTRUCTIONS IN THIS SCRIPT "
echo " OPEN A SEPRATE TEMRINAL AND FOLLOW INSTRUCTIONS IN THIS SCRIPT "
echo "-----------------------------------------------------------------"
echo "Edit your network configuration file : [ sudo nano /etc/network/interfaces ]"
echo " Configure : " $(ip -o -4 route get 8.8.8.8 | sed -nr 's/.*dev ([^\ ]+).*/\1/p')
echo "The FORMAT SHOULD LOOK LIKE: "
echo "-----------------------------------------------------------------"
format="
auto eth0
iface eth0 inet static
 address 193.33.61.85
 netmask 255.255.255.0
 gateway 193.33.61.1
 dns-nameservers 89.207.128.252 89.207.130.252"
echo "$format"
echo "-----------------------------------------------------------------"
echo " Script will sleep for 1 minute for allow changes to be completed"
sleep 60
echo "-----------------------------------------------------------------"
echo "TO APPLY CHANGES : [ sudo systemctl restart networking.service ] "
echo "-----------------------------------------------------------------"
echo "YOU MAY ALSO NEED TO UPDATE DNS FILES..."
echo "CHECK IF resolvconf is installed or not by : [ dpkg -l | grep resolvconf ] "
echo "DNS can be added in the file [ nano /etc/resolv.conf ]"
echo " Script will sleep for 30 seconds for allow changes to be completed"
sleep 30
echo "The FORMAT SHOULD LOOK LIKE: "
echo "-----------------------------------------------------------------"
dns="
nameserver	8.8.8.8 
nameserver	8.8.4.4"
echo "$dns"
echo "-----------------------------------------------------------------"
echo " Script will sleep for 1 minute for allow changes to be completed"
sleep 60
echo "-----------------------------------------------------------------"



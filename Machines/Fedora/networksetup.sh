#!/bin/bash

#This script instructs on how to set a static DNS and IP on FEDORA

echo "THIS SCRIPT WILL INSTRUCT YOU ON HOW TO SET UP NETWORK FOR FEDORA"
echo "Follow the directions below to set up DNS, GATEWAY, and IP"
echo "-----------------------------------------------------------------"
echo "Enter the command specified below, you may write this info down,s ince this there is no seperate terminal window"
echo " [ cd /etc/sysyconfig/network-scripts/ifcfg-ens32 ] "
echo "-----------------------------------------------------------------"

format="
TYPE=Ethernet
BOOTPROTO=none
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=yes
IPV6_AUTOCONF=yes
IPV6_DEFROUTE=yes
IPV4_FAILURE_FATAL=no
NAME=eth0
UUID=...
ONBOOT=yes
HWADDR=0e:a5:1a:b6:fc:86
IPADDR0=172.31.24.10
PREFIX0=23
GATEWAY0=172.31.24.1
DNS1=192.168.154.3
DNS2=10.216.106.3
DOMAIN=example.com
IPV6_PEERDNS=yes
IPV6_PEERROUTES=yes"

echo "THE FORMAT SHOULD BE: " 
echo "$format"
echo "-----------------------------------------------------------------"
echo "CHANGE DNS and GATEWAY TO: GATEWAY: 172.20.241.254   DNS: 172.20.242.200"
echo "-----------------------------------------------------------------"
echo "MAKE SURE BOOTPROTO is set to Static or NONE"
echo "-----------------------------------------------------------------"
echo "-----------------------------------------------------------------"
echo "NOW WE WILL EDIT GLOBAL DNS"
echo " [ nano nano /etc/resolv.conf ] "
echo "ADD DNS SERVER..." 

dns="
nameserver 172.20.242.200"

echo "use the following format: "
echo "$nameserver"
echo "-----------------------------------------------------------------"
echo "restart networking with [ systemctl restart NetworkManager ]




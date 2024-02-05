#!/bin/bash


#Grab IP  of hostmachine
ip=$(hostname -I)

#show ip
echo "your ip is: "
echo $ip
echo ""
echo ""
echo ""
#script to show open ports and services using nmap

#Grab open ports and services for your own machine
echo "Host Machine Scan for IP : "; $ip
echo "Host machine running scan"
echo "" 
nmap $ip -p- -sS 
echo ""

#Grab open ports and services for User Subnet
#User Ubuntu Wkst, 2012, Ubuntu Web, Palo Alto
echo "Enter the IP (range) of your User Workstations in the form of 0.0.0.0-250"
read ip1user
echo "User Report: "
nmap $ip1user -p- -sV
echo ""

#grab open ports and services for subnet 172.20.240.0/24
#internal Docker and Debian
echo "Enter the IP (range) of your Internal Machines in the form of 0.0.0.0-250"
read ip2internal
echo " Internal Report: "
nmap $ip2internal -p- -sV
echo ""

#grab open ports and services for subnet 172.20.141.0/24
#Public Splunk, CentOS, and Fedora
echo "Enter the IP (range) of your External/Public Machines in the form 0.0.0.0-250"
read ip3external
echo "External Report "
nmap $ip3external -p- -sV
echo ""

#grab open ports and services for Windows Machine 172.31.xx.5
echo "Enter the IP of Windows machine in form of 0.0.0.0"
read ip4windows
echo " Windows Report: "
nmap $ip4windows -p- -sV
echo ""

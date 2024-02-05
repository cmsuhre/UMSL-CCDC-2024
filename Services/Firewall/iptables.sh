#!/bin/bash

#This scipt sets up Linux Firewall

echo " Saving Iptables Backup.."
touch ~/iptablesBU.txt

iptables-save
iptables -L >> ~/iptablesBU.txt

echo "Flushing all Rules.."
iptables -F
echo "Flushed"

#Blocking telnet
echo "Blocking telnet"
sudo iptables -A INPUT -p tcp --dport 23 -j DROP

#echo "Allowing Loopback traffic"
#iptables -A INPUT -i lo -j ACCEPT
#iptables -A OUTPUT -o lo -j ACCEPT
#echo " "

#echo "Block ICMP"
#iptables -I INPUT -p icmp --icmp-type 0 -j DROP
#iptables -I output -p --icmp-type 8 -j DROP
#echo " "

echo "Creating IPTABLE file after edit"
touch ~/iptablesBUafter.txt
iptables -L >> ~/iptablesBUafter.txt

echo "enabling Logging.."
iptables -N LOGGING
iptables -A INPUT -j LOGGING
iptables -A LOGGING -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j LOG --log-prefix "Incoming SSH Connection: " --log-level 7
iptables -I OUTPUT -p tcp -m tcp --sport 22 -m state --state NEW,ESTABLISHED -j LOG --log-prefix "Outgoing SSH connection: " --log-level 7
iptables -A LOGGING -j ACCEPT

echo "Locking backupfiles"
chattr +i ~/iptablesBU.txt
chatter +i ~/iptablesBUafter.txt
echo "Locked: "
lsattr ~/iptablesBU.txt
lsattr ~/iptablesBUafter.txt

#!/bin/bash

#this script installs, enables, and sets up ufw firewall
#To enable a service, uncomment particular line

#install ufw
apt-get install ufw

#set default rule
#will deny ANY incoming that is not specified in services
ufw default deny incoming
#ufw default deny outgoing

#Check added services
echo "Checking services for UFW...."
echo " : "
ufw app list
echo " "

#AddSSH
echo " Allowing ssh .... "
#ufw allow ssh

#Add HTTP and HTTPS
echo "Allowing Http and Https"
#ufw allow 80
#ufw allow 443

#Add DNS
echo "Allowing DNS Traffic"
#ufw allow 53/udp

#list ufw rules and status
ufw status verbose

#Enable rsyslog for ufw logging
echo "Enabling rsyslog for ufw logging"
systemctl enable rsyslog
systemctl start rsyslog

#Enable ufw logging
echo "turning on Logging"
ufw logging on 
echo " Changing to medium log level"
ufw logging medium
echo "Logging enabled! Check logs in /var/log/ufw"
echo "Use LESS command to open logs"

#Enable Ufw
echo "Enabling ufw ..."
#ufw enable

#Locking ufw configuration file and creating backup
cp /etc/default/ufw /etc/default/ufwbu
chattr +i /etc/default/ufw
chattr +i /etc/default/ufwbu

#check locked files
echo "Locked Files..."
lsattr /etc/default/ufw*

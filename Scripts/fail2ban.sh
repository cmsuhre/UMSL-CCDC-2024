!#/bin/bash

#uncomment lines per machine

#FOR Ubuntu and Debian
#apt-get install fail2ban

#For CentOS and Fedora
yum -y update
yum install epel-release
#yum install fail2ban

#enable fail2ban
sudo systemctl enable fail2ban

#create config file
echo "Created jail.local file for configuration"
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

#Configuration file edits needed
#under Default Section
#ignoreip = 127.0.0.1/8
#bantime=30m
#maxretry=4
#findtime=30m



#!/bin/bash

#This script sets up CentOD Firewalld Service
#Firewalld is included by default  

#start firewall service and enable on boot
systemctl start firewalld
systemctl enable firewalld

#Check firewall state
firewall-cmd --state

#Check firewall status
systemctl status firewalld

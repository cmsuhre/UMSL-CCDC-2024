#!/bin/bash

echo "8888888888            888"                          
echo "888                   888"                          
echo "888                   888"                          
echo "8888888  .d88b.   .d88888  .d88b.  888d888 8888b." 
echo "888     d8P  Y8b d88" 888 d88""88b 888P"      "88b"
echo "888     88888888 888  888 888  888 888    .d888888"
echo "888     Y8b.     Y88b 888 Y88..88P 888    888  888" 
echo "888      "Y8888   "Y88888  "Y88P"  888    "Y888888" 
echo "-------------------------------------------------------------------------"
echo "-------------------------------------------------------------------------"
echo "Run THIS SCRIPT AS ROOT, or SUDO if avaliable. If cannot login to root, run Sudo su -"
echo "YOU ARE RUNNING AS..."
echo ""
whoami
echo "-------------------------------------------------------------------------"
mkdir fedorascript
cd fedorascript
echo "-------------------------------------------------------------------------"
echo "CHANGING PASSWORDS..."
echo "Changing sysadmin password: "
passwd sysadmin
echo "changing root password: "
passwd root
echo ""
echo "Passwords Changed"
echo "-------------------------------------------------------------------------"
echo "CHANGING PERMISSIONS..."
echo "changing file permission specified files"
chmod 640 /etc/shadow
chmod 644 /etc/passwd
chmod 640 /var/log/wtmp
chmod 640 /var/log/utmp
chmod 640 /etc/group
chmod 740 ~/.bashrc
echo "changed "
echo "-------------------------------------------------------------------------"
echo "REMOVING VULNERABLE SERVERS..."
yum remove xinetd nis yp-tools tftpd atftpd tftp d-hpa telnetd rsh-server rsh-redone-server 
echo "-------------------------------------------------------------------------"
echo "LOGGED IN USERS:"
echo ""
who
echo ""
echo "-------------------------------------------------------------------------"
echo "SETTING DNS AND GATEWAY..."
echo " Please open a SEPERATE TERMINAL WINDOW"
echo "After naviagting, run networksetup.sh"
echo "-------------------------------------------------------------------------"
echo "Downloading Incident tools..."
yum -y install tcpdump
yum -y install nmap
yum -y install rkhunter
yum -y install tmux
yum -y install NetworkManager-tui
echo "-------------------------------------------------------------------------"
echo "SETTING UP FIREWALL"
yum -y install firewalld
systemctl start firewalld
systemctl enable firewalld
echo "-------------------------------------------------------------------------"
echo "The zone which you will be setting rules for, SHOULD BE FedoraServer: "
firewall-cmd --get-default-zone
echo "-------------------------------------------------------------------------"
echo "Adding Allowed services..."
firewall-offline-cmd --zone=FedoraServer --permanent --add-port=110/tcp --add-port=995/tcp --add-port=143/tcp --add-port=993/tcp --add-port=3306/tcp
firewall-cmd --zone=FedoraServer --permanent --add-service=smtp 
firewall-cmd --zone=FedoraServer --permanent --add-service=https
firewall-cmd --zone=FedoraServer --permanent --add-service=http
firewall-cmd --zone=FedoraServer --permanent --add-port=110/tcp --add-port=995/tcp --add-port=143/tcp --add-port=993/tcp --add-port=3306/tcp
echo "-------------------------------------------------------------------------"
echo "INSTALLING AND ENABLING RSYSYLOG FOR LOGGING FIREWALL"
yum -y install rsyslog
systemctl enable rsyslog
echo "-------------------------------------------------------------------------"
echo "UPDATING...."
#yum update
echo "-------------------------------------------------------------------------"
echo "GETTING USERS WITH LOGIN SHELL...."
echo "SENT TO FILE: shloginshell.txt bashloginshell.txt"
awk -F: '{ print $1,$3,$6,$7}' /etc/passwd | grep -i "bin/sh" > shloginshell.txt
awk -F: '{ print $1,$3,$6,$7}' /etc/passwd | grep -i "bin/bash" > bashloginshell.txt
echo "---------------------------------------------------------------"
#Get wheel group
echo "GETTING Wheel USERS...."
echo "SENT TO FILE: wheel.txt"
getent group wheel | awk -F: '{print $4}' > wheel.txt
echo "---------------------------------------------------------------"
#Get sudoers group
echo "GETTING SUDO USERS...."
echo "SENT TO FILE: sudouser.txt"
getent group sudo | awk -F: '{print $4}' > sudouser.txt
echo "---------------------------------------------------------------"
echo "GETTING SYSTEM PROCESSES...."
echo "SENT TO FILE: processes.txt "
ps aux > processes.txt
echo "---------------------------------------------------------------"
echo "GETTING SYSTEM Services...."
echo "SENT TO FILE: service.txt "
lsof -i > service.txt
echo "---------------------------------------------------------------"
echo "GETTING NETWORK CONNECTIONS..."
echo "SENT TO FILE: network.txt"
netstat -tuplant > network.txt
echo "---------------------------------------------------------------"
echo "Chattr LOCKING FILES..."
echo "Locking : /etc/shadow  /etc/gshadow /etc/passwd"
chattr +i /etc/shadow && chattr +i /etc/gshadow && chattr +i /etc/passwd
echo " "
echo "Locking : /etc/group"
chattr +i /etc/group
echo " "
echo "Locking Bashrc"
chattr +i ~/.bashrc
echo " "
echo "Locking : /etc/sudoers $ sudoers.d"
chattr +i /etc/sudoers && chattr -R +i /etc/sudoers.d
echo " "

echo " "



                                                                                                                                         
                                                                                                                                         

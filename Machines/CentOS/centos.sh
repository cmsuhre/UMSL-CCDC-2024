#!/bin/bash
echo " __   ___      ___  __   __  "
echo "/  ` |__  |\ |  |  /  \ /__` "
echo "\__, |___ | \|  |  \__/ .__/"                              
echo "-------------------------------------------------------------------------"
echo "-------------------------------------------------------------------------"
echo "Run THIS SCRIPT AS ROOT, or SUDO if avaliable. If cannot login to root, run Sudo su -"
echo "YOU ARE RUNNING AS..."
echo ""
whoami
echo "-------------------------------------------------------------------------"
mkdir centosscript
cd centosscript
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
firewall-cmd --zone=FedoraServer --permanent --add-service=smtp 
firewall-cmd --zone=FedoraServer --permanent --add-service=https
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
echo " "
echo "Locking Bashrc"
chattr +i ~/.bashrc
echo " "
echo "Locking : /etc/sudoers $ sudoers.d"
chattr +i /etc/sudoers && chattr -R +i /etc/sudoers.d
echo " "
echo "Locking /etc/sysctl.conf /etc/sysctl.d"
chattr +i /etc/sysctl.conf 
echo " "



                                                                                                                                         
                                                                                                                                         

#!/bin/bash



echo " _   _ _                 _         "
echo "| | | | |__  _   _ _ __ | |_ _   _ "
echo "| | | | '_ \| | | | '_ \| __| | | |"
echo "| |_| | |_) | |_| | | | | |_| |_| |"
echo " \___/|_.__/ \__,_|_| |_|\__|\__,_|"
echo "-------------------------------------------------------------------------"
echo "-------------------------------------------------------------------------"
echo "Run THIS SCRIPT AS ROOT, or SUDO if avaliable. If cannot login to root, run Sudo su -"
echo "-------------------------------------------------------------------------"
mkdir ubuntuscript
cd ubuntuscript
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
chmod 640 ~/.bashrc
echo "changed "
echo "-------------------------------------------------------------------------"
echo "REMOVING VULNERABLE SERVERS..."
apt-get remove xinetd nis yp-tools tftpd atftpd tftp d-hpa telnetd rsh-server rsh-redone-server 
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
apt-get install tcpdump
apt-get install nmap
echo "-------------------------------------------------------------------------"
echo "SETTING UP FIREWALL"
apt-get install ufw
ufw default deny incoming
ufw allow http
ufw allow https
echo "-------------------------------------------------------------------------"
echo "CHECKING LOGGING STATUS OF RSYSLOG SERVICE..."
service rsyslog status
echo "--------------------------------------------------"
ufw logging on 
echo "LOGGING MEDIUM"
ufw logging medium
echo "Check logs in /var/log/ufw"
echo "Use LESS command to open logs"
ufw enable
echo "---------------------------------------------------------------"
echo "UPDATING...."
apt-get update
echo "-------------------------------------------------------------------------"
echo "GETTING USERS WITH LOGIN SHELL...."
echo "SENT TO FILE: shloginshell.txt bashloginshell.txt"
awk -F: '{ print $1,$3,$6,$7}' /etc/passwd | grep -i "bin/sh" > shloginshell.txt
awk -F: '{ print $1,$3,$6,$7}' /etc/passwd | grep -i "bin/bash" > bashloginshell.txt
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
echo "GETTING NETWORK CONNECTIONS..."
echo "SENT TO FILE: network.txt"
netstat -tuplant > network.txt
echo "---------------------------------------------------------------"
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

#!/bin/bash

echo "Making backup!..."
echo " "
cp /etc/ssh/sshd_config /etc/ssh/sshd_config_bu
echo "Done!"

echo "Current Configuration of sshd:"
echo " "
sshd -T
echo " "

echo "Changing Configuration..."
echo "Protocol 2" >> /etc/ssh/sshd_config
echo "AllowUsers root admin webmaster" >> /etc/ssh/sshd_config
echo "AllowGroup sshusers" >> /etc/ssh/sshd_config
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
echo "RSAAuthentication yes" >> /etc/ssh/sshd_config
echo "PubkeyAuthentication yes" >> /etc/ss/sshhd_config
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "ServerKeyBits 2048" >> /etc/ssh/sshd_config
echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
echo "RhostsAuthentication no" >> /etc/ssh/sshd_config
echo "RhostsRSAAuthentication no" >> /etc/ssh/sshd_config
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
echo "KerberosAuthentication no" >> /etc/ssh/sshd_config
echo "ChallengeResponseAuthentication no" >> /etc/ssh/sshd_config
echo "GSSAPIAuthentication no" >> /etc/ssh/sshd_config
echo "X11Forwarding no" >> /etc/ssh/sshd_config
echo "PermitUserEnviroment no" >> /etc/ssh/sshd_config
echo "AllowAgentForwarding no >> /etc/ssh/sshd_config
echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
echo "PermitTunnel no" >> /etc/ssh/sshd_config


echo "changed configuration.."
echo "Locking Files.."

chattr +i /etc/ssh/sshd_config
chattr +i /etc/ssh/sshd_config_bu

echo "Locked: "
lsattr /etc/ssh/*

echo "Testing ssh service..." 
echo " Test: "
echo " "
sshd -t
echo " Test Parameters : ^ "



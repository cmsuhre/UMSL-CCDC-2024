#!/bin/bash

echo "Making backup!..."
echo " "
cp /etc/ssh/ssh_config /etc/ssh/ssh_config_bu
echo "Done!"

echo "Changing Configuration..."
echo "Protocol 2" >> /etc/ssh/ssh_config
#echo "AllowUsers webmaster" >> /etc/ssh/ssh_config
echo "AllowGroup sshusers" >> /etc/ssh/ssh_config
echo "PasswordAuthentication no" >> /etc/ssh/ssh_config
echo "HostbasedAuthentication no" >> /etc/ssh/ssh_config
echo "RSAAuthentication yes" >> /etc/ssh/ssh_config
echo "PubkeyAuthentication yes" >> /etc/ss/sshh_config
echo "PermitEmptyPasswords no" >> /etc/ssh/ssh_config
echo "PermitRootLogin no" >> /etc/ssh/ssh_config
echo "ServerKeyBits 2048" >> /etc/ssh/ssh_config
echo "IgnoreRhosts yes" >> /etc/ssh/ssh_config
echo "RhostsAuthentication no" >> /etc/ssh/ssh_config
echo "RhostsRSAAuthentication no" >> /etc/ssh/ssh_config
echo "MaxAuthTries 3" >> /etc/ssh/ssh_config
echo "MaxAuthTries 3" >> /etc/ssh/ssh_config
echo "KerberosAuthentication no" >> /etc/ssh/ssh_config
echo "ChallengeResponseAuthentication no" >> /etc/ssh/ssh_config
echo "GSSAPIAuthentication no" >> /etc/ssh/ssh_config
echo "X11Forwarding no" >> /etc/ssh/ssh_config
echo "PermitUserEnviroment no" >> /etc/ssh/ssh_config
echo "AllowAgentForwarding no >> /etc/ssh/ssh_config
echo "AllowTcpForwarding no" >> /etc/ssh/ssh_config
echo "PermitTunnel no" >> /etc/ssh/ssh_config


echo "changed configuration.."
echo "Locking Files.."

chattr +i /etc/ssh/ssh_config
chattr +i /etc/ssh/ssh_config_bu

echo "Locked: "
lsattr /etc/ssh/*

#!/bin/bash

#This script changes file permissions

echo "changing file permission specified files"

chmod 640 /etc/shadow
chmod 640 /etc/passwd
chmod 640 /var/log/wtmp
chmod 640 /var/log/utmp
chmod 640 /etc/groups
chmod 640 ~/.bashrc



echo " changed "


#!/bin/bash



#inital scirpt to get hashes in hashfile. This script will only be run once



#Create a directory to hold previous hashes. This will create a directory in which ever location you run this script
mkdir hashes



#Create hashfile to hold hashes to compare
touch hashes/hashfile.txt
touch hashes/dirfile.txt

#Get Hashes of specified directories
ls -al /etc | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 > hashes/dirfile.txt
ls -al /etc/pam.d | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/dirfile.txt
ls -al /etc/systemd | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/dirfile.txt
ls -al /etc/security | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/dirfile.txt
ls -al /etc/securetty | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/dirfile.txt
ls -al /bin | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/dirfile.txt
ls -al /usr/sbin | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/dirfile.txt
ls -al /usr/bin | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/dirfile.txt
ls -al /usr/local/bin | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/dirfile.txt
ls -al /usr/local/sbin | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/dirfile.txt
ls -al /sbin | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/dirfile.txt
ls -al /var/www/ | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/dirfile.txt


#get hashes of  files
md5sum /etc/shadow >> hashes/hashfile.txt
md5sum /etc/passwd >> hashes/hashfile.txt
md5sum /etc/group >> hashes/hashfile.txt
md5sum /etc/groups >> hashes/hashfile.txt
md5sum /etc/gshadow >> hashes/hashfile.txt
md5sum /proc/cmdline >> hashes/hashfile.txt
md5sum /etc/hosts >> hashes/hashfile.txt
md5sum /etc/resolve.conf >> hashes/hashfile.txt
md5sum /etc/login.defs >> hashes/hashfile.txt
md5sum /etc/shells >> hashes/hashfile.txt
md5sum ~/.bashrc >> hashes/hashfile.txt



#Create compare file
touch hashes/newhashfile.txt
touch hashes/newdirfile.txt

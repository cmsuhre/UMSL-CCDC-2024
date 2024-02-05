#!/bin/bash

while true
do 
  #Calculate new hashes in newhashfile.txt
  md5sum /etc/shadow > hashes/newhashfile.txt
  md5sum /etc/passwd >> hashes/newhashfile.txt
  md5sum /etc/group >> hashes/newhashfile.txt
  md5sum /etc/groups >> hashes/newhashfile.txt
  md5sum /etc/gshadow >> hashes/newhashfile.txt
  md5sum /proc/cmdline >> hashes/newhashfile.txt
  md5sum /etc/hosts >> hashes/newhashfile.txt
  md5sum /etc/resolve.conf >> hashes/newhashfile.txt
  md5sum /etc/login.defs >> hashes/newhashfile.txt
  md5sum /etc/shells >> hashes/newhashfile.txt
  md5sum ~/.bashrc >> hashes/newhashfile.txt


  #calculate new directory ls -l listing
  ls -al /etc/ | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 > hashes/newdirfile.txt
  ls -al /etc/pam.d | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9  >> hashes/newdirfile.txt
  ls -al /etc/systemd | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/newdirfile.txt
  ls -al /etc/security | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/newdirfile.txt
  ls -al /etc/securetty | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/newdirfile.txt
  ls -al /bin | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/newdirfile.txt
  ls -al /usr/sbin | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/newdirfile.txt
  ls -al /usr/bin | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/newdirfile.txt
  ls -al /usr/local/bin | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/newdirfile.txt
  ls -al /usr/local/sbin | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/newdirfile.txt
  ls -al /sbin | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/newdirfile.txt
  ls -al /var/www/ | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/newdirfile.txt
  ls -al /etc/dovecot | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/newdirfile.txt
  ls -al /etc/postfix | tr -s ' ' | cut -d ' ' -f 1,2,3,4,5,9 >> hashes/newdirfile.txt

  echo " Adding new directories file and listing"
  echo ""

  #this will compare dirfile.txt ls -l listing with new
  diff hashes/dirfile.txt hashes/newdirfile.txt > hashes/diffdir.txt

  #This script will compare the differnt hash files 
  diff hashes/hashfile.txt hashes/newhashfile.txt > hashes/diff.txt

  echo " "
  echo "Checking to see if any differences where reported....."
  echo "Hashes: "
  echo " "
  cat hashes/diff.txt
  echo "Directory Listing :"
  echo " "
  cat hashes/diffdir.txt
  echo "Wrote hashes to file. Any diff will be reported in text file difference"
  sleep 900
 done
  

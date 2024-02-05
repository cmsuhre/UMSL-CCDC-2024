#!/bin/bash

#This will find any SUID/SGID apps

mkdir ~/filepermission

#SUID
find / -perm /4000 -type f > filepermission/suid.txt

#SGID
find / -perm /2000 -type f > filepermission/sgid.txt

#WorldWriteable Files
find / -perm -2 ! -type l -ls > filepermission/worldwriteable.txt

#noOwner
find / \( -nouser -o -nogroup \) -print > filepermission/nouserorown.txt

#rhost
find /home -name .rhosts -print > rhost.txt 

#set default file creation with umask
echo "Setting umask.."
umask 077
#will disable read, write, and execute permission for other users, unless explicitly changed using chmod
#have to change in confgiuration file for reboot peristance





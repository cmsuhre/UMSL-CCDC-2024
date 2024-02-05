#!/bin/bash


#script to change password of current user, root, and sysadmin on Linux 


#change pass of current user
echo "Changing password of current user:" 
whoami
passwd


#change pass of root
echo "Changing password of root"
passwd root
 
#change pass of sysadmin
echo "changing password of sysadmin"
passwd sysadmin

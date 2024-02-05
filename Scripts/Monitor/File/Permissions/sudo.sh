#!/bin/bash

#This script will check sudo usage for current user and allow a variable
#to  be passed thorugh to check for other users

echo "Checking currrent user sudo permissions : "
echo ""
sudo -l
echo ""
echo ""

echo "Enter the name of the user  you would like to check permission for"
read user
echo "sudo permission for : " $user 
echo ""
sudo -l -U $user

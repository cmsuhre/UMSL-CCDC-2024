#!/bin/bash

#This script will list root cron jobs and allow for user input to check
#cron jobs for specific users

echo "Checking cron job for root:"
echo ""
less /etc/crontab
echo ""


echo "Enter user you would like to check cron job for: "
read user
echo "Checking cron job for : " $user
echo "" 
crontab -u $user -l


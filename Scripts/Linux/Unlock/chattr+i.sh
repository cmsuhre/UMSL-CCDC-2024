#!/bin/bash

#this scirpt outline sets immovable bit in chattr for resources needed

echo "Locking : /etc/shadow  /etc/gshadow"
chattr +i /etc/shadow && chattr +i /etc/gshadow
echo " "

echo "Locking : /etc/group"
chattr +i /etc/group
echo " "

echo "Locking : /etc/sudoers $ sudoers.d"
chattr +i /etc/sudoers && chattr -R +i /etc/sudoers.d
echo " "

echo "Locking /etc/sysctl.conf /etc/sysctl.d"
chattr +i /etc/sysctl.conf && chattr -R +i /etc/sysctl.d
echo " "

echo "Loacking /etc/cron* /etc/anacrontab"
chattr +i /etc/anacrontab && chattr -R +i /etc/cron.d && chattr -R +i /etc/cron.daily && chattr -R +i /etc/cron.hourly && chattr -R +i /etc/cron.monthly
&& chattr +i /etc/crontab && chattr -R +i /etc/cron.weekly
echo " "

echo "Files have changed: "
lsattr /etc/group /etc/shadow /etc/gshadow /etc/sudoers /etc/sudoers.d /etc/sysctl.conf /etc/sysctl.d /etc/anacrontab /etc/cron*
echo "Done"

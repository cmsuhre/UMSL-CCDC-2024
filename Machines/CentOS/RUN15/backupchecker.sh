!#/bin/bash

#Script to check current system state run in BACKGROUND

while true
do 
  cd centosscript

  #Login users
  awk -F: '{ print $1,$3,$6,$7}' /etc/passwd | grep -i "bin/sh" > shloginshell1.txt
  awk -F: '{ print $1,$3,$6,$7}' /etc/passwd | grep -i "bin/bash" > bashloginshell1.txt

  #firewall rules
  firewall-cmd --list-all > firewall.txt

  #wheel users
  getent group sudo | awk -F: '{print $4}' > sudouser1.txt

  #sudo users
  getent group wheel | awk -F: '{print $4}' > wheel1.txt

  #Proccesses
  ps aux > processes1.txt

  #services
  lsof -i > services.txt

  #Show listening ports with name, user, protocol, PID ,IP
  #lsof
  lsof -i -P -n | grep -i LISTEN | tr -s ' ' | cut -d ' ' -f 1,2,3,5,6,9 > lsofports.txt

  #netstat
  netstat -tulpn | grep -i LISTEN > netstatports.txt

  #SUID
  find / -perm /4000 -type f > suid1.txt
  #SGID
  find / -perm /2000 -type f > sgid1.txt
  #WorldWriteable Files
  find / -perm -2 ! -type l -ls > worldwriteable1.txt
  #noOwner
  find / \( -nouser -o -nogroup \) -print > nouserorown1.txt
  #rhost
  find /home -name .rhosts -print > rhost1.txt 

  #allUsers
  awk -F: '{ print $1}' /etc/passwd > userlist1.txt

  #SSHprocceses
  ps ea | grep sshd > sshproccess1.txt



  crontab -l > cronjobs.txt
  cp -R /etc/cron.d cron.d
  cp -R /etc/cron.daily cron.daily
  cp -R /etc/cron.monthly cron.monthly
  cp -R /etc/cron.weekly cron.weekly
  cp -R /etc/cron.hourly cron.hourly


  #show proccesses on system
  ps -ea | grep apache2  >> apache.txt


  #Setting unmask
  #umask 077
  echo "WROTE FILES"
  sleep 900
 done







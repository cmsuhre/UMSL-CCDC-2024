
#!/bin/bash


#This script will grab ip addresses ,hostname, version of Ubuntu systems
#also check if there is version upgrade avaliale 

#grab hostname
echo "Hostname:"
hostname 
echo ""

#grab ip
echo "IP:"

hostname -I 
echo ""
 

#grab version
cd /etc
echo "Version:"
cat os-release | head -n 3
echo ""

#Check if update is avaliable
echo ""
echo "The Ubuntu Latest Release is 20.04."
do-release-upgrade
echo ""

#12.04 Release Vulnerabilities
#echo "12.04 Ubuntu Release Vulnerabilities: "
#echo ""
#echo "Bind Vulnerability: Bind could be made to crash or run programs if it received specially crafted network traffic. /n"
#echo "CVE-2020-8625 "
#echo ""
#echo "lxml Vulnerability: lxml could allow cross-site scripting (XSS) attacks /n"
#echo "CVE-2020-27783 "
#echo ""
#echo "Sudo Vulnerability: Sudo incorrectly handled memory when parsing command"
#echo "lines. A local attacker could possibly use this issue to obtain unintended"
#echo "access to the administrator account"   

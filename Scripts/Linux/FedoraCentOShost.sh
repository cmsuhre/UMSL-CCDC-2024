
#!/bin/bash


#This script will grab ip addresses ,hostname, version of Fedora systems
#will show if there is any avaliable packages to update, but may need to look
# up latest fedora version

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

#Check if package update is avilable
echo ""
echo "The Fedora Latest release is Fedora 35."
dnf check-update
echo ""

#Fedora 21 Release Vulnerabilities
#echo "Fedora Server 21 Release Vulnerabilities: "
#echo ""
#echo "Ganglia-Web Vulnerbaility: ganglia-web prior to 3.7.1 allows remote malicious users to bypass authentication."
#echo ""
#echo "Simple Desktop Display Manager (SDDM) prior to 0.10.0 allows local users to log in as user (sddm) without authentication."
#echo ""
#echo "XSS Vulnerability: Cross-site scripting (XSS) vulnerability in templates/openid-selector.tmpl in ikiwiki prior to 3.20150329 allows remote"
#echo "malicious users to inject arbitrary web script or HTML via the openid_identifier parameter in a verify action to ikiwiki.cgi"

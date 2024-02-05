#This script list all users on machine and changes password of selected accounts
Import-Module ActiveDirectory

#List all local user
Get-LocalUser | Out-File -FilePath c:\export\AllLocalUser.txt



#List all enabled Local Users
Get-LocalUser | findstr "True" | Out-File -FilePath c:\export\EnabledUser.txt


#export AD User
Get-ADUser -Filter * | Out-File -FilePath c:\export\allusersAD.txt

#Get Domain and forest info for current user 
Get-ADForest | Out-File -Filepath c:\export\CurrentUserADDomain.txt

#Get all domains controller for all domains in forest
(Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $_ } | Out-File -Filepath c:\export\dcforest.txt

#GetGPO Policy report
Get-GPOReport -All -ReportType XML -Path "C:\export\GPOReportsAll.xml"

#list firewall rules
netsh advfirewall firewall show rule name=all | Export-clixml -path c:\export\allfirewall.xml

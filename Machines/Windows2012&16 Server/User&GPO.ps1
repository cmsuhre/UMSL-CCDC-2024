#This script list all users on machine and changes password of selected accounts
Import-Module ActiveDirectory

#List all local user
Write-Output("Sending Local Users to user.txt file in current directory...")
Get-LocalUser | Out-File -FilePath c:\export\AllLocalUser.txt
Write-Output("Local Users have been written to file, now displaying!")
Get-LocalUser


#List all enabled Local Users
Write-Output("sending Enabled Local users to enableduser.txt in current directory...")
Get-LocalUser | findstr "True" | Out-File -FilePath c:\export\EnabledUser.txt
Write-Output("Local Users enabled have been written to file, now displaying!")
Get-LocalUser | findstr "True"

#export AD User
Write-Output("Writing ADUsers to file!")
Get-ADUser -Filter * |Out-File -FilePath c:\export\allusersAD.txt

#Get Domain and forest info for current user 
Get-ADForest | Out-File -Filepath c:\export\CurrentUserADDomain.txt

#Get all domains controller for all domains in forest
(Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $_ } | Out-File -Filepath c:\export\dcforest.txt

#GetGPO Policy report
Get-GPOReport -All -ReportType XML -Path "C:\export\GPOReportsAll.xml"

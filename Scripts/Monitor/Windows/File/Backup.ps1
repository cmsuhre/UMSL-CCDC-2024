cd C:\backup

#Users and GPO
Get-LocalUser >> c:\backup\AllLocalUser.txt
Add-Content -Path c:\backup\AllLocalUser.txt -Value '----------------------------------------------------------------------------------------------------------------------------------------------' 

Get-LocalUser >> c:\backup\EnabledUser.txt
Add-Content -Path c:\backup\EnabledUser.txt -Value '----------------------------------------------------------------------------------------------------------------------------------------------'

Get-ADUser -Filter * >> c:\backup\allusersAD.txt
Add-Content -Path c:\backup\allusersAD.txt -Value '----------------------------------------------------------------------------------------------------------------------------------------------'

Get-ScheduledTask >> c:\backup\scheduletasks.txt
Add-Content -Path c:\backup\scheduletasks.txt -Value '----------------------------------------------------------------------------------------------------------------------------------------------'

Get-ADForest >> c:\backup\ADForest.txt
Add-Content -Path c:\backup\ADForest.txt -Value '----------------------------------------------------------------------------------------------------------------------------------------------'

(Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $_ } >> c:\backup\dcforest.txt
Add-Content -Path c:\backup\dcforest.txt -Value '----------------------------------------------------------------------------------------------------------------------------------------------'

Get-GPOReport -All -ReportType XML -Path "C:\backup\GPOReportsAll.xml"
Add-Content -Path C:\backup\GPOReportsAll.xml -Value '----------------------------------------------------------------------------------------------------------------------------------------------'



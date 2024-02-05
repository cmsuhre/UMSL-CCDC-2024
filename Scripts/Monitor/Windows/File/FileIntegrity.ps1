#Change to TLS1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Install Module
Install-Module -Name PsFCIV

#Import module
Import-Module PsFCIV

#Create dBFiles
cd C:\temp
Start-PsFCIV -Path C:\temp -XML DBtemp.XML


cd C:\Program Files
Start-PsFCIV -Path C:\Program Files -XML DBProgramFiles.XML


cd C:\Program Files (x86)
Start-PsFCIV -Path C:\Program Files (x86) -XML DBProgramFiles(x86).XML


cd C:\Windows\System32
Start-PsFCIV -Path C:\Windows\System32 -XML DBSystem32.XML

cd C:\Export
Start-PsFCIV -Path C:\Export -XML DBExport.XML


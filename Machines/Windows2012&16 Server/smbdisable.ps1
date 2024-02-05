#Script to block smb ports and restrict version


#Disable on SMBServer on 8, 2012, 2012 R2, 10 and 2019 Server
Set-SmbServerConfiguration -EnableSMB1Protocol $false
Set-SmbServerConfiguration -EnableSMB2Protocol $false

#Disable on 8, 2019 server, 2016 server and 2012 R2
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

#Disbale on 7, 2008 R2, Vista, server 2008
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 0 -Force

#Smbv2v3 on SMB client windows 10 and servers
sc.exe config lanmanworkstation depend= bowser/mrxsmb10/nsi
sc.exe config mrxsmb20 start= disabled

#Enable SmbAuditing
Set-SmbServerConfiguration -AuditSmb1Access $true





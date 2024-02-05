
#ACTIVE DIRECTORY (AD) - GROUP POLICY OBJECT (GPO) 

#Get  and  force new  policies: 
gpupdate /force C:\> gpupdate /sync 

#Audit Success and Failure for user Bob:
auditpol /set /user:bob /category:"Detailed Tracking" /include /success:enable /failure:enable 

#Create an  Organization Unit to  move suspected or infected users and machines: 
dsadd OU <QUARANTINE BAD  OU>

#Move an  active directory user object into NEW GROUP: PS  
Move-ADObject 'CN=<USER NAME>,CN=<OLD USER GROUP>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>' -TargetPath 'OU=<NEW USER GROUP>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>' 

#Alt Option: 
dsmove "CN=<USER NAME>,OU=<OLD USER OU>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>"  -newparent OU=<NEW USER GROUP>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION

#Disable Remote Desktop: 
reg  add "HKLM\SYSTEM\Cu rrentCont ro lSet\Cont ro l \  Terminal Server" /f  /v  fDenyTSConnections /t  REG_DWORD /d  1 

#Send NTLMv2 response only/refuse LM  and NTLM: (Windows 7  default)
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t  REG_DWORD /d  5  /f 

#Restrict Anonymous Access: 
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t  REG_DWORD /d  1  /f 

#Do  not  allow  anonymous  enumeration of  SAM accounts and shares: 
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t  REG_DWORD /d  1  /f 

#Disable sticky keys: 
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v  Flags /t  REG_SZ /d  506 /f 

#Disable Toggle Keys: 
reg add "HKCU\Control Panel \Accessibility\ ToggleKeys" /v  Flags /t  REG_SZ Id 58  /f 

#Disable  Filter Keys: 
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v  Flags /t REG_SZ /d  122 /f 

#Disable  On-screen Keyboard: 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI /f  /v  ShowTabletKeyboard /t REG_DWORD /d  0 


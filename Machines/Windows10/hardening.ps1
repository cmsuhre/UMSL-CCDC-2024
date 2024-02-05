#SMB3 compression
CVE-2020-0796 Flaw Mitigation - Active Directory Administrative Templates

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force

#Create dBFiles
cd C:\temp
Start-PsFCIV -Path C:\temp -XML DBtemp.XML -HashAlgorithm SHA1 -Recurse -Show Bad

cd C:\Program Files
Start-PsFCIV -Path C:\Program Files -XML DBProgramFiles.XML -HashAlgorithm SHA1 -Recurse -Show Bad

cd C:\Program Files (x86)
Start-PsFCIV -Path C:\Program Files (x86) -XML DBProgramFiles(x86).XML -HashAlgorithm SHA1 -Recurse -Show Bad

cd C:\Windows\System32
Start-PsFCIV -Path C:\Windows\System32 -XML DBSystem32.XML -HashAlgorithm SHA1 -Recurse -Show Bad

cd C:\Export
Start-PsFCIV -Path C:\export -XML DBExport.XML -HashAlgorithm SHA1 -Recurse -Show Bad

REM make folder
mkdir C:/export/domain

REM List Workstation in domain: 
netdom query WORKSTATION >C:/export/domain/domaininfo.txt

REM List of  servers in  the domain: 
netdom query SERVER >> C:/export/domain/domaininfo.txt

REM List of  domain controllers: 
netdom query DC >> C:/export/domain/domaininfo.txt

REM List of  organizational units under which the specified user can create a  machine object: 
netdom query OU >> C:/export/domain/domaininfo.txt

REM List of  primary domain controller: 
netdom query PDC >> C:/export/domain/domaininfo.txt

REM List the domain trusts: 
netdom query TRUST >> C:/export/domain/domaininfo.txt

REM Query the domain for the current list of  FSMO owners:
netdom query FSMO >> C:/export/domain/domaininfo.txt

REM List all computers from Active Directory: 
dsquery COMPUTER "OU=servers,DC=<DOMAIN NAME>,DC=<DOMAIN EXTENSION>" -o  rdn -limit 0  >> C:/export/domain/machines.txt 




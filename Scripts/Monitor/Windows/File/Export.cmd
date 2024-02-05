cd C:/Export

REM List Workstation in domain: 
netdom query WORKSTATION > WorkstationDomain.txt

REM List of  servers in  the domain: 
netdom query SERVER > serverDomain.txt

REM List of  domain controllers: 
netdom query DC > DCDomain.txt

REM List of  organizational units under which the specified user can create a  machine object: 
netdom query OU >  OUDomain.txt

REM List of  primary domain controller: 
netdom query PDC > primaryDC.txt

REM List the domain trusts: 
netdom query TRUST > DomainTrust.txt

REM Query the domain for the current list of  FSMO owners:
netdom query FSMO > FSMO.txt

REM List all computers from Active Directory: 
dsquery COMPUTER "OU=servers,DC=<DOMAIN NAME>,DC=<DOMAIN EXTENSION>" -o  rdn -limit 0  > machines.txt 

netstat -na | findstr LISTENING > Openports.txt

sc  query > services.txt





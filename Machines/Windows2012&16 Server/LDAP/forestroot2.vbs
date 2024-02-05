Set objRootDSE = GetObject("LDAP://RootDSE")
Wscript.Echo "Root Domain: " & objRootDSE.Get("RootDomainNamingContext")

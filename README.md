# Enum-AD Environnement

# RECON 

with PowerView Module: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

# DOMAIN

Get-NetDomain / Get-NetDomain -Domain "otherdomain" (enum domain)

Get-DomainSID

Get-DomainPolicy

Get-NetDomainController / Get-NetDomainController –Domain "otherdomain"

# USER / GROUP

Get-NetUser / Get-NetUser –Username student1 (enum user)

Get-UserProperty / Get-UserProperty –Properties pwdlastset (enum user properties)

Get-NetComputer / Get-NetComputer –OperatingSystem "*Server 2016* (Get a list of computers in the current domain)

Get-NetGroup / Get-NetGroup –Domain "targetdomain" (enum group) / Get-NetGroup *admin (all grp with admin word)

Get-NetGroupMember -GroupName "Domain Admins" -Recurse (Get all the members of the Domain Admins group)

Get-NetGroup –UserName "user" (Get the group membership for a user)

Get-NetLocalGroup -ComputerName "computername" -ListGroups (List all the local groups on a machine) need privs

Get-NetLocalGroup -ComputerName "computername" -Recurse (Get members of all the local groups on a machine) need privs

Get-NetLoggedon –ComputerName "servername" (Get actively logged users on a computer) local privs

Get-LoggedonLocal -ComputerName "computername" (Get locally logged users on a computer) needs remote registry on the target

# SHARE

Invoke-ShareFinder –Verbos (Find shares on hosts in current domain)

Invoke-FileFinder –Verbose (Find sensitive files on computers in the domain)

Get-NetFileServer (Get all fileservers of the domain)

# GPO

Get-NetGPO / Get-NetGPO -ComputerName "computername" (Get list of GPO in current domain)

Get-NetGPOGroup (Get GPO(s) which use Restricted Groups or groups.xml for interesting user)

Find-GPOComputerAdmin –Computername "computername" (Get users which are in a local group of a machine using GPO)

Find-GPOLocation -UserName "user" -Verbose (Get machines where the given user is member of a specific group)

# OU

Get-NetOU -FullData (Get OUs in a domain)

Get-NetGPO -GPOname "{AB306569-220D-43FF-B03B-83E8F4EF8081} (Get GPO applied on an OU. Read GPOname from gplink attribute from Get-NetOU)

# ACLs

Get-ObjectAcl -SamAccountName "user" –ResolveGUIDs (Get the ACLs associated with the specified object)

Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbos (Get the ACLs associated with the specified prefix to be used for search)

Invoke-ACLScanner -ResolveGUID (Search for interesting ACEs)

Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol (Get the ACLs associated with the specified path)

# TRUST / FOREST

Get-NetDomainTrust / Get-NetDomainTrust –Domain "domain"

Get-NetForest / Get-NetForest –Forest "forestname"

Get-NetForestDomain / Get-NetForestDomain –Forest eurocorp.local (Get all domains in the current forest)

Get-NetForestCatalog / Get-NetForestCatalog –Forest eurocorp.local (Get all global catalogs for the current forest)

Get-NetForestTrust / Get-NetForestTrust –Forest "forestname" (Map trusts of a forest)

# User Hunting

/!\ really noisy /!\

Find-LocalAdminAccess –Verbose (Find all machines on the current domain where the current user has local admin access)

-- more info about this command : query the dc to get list of all the computer of the domain (Get-NetComputer) and then query each machine on the domain with "Invoke-CheckLocalAdminAccess" --

Invoke-UserHunter / Invoke-UserHunter -GroupName "RDPUsers" (Find computers where a domain admin (or specified user/group) has sessions)

Invoke-UserHunter -CheckAccess (To confirm admin access)

Invoke-UserHunter -Stealth (Find computers where a domain admin is logged-in)

//Defense -> .\NetCease.ps1 (change permissions on the netsession enum method by removing permission for authenticated users group. 

# Priv Esc

PowerUp: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc

Invoke-AllChecks

# BloodHound

coming ...


--------------------------------------------------------------

# Check LIST

Check SPN -> kerberoasting -> crack offline hash

AS-REPs Roasting -> ASKTGT for the specific user

Find Delegation : Uncontrained / Constrained

Check DNSAdmin right

Check TGT or TGS in memory of compromise machine


# Persistance

DSRM persistance

Custom SSP -> clear text password

AdminSDHolder persistance

Give ACL perm DCSync to a user

Security Descriptors -> modif remote access methods for specific user (wmi)

Skeleton Key (!!!!!!)


-----------------------------------------------------------------------------

### Impacket
```python3 findDelegation.py -hashes <:hash> FQDN/user -dc-ip <ip>```
### Pywerview 
```pywerview get-netuser -u cturpin --hashes 8432ec4c4f9b9ce96b73a6451a1d9dcc -d telecorp.local -t DC-01 --dc-ip 10.10.50.15 --unconstrained```



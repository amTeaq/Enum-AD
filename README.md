# Enum-AD

# RECON ENV

## DOMAIN

### Get-NetDomain / Get-NetDomain -Domain "otherdomain" (enum domain)

### Get-DomainSID

### Get-DomainPolicy

### Get-NetDomainController / Get-NetDomainController –Domain "otherdomain"

## USER / GROUP

### Get-NetUser / Get-NetUser –Username student1 (enum user)

### Get-UserProperty / Get-UserProperty –Properties pwdlastset (enum user properties)

### Get-NetComputer / Get-NetComputer –OperatingSystem "*Server 2016* (Get a list of computers in the current domain)

### Get-NetGroup / Get-NetGroup –Domain "targetdomain" (enum group) / Get-NetGroup *admin (all grp with admin word)

### Get-NetGroupMember -GroupName "Domain Admins" -Recurse (Get all the members of the Domain Admins group)

### Get-NetGroup –UserName "user" (Get the group membership for a user)

### Get-NetLocalGroup -ComputerName "computername" -ListGroups (List all the local groups on a machine) need privs

### Get-NetLocalGroup -ComputerName "computername" -Recurse (Get members of all the local groups on a machine) need privs

### Get-NetLoggedon –ComputerName "servername" (Get actively logged users on a computer) local privs

### Get-LoggedonLocal -ComputerName "computername" (Get locally logged users on a computer) needs remote registry on the target

# SHARE

### Invoke-ShareFinder –Verbos (Find shares on hosts in current domain)

### Invoke-FileFinder –Verbose (Find sensitive files on computers in the domain)

### Get-NetFileServer (Get all fileservers of the domain)

# GPO

### Get-NetGPO 






good ressource : https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters/powerview

--------------------------------------------------------------

### Check SPN -> kerberoasting

## Find Delegation

### Impacket
```python3 findDelegation.py -hashes <:hash> FQDN/user -dc-ip <ip>```
### Pywerview 
```pywerview get-netuser -u cturpin --hashes 8432ec4c4f9b9ce96b73a6451a1d9dcc -d telecorp.local -t DC-01 --dc-ip 10.10.50.15 --unconstrained```

### Check DNSAdmin right

-----------------------------------------------

## Persistance

### DSRM persistance

### Custom SSP -> clear text password

### AdminSDHolder

### Give ACL perm DCSync to a user

### Security Descriptors -> modif remote access methods for specific user (wmi)


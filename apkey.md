# APKey
# Keep locked until room expires
## jadx-gui
## apktool
## Android Studio
## keytool
## jarsigner

```bash

# CHALLENGE DESCRIPTION
# This app contains some unique keys. Can you get one?

➜  mkdir ~/htb/Intro_to_Android_Exploitation/APKey ; cd ~/htb/Intro_to_Android_Exploitation/APKey ; sudo mv ~/Downloads/APKey.zip .
➜  sha256sum APKey.zip | grep  0e901ee8858a83d64bf65daead62785c89ac157440b8c1affbc62b32036cccf1 

0e901ee8858a83d64bf65daead62785c89ac157440b8c1affbc62b32036cccf1  APKey.zip

➜  unzip APKey.zip
➜  jadx-gui &

Open file -> APKey.apk -> Open file
Go to: Source code -> com -> example.apkey -> MainActivity
Review code

➜  apktool d APKey.apk
➜  code APKey

Extensions -> 'smali' -> Download 'APKLab'

Go to: APKey -> smali -> com -> example/apkey -> MainActivity$a.smali
On line 141:
Change:

const-string v1, "a2a3d412e92d896134d9c9126d756f"

To

const-string v1, "6057f13c496ecf7fd777ceb9e79ae285"

➜  echo -n "hey" | md5sum

6057f13c496ecf7fd777ceb9e79ae285  -

➜  wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.6.1.jar
➜  java -jar apktool_2.6.1.jar b APKey -o new_APKey.apk
➜  keytool -genkey -v -keystore my-key-2.keystore -alias new_APKey -keyalg RSA -keysize 2048 -validity 1000

Password: 

c0rvu5

Enter
Enter
Enter
Enter
Enter
Is CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown correct?

yes

Response:

Generating 2,048 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 1,000 days
	for: CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
[Storing my-key-2.keystore]

➜  jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-key-2.keystore new_APKey.apk new_APKey

Passphrase: 

c0rvu5

Go to: Android Studio -> File -> new_APKey.apk -> OK -> Run 'new_APKey' (or shift+F10)
It will prompt you to delete original apk file:

Yes

Enter VIP code to get your ticket:

'hey'

Response:

HTB{m0r3_0bfusc4t1on_w0uld_n0t_hurt}

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220627053831.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220627060258.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220627053912.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220627060835.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220627060908.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220627061005.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220627053015.png)

#hacking

# APKrypt
## apktool
## Android Studio
## keytool
## jarsigner
```bash

# CHALLENGE DESCRIPTION
# Can you get the ticket without the VIP code?

➜  mkdir ~/htb/Intro_to_Android_Exploitation/APKrypt ; cd ~/htb/Intro_to_Android_Exploitation/APKrypt ; sudo mv ~/Downloads/APKrypt.apk .
➜  sha256sum APKrypt.zip | grep  1c1101314e83f3c8219f15e4f9b1653097da6c1dc2ce6ad80a2863f7af975a56

1c1101314e83f3c8219f15e4f9b1653097da6c1dc2ce6ad80a2863f7af975a56  APKrypt.zip

➜  apktool d APKrypt.apk 

I: Using Apktool 2.6.1-dirty on APKrypt.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/windows_kali/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...

➜  code ~/htb/Intro_to_Android_Exploitation/APKrypt/APKrypt

Extensions -> 'smali' -> Download 'APKLab'

Go to: APKrypt -> smali -> com -> MainActivity$1.smali
On line 59:
Change:

const-string v0, "735c3628699822c4c1c09219f317a8e9"

To

const-string v0, "6057f13c496ecf7fd777ceb9e79ae285"

➜  echo -n "hey" | md5sum

6057f13c496ecf7fd777ceb9e79ae285  -

➜  wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.6.1.jar
➜  java -jar apktool_2.6.1.jar b APKrypt -o new_APKrypt.apk# Write-ups
➜  keytool -genkey -v -keystore my-key.keystore -alias new_APKrypt -keyalg RSA -keysize 2048 -validity 1000

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
[Storing my-key.keystore]
# Write-ups
➜  jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-key.keystore new_APKrypt.apk new_APKrypt


jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-key-4.keystore new_com.companyname.seethesharpflag-x86.apk new_com.companyname.seethesharpflag-x86
Passphrase: 

c0rvu5

Go to: Android Studio -> File -> new_APKrypt.apk -> OK -> Run 'new_APKrypt' (or shift+F10)
It will prompt you to delete original apk file:

Yes

Enter VIP code to get your ticket:

'hey'

Response:

HTB{3nj0y_y0ur_v1p_subscr1pt1on}

java -jar apktool_2.6.1.jar b com.companyname.seethesharpflag-x86 -o new_com.companyname.seethesharpflag-x86.apk


keytool -genkey -v -keystore my-key-5.keystore -alias new_com.companyname.seethesharpflag-x86 -keyalg RSA -keysize 2048 -validity 1000


jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-key-5.keystore new_com.companyname.seethesharpflag-x86.apk new_com.companyname.seethesharpflag-x86



```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220627044240.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220627045629.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220627044457.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220627044622.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220627044701.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220627044832.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220627043336.png)

#hacking

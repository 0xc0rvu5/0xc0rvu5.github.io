# Pinned
## Android Studio
## Frida
## Objection
### Download Android Studio from here
https://developer.android.com/studio

```bash

# CHALLENGE DESCRIPTION
# This app has stored my credentials and I can only login automatically. I tried to intercept the login request and restore my password, but this seems to be a secure connection. Can you help bypass this security restriction and intercept the password in plaintext?

➜  mkdir ~/htb/Intro_to_Android_Exploitation/Pinned ; cd htb/Intro_to_Android_Exploitation/Pinned ; sudo mv ~/Downloads/Pinned.zip .
➜  Pinned sha256sum Pinned.zip | grep 85fe8376196c2b5dbb266fc302ed502057a72ec1ba4037f03f3a531852f409d3

85fe8376196c2b5dbb266fc302ed502057a72ec1ba4037f03f3a531852f409d3  Pinned.zip

➜  sudo mv android-studio-2021.2.1.15-linux.tar.gz ~/bin

➜  sudo tar xvf android-studio-2021.2.1.15-linux.tar.gz

➜  cd bin/

➜  ./studio.sh

Android Studio Setup Wizard:
Next -> Standard (Next) -> Darcula (Next) -> Next 
SDK Folder: /home/windows_kali/Android/Sdk
JDK Location: /home/windows_kali/bin/android-studio/jre
-> Accept (Next) -> Finish -> Finish

# Ensure qemu-kvm is installed and configured to allow for avd emulator to work
➜  sudo apt install android-sdk qemu-kvm

➜  sudo adduser windows_kali kvm

➜  sudo chown windows_kali:windows_kali /dev/kvm

➜  sudo vi ~/.zshrc

# Paste at bottom of file
➜  export PATH=~/Android/Sdk/platform-tools:~/Android/Sdk/tools:~/bin/android-studio/bin:$PATH

# Create a desktop icon for Android Studio
➜  sudo vi /usr/share/applications/Android_Studio.desktop
Add:

[Desktop Entry]
Name=Android Studio
Exec=/home/windows_kali/bin/android-studio/bin/studio.sh
Icon=/home/windows_kali/bin/android-studio/android_studio.jpeg
comment=Android Development
Type=Application
Terminal=false
Encoding=UTF-8
Categories=Utility;

➜  chown windows_kali:windows_kali /usr/share/applications/Android_Studio.desktop

Open Android Studio -> Device Manager -> Create virtual device ->
Choose a device definition: Nexus 6
-> Next ->
Select a system image (ABI: x86) && (Target: <= Androd 6.0): Lollipop
-> Next -> Verify Configuration -> 
AVD Name: Pinned
-> Finish

➜  export ANDROID_HOME=/home/windows_kali/Android/Sdk
➜  cd ~/Android/Sdk/tools
➜  emulator -list-avds
➜  emulator -avd Pinned -writable-system

Drag and drop pinned.apk from folder into 'Application menu' in emulator

# Setup Burpsuite cert
➜  cd ~/htb/Intro_to_Android_Exploitation/Pinned
➜  cp ~/Downloads/BurpSuitePro/cacert.der .
➜  openssl x509 -inform DER -in cacert.der -out cacert.pem
➜  openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
➜  mv cacert.pem 9a5ba575.0
➜  adb remount
➜  adb push 9a5ba575.0 /system/etc/security/cacerts  
➜  adb shell "chmod 664 /system/etc/security/cacerts/9a5ba575.0"
➜  adb reboot

# Instal frida-server
➜  sudo wget https://github.com/frida/frida/releases/download/15.1.27/frida-server-15.1.27-android-x86.xz
➜  unxz frida-server-15.1.27-android-x86.xz
➜  mv frida-server-15.1.27-android-x86 frida-server
➜  adb push frida-server /data/local/tmp
➜  adb shell
root@generic_x86:/ # cd /data/local/tmp
root@generic_x86:/data/local/tmp # chmod 755 frida-server
root@generic_x86:/data/local/tmp # ./frida-server

# Prepare necessary package
➜  pip3 install frida-tools # not required
➜  pip3 install objection
➜  export PATH=/home/windows_kali/.local/bin:$PATH

Make sure the pinned app is running on phone on host system run:

➜  frida-ps -Ua
➜  frida-ps -U | grep -i pinned

➜  objection -g com.example.pinned explore
com.example.pinned on (Android: 5.1.1) [usb] # android sslpinning disable

```
### References
##### Android Studio
https://developer.android.com/studio

https://www.hackthebox.com/blog/intro-to-mobile-pentesting
##### Frida
https://github.com/frida/frida/
##### Objection
https://www.youtube.com/watch?v=SEySgg3vQjg

https://www.hackingarticles.in/android-hooking-and-sslpinning-using-objection-framework/

![image](https://0xc0rvu5.github.io/docs/assets/images/20220625234454.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220625234909.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220625202736.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220626004811.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220626005227.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220626005150.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220626005528.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220626010117.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220626010051.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220626010726.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220626011015.png)

#hacking 

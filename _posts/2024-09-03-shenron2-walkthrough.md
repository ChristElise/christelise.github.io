---
title: CTF Walkthrough for VulnHub Machine Shenron 2
date: 2024-09-03 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [vulnhub, writeup, shenron, machines, pentest]   
image:
  path: /assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/box-shenron2.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Shenron 2 which is the second machine of the Vulnhub Shenron series machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Shenron 2<br>
Goal: Get two flags<br>
Difficulty: Beginner<br>
Operating System: Linux<br>
Download link: [Shenron-2](https://download.vulnhub.com/shenron/shenron-2.ova)<br>
### Tools used
1) Nmap<br>
2) Netcat<br>

### Environment Set up
To ensure success as a penetration tester, staying organised is crucial. Proper organisation streamlines documentation and tracking of progress. In this workshop, we will create a directory tree to systematically manage our work, with detailed descriptions of each directory's purpose available here. 
![Working Dir](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/working-dir.png)


## Reconnaissance
As in every penetration test, we need to identify our target on the network. We can do this by launching a quick host discovery scan against the network using Nmap. To perform the host verification we need to know our current subnet. We can perform these using the commands below:<br>
Current subnet identification: ```ip a```<br>
Host discovery scan: ```sudo nmap -sn 10.0.2.15/24```<br><br>
![Host Identification](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/target-dis.png)

After identifying our target on the network we need to know what services are run by our target to create different possible attack scenarios. We can start a service scan on our target using Nmap.  
```sudo nmap -sV -sC  10.0.2.4 -oA services-dis```
![Service Scan](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/service-scan.png)

We identified two web applications that are on port 80 and 8080. Let's start by fuzzing the one running on port 80. We can notice two directories, browsing them reveals that directory listing is enabled. Digging in each directory gives us nothing interesting.
![Directory Fuzzing 1](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/dir-fuzzing-1.png)

Let's move to the web application running on port 8080, from the front page we notice a link at the button of the page that directs us to a login page containing a domain name that appears to be the domain of our target. So we can add it to the /etc/hosts file.
![Hosts Config](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/hosts-config.png)

After adding our target's domain to our /etc/hosts file we then access the login page which appears to be that of the well-known WordPress CMS. I attempted some default passwords, which were unsuccessful. However, after reviewing some posts on the WordPress instance, I identified that one username to be 'admin'. I then tested weak credentials such as 'Welcome1', 'Spring123', and 'admin', and successfully gained access using the 'admin' username.
![WordPress Login](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/wordpress-login.png)

With this access, I desperately tried to modify templates, upload plugins, or even modify existing plugins but it failed because the user running the WordPress instance didn't have writing permission in the WordPress directory. Since all attempts to add a reverse shell code failed I enumerated all installed plugins and their versions to see if the is one with a public exploit.
![Plugins Enumeraion](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/plugins-enum.png)

## Exploitation

By making a quick Google search we can see that the Site Editor plugin version 1.1.1 is vulnerable to LFI. Let's use this vulnerability to enumerate internal users in the system by reading the 
/etc/passwd file.
![LFI Exploit](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/lfi-vuln.png)

Trying to gain access to the target through the two web applications failed so Let's try to access the system by force through brute-forcing of the SSH service with the usernames obtained through the LFI vulnerability above. 
![Password BruteForce](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/password-bruteforce-1.png)

We got a hit for the user Jenny during the brute-force process so let's login to the target as the user Jenny.
![User Auth](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/user-auth-1.png)

Since WordPress instances are associated with MySQL database let's hunt for MySQL credentials and see if we can use them to escalate privileges. Enumerating the system reveals that we can access Shenron's home directory where the WordPress root directory is found. The wp-config.php file in this directory contains the database user credentials.
![Weak Permissions](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/directory-weak-perm.png)
![DB Creds](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/db-creds.png)

The database credential doesn't seem to be related to any user so we can move to the next step and enumerate all accessible executables with SUID bit set on the system.
![SUID Binaries](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/suid-enum.png)

We identified a non-common executable with the root's SUID set. Upon examining the file, its content reveals that this file uses its SUID permission to make a copy of the bash executable in the /mnt directory and set Shenron's SUID bit on it.
![File Examine](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/file-examine-1.png)

We can now execute /usr/bin/Execute to create the bash binary in /mnt with Shenron's SUID bit set. After that, we can execute the /mnt/bash binary to inherit Shenron's privileges.
![Escalation 1](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/exploit-suids.png)

With Shenron's access, we can read the user flag in Sharon's home directory and continue the enumeration process. Enumerating Shenron's home directory further reveals to us a file named interestingly i.e. .pass. 
![User Flag](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/user-flag.png)

After reading the content of this file, we can see that it resembles encoded data. I tried various decoding algorithms and I finally got a hit while using base32.
![Decoding Pass](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/password-decoding.png)

## Post Exploitation
We can use that password to log in using SSH as the user Shenron. After obtaining a full interactive session we can now check Shenron's sudo rights. 
![Sudo Rights](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/sudo-right-1.png)

We see Shenron can run all commands as root so we use this to log in as root in that session and read the root's flag.
![Root Access](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron:2/root-access.png)

## Conclusion
Great, In this walkthrough, you explored how maintaining unpatched software and using weak passwords can lead to the complete compromise of a machine. We demonstrated the severe impact of storing unencrypted passwords on a system, illustrating how such practices can facilitate account compromises and unauthorized access. By addressing both the importance of timely software updates and the risks associated with weak password management, we highlighted critical security practices necessary to safeguard systems against potential breaches. In a real-world assessment, the last step will be to gather our findings and draft a report for our clients. Thanks for following up on this walkthrough.

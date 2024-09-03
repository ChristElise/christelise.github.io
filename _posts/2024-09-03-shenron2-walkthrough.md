---
title: CTF Walkthrough for VulnHub Machine Shenron 2
date: 2024-09-03 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [vulnhub, writeup, shenron, machines, pentest]   
author: christ
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Shenron 1 which is the first machine of the Vulnhub Shenron series machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Description
Name: Shenron 2<br>
Goal: Get two flags<br>
Difficulty: Beginner<br>
Operating System: Linux<br>
Download link: [Shenron-2](https://download.vulnhub.com/shenron/shenron-2.ova)<br>
### Tools used
1) Nmap<br>
2) Netcat<br>
3) Metasploit Framework<br>
### Environment Set up
To ensure success as a penetration tester, staying organised is crucial. Proper organisation streamlines documentation and tracking of progress. In this workshop, we will create a directory tree to systematically manage our work, with detailed descriptions of each directory's purpose available here.
![Working Dir]()


## Reconnaissance
As in every penetration test, we need to identify our target on the network. We can do this by launching a quick host discovery scan against the network using Nmap. To perform the host verification we need to know our current subnet. We can perform this using the commands below:<br>
Current subnet identification: ```ip a```<br>
Host discovery scan: ```sudo nmap -sn 10.0.2.15/24```<br><br>
![Host Identification]()

After identifying our target on the network we need to know what services are run by our target to create different possible attack scenarios. We can start a service scan on our target using Nmap with the command ```sudo nmap -sV -sC  10.0.2.4 -oA services-dis```
![Service Scan]()

we identified two web applications that are on port 80 and 8080. Let's start by fuzzing the one running on port 80. We can notice two directories, browsing them reveals that directory listing is enabled. Digging in each directory gives us nothing interesting so we can switch to port 8080
![Directory Fuzzing 1]()

Let's move to the web application running on port 8080, from the front page we notice a link that directs us to a login page containing a domain name that appears to be the domain of our target. So we can add it to the /etc/hosts file.
![Hosts Config]()

After adding our target's domain to our /etc/hosts file we then access the login page which appears to be that of the well-known WordPress CMS. I attempted some default passwords, which were unsuccessful. However, after reviewing some posts, I identified that one username is 'admin'. I then tested weak credentials such as 'Welcome1', 'Spring123', and 'admin', and successfully gained access using the 'admin' username.
![WordPress Login]()

With access to the WordPress admin portal, I desperately tried to modify templates, upload plugins, or even modify existing plugins but it failed because the user running the WordPress instance doesn't have writing permission in the WordPress directory. Since all attempts to add a reverse shell code failed let's enumerate all installed plugins and their versions to see if the is one with a public exploit.
![Plugins Enumeraion]()

By making a quick Google search we get a hit on the Site Editor plugin version 1.1.1 which is vulnerable to LFI. Let's use this vulnerability to enumerate internal users in the system by reading the 
/etc/passwd file.
![LFI Exploit]()

Trying to gain access to the target through the two web applications failed so Let's try to access the system by force through brute-forcing of the SSH service with the usernames obtained through the LFI vulnerability above. 
![Password BruteForce]()

We got a hit for the user Jenny during the brute-force process so let's login to the target as the user Jenny.
![User Auth]()

Since WordPress instances are associated with MySQL database let's hunt for MySQL credentials and see if we can use them to escalate privileges. Enumerating the system reveals that we can access Shenron's home directory where the wp-config.php is found. We can read this file to see the database user credentials.
![Weak Permissions]()
![DB Creds]()

The database credential doesn't seem to be related to any user so we can move to the next step  and enumerate all accessible executables with SUID bit set on the system.
![SUID Binaries]()

We identified a non-common executable with the root's SUID set. Examining the file by reading its content reveals to us that this file uses its SUID permission to copy the bash executable to the /mnt directory and set Shenron's SUID bit on it.
![File Examine]()

We can now execute /usr/bin/Execute to create the bash binary with Shenron's SUID bit set in the /mnt directory. After that, we will execute the /mnt/bash binary to inherit Shenron's privileges.
![Escalation 1]()

With Shenron's access, we can read the user flag in Sharon's home directory. Enumerating Shenron's home directory further reveals  to us a file named interestingly i.e. .pass. 
![User Flag]()

After reading the content of this file, we can see that it resembles a sort of encoded data. I tried various decoding algorithms and I finally got a hit base32.
![Decoding Pass]()

We can use that password to log in using SSH as the user Shenron.

Having a full interactive session we can now go into checking Shenron sudo rights. 
![Sudo Rights]()

We can see Shenron can run all commands as root so we use this to log in as root in that session and read the root's flag.
![Root Access]()





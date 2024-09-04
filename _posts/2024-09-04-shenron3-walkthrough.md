---
title: CTF Walkthrough for VulnHub Machine Shenron 3
date: 2024-09-04 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [vulnhub, writeup, shenron, machines, pentest]   
author: christ
---
## Introduction
Greetings everyone, in this walkthrough, we will talk about Shenron 3 which is the third and the last machine of the Vulnhub Shenron series machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Shenron 3<br>
Goal: Get two flags<br>
Difficulty: Beginner<br>
Operating System: Linux<br>
Download link: [Shenron-3](https://download.vulnhub.com/shenron/shenron-3.ova)<br>
### Tools used
1) Nmap<br>
2) Netcat<br>
3) ffuf
### Environment Set up
To ensure success as a penetration tester, staying organised is crucial. Proper organisation streamlines documentation and tracking of progress. In this workshop, we will create a directory tree to systematically manage our work, with detailed descriptions of each directory's purpose available here. 
![Working Dir](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/working-dir.png)

## Reconnaissance
As in every penetration test, we need to identify our target on the network. We can do this by launching a quick host discovery scan against the network using Nmap. Remember that to perform the host verification you need to know your current subnet. I used to command below to identify live hosts on my network.<br>
Host discovery scan: ```sudo nmap -sn 10.0.2.15/24```<br><br>
![Target Discovery](/assets/img/posts/walthrough/vulnhub/2024-09-0-04-shenron:3/target-dis.png)

After identifying our target on the network we need to know what services are run by our target to create different possible attack scenarios. We can start a service scan on our target using Nmap.  
```sudo nmap -sV -sC  10.0.2.4 -oA services-dis```
![Service Scan](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/service-scan.png)

From the scan result, we can see that the site runs WordPress. visiting the site proves that it uses WordPress and we can identify one user name 'admin'.
Those familiar with WordPress will know that the login portal is located in the administrator directory. Upon browsing to this directory it will redirect us to the domain named 'shenron' So let's add a new line in the /etc/hosts file.
![First Browse](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/first-browse.png)
![Host Config](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/hosts-config.png)

After adding it we can now browse to wp-admin where we see the WordPress login page.
![WordPress Login](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/wordpress-login.png)

Upon trying, default credentials give no hit. We can notice after several login failure attempts that the is no protection against brute force so we may want to launch an automated brute-force attack against the login page. I used ffuf in this assessment but other tools as well can be used.
![Password Bruteforce](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/password-bruteforce-1.png)

The bruteforce is successful and we obtain two hits, but one of this appears to be a false positive. With this access we can navigate to Appearrance -> Theme Editor and add a reverse shell in one page of and unused template. I selected the 404.php page from  the Twenty Fourteen template and added a PHP code that executes a Python reverse shell.
![Template Modification](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/template-modification.png)

Before executing the shell we need start a listerner.
![Shell Listener](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/shell-listener.png)

When we browse to the 404.php page of the template we make the server execute the PHP code that sends us a reverse connection.
![Catching Shell](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/catching-shell-1.png)

As usual, let's hunt for database credentials in the wp-config.php file since we obtained a foothold on a machine running a WordPress.
![DB Credentials](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/db-creds.png)

These credentials don't look as they are associated with any user on the system. When I tried to authenticate with these I received and authentication error. But remember this is not the only password we have, we also obtained a password from our previous bruteforce attack. Users are always prone to reuse thesame passwords across different services so let's use the aboved password to authnticate to each user on the target.
Upon many trials we can succefully log in as Shenron.
![User Auth1](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/user-auth-1.png)

With this access we can read the user flag and further our enumeration.
![User Flag](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/user-flag.png)

During the enumeration process we can notice that Shenron's home directory contains and executable with the SUID bit set for the root user. Running this executable displays thesame output displayed by the netstat command.
![File Enum 1](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/file-enum-1.png)

We can use the **file** command to identify the nature of the executable. We will notice that it's and ELF file and ELF (Executable and Linkable Format) files are partially readable, but the readability depends on the context and tools you use. Here, we can simply use cat to print the content of the file and see which commands it runs.
![File Examine](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/file-examine-1.png)

As already mentioned above the file runs netstat command with the some arguments but what we can notice that it calls the netstat command using its relative path. Relative paths can be abuse easily by creating a file named thesame way as the executed command and placing path to the file at the beginning of the PATH variable of the user executing that command. This will trick the system because when a command is executed the system looks for that command in the directories in the PATH variable starting from left going to the right. 
Let's start by creating a file name netstat and place a line which executes the bash shell.
![Fake File](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/fakefile.png)
Next since we are the one executing the command let's edit our PATH variable and place the directory containing the fake netstat command at the beginning of our PATH variable.
![Change Path](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/path-change.png)
Let's now execute the network command which has the root SUID bit set on it.
![Root Access](/assets/img/posts/walthrough/vulnhub/2024-09-04-shenron:3/root-access.png)

## Conclusion
Great, In this walkthrough, you explored how exploiting weak credentials in web applications and password reuse, combined with other bad practices such as using relative paths instead of absolute paths, can lead to complete target takeover.In a real-world assessment, the last step will be to gather our findings and draft a report for our clients. Thanks for following up on this walkthrough.





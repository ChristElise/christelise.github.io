---
title: CTF Walkthrough for HTB Machine Cap
date: 2024-09-04 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [htb, writeup, cap, machines, pentest]   
author: christ
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Cap a retired Hack The Box machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: Cap<br>
Difficulty: Easy<br>
Operating System: Linux<br>
Machine link: [Cap HTB](https://app.hackthebox.com/machines/Cap)<br>
### Tools used
1) Nmap<br>
2) Netcat<br>
3) ffuf

## Reconnaissance
First, we should note that this machine is not hosted locally i.e. it's being accessed by many other hackers that is why any traffic sent to the machine must be done intelligently to avoid useless crashes. This is why we will first start with a port discovering scan to uncover open ports on the target. The command used to perform this can be seen below.
``` sudo nmap -sS -n 10.10.10.245 -oN ports-dis.nmap ```<br><br>
![Port Discovery](/assets/img/posts/walthrough/vulnhub/2024-09-04-cap-htb/ports-dis.png)
Once we have enumerated the open ports on the target we can now attempt to do targeted service enumeration on those open ports using the command below.
```sudo nmap -sV -sC -n 10.10.10.245 -p 21,22,80 -oN services-dis.nmap```
![Service Scan](/assets/img/posts/walthrough/vulnhub/2024-09-04-cap-htb/services-dis.png)

From the scan result above, we can see that anonymous login is not enabled on the FTP server so let's pass for the moment. Next, let's visit the web application hosted by the target.
![First Browse](/assets/img/posts/walthrough/vulnhub/2024-09-04-cap-htb/first-browse.png)

We can see that we have access to a dashboard that doesn't require any form of authentication. Also, by browsing the navigation bar we noticed that the web app displays outputs of commands such as netstat and ip. I tried to replace it with basic commands such as 'ls' but it gave me a 404 error. Having no hint, We can try to brute-force hidden directories.
![Dir Fuzzing](/assets/img/posts/walthrough/vulnhub/2024-09-04-cap-htb/dir-bruteforce.png)

We already know the content of the ip and netstat directory so let's visit the remaining two i.e. the data and capture directory. When we visit the data directory we can see an error return by the server whereas when visit the capture directory it redirects us to the data directory but with a number in front. This directory allows us to download pcap files. This index looks quite interesting. Let's create a custom wordlist with numbers ranging from 0 to 100 and fuzz the data directory to identify valid directories.
![Custom Wordlist](/assets/img/posts/walthrough/vulnhub/2024-09-04-cap-htb/data-list-create.png)
![Dir Fuzzing](/assets/img/posts/walthrough/vulnhub/2024-09-04-cap-htb/data-dir-fuzzing.png)

From the fuzzing result, we can identify three valid directories. Upon visiting these directories we can see that the directory named 0 gives us a pcap file containing TCP packets
![](/assets/img/posts/walthrough/vulnhub/2024-09-04-cap-htb/directory-0.png)

We can download this pcap file and import it into our packet analyses tool of preference for further analyses. I will use Wireshark for this walkthrough.

![](/assets/img/posts/walthrough/vulnhub/2024-09-04-cap-htb/)

![](/assets/img/posts/walthrough/vulnhub/2024-09-04-cap-htb/)

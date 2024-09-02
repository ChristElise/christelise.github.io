---
title: CTF Walkthrough for VulnHub Machine Shenron 2
date: 2024-09-03 00:00:00 +0300
categories: [Walkthrough, CTF]
tags: [vulnhub, writeup, shenron, machines, pentest]   
author: christ
---

## Introduction
Greetings everyone, in this walkthrough, we will talk about Shenron 1 which is the first machine of the Vulnhub Shenron series machines. This walkthrough is not only meant to catch the flag but also to demonstrate how a penetration tester will approach this machine in a real-world assessment.
This machine was set up using VirtualBox as recommended by the creator and the Network configuration was changed to 'Nat Network'.
### Description
Name: Shenron 2<br>
Goal: Get two flags<br>
Difficulty: Beginner<br>
Operating System: Linux<br>
Download link: [Shenron-1](https://download.vulnhub.com/shenron/shenron-2.ova)<br>
### Tools used
1) Nmap<br>
2) Netcat<br>
3) Metasploit Framework<br>
### Environment Set up
To ensure success as a penetration tester, staying organised is crucial. Proper organisation streamlines documentation and tracking of progress. In this workshop, we will create a directory tree to systematically manage our work, with detailed descriptions of each directory's purpose available here.
![Working Dir]()


## Reconnaissance
As in every penetration test, we need to identify our target on the network. We can do this by launching a quick host discovery scan against the network using Nmap. To perform the host verification we need to know our current subnet. We can perform this using the commands below:<br>
Current subnet identification: ```ip a```<br>
Host discovery scan: ```sudo nmap -sn 10.0.2.15/24```<br><br>
![Host Identification]()

After identifying our target on the network we need to know what services are run by our target to create different possible attack scenarios. We can start a service scan on our target using Nmap with the command ```sudo nmap -sV -sC  10.0.2.4 -oA services-dis```
![Service Scan]()

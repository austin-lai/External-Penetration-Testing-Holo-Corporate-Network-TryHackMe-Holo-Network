# External Penetration Testing - Holo Corporate Network - TryHackMe - Holo Network

> Austin Lai | September 20th, 2021

---

<!-- Description -->

[Room = TryHackMe(THM) - Holo](https://tryhackme.com/room/hololive)

The room is completed on September 5th, 2021

It was fun and be sure you can learn a lots from this room !

<!-- /Description -->

<br />

## Table of Contents

<!-- TOC -->

- [External Penetration Testing - Holo Corporate Network - TryHackMe - Holo Network](#external-penetration-testing---holo-corporate-network---tryhackme---holo-network)
    - [Table of Contents](#table-of-contents)
    - [Overview of Holo](#overview-of-holo)
    - [Let's Begin Here !!!](#lets-begin-here-)
        - [**HOLO External Penetration Test Report**](#holo-external-penetration-test-report)
        - [Brief Addon WriteUp](#brief-addon-writeup)

<!-- /TOC -->

<br />

## Overview of Holo

Welcome to Holo!

Holo is an Active Directory (AD) and Web Application attack lab that teaches core web attack vectors and advanced or obscure Active Directory attacks along with general red teaming methodology and concepts.

This network simulates an external penetration test on a corporate network "Hololive" with one intended kill chain. All concepts and exploits will be taught in a red teaming methodology and mindset with other methods and techniques taught throughout the network.

This network brings you from zero to red-team, but you are expected to have a general understanding of basic Windows and Linux architecture and the command line for both Windows and Linux.

<br />

In this lab, you will learn and explore the following topics:

- .NET basics
- Web application exploitation
- AV evasion
- Whitelist and container escapes
- Pivoting
- Operating with a C2 (Command and Control) Framework
- Post-Exploitation
- Situational Awareness
- Active Directory attacks

<br />

You will learn and exploit the following attacks and misconfigurations:

- Misconfigured sub-domains
- Local file Inclusion
- Remote code execution
- Docker containers
- SUID binaries
- Password resets
- Client-side filters
- AppLocker
- Vulnerable DLLs
- Net-NTLMv2 / SMB

<br />

[Overview and Background Section]

- [Task 1] Generation 1 - An Overview of Holo
- [Task 2] Patching Into the Matrix  - Get Connected!
- [Task 3] Kill Chain - Well, you're already here
- [Task 4] Flag Submission Panel - Submit your flags here

<br />

[Exploitation Guide]

- [Task 8] and [Task 11]  - Enumerating Files and Subdomains found on L-SRV01
- [Task 11] and [Task 12] Exploiting RCE and LFI vulnerabilities found on L-SRV01
- [Task 14] Enumerating a Docker container
- [Task 15] Enumerating the Docker host from L-SRV02
- [Task 16] through [Task 18] Gaining RCE on L-SRV01
- [Task 19] L-SRV01 Privilege Escalation
- [Task 22] Pivoting into the rest of the 10.200.x.0/24 network
- [Task 27] Exploiting password reset tokens on S-SRV01
- [Task 28] Bypassing file upload restrictions on S-SRV01
- [Task 35] Dumping Credentials on S-SRV01
- [Task 36] Passing the Hash to PC-FILESRV01
- [Task 37] Bypassing AppLocker on PC-FILESRV01
- [Task 42] and [Task 43] DLL Hijacking on PC-FILESRV01
- [Task 46] Preform a Remote NTLM Relay attack on PC-FILESRV01 to DC-SRV01
- [Task 47] Looting, submitting the final flags from S-SRV02, and Thank You's.

<br />

[Learning Guide]

- [Task 8] Punk Rock 101 err Web App 101 - Fuzzing for Files and  Subdomains using GoBuster
- [Task 9] What the Fuzz? - Fuzzing for Files and Subdomains using WFuzz
- [Task 11] What is this? Vulnversity? - Web Exploitation Basics, LFI and RCE
- [Task 15] Living of the LANd - Building your own Portable Port Scanner!
- [Task 17] Making Thin Lizzy Proud - Docker Enumeration and RCE via MySQL
- [Task 22] Digging a tunnel to nowhere - An overview of Pivoting with Chisel and SSHuttle
- [Task 23] Command your Foes and Control your Friends - Installing and Setting up Covenant C2
- [Task 27] Hide yo' Kids, Hide yo' Wives, Hide yo' Tokens - Password Reset Tokens - Grindr Case Study
- [Task 28] Thanks, I'll let myself in - Exploiting Client Side scripts
- [Task 28] Basically a joke itself... - AV Bypass
- [Task 35] That's not a cat, that's a dawg - Gaining Persistence and Dumping Credentials with Mimikat ft. Covenant
- [Task 36] Good Intentions, Courtesy of Microsoft Part: II - Hash spraying with CrackMapExec
- [Task 37] Watson left her locker open - An Intro to AppLocker Bypass
- [Task 42] and [Task 43] WE'RE TAKING OVER THIS DLL! - DLL Hijacking
- [Task 44] Never Trust LanMan - Understanding how NetNTLM Sessions are established
- [Task 45] No you see me, now you dont - Real World Case Study, How Spooks pwned a network in 5 minutes using Responder and NTLMRelayX
- [Task 46] Why not just turn it off? - Showcasing a new AD Attack vector; Hijacking Windows' SMB server

<br />

## Let's Begin Here !!!

### [**HOLO External Penetration Test Report**](https://github.com/austin-lai/External-Penetration-Testing-Holo-Corporate-Network-TryHackMe-Holo-Network/blob/master/BlackSunSecurity-ExternalPenetrationTestReport-HOLO-v1.0.pdf)

<br />

### Brief Addon WriteUp
























<br />

---

> Do let me know any command can be improve or you have any question you can contact me via THM message or write down comment below or via FB


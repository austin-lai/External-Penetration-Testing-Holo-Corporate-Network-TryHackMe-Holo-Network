# External Penetration Testing - Holo Corporate Network - TryHackMe - Holo Network

> Austin Lai | September 20th, 2021

---

<!-- Description -->

[Room = TryHackMe(THM) - Holo](https://tryhackme.com/room/hololive)

The room is completed on September 7th, 2021

It was fun and be sure you can learn a lots from this room !

My first ever Pentest Report or OSCP like report, truly appreciate and welcome anyone would willing to provide feedback, I wish to have better report writing skill.

Thank you so much in advance.

<!-- /Description -->

<br />

## Table of Contents

<!-- TOC -->

- [External Penetration Testing - Holo Corporate Network - TryHackMe - Holo Network](#external-penetration-testing---holo-corporate-network---tryhackme---holo-network)
    - [Table of Contents](#table-of-contents)
    - [Overview of Holo](#overview-of-holo)
    - [Let's Begin Here !!!](#lets-begin-here-)
        - [**HOLO External Penetration Test Report**](#holo-external-penetration-test-report)
        - [Brief WriteUp Add-on for Report](#brief-writeup-add-on-for-report)

<!-- /TOC -->

<br />

## Overview of Holo

Welcome to Holo!

Holo is an Active Directory (AD) and Web Application attack lab that teaches core web attack vectors and advanced or obscure Active Directory attacks along with general red teaming methodology and concepts.

This network simulates an external penetration test on a corporate network "Hololive" with one intended kill chain. All concepts and exploits will be taught in a red teaming methodology and mindset with other methods and techniques taught throughout the network.

This network brings you from zero to red-team, but you are expected to have a general understanding of basic Windows and Linux architecture and the command line for both Windows and Linux.

Before we get too overzealous in attacking web servers and hacking the world, we need to identify our scope and perform some initial recon to identify assets. Your trusted agent has informed you that the scope of the engagement is 10.200.x.0/24 and 192.168.100.0/24.

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

The report has included below section in general for your references:

1. Cover page
2. Business Confidential
3. Table of Content
4. Holo External Penetration Test Report
    - Introduction | Purpose
    - External Penetration Test Scope
    - Executive Summary
    - Attack Timeline and Summary
    - Severity Classification
    - Summary of Vulnerability
    - Security Weakness and Recommendation
    - External Penetration Test Methodologies (include detail of Information Gathering, Penetration, Maintain Access, House Cleaning)
5. Conclusion | Summary
6. Additional Items
    - Appendix 1 - References
    - Appendix 2 - MITRE ATT&CK Framework
    - Appendix 3 - Trophies
    - Appendix 4 - Meterpreter Usage
    - Appendix 5 - Account Usage
    - Appendix 6 - Additional [tools | binary] Usage

<br />

### Brief WriteUp Add-on for Report

Information gathering - basic network scan for host alive:

<details><summary>nmap result</summary>

```bash
nmap -nvv -sn -oN ./holo-kali-08092021/10.200.107.0-network-scan 10.200.107.0/24 && ./holo-kali-08092021/10.200.107.0-network-scan | grep --color=always -B 1 up

Nmap scan report for 10.200.107.0 [host down, received no-response]
Nmap scan report for 10.200.107.1 [host down, received no-response]
Nmap scan report for 10.200.107.2 [host down, received no-response]
Nmap scan report for 10.200.107.3 [host down, received no-response]
Nmap scan report for 10.200.107.4 [host down, received no-response]
Nmap scan report for 10.200.107.5 [host down, received no-response]
Nmap scan report for 10.200.107.6 [host down, received no-response]
Nmap scan report for 10.200.107.7 [host down, received no-response]
Nmap scan report for 10.200.107.8 [host down, received no-response]
Nmap scan report for 10.200.107.9 [host down, received no-response]
Nmap scan report for 10.200.107.10 [host down, received no-response]
Nmap scan report for 10.200.107.11 [host down, received no-response]
Nmap scan report for 10.200.107.12 [host down, received no-response]
Nmap scan report for 10.200.107.13 [host down, received no-response]
Nmap scan report for 10.200.107.14 [host down, received no-response]
Nmap scan report for 10.200.107.15 [host down, received no-response]
Nmap scan report for 10.200.107.16 [host down, received no-response]
Nmap scan report for 10.200.107.17 [host down, received no-response]
Nmap scan report for 10.200.107.18 [host down, received no-response]
Nmap scan report for 10.200.107.19 [host down, received no-response]
Nmap scan report for 10.200.107.20 [host down, received no-response]
Nmap scan report for 10.200.107.21 [host down, received no-response]
Nmap scan report for 10.200.107.22 [host down, received no-response]
Nmap scan report for 10.200.107.23 [host down, received no-response]
Nmap scan report for 10.200.107.24 [host down, received no-response]
Nmap scan report for 10.200.107.25 [host down, received no-response]
Nmap scan report for 10.200.107.26 [host down, received no-response]
Nmap scan report for 10.200.107.27 [host down, received no-response]
Nmap scan report for 10.200.107.28 [host down, received no-response]
Nmap scan report for 10.200.107.29 [host down, received no-response]
Nmap scan report for 10.200.107.30 [host down, received no-response]
Nmap scan report for 10.200.107.31 [host down, received no-response]
Nmap scan report for 10.200.107.32 [host down, received no-response]
Nmap scan report for 10.200.107.33
Host is up, received syn-ack (0.33s latency).
Nmap scan report for 10.200.107.34 [host down, received no-response]
[---OMMITED---]
Read data files from: /usr/bin/../share/nmap
# Nmap done at Wed Sep  8 22:37:08 2021 -- 256 IP addresses (2 hosts up) scanned in 15.38 seconds

Nmap scan report for 10.200.107.33
Host is up, received syn-ack (0.33s latency).
```

</details>

Information gathering - detail rustscan for target 10.200.107.33:

<details><summary>rustscan result</summary>

```bash
sudo rustscan -u 5000 -b 1900 -t 4000 --tries 2 --scan-order serial -a 10.200.107.33 -- -A -sVC --script=safe,default,discovery,version,vuln | sudo tee rustscan-full-result-10.200.107.33

.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.200.107.33:22
Open 10.200.107.33:80
Open 10.200.107.33:33060
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-08 22:38 EDT
NSE: Loaded 487 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:38
NSE: [targets-ipv6-wordlist] Need to be executed for IPv6.
NSE: [shodan-api] Error: Please specify your ShodanAPI key with the shodan-api.apikey argument
NSE: [broadcast-ataoe-discover] No interface supplied, use -e
NSE: [targets-ipv6-map4to6] This script is IPv6 only.
NSE: [url-snarf] no network interface was supplied, aborting ...
NSE: [broadcast-sonicwall-discover] No network interface was supplied, aborting.
NSE: [targets-xml] Need to supply a file name with the targets-xml.iX argument
NSE: [mtrace] A source IP must be provided through fromip argument.
NSE Timing: About 99.37% done; ETC: 22:39 (0:00:00 remaining)
Completed NSE at 22:39, 40.12s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:39
Completed NSE at 22:39, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:39
Completed NSE at 22:39, 0.00s elapsed
Pre-scan script results:
| broadcast-dhcp-discover:
|   Response 1 of 1:
|     Interface: eth0
|     IP Offered: 10.10.10.10
|     Server Identifier: 10.10.10.3
|     DHCP Message Type: DHCPOFFER
|     Subnet Mask: 255.255.255.0
|     Router: 10.10.10.1
|     Domain Name Server: 192.168.100.103, 8.8.8.8, 8.8.4.4
|_    IP Address Lease Time: 5m00s
| broadcast-igmp-discovery:
|   10.10.100.1
|     Interface: eth1
|     Version: 2
|     Group: 224.0.0.9
|     Description: RIP2 Routers (rfc1723)
|   10.10.100.1
|     Interface: eth1
|     Version: 2
|     Group: 224.0.0.252
|     Description: Link-local Multicast Name Resolution (rfc4795)
|_  Use the newtargets script-arg to add the results as targets
| broadcast-listener:
|   ether
|   udp
|       SSDP
|         ip           uri
|         10.10.100.1   urn:schemas-upnp-org:device:InternetGatewayDevice:1
|       LLMNR
|         ip                         query
|         fe80::d980:93eb:cf49:2bd7  austin-helper-x13
|_        10.10.100.1                austin-helper-x13
|_eap-info: please specify an interface with -e
|_hostmap-robtex: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
|_http-robtex-shared-ns: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
| ipv6-multicast-mld-list:
|   fe80::d980:93eb:cf49:2bd7:
|     device: eth1
|     mac: 0a:00:27:00:00:0f
|     multicast_ips:
|       ff02::1:ff49:2bd7         (NDP Solicited-node)
|       ff02::1:3                 (Link-local Multicast Name Resolution)
|       ff02::1:3                 (Link-local Multicast Name Resolution)
|       ff02::1:3                 (Link-local Multicast Name Resolution)
|       ff02::1:ff17:d849         (Solicited-Node Address)
|       ff02::fb                  (mDNSv6)
|       ff02::c                   (SSDP)
|       ff02::1:3                 (Link-local Multicast Name Resolution)
|_      ff02::1:3                 (Link-local Multicast Name Resolution)
| targets-asn:
|_  targets-asn.asn is a mandatory parameter
| targets-ipv6-multicast-invalid-dst:
|   IP: fe80::d980:93eb:cf49:2bd7  MAC: 0a:00:27:00:00:0f  IFACE: eth1
|_  Use --script-args=newtargets to add the results as targets
| targets-ipv6-multicast-mld:
|   IP: fe80::d980:93eb:cf49:2bd7  MAC: 0a:00:27:00:00:0f  IFACE: eth1
|
|_  Use --script-args=newtargets to add the results as targets
| targets-ipv6-multicast-slaac:
|   IP: fe80::d980:93eb:cf49:2bd7  MAC: 0a:00:27:00:00:0f  IFACE: eth1
|   IP: fe80::c938:93dc:1b17:d849  MAC: 0a:00:27:00:00:0f  IFACE: eth1
|_  Use --script-args=newtargets to add the results as targets
Initiating Ping Scan at 22:39
Scanning 10.200.107.33 [4 ports]
Completed Ping Scan at 22:39, 0.37s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:39
Completed Parallel DNS resolution of 1 host. at 22:39, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 22:39
Scanning 10.200.107.33 [3 ports]
Discovered open port 22/tcp on 10.200.107.33
Discovered open port 80/tcp on 10.200.107.33
Discovered open port 33060/tcp on 10.200.107.33
Completed SYN Stealth Scan at 22:39, 0.38s elapsed (3 total ports)
Initiating Service scan at 22:39
Scanning 3 services on 10.200.107.33
Completed Service scan at 22:40, 39.38s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 10.200.107.33
Retrying OS detection (try #2) against 10.200.107.33
Initiating Traceroute at 22:40
Completed Traceroute at 22:40, 0.34s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 22:40
Completed Parallel DNS resolution of 2 hosts. at 22:40, 0.02s elapsed
DNS resolution of 2 IPs took 0.02s. Mode: Async [#: 2, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.200.107.33.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:40
NSE Timing: About 99.03% done; ETC: 22:41 (0:00:00 remaining)
NSE Timing: About 99.76% done; ETC: 22:41 (0:00:00 remaining)
NSE Timing: About 99.76% done; ETC: 22:42 (0:00:00 remaining)
NSE Timing: About 99.84% done; ETC: 22:42 (0:00:00 remaining)
NSE Timing: About 99.92% done; ETC: 22:43 (0:00:00 remaining)
Completed NSE at 22:43, 157.47s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:43
Completed NSE at 22:43, 4.42s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:43
Completed NSE at 22:43, 0.00s elapsed
Nmap scan report for 10.200.107.33
Host is up, received reset ttl 63 (0.27s latency).
Scanned at 2021-09-08 22:39:40 EDT for 211s

PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
|_banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2
| ssh-hostkey:
|   3072 11:29:89:c3:c7:39:17:65:7f:81:3a:c3:d1:ab:69:c7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCsPBETi9B91pOIm2E8ISSEwY27HWW6cqR6O2RLRZhOuhWSZ9pbKKcvaJl7FyfQsPpr9LVdaA8jvNTmFuzPsXVybJhst007qq+cUBGhmLMt4e9FlIxibuutv+FNbnguEpL95iqNrjSmPaYTZX7zVsP97e9Euhxy9hlLQjLqwlyJcswYWFBn6N6wEFfGNGO+7MmZTvrZM0TOJAjkhnjKxrHX5ulQddak5fi//I3sgd7/XMaryhVMmVBLRul726RSOSh9QFDCKFoAKoZF0iMM0vx1c7uD9zw5gD5xf+xDipAhS1h05CrhDCjTFyqIe+Q+/vH6f8oXLAVue/WnNU0yXT90CM5IOPhz1Zz53WP05li7vtTJhOrSo72oyZsgS+TVn0PFGfoGXG5M9M+tppejfXYQCF071iY+31zUdecu1IovN0aWqVccRHCxfomstXBYuiQOwHUsNmgfZShWHAWKDYcwFlip3x9ote9XUTBBZSiH7+eXsKjr2swYnKjya/tpIC0=
|   256 e8:ce:d8:24:78:98:8b:c2:42:1a:1c:4c:7b:70:5c:db (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBH+aK0Ud/r2l55EJz2i50p7aoe7eZjUouxuPTz4lVRlzxfHitT+TvLjyfdLrRNoXUjViE59n9igRuwHox2B0uY=
|   256 77:8e:57:e6:eb:55:9d:47:5a:3f:a1:66:55:cb:45:bd (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKAxmkLKl73VofsKto7pgPKgjvLS0xK1rv3vgzANgTDy
| ssh2-enum-algos:
|   kex_algorithms: (9)
|       curve25519-sha256
|       curve25519-sha256@libssh.org
|       ecdh-sha2-nistp256
|       ecdh-sha2-nistp384
|       ecdh-sha2-nistp521
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group16-sha512
|       diffie-hellman-group18-sha512
|       diffie-hellman-group14-sha256
|   server_host_key_algorithms: (5)
|       rsa-sha2-512
|       rsa-sha2-256
|       ssh-rsa
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (6)
|       chacha20-poly1305@openssh.com
|       aes128-ctr
|       aes192-ctr
|       aes256-ctr
|       aes128-gcm@openssh.com
|       aes256-gcm@openssh.com
|   mac_algorithms: (10)
|       umac-64-etm@openssh.com
|       umac-128-etm@openssh.com
|       hmac-sha2-256-etm@openssh.com
|       hmac-sha2-512-etm@openssh.com
|       hmac-sha1-etm@openssh.com
|       umac-64@openssh.com
|       umac-128@openssh.com
|       hmac-sha2-256
|       hmac-sha2-512
|       hmac-sha1
|   compression_algorithms: (2)
|       none
|_      zlib@openssh.com
| vulners:
|   cpe:/a:openbsd:openssh:8.2p1:
|       CVE-2020-15778  6.8     https://vulners.com/cve/CVE-2020-15778
|       CVE-2020-12062  5.0     https://vulners.com/cve/CVE-2020-12062
|       MSF:ILITIES/GENTOO-LINUX-CVE-2021-28041/        4.6     https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2021-28041/ *EXPLOIT*
|       CVE-2021-28041  4.6     https://vulners.com/cve/CVE-2021-28041
|       MSF:ILITIES/OPENBSD-OPENSSH-CVE-2020-14145/     4.3     https://vulners.com/metasploit/MSF:ILITIES/OPENBSD-OPENSSH-CVE-2020-14145/      *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-14145/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-14145/       *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-14145/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-14145/       *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2020-14145/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2020-14145/       *EXPLOIT*
|       MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/   4.3     https://vulners.com/metasploit/MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/    *EXPLOIT*
|_      CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145
80/tcp    open  http    syn-ack ttl 62 Apache httpd 2.4.29 ((Ubuntu))
|_citrix-enum-apps-xml: ERROR: Script execution failed (use -d to debug)
|_citrix-enum-servers-xml: ERROR: Script execution failed (use -d to debug)
|_http-chrono: Request times for /; avg: 1128.12ms; min: 1054.10ms; max: 1161.87ms
| http-comments-displayer:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.200.107.33
|
|     Path: http://10.200.107.33:80/
|     Line number: 110
|     Comment:
|         <!-- #post-## -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 70
|     Comment:
|         <!-- .entry-meta -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 132
|     Comment:
|         <!-- .inside-right-sidebar -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 55
|     Comment:
|         <!-- .inside-navigation -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 71
|     Comment:
|         <!-- .entry-header -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 33
|     Comment:
|         /* End cached CSS */
|
|     Path: http://10.200.107.33:80/
|     Line number: 136
|     Comment:
|         <!-- #page -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 135
|     Comment:
|         <!-- #content -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 57
|     Comment:
|         <!-- .inside-header -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 148
|     Comment:
|         <!--[if lte IE 11]>
|         <script type='text/javascript' src='http://www.holo.live/wp-content/themes/generatepress/js/classList.min.js?ver=2.4.2' id='generate-classlist-js'></script>
|         <![endif]-->
|
|     Path: http://10.200.107.33:80/
|     Line number: 146
|     Comment:
|         <!-- .site-footer -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 54
|     Comment:
|         <!-- .main-nav -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 145
|     Comment:
|         <!-- .site-info -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 112
|     Comment:
|         <!-- #primary -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 56
|     Comment:
|         <!-- #site-navigation -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 133
|     Comment:
|         <!-- #secondary -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 109
|     Comment:
|         <!-- .inside-article -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 58
|     Comment:
|         <!-- #masthead -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 105
|     Comment:
|         <!-- .entry-content -->
|
|     Path: http://10.200.107.33:80/
|     Line number: 111
|     Comment:
|_        <!-- #main -->
| http-csrf:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.200.107.33
|   Found the following possible CSRF vulnerabilities:
|
|     Path: http://10.200.107.33:80/
|     Form id:
|_    Form action: http://www.holo.live/
|_http-date: Thu, 09 Sep 2021 02:40:49 GMT; 0s from local time.
|_http-devframework: Wordpress detected. Found common traces on /
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-drupal-enum: Nothing found amongst the top 100 resources,use --script-args number=<number|all> for deeper analysis)
| http-enum:
|   /robots.txt: Robots file
|   /readme.html: Wordpress version: 2
|   /: WordPress version: 5.5.3
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /readme.html: Interesting, a readme.
|_  /0/: Potentially interesting folder
|_http-errors: Couldn't find any error pages.
|_http-feed: Couldn't find any feeds.
|_http-fetch: Please enter the complete path of the directory to save data in.
|_http-generator: WordPress 5.5.3
| http-grep:
|   (1) http://10.200.107.33:80/:
|     (1) ip:
|_      + 192.168.100.138
| http-headers:
|   Date: Thu, 09 Sep 2021 02:40:48 GMT
|   Server: Apache/2.4.29 (Ubuntu)
|   X-UA-Compatible: IE=edge
|   Link: <http://www.holo.live/index.php/wp-json/>; rel="https://api.w.org/"
|   Connection: close
|   Content-Type: text/html; charset=UTF-8
|
|_  (Request type: HEAD)
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-malware-host: Host appears to be clean
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-mobileversion-checker: No mobile version detected.
| http-php-version: Logo query returned unknown hash 2052bf63dfddcd1d2f052ead29f3a8d7
|_Credits query returned unknown hash 2052bf63dfddcd1d2f052ead29f3a8d7
|_http-referer-checker: Couldn't find any cross-domain scripts.
| http-robots.txt: 21 disallowed entries
| /var/www/wordpress/index.php
| /var/www/wordpress/readme.html /var/www/wordpress/wp-activate.php
| /var/www/wordpress/wp-blog-header.php /var/www/wordpress/wp-config.php
| /var/www/wordpress/wp-content /var/www/wordpress/wp-includes
| /var/www/wordpress/wp-load.php /var/www/wordpress/wp-mail.php
| /var/www/wordpress/wp-signup.php /var/www/wordpress/xmlrpc.php
| /var/www/wordpress/license.txt /var/www/wordpress/upgrade
| /var/www/wordpress/wp-admin /var/www/wordpress/wp-comments-post.php
| /var/www/wordpress/wp-config-sample.php /var/www/wordpress/wp-cron.php
| /var/www/wordpress/wp-links-opml.php /var/www/wordpress/wp-login.php
|_/var/www/wordpress/wp-settings.php /var/www/wordpress/wp-trackback.php
|_http-security-headers:
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-sitemap-generator:
|   Directory structure:
|     /
|       Other: 1
|   Longest directory structure:
|     Depth: 0
|     Dir: /
|   Total files found (by extension):
|_    Other: 1
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-title: holo.live
| http-useragent-tester:
|   Status for browser useragent: 200
|   Allowed User Agents:
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
| http-vhosts:
|_128 names had status 200
| http-wordpress-enum:
| Search limited to top 100 themes/plugins
|   plugins
|     akismet
|   themes
|     generatepress 2.4.2
|_    twentyseventeen 2.4
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
|_http-xssed: No previously reported XSS vuln.
| vulners:
|   cpe:/a:apache:http_server:2.4.29:
|       CVE-2021-26691  7.5     https://vulners.com/cve/CVE-2021-26691
|       MSF:ILITIES/REDHAT_LINUX-CVE-2019-0211/ 7.2     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2019-0211/  *EXPLOIT*
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0211/      7.2     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0211/       *EXPLOIT*
|       EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB    7.2     https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB    *EXPLOIT*
|       CVE-2019-0211   7.2     https://vulners.com/cve/CVE-2019-0211
|       1337DAY-ID-32502        7.2     https://vulners.com/zdt/1337DAY-ID-32502        *EXPLOIT*
|       MSF:ILITIES/UBUNTU-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1312/        *EXPLOIT*
|       MSF:ILITIES/UBUNTU-CVE-2017-15715/      6.8     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2017-15715/       *EXPLOIT*
|       MSF:ILITIES/SUSE-CVE-2017-15715/        6.8     https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2017-15715/ *EXPLOIT*
|       MSF:ILITIES/REDHAT_LINUX-CVE-2017-15715/        6.8     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2017-15715/ *EXPLOIT*
|       MSF:ILITIES/ORACLE_LINUX-CVE-2017-15715/        6.8     https://vulners.com/metasploit/MSF:ILITIES/ORACLE_LINUX-CVE-2017-15715/ *EXPLOIT*
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2017-15715/      6.8     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2017-15715/       *EXPLOIT*
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2017-15715/     6.8     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE-2017-15715/      *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2018-1312/        *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2017-15715/      6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2017-15715/       *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2018-1312/        *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2017-15715/      6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2017-15715/       *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2018-1312/       6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2018-1312/        *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2017-15715/      6.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2017-15715/       *EXPLOIT*
|       MSF:ILITIES/FREEBSD-CVE-2017-15715/     6.8     https://vulners.com/metasploit/MSF:ILITIES/FREEBSD-CVE-2017-15715/      *EXPLOIT*
|       MSF:ILITIES/DEBIAN-CVE-2017-15715/      6.8     https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2017-15715/       *EXPLOIT*
|       MSF:ILITIES/CENTOS_LINUX-CVE-2017-15715/        6.8     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2017-15715/ *EXPLOIT*
|       MSF:ILITIES/APACHE-HTTPD-CVE-2017-15715/        6.8     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2017-15715/ *EXPLOIT*
|       MSF:ILITIES/AMAZON_LINUX-CVE-2017-15715/        6.8     https://vulners.com/metasploit/MSF:ILITIES/AMAZON_LINUX-CVE-2017-15715/ *EXPLOIT*
|       MSF:ILITIES/ALPINE-LINUX-CVE-2018-1312/ 6.8     https://vulners.com/metasploit/MSF:ILITIES/ALPINE-LINUX-CVE-2018-1312/  *EXPLOIT*
|       MSF:ILITIES/ALPINE-LINUX-CVE-2017-15715/        6.8     https://vulners.com/metasploit/MSF:ILITIES/ALPINE-LINUX-CVE-2017-15715/ *EXPLOIT*
|       CVE-2020-35452  6.8     https://vulners.com/cve/CVE-2020-35452
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-15715  6.8     https://vulners.com/cve/CVE-2017-15715
|       CVE-2019-10082  6.4     https://vulners.com/cve/CVE-2019-10082
|       MSF:ILITIES/REDHAT_LINUX-CVE-2019-0217/ 6.0     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2019-0217/  *EXPLOIT*
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0217/      6.0     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0217/       *EXPLOIT*
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217
|       EDB-ID:47689    5.8     https://vulners.com/exploitdb/EDB-ID:47689      *EXPLOIT*
|       CVE-2020-1927   5.8     https://vulners.com/cve/CVE-2020-1927
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098
|       1337DAY-ID-33577        5.8     https://vulners.com/zdt/1337DAY-ID-33577        *EXPLOIT*
|       MSF:ILITIES/UBUNTU-CVE-2018-1333/       5.0     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1333/        *EXPLOIT*
|       MSF:ILITIES/UBUNTU-CVE-2018-1303/       5.0     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1303/        *EXPLOIT*
|       MSF:ILITIES/UBUNTU-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2017-15710/       *EXPLOIT*
|       MSF:ILITIES/REDHAT_LINUX-CVE-2020-9490/ 5.0     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2020-9490/  *EXPLOIT*
|       MSF:ILITIES/ORACLE_LINUX-CVE-2020-9490/ 5.0     https://vulners.com/metasploit/MSF:ILITIES/ORACLE_LINUX-CVE-2020-9490/  *EXPLOIT*
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2020-1934/       5.0     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2020-1934/        *EXPLOIT*
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2017-15710/       *EXPLOIT*
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2017-15710/     5.0     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE-2017-15710/      *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-9490/       5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-9490/        *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-9490/       5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-9490/        *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2017-15710/       *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2017-15710/      5.0     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2017-15710/       *EXPLOIT*
|       MSF:ILITIES/FREEBSD-CVE-2020-9490/      5.0     https://vulners.com/metasploit/MSF:ILITIES/FREEBSD-CVE-2020-9490/       *EXPLOIT*
|       MSF:ILITIES/CENTOS_LINUX-CVE-2020-9490/ 5.0     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2020-9490/  *EXPLOIT*
|       MSF:ILITIES/CENTOS_LINUX-CVE-2017-15710/        5.0     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2017-15710/ *EXPLOIT*
|       MSF:ILITIES/APACHE-HTTPD-CVE-2020-9490/ 5.0     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2020-9490/  *EXPLOIT*
|       MSF:ILITIES/AMAZON-LINUX-AMI-2-CVE-2020-9490/   5.0     https://vulners.com/metasploit/MSF:ILITIES/AMAZON-LINUX-AMI-2-CVE-2020-9490/    *EXPLOIT*
|       CVE-2021-33193  5.0     https://vulners.com/cve/CVE-2021-33193
|       CVE-2021-26690  5.0     https://vulners.com/cve/CVE-2021-26690
|       CVE-2020-9490   5.0     https://vulners.com/cve/CVE-2020-9490
|       CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934
|       CVE-2019-17567  5.0     https://vulners.com/cve/CVE-2019-17567
|       CVE-2019-10081  5.0     https://vulners.com/cve/CVE-2019-10081
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220
|       CVE-2019-0196   5.0     https://vulners.com/cve/CVE-2019-0196
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199
|       CVE-2018-17189  5.0     https://vulners.com/cve/CVE-2018-17189
|       CVE-2018-1333   5.0     https://vulners.com/cve/CVE-2018-1333
|       CVE-2018-1303   5.0     https://vulners.com/cve/CVE-2018-1303
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2019-0197/       4.9     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2019-0197/        *EXPLOIT*
|       CVE-2019-0197   4.9     https://vulners.com/cve/CVE-2019-0197
|       MSF:ILITIES/UBUNTU-CVE-2018-1302/       4.3     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1302/        *EXPLOIT*
|       MSF:ILITIES/UBUNTU-CVE-2018-1301/       4.3     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1301/        *EXPLOIT*
|       MSF:ILITIES/REDHAT_LINUX-CVE-2020-11993/        4.3     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2020-11993/ *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-11993/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-11993/       *EXPLOIT*
|       MSF:ILITIES/DEBIAN-CVE-2019-10092/      4.3     https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2019-10092/       *EXPLOIT*
|       MSF:ILITIES/CENTOS_LINUX-CVE-2020-11993/        4.3     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2020-11993/ *EXPLOIT*
|       MSF:ILITIES/APACHE-HTTPD-CVE-2020-11993/        4.3     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2020-11993/ *EXPLOIT*
|       MSF:ILITIES/APACHE-HTTPD-CVE-2019-10092/        4.3     https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2019-10092/ *EXPLOIT*
|       MSF:ILITIES/AMAZON-LINUX-AMI-2-CVE-2020-11993/  4.3     https://vulners.com/metasploit/MSF:ILITIES/AMAZON-LINUX-AMI-2-CVE-2020-11993/   *EXPLOIT*
|       EDB-ID:47688    4.3     https://vulners.com/exploitdb/EDB-ID:47688      *EXPLOIT*
|       CVE-2020-11993  4.3     https://vulners.com/cve/CVE-2020-11993
|       CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092
|       CVE-2018-1302   4.3     https://vulners.com/cve/CVE-2018-1302
|       CVE-2018-1301   4.3     https://vulners.com/cve/CVE-2018-1301
|       CVE-2018-11763  4.3     https://vulners.com/cve/CVE-2018-11763
|       1337DAY-ID-35422        4.3     https://vulners.com/zdt/1337DAY-ID-35422        *EXPLOIT*
|       1337DAY-ID-33575        4.3     https://vulners.com/zdt/1337DAY-ID-33575        *EXPLOIT*
|       MSF:ILITIES/UBUNTU-CVE-2018-1283/       3.5     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1283/        *EXPLOIT*
|       MSF:ILITIES/REDHAT_LINUX-CVE-2018-1283/ 3.5     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2018-1283/  *EXPLOIT*
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2018-1283/       3.5     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2018-1283/        *EXPLOIT*
|       MSF:ILITIES/IBM-HTTP_SERVER-CVE-2018-1283/      3.5     https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE-2018-1283/       *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2018-1283/       3.5     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2018-1283/        *EXPLOIT*
|       MSF:ILITIES/CENTOS_LINUX-CVE-2018-1283/ 3.5     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2018-1283/  *EXPLOIT*
|       CVE-2018-1283   3.5     https://vulners.com/cve/CVE-2018-1283
|       PACKETSTORM:152441      0.0     https://vulners.com/packetstorm/PACKETSTORM:152441      *EXPLOIT*
|       EDB-ID:46676    0.0     https://vulners.com/exploitdb/EDB-ID:46676      *EXPLOIT*
|       1337DAY-ID-663  0.0     https://vulners.com/zdt/1337DAY-ID-663  *EXPLOIT*
|       1337DAY-ID-601  0.0     https://vulners.com/zdt/1337DAY-ID-601  *EXPLOIT*
|       1337DAY-ID-4533 0.0     https://vulners.com/zdt/1337DAY-ID-4533 *EXPLOIT*
|       1337DAY-ID-3109 0.0     https://vulners.com/zdt/1337DAY-ID-3109 *EXPLOIT*
|_      1337DAY-ID-2237 0.0     https://vulners.com/zdt/1337DAY-ID-2237 *EXPLOIT*
33060/tcp open  mysqlx? syn-ack ttl 63
|_banner: \x05\x00\x00\x00\x0B\x08\x05\x1A\x00
| fingerprint-strings:
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp:
|     Invalid message"
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.91%I=7%D=9/8%Time=613973F3%P=x86_64-pc-linux-gnu%r(NU
SF:LL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPOpt
SF:ions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVersi
SF:onBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,2B
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fIn
SF:valid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%
SF:r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\
SF:x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCookie,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\
SF:x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNeg,9,
SF:"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY00
SF:0")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString,9
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x08
SF:\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x
SF:05HY000")%r(LDAPBindReq,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SIPOptions,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,9,"\x05\0\0\0\x0b\x08\x0
SF:5\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NCP,9,"\
SF:x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\0\0\0\x0b\x08\x05\x1a
SF:\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000"
SF:)%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(WMSRequest,9,"\x05\0\0\
SF:0\x0b\x08\x05\x1a\0")%r(oracle-tns,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(
SF:ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(afp,2B,"\x05\0\0\0\x0b\x08
SF:\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x
SF:05HY000")%r(giop,9,"\x05\0\0\0\x0b\x08\x05\x1a\0");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%), Linux 3.7 - 3.10 (92%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=9/8%OT=22%CT=%CU=32350%PV=Y%DS=2%DC=T%G=N%TM=613974BF%P=x86_64-pc-linux-gnu)
SEQ(SP=107%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11NW7%O6=M506ST11)
WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)
ECN(R=Y%DF=Y%T=40%W=F507%O=M506NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 44.234 days (since Mon Jul 26 17:06:24 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 0s
| dns-blacklist:
|   SPAM
|_    l2.apews.org - FAIL
|_dns-brute: Can't guess domain of "10.200.107.33"; use dns-brute.domain script argument.
|_fcrdns: FAIL (No PTR record)
|_ipidseq: All zeros
|_path-mtu: PMTU == 1500
| qscan:
| PORT   FAMILY  MEAN (us)  STDDEV   LOSS (%)
| 22     0       332306.60  4780.36  0.0%
| 80     0       332320.30  1980.42  0.0%
|_33060  0       331512.00  1988.13  0.0%
| traceroute-geolocation:
|   HOP  RTT     ADDRESS        GEOLOCATION
|   1    331.56  10.50.103.1    - ,-
|_  2    331.76  10.200.107.33  - ,-

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   331.56 ms 10.50.103.1
2   331.76 ms 10.200.107.33

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:43
Completed NSE at 22:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:43
Completed NSE at 22:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:43
Completed NSE at 22:43, 0.00s elapsed
Post-scan script results:
| reverse-index:
|   22/tcp: 10.200.107.33
|   80/tcp: 10.200.107.33
|_  33060/tcp: 10.200.107.33
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 253.77 seconds
           Raw packets sent: 107 (10.784KB) | Rcvd: 2590 (2.966MB)
```

</details>





















<br />

---

> Do let me know any command can be improve or you have any question you can contact me via THM message or write down comment below or via FB


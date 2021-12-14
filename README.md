# drwho.sh
Domain, IPv4 &amp; v6 address &amp; network information gathering, web server analysis, DNS- &amp; BGP- related information



_______________________________________________________________________________


 ---------------
  drwho.sh
 ---------------

https://github.com/ThomasPWy/drwho.sh,  Author: Thomas Wy,  Version: 2.0 (Dec 2021)
_______________________________________________________________________________

Installation

No installation, just chmod

_______________________________________________________________________________

Dependencies 

Dependencies (essential): 

curl, dnsutils (installs dig & host), jq, ipcalc, lynx, nmap, openssl, whois


Dependencies (recommended): 

dublin-traceroute, lbd, mtr, netcat, sslscan, testssl, thc-ipv6, tracepath, wfuzz, whatweb

_______________________________________________________________________________

Version 2.O - Bugfixes:

Failure to find responsible internet registry due to changes in the RIPEstat Data API - solved

Lack of information for parent networks of announced prefixes without whois records
(especially in regard to ARIN) - most likely solved.

Results for RIPE are perfectly ok. Due to lack of testing of their depressing database,
it is currently unknown how this issue manifests when searching LACNIC's whois records.

_______________________________________________________________________________

Additions to Version 2

Changed menu structure from numbering to a more intuitive alphabetical order

Improved readability, especially for DNS lookups

IPv4 Ping Sweep with free combination of protocols and destination ports (support for ICMP, TCP, UDP and SCT)

Local network enumeration using broadcasts (ARP & DHCP/RIP2/OSPF2 discover broadcasts) and
service version scans (including BACNET,KNX & Modbus)

Plain abuse contact finder for quick lookups

Whois - address space/BGP consistency checks for autonomous systems & networks

A dedicated option for IP-reputation/blocklisting checks (input: IPv4 addresses/networks),
querying the superb Grey Noise API (community version only), Project Honeypot, Stop Forum Spam and most common
DNS blocklists (barracuda central, uceprotect, spamhaus etc.)

Ditching dig and host in favour of the surprisingly fast Nmap for IPv4 network reverse DNS lookups
More detailed BGP und ROA status information

MX records / mail server SSL testing using openSSL und SSLscan

Load balancing detection using lbd (suboption of option d) - domain recon)

_______________________________________________________________________________

Complete List of Options


  Object/Target Categories

   a)  Abuse Contact Finder
  as)  ASN
  bl)  IP Reputation & Blocklist Check (IPv4-Networks & -Hosts)
   d)  Domain Recon
 dns)  DNS, NS- & MX Servers
   g)  Rev. GoogleAnalytics Search
   i)  Network Interfaces & Public IP
  ip)  Hosts (IPv4/IPv6/Hostname)
  ix)  Internet Exchange (IX)
   l)  LAN
   n)  Networks
   p)  Port Scanning
   t)  Tracerouting
   w)  Whois (inverse, organization- & bulk lookup options)
 www)  Web Server


 Options > AUTONOMOUS SYSTEMS 

 [1]  AS & Announced Prefixes Summary
 [2]  AS Details
 [3]  Announced Prefixes
 [4]  AS Peers
 [5]  Whois <> Address Space Consistency Check


 Options > DNS 

 [1]  Domain DNS Records
 [2]  Shared Name Servers
 [3]  Zone Transfer, Zone Walk
 [4]  Name Server Health Check
 [5]  MX SSL Status & Ciphers
 [6]  dig Batch Mode (Mass DNS Lookup) 
 
 
 Options > IP ADDRESS INFORMATION  (IPV4)

 [1]  Hostname / IPv4 Address Overview (Geolocation, DNS, Prefix, Whois Summary)
 [2]  Customize Options (e.g. Banners, IP Reputation, Contact or Network Details)
 [3]  Send TestPing via hackertarget.com API (API key required)
 [4]  Virtual Hosts
 [b]  Back to the Global Options Menu
 
 
 Options > IP ADDRESS INFORMATION  (IPV6)

 [1]  IP Address Info (Geolocation, RDNS, Prefix BGP Status, Whois Summary)
 [2]  IP Address Info, Whois Contact Details
 [3]  THC-Ping6 ICMPv6/TCP Packet Builder 


  Options > Look up Host Information by Host Name  (IPV4)

 [1]  Hostname/IP Overview (Geolocation, DNS, Prefix, Whois Summary)
 [2]  Customize Options (e.g. Banners, WhatWeb, Certificates (via certspotter), Whois Contact Details)


. Options > LOCAL NETWORKS (IPv4)  

 [1]  Send ARP Broadcast (Host Discovery)
 [2]  Send DHCP Discover Broadcast
 [3]  Send RIP2 Discover Broadcast
 [4]  Send OSPF2 Discover Broadcast
 [5]  Discover Network & SCADA Services (NMAP)


 Options > NETWORKS

 [1]  Network Summary (Whois, BGP- & RPKI Status)
 [2]  Generate Network Report  (IPv4) 
 [3]  Customize Options (e.g. BGP-Whois Consistency, Geolocoation, Related Networks, Contact Details)
 [4]  Prefix Address Space (More Specifics/Subnets)
 [5]  Reverse DNS Lookup
 [6]  Reverse IP Lookup (Virtual Hosts)  (IPv4)
 [8]  Ping Sweep  (IPv4) 


Options > WEB SERVERS 

 [1]  Quick Health Check  (Ping, SSL (Ciphers, Basic Vulners), Response & Page-Loading-Times, Security Headers, Website Hash)
 [2]  Customize Test Options (Vulnerabilities, SSL Configs, Connectivity & Server Response)
 [3]  Website Overview (Contacts,Content,Markip)
 [4]  Dump HTTP Headers
 [5]  Dump SSL Certificate Files


 Options > WHOIS 

 [1] RIPE|AFRINIC|APNIC >  Organisations, Networks & PoCs (inverse & regular searches)
 [2] ARIN               >  Organisations, Networks & PoCs
 [3] pwhois.org         >  Org & NetBlock Searches
 [4] pwhois.org         >  Whois Bulk Lookup (file input)


 Options > NMAP PORT SCANS

 [p1]  Port-, OS/Version- & Vulnerability Scans 
 [p2]  Port Scan via hackertarget.com IP (hackertarget.com IP API, IPv4 support only)
 [p3]  Firewalk & TCP Flags 


 Options > TRACEROUTING & MTU DISCOVERY 

 [t1]  NMAP              Path-MTU Discovery 
 [t2]  Tracepath         (traceroute & MTUs, non-root) 
 [t3]  MTR               (RT-Times, Packet Loss, Jitter; TCP,UDP,ICMP) 
 [t4]  MTR               (hackertarget.com IP API, IPv4 support only)
 [t5]  Nmap              (TCP Traceroute & MaxMind Geolocation Data) 
 [t6]  atk-trace6        (ICMPv6 Traceroute MTU- & Tunnel-Discovery) 
 [t7]  Dublin Traceroute (NAT-aware, Multipath Tracerouting) 
 [b]                     Back to the Global Options Menu

 *    Additional Options > t1), t3), t6) ROA Validation, Geolocation & whois Summary for each Hop



















 





 
 

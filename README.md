# drwho.sh

extensive rewrite of the drwho.sh script;
bug fixes, improved output formatting, nmap-output in grepable format, 
more features for RIPE inverse search, better IPv6 support;
most options now allow input of individual targets or target lists for bulk queries



DEPENDENCIES

Necessary: curl, dnsutils, lynx, jq, ncat, nmap, openssl, testssl, ipcalc, mtr, sipcalc, thc-ipv6, whois-client

Recommended: dublin-traceroute, tracepath (iputils-tracepath, bzw. inetutils-tracepath), wfuzz whatweb 

FEATURES

Information about domains & websites 
(whois, DNS records, subdomains, address ranges, networks, administrative contacts,
webserver service banners, HTTP methods, ciphersuites, CMS & cookie-flags, website title & description, 
social media links; automated dump of headers, robots.txt, hyperlinks, certificate files & whois lookup results)

Webserver & -site diagnostics 
(traceroute, response- & round-trip times, page-loading times, SSL & TCP handshake details, 
supported ciphersuites & HTTP methods, XXS & SSL vulnerabilities

Information about IPv4 & v6 Addresses 
(IP geolocation, service banners, virtual hosts, dns delegation, network details, blacklisting & threatfeeds, 
service provider, network, AS) 

Information about Networks, BGP Prefixes & Autonomous Systems
(Owner, contacts, geographic distribution, reverse DNS consistency, blacklisting, network upstreams, 
reverse DNS and reverse IP, network service banners, AS name, country, contact, announced prefixes, 
IX-memberships, peering & transit)

Enumeration of Networks & Address Ranges belonging to an organisation via RIPE inverse search, bgpview.io ORG-search & BGP prefixes 

MX, NS & DNS Zone information (smtp & imap methods, blacklisting, DNS records, 
DNS lookup delegation tracing, zone configs, zone transfers, soa record comparison, BIND version, shared name servers)

Nmap Port & Vulnerability Scans
Traceroute (MTR Traceroute, NAT-aware tracerouting using dublin-traceroute, tracepath)
ICMPv6 Ping, IPv4 Ping Sweep, ARP Broadcasts

Most option support bulk queries (input via textfile) as well as individual targets

Menu Structure

1) Domain Enumeration

    Domain Webhost, DNS Records, SSL Info & Certificates, Subdomains, Networks, Prefixes, Owners, Contacts

 2) Name Server & DNS Lookup Options 

 22)  DNS Records
 23)  dig Batch Mode (Bulk Lookup)
 24)  Shared Name Servers
 25)  Zone Walk & Zone Transfer

 3) Whois & BGP Related Options 

 31)  Domain whois Status
 32)  Bulk whois Lookup (pwhois.org)
 33)  Inverse Lookup & Object Search (RIPE, APNIC, AFRINIC)
 34)  Prefix Address Space Enumeration
 35)  ARIN Network & PoC Search
 36)  Org & NetBlock Searches (pwhois.org)
 37)  AS Information, BGP Prefixes, Peering & Transit
 38)  IX Information

      LACNIC Whois Lookups are supported in Options 44), 45), 66), 67)
      Use Options 33)-35) to search for address ranges & network owner contacts

 4) IPv4 Hosts & Networks 

 44)  IPv4 Hosts > Whois Geolocation, Blocklists, Banners, VHost
 45)  IPv4 Nets  > Whois, Geolocation, Routing Consistency
 46)  IPv4 Nets  > Reverse DNS, VHosts & Banners
 47)  IPv4 Nets  > Network Blocklists Check
 p4)  IPv4 Nets  > NMAP Ping Sweep

 5) Reverse GoogleAnalytics Search

 6) IPv6 Addresses & Networks 

 66)  IPv6 Hosts > Whois, Geolocation, DNS Delegation
 67)  IPv6 Nets  > Whois, Geolocation, DNS Delegation
 68)  IPv6 Nets  > Reverse DNS Lookup
 69)  Subdomain Bruteforcing (IPv4 & IPv6)
 p6)  thc-atk6 ICMPv6 Packets Builder
 t6)  thc-atk6 IPv6 Traceroute (MTU- & Tunnel Discovery) & RPKI Validation

 7) Webservers 

 77)  Webserver Information & Diagnostics (Connectivity- & SSL-Issues, Vulnerabilities)
 78)  Dump Certificates, Hyperlinks, HTTP Headers, robots.txt

 i) Manage target interaction

    Allow direct target interaction (default) or 
    avoid revealing your IP address by working with whois Lookups & API calls only

 p) Port Scans & Ping

 p1)  NMAP Port-, Version- & Vulnerability Scans
 p2)  NMAP Port Scan (hackertarget.com API, IPv4) 
 p3)  NPING (hackertarget.com API, IPv4)
 p4)  NMAP Ping Sweep (IPv4)
 p5)  NMAP Firewalk & Alternative Scanflags
 p6)  thc-atk6 ICMP6 Packets Builder

 t) Tracerouting, MTU Discovery, RPKI Validation

 t1)  Path MTU Discovery (Nmap, ICMP/TCP)
 t2)  Tracepath (IPv4 & v6, MTU Discovery, ICMP only, non-root)
 t3)  MTR (Traceroute, RT-Times, Packet Loss; IPv4, IPv6, TCP,UDP,ICMP)
 t4)  NMAP Geo Traceroute (ICMP, TCP)
 t5)  Dublin Traceroute (NAT-aware, Multipath Tracerouting, ICMP only)
 t6)  atk-trace6 ICMPv6 Traceroute (MTU- & Tunnel-Discovery)
      Additional Option: 53), 54), 56) RPKI Validation, ISP, Contact, Geolocation & whois Summary for each Hop



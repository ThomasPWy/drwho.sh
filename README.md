# drwho.sh

APIs used in drwho.sh

BGPview ASN, Prefix & IX APIs
https://bgpview.docs.apiary.io/#
https://bgpview.io/contact

https://dns.bufferover.run 
(https://github.com/erbbysam/DNSGrep ; source of data: Rapid7 Labs,  https://opendata.rapid7.com/about/)

hackertarget.com IP Tools (without membership, API calls are limited to 50/day)
hackertarget.com 

ip-api.com
(https://ip-api.com/docs/legal)

ipapi.co
https://ipapi.co/

RIPEstat Data API
(https://stat.ripe.net/docs/data_api)

SANS Internet Storm Center IP- API
(https://isc.sans.edu/api/ip/)


WHOIS SERVERS used in drwho.sh

pwhois.org  
shadowserver.org
whois.cymru.com 
registry whois servers (whois.afrinic.net, whois.apnic.net, whois.arin.net, whois.ripe.net)


DEPENDENCIES

Necessary: curl, dnsutils, lynx, jq, ncat, nmap, openssl, testssl, ipcalc, mtr, sipcalc, thc-ipv6, whois-client

Recommended: dublin-traceroute, tracepath (iputils-tracepath, bzw. inetutils-tracepath), whatweb 

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

MX, NS & DNS Zone information (smtp & imap methods, blacklisting, DNS records, 
DNS lookup delegation tracing, zone configs, zone transfers, soa record comparison, BIND version, shared name servers)

Nmap Port & Vulnerability Scans
Traceroute (MTR Traceroute, NAT-aware tracerouting using dublin-traceroute, tracepath)
ICMPv6 Ping, IPv4 Ping Sweep, ARP Broadcasts

Most option support bulk queries (input via textfile) as well as individual targets




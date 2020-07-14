# drwho.sh
A humble bash script, designed to remove the clutter from the output of dig, openssl, whois, etc. 

Dependencies:

curl 
dnsutils
lynx
iputils-tracepath (tracepath in Termux) 
openssl (openssl & openssl-tool in Termux) 
any whois client


Options for Domains:

  11)   Website Overview
        (headers summary, IP, CMS, title- & content tags, social media links)
  12)   A,AAAA,MX,NS,PTR,SOA & TXT records
  13)   certificate information & -files
  
  14)   whois lookup options
             41) host whois & reverse whois summary
  	         42)  MX reverse whois summary
  	         43)  SOA reverse  whois summary
  15)   geolocation options (ext.API)
  	         51)  host geolocation
             52)  MX record geolocation
             53)  SOA record geolocation
             
  16)   server response times & tracepath
  17)   HTTP headers
  18)   robots.txt / link dump
  19)   zone transfer check
  20)   address block reverse host search
  21)   subdomain enumeration (ext.API)
  22)   reverse IP lookup (ext.API)
  
  
  
  Options for IPv4 Addresses

  31)   dns & whois reverse lookup
  32)   target geolocation (ext. API)
  33)   HTTP headers summary & website title
  34)   server response times & tracepath
  35)   server certificates
  36)   HTTP headers
  37)   link dump
  38)   address block reverse host search
  39)   reverse IP lookup (ext. API)

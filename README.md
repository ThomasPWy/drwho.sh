# drwho.sh
A humble bash script, designed to remove the clutter from the output of dig, openssl, whois, etc. 

Dependencies:
curl, dnsutils, lynx, iputils-tracepath (or 'tracepath', e.g. in Termux), openssl (openssl & openssl-tool in Termux), whois (any whois client should work)

This script has no relation to either the British Broadcasting Company or their beloved TV series, Dr Who. 
Feel free to use, change or share the script. Any suggestions, esp. regarding bash syntax, are highly appreciated.

For commercial usage please check the terms & conditions of the external APIs.
For more information visit:
### https://ipapi.co ### https://hackertarget.com ### https://crt.sh ###


       Global Menu

   1)  SET TARGET DOMAIN
   2)  SET TARGET IP
   3)  DOMAIN OPTIONS
   4)  IP OPTIONS
   5)  ASN QUERY (ext. API)
   0)  QUIT
   

	Options for Domains

  11)   website overview
        (headers summary, IP, CMS, title- & content tags, social media links)
  12)   A,AAAA,MX,NS,PTR,SOA & TXT records
  13)   domain whois & reverse whois lookup
  14)   whois lookup options
  15)   server certificates
  16)   IP geolocation (ext.API)
  17)   HTTP headers / robots.txt / link dump
  18)   IPv4 address block host search
  19)   subdomain enumeration options (ext.APIs)
  20)   AS information (ext. API)
  21)   reverse IP lookup (ext.API)
  22)   zone transfer check
  23)   server response times & tracepath

  

	Options for IPv4 Addresses
	
  31)   dns & whois reverse lookup
  32)   HTTP headers summary & website title
  33)   server certificates
  34)   IP geolocation (ext. API)
  35)   HTTP headers / link dump
  36)   IPv4 address block reverse host search
  37)   AS information (ext. API)
  38)   reverse IP lookup (ext. API)
  39)   server response times & tracepath

# drwho.sh
A humble bash script, designed to remove the clutter from the output of dig, openssl, whois, etc. 

Dependencies:
curl, dnsutils, lynx, iputils-tracepath (tracepath in Termux), openssl (openssl & openssl-tool in Termux), whois (any whois client should work)

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
  13)   certificate information
  14)   whois lookup options
  		41)  host whois & reverse whois summary
  		42)  'First' MX* record reverse whois summary
  		43)  SOA record reverse whois summary
  15)   geolocation options (ext.API)
  		51)  host geolocation
  		52)  'First' MX* record geolocation
  		53)  SOA record geolocation
  16)   HTTP headers / robots.txt / link dump
  		61)  HTTP headers
  		62)  robots.txt
  		63)  linkdump
  17)   subdomain enumeration - options (ext.APIs)
		71)  search with hackertarget.com
		72)  search with crt.sh
  18)   address block reverse host search - options
  		81)  domain host address block reverse host search
  		82)  MX* record- address block reverse host search - 
  		83)  SOA- record address block reverse host search - 202.12.27
  		84)  custom- address block reverse host search
  19)   reverse IP lookup (ext.API)
  20)   zone transfer check
  21)   server response times & tracepath

*Results are given for the MX record that comes first in either priority or alphabetical order

	Options for IPv4 Addresses

  31)   dns & whois reverse lookup
  32)   target geolocation (ext. API)
  33)   HTTP headers summary & website title
  34)   certificate information & -file
  35)   server response times & tracepath
  36)   HTTP headers
  37)   link dump
  38)   address block reverse host search
  39)   reverse IP lookup (ext. API)




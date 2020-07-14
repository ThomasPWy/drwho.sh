# drwho.sh
A humble bash script, designed to remove the clutter from the output of dig, openssl, whois, etc. 

Dependencies:
curl, dnsutils, lynx, iputils-tracepath (tracepath in Termux), openssl (openssl & openssl-tool in Termux), whois (any whois client should work)


       Global Menu

   1)  SET TARGET DOMAIN
   2)  SET TARGET IP
   3)  DOMAIN OPTIONS
   4)  IP OPTIONS
   5)  ASN QUERY (ext. API)
   0)  QUIT
   

	Options for Domains

  11)   Website Overview
        (headers summary, host IP, CMS, title- & content tags, social media links)      
  12)   A,AAAA,MX,NS,PTR,SOA,SRV & TXT records
  13)   certificate information & -file
  14)   whois lookup options 	   
               41)  host whois & reverse whois summary
               42)  'First' MX record reverse whois summary*
               43)  SOA record reverse whois summary
  15)   geolocation options (ext.API)
               51)  host geolocation
               52)  'First' MX record geolocation*
               53)  SOA record geolocation           
  16)   server response times & tracepath
  17)   HTTP headers
  18)   robots.txt / link dump
               61)  robots.txt
               62)  linkdump         
  19)   zone transfer check
  20)   address block reverse host search - options
               71)  host address block reverse host search
               72)  custom- address block reverse host search	         
  21)   subdomain enumeration (ext.API)
  22)   reverse IP lookup (ext.API)

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




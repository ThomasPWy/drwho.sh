
# drwho.sh
A humble bash script, designed to remove the clutter from the output of dig, openssl, whois, etc. 

Dependencies:
curl, dnsutils, lynx, iputils-tracepath (or 'tracepath', e.g. in Termux), nmap, openssl (openssl & openssl-tool in Termux), a whois client 

This script has no relation to either the British Broadcasting Company or their beloved TV series, Dr Who. 
Feel free to use, change or share the script. Any suggestions, esp. regarding bash syntax, are highly appreciated.

For commercial usage please check the terms & conditions of the external APIs.
For more information visit:

### https://ipapi.co ### https://hackertarget.com ### 



   a)  SET TARGET
   s)  OPTIONS (IPv4)
   d)  OPTIONS (DOMAINS)
   p)  PORT SCAN & PING SWEEP
   q)  QUIT

   ?  a
----------------------------------------------------------------------

 Set Target DOMAIN or IP

  >>  github.com

 Save output? [y] | [n] n

----------------------------------------------------------------------

   >> Target: github.com - 140.82.121.3 

   1)  website overview          11)  certificates
   2)  DNS records               12)  AS Info
   3)  resp.times,tracepath      13)  IP geolocation (ext.API)
   4)  shared NS (ext.API)       14)  whois
   5)  subdomains (ext.API)      15)  IP address block host search
   6)  zone transfer             16)  reverse IP lookup (ext.API)
   0)  MAIN MENU                 17)  headers, robots.txt, link dump


----------------------------------------------------------------------

   >> Target: 140.82.121.3

  11)  certificates              15)  IP address block host search
  12)  AS Info                   16)  reverse IP lookup (ext.API)
  13)  IP geolocation (ext.API)  17)  headers, robots.txt, link dump
  14)  whois options             21)  resolve ip
   0)  MAIN MENU                 22)  website overview
   q)  QUIT                      23)  resp.times,tracepath



   12)  AS Info
  122)  github.com AS Information (whois.pwhois.org lookup)
  123)  custom IP AS Information (whois.pwhois.org lookup)
  
  
  13)  IP geolocation (ext.API)
  31)  github.com geolocation
  32)  custom IP/domain geolocation
  
  
  14)  whois
  41)  github.com whois & reverse whois lookup
  42)  custom IP/domain whois & reverse whois lookup
  

  15)  IP address block host search  
  51)  github.com IPv4 address block host search
  52)  custom IPv4 address block host search


  17)  headers, robots.txt, link dump
  71)  HTTP headers
  72)  robots.txt
  73)  link dump






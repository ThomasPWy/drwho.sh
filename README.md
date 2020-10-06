
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

----------------------------------------------------------------------

OPTIONS (DOMAINS)

   1)  website overview    
       (server status, HTTP headers summary, A & AAAA- records, website title, AS-information (via pwhois lookup), 
       IP geolocation (via ip-api.co), certificate date of expiry, subject & issuer, website description, 
       social media & contact links
       
   2)  DNS records       
       (host A, AAAA & PTR records, SOA record, MX priorities, NS & MX records, 
        A & AAAA records for NS & MX, host SRV & TXT records)
   3)  server response times, tracepath 
       (server response times via curl, option to run tracepath)
    
   4)  shared name servers (via hackertarget.com)         
       prints out results from hackertarget.com about domains sharing a specific name server   
       
   5)  subdomains (via hackertarget.com)   
   
   6)  zone transfer   
       uses dig to try zone transfers with all name servers listed in the target domain's NS records
       
  11)  certificates
       uses openssl to request certificate information and extracts date of expiry, subject common name, org and country, 
       name, org & country of issuer, TLS version, the ciphersuite used during the connection, public key algo & 
       key length, as well as root CA name, org & country; allows to save certificate files retrieved by openssl 
       
  12)  AS Info
       122)  current target AS Information (whois.pwhois.org lookup)
       123)  custom IP AS Information (whois.pwhois.org lookup)
       Uses whois lookup at pwhois.whois.org to retrieve information about given AS 
       
  13)  IP geolocation (via ip-api.co)
       31)  current target geolocation
       32)  custom IP/domain geolocation
       
  14)  whois
       41)  current target whois & reverse whois lookup
       42)  custom IP/domain whois & reverse whois lookup
       Performs a whois (summary) & reverse whois lookup for a given domain 
       
  15)  IP address block host search
       51)  current target IPv4 address block host search
       52)  custom IPv4 address block host search
       Takes an IPv4 address prefix (last octett removed) as input and 
       looks up PTR records for all hosts within /24 address block
       
  16)  reverse IP lookup (via hackertarget.com)
       Asks hackertarget.com's API for hosts sharing a common IPv4 address
       
  17)  headers, robots.txt, link dump
       71)  HTTP headers
       72)  robots.txt
       73)  link dump
       
  
   0)  MAIN MENU                    


----------------------------------------------------------------------

OPTIONS (IPv4 ADDRESSES)

  11)  certificates               
  12)  AS Info                     
  13)  IP geolocation (ext.API)   
  14)  whois options                
  15)  IP address block host search
  16)  reverse IP lookup (ext.API)
  17)  headers, robots.txt, link dump
  21)  resolve ip
  22)  website overview
  23)  resp.times,tracepath
  0)  MAIN MENU             
                       



  

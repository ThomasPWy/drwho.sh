#!/bin/bash
#************ Variables  ***********
#************ COLORS & TEXT FORMATTING ***********
B='\e[34m'
D='\e[0m'
GREY='\e[90m'
GREEN='\e[32m'
R='\e[31m'
Y='\e[33m'
IT='\e[3m'
YIT='\e[3;33m'
BBG='\e[44m'
white=$'\e[97m'
blue=$'\e[94m'
default=$'\e[0m'
#************ TEMPORARY WORKING DIRECTORY ***********
tempdir="${PWD}/drwho_temp"
out="${PWD}/drwho_temp"
#************ REGEX ***********
REGEX_IP4="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
#************ API KEYS ***********
api_key_ht=''
#************ OTHER ***********
target="none"
option_connect="1"
conn="${GREEN}true${D}"
report="false"
web_ports="20,21,22,23,80,111,135,443,1433,1434,3306,8000,8009,8080,8090"
#************ BLACKLISTS ***********
blacklists="
all.s5h.net
all.spamrats.com
apache.bl.blocklist.de
b.barracudacentral.org
bogons.cymru.com
bruteforcelogin.bl.blocklist.de
dnsbl-1.uceprotect.net
dnsbl-2.uceprotect.net
dnsbl-3.uceprotect.net
dnsbl.darklist.de
dyn.nszones.com
ftp.bl.blocklist.de
imap.bl.blocklist.de
images.rbl.msrbl.net
ips.backscatterer.org
mail.bl.blocklist.de
netscan.rbl.blockedservers.com
phishing.rbl.msrbl.net
proxies.dnsbl.sorbs.net
rbl.realtimeblacklist.com
recent.spam.dnsbl.sorbs.net
relays.dnsbl.sorbs.net
rep.mailspike.net
sip.bl.blocklist.de
spam.pedantic.org
ssh.bl.blocklist.de
talosintelligence.com
torexit.dan.me.uk
zen.spamhaus.org
zombie.dnsbl.sorbs.net
"
#************* startmenu with global options  ******************
function f_startMenu {
  echo -e "\n  a)  ADD NEW FOLDER"
  echo -e "  s)  SET MAIN TARGET"
  echo "  o)  OPTIONS"
  echo "  c)  CLEAR SCREEN"
  echo "  q)  QUIT"
}

echo -e " ${B}
  ____                _           
 |  _ \ _ ____      _| |__   ___  
 | | | | '__\ \ /\ / / '_ \ / _ \ 
 | |_| | |   \ V  V /| | | | (_) |
 |____/|_|    \_/\_/ |_| |_|\___/ 
 ${D}"
 echo -e "\033[3;39m  \"whois the Doctor? Who? Dr Who?\" ${D}\n"
f_startMenu

#************ create temporary working directory *************
function f_makeNewDir {
if [ -d $tempdir ]; then
rm -rf $tempdir ; mkdir $tempdir ; else
mkdir $tempdir ; fi
}
#************ delete temporary working directory *************
function f_removeDir {
if [ -d $tempdir ]; then
rm -rf $tempdir ; fi
}
function f_CONNECT {
if [ $option_connect = "9" ] ; then
echo -e " ${B}Connect >  ${R}FALSE${D}" ; else
echo -e " ${B}Connect >  ${GREEN}TRUE${D}" ; fi
}
function f_optionTarget {
if ! [ $(echo $target | wc -w) = "1" ] ; then
echo "none" ; else
echo "$target" ; fi
}
#************ separators (solid, dashed) *************
function f_solidGrey {
 echo -e "${GREY}____________________________________________________________________________${D}"
}
function f_solidLong {
echo -e "\n____________________________________________________________________________\n"
}
function f_solidShort {
echo -e "_________________________________________________________\n"
}
function f_solidShorter {
echo -e "________________________________\n"
}
function f_solidShortest {
echo -e "__________\n"
}
function f_dashedGrey {
echo -e "${GREY}------------------------------------------------------------------------------${D}"
}
#************ menu *************
function f_Menu {
  f_dashedGrey
  echo -e "\n  ${B}Domain  >  $(f_optionTarget)  $host_ip"
  echo -e "  ${B}Connect >  $conn"
  echo -e "  ${B}Folder  >  $dirname${D}\n"
  echo -e "  ${B}1)${D}  Target Webpresence             ${B}11)${D}  Web Servers"
  echo -e "  ${B}2)${D}  DNS Records, Subdomains        ${B}12)${D}  NS- & Mail Servers"
  echo -e "  ${B}3)${D}  whois & BGP                    ${B}13)${D}  phwois Bulk Lookup"
  echo -e "  ${B}4)${D}  IPv4                           ${B}14)${D}  dig Batch Mode"
  echo -e "  ${B}5)${D}  SSL/TLS & SSH                  ${B} p)${D}  PORT SCANS, ICMP & ARP"
  echo -e "  ${B}6)${D}  IPv6                           ${B} t)${D}  Traceroute"
  echo -e "  ${B}7)${D}  Rev. Google Analytics Search   ${B} m)${D}  MAIN MENU"
  echo -e "  ${B}i)${D}  Manage target interaction"
}
#*********** banner for output file *************
function f_textfileBanner {
    echo -e "\n\n ---------------"
    echo -e "  drwho.sh"
    echo -e " ---------------"
    echo -e "\nAuthor - Thomas Wy, Feb 2021\n"
    echo -e "https://github.com/ThomasPWy/drwho.sh \n"
    echo -e "DATETIME  > $(date) \n"
}
#*********** fancy text box (https://unix.stackexchange.com/a/70616) ************
function f_BOX {
        local s="$*"
      echo -e "\n ${white}╭─${s//?/─}─╮
 │ ${blue}${s}${white} │
 ╰─${s//?/─}─╯"
        tput sgr 0
}
function f_BOX_BANNER {
local s="$*"
curl -s http://ip-api.com/json/${s}?fields=54738911 > $tempdir/geo.json
whois -h whois.cymru.com -- "-v -f ${s}" > $tempdir/cymru.txt
country=`jq -r '.country' $tempdir/geo.json`
as=`cut -d '|' -f 1 $tempdir/cymru.txt | sed 's/^ *//'`
echo '' ; f_BOX " ${s} - $country - AS $as " ; echo ''
}
function f_OUTPUT_HEADER {
local s="$*" ; echo -e "\n   [ ${s} ] " >> ${output} 
}
function f_WARNING {
echo -e "\n${R} Warning >${D} This option requires sending packets to target systems!"
echo -e "\nPlease deactivate safe mode via options a) or s)."
echo -e "\n${R}${IT}Aborting...${D}"
}
#*********** get A & AAAA records *************
function f_aRecord {
local s="$*"
dig ${s} +short
echo -e "---------------"
host -t aaaa ${s} | cut -d ' ' -f 3-
echo ''
}
#*************************** whois ***************************
function f_REGISTRY {
local s="$*"
whois_registry=`whois -h whois.cymru.com -- "-r -f ${s} " | cut -d '|' -f 3 | sed 's/^ *//'`
if   [ $whois_registry = "ripencc" ] ; then
     registry_server="whois.ripe.net"
elif [ $whois_registry = "arin" ] ; then
     registry_server="whois.arin.net"
elif [ $whois_registry = "apnic" ] ; then
     registry_server="whois.apnic.net"
elif [ $whois_registry = "lacnic" ] ; then
     registry_server="whois.lacnic.net"
elif [ $whois_registry = "afrinic" ] ; then
     registry_server="whois.afrinic.net"
else
echo -e "\n ${R}No registry found${D} \n"
fi
export registry_server=`echo $registry_server`
export whois_registry=`echo $whois_registry`
whois -h ${registry_server} ${s} > $tempdir/whois.txt
}
function f_revWHOIS {
cat $tempdir/whois.txt | sed 's/^% Abuse/Abuse/' |  sed '/^#/d' | sed '/^%/d' | sed '/inject:/d' |
sed '/\*/d' | sed '/[Cc]omment:/d' | sed -r '/^\s*$/d' | sed '/ResourceLink:/d' | sed '/please/d' |
sed '/mnt-domains:/d' | sed '/mnt-ref:/d' | sed '/Ref:/d' | sed '/NetType:/d' | sed '/org-type:/d' |
sed '/Parent:/d' | sed '/[Rr]emarks/d' | sed '/[Ff]ax/d' | sed '/PostalCode:/d' |
sed '/mnt-irt:/d' | sed '/irt:/d' | sed '/tech-c:/d' | sed '/StateProv:/d' | sed '/OrgTech/d' | sed "/^[[:space:]]*$/d" |
sed 's/inetnum/\ninetnum/' | sed 's/organisation/\norganisation/' | sed 's/role/\nrole/' | sed 's/person/\nperson/' |
sed 's/route/\nroute/' | sed 's/OrgName/\nOrgName/' | sed 's/OrgNOCHandle:/\nOrgNOCHandle:/' |
sed 's/OrgAbuseHandle:/\nOrgAbuseHandle:/' > $tempdir/rev_whois.txt
if [ $whois_registry = "arin" ] ; then
sed -n '/NetRange/,/Updated/p'  $tempdir/rev_whois.txt | sed 's/OriginAS/\nOriginAS/'
echo -e "\n---------------------------------------------\n"
sed -n '/OrgName/,/Updated/p' $tempdir/rev_whois.txt
echo -e "\n---------------------------------------------\n"
sed -e '/./{H;$!d;}' -e 'x;/OrgNOCName:/!d;' $tempdir/rev_whois.txt
sed -e '/./{H;$!d;}' -e 'x;/OrgAbuseName:/!d;' $tempdir/rev_whois.txt
else
sed -n '/inetnum/,/source/{/source/!p}' $tempdir/rev_whois.txt | sed '/netname/G' | sed '/org:/d'
sed -n '/source/,/route/{/route/!p}' $tempdir/rev_whois.txt | sed '/tech-c:/d' |
sed '/abuse-mailbox/d' | sed '/phone/d' | sed '/e-mail/d' | sed '/created/d'  > $tempdir/ripe.txt
sed -n 'H; /^organisation:/h; ${g;p;}' $tempdir/ripe.txt |
sed -n '/organisation:/,/source:/{/source:/!p}' |
sed '/organisation:/i \\n---------------------------------------------\n'
sed -n 'H; /^role/h; ${g;p;}' $tempdir/ripe.txt  | sed -n '/role/,/source/p' | grep 'role:\|address:' |
sed '/role:/i \\n---------------------------------------------\n'
sed -n 'H; /^person/h; ${g;p;}' $tempdir/ripe.txt  | sed -n '/person/,/source/p' | grep 'person:\|address:\|nic-hdl:' |
sed '/person:/i \\n---------------------------------------------\n'
sed -n 'H; /^route:/h; ${g;p;}' $tempdir/rev_whois.txt | sed -n '/route:/,/source:/p' | sed '/origin/G' |
sed 's/AS/AS /' | sed '/route:/i \\n---------------------------------------------\n'
echo -e "\n---------------------------------------------\n"
echo -e "Contact:\n"
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/rev_whois.txt | sort | uniq
grep -i -w -m 2 "phone" $tempdir/rev_whois.txt | sed 's/phone://' | sed 's/^ *//' ; echo ''
fi
}
function f_whoisLOOKUP {
local s="$*"
whois ${s} > $tempdir/whois_lookup.txt
cat $tempdir/whois_lookup.txt | sed '/^#/d' | sed '/^%/d' | sed '/icann.org/d' | sed '/NOTICE/d' |
sed '/reflect/d' | sed '/Fax:/d' |sed '/Fax Ext:/d' | sed '/unsolicited/d' | sed '/HKIRC-Accredited/d' |
sed '/how to/d' | sed '/queried/d' | sed '/Bundled/d' | sed '/Registry Domain ID:/d' | sed 's/^ *//' |
sed "/^[[:space:]]*$/d"  > $tempdir/host-whois.txt
grep -w -i -A 1 -m 1 "domain name:" $tempdir/host-whois.txt> $tempdir/whois2.txt
grep -w -i "Domain:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -w -i "Registry Domain ID:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -w -m 1 -A 1 "Registrar:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -w "Nserver:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -w -i -s "Status:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -w -s "Changed:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -w "Company Chinese name:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -w -m 1 "Registrar URL:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -w -m 1 "Registrar Abuse Contact Email:"  $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -w "Registry Creation Date:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -w -s "Last Modified:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -i "Expiry" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -w -m 1 "registrar:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -w -m 1 "e-mail:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -w -m 1 "website:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -w -i -A 8 "nic-hdl:" $tempdir/host-whois.txt  >> $tempdir/whois2.txt
echo '' >> $tempdir/whois2.txt
grep -s -w -i -m 1 "Organization:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i -m 1 "Registrant Name:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i -m 1 "Country:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i -m 1 "State/Province" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i -m 1 "Address:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i -m 1 "Registrant Street:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i -m 1 "Registrant City:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i -m 1 "Registrant Postal Code:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i -m 1 "Registrant Phone:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i -m 1 "Registrant Email:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -B 1 -A 16 "ADMINISTRATIVE" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w "Registrant:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i "Eligibility Type:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -w "Name Server:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i "dnssec:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i -m 1 "source:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
cat $tempdir/whois2.txt | sed '$!N; /^\(.*\)\n\1$/!P; D' | sed 's/nic-hdl:/\nnic-hdl:/' |
sed 's/Registrant:/\nRegistrant:/' | sed 's/Administrative/\nAdministrative/' |
sed 's/Technical/\nTechnical/' | fmt -w 80 -s > $tempdir/host-whois2.txt
}
#************************** SSL/TLS  *********************
function f_certInfo {
local s="$*"
echo | timeout 3 openssl s_client -connect ${s}:443 -brief 2> $tempdir/brief.txt
echo | timeout 3 openssl s_client -connect ${s}:443 2>$out/CERTIFICATE.${s}.txt | openssl x509 -text -fingerprint >> $out/CERTIFICATE.${s}.txt
echo | timeout 3 openssl s_client -connect ${s}:443 2>/dev/null | openssl x509 -text -fingerprint -ocspid > $tempdir/x509.txt
echo | timeout 3 openssl s_client -connect ${s}:443 2>/dev/null -status > $tempdir/status.txt
grep -m 1 '0 s:*' $tempdir/status.txt | cut -d ':' -f 2- | sed 's/ = /=/g' > $tempdir/subject.txt
grep -m 1 -A 1 '0 s:*' $tempdir/status.txt | grep -i -w 'i:*' | cut -d ':' -f 2- | sed 's/ = /=/g' > $tempdir/issuer.txt
subject_cn=`grep -m1 -Po 'CN=\K.*' $tempdir/subject.txt | cut -d '=' -f 2-`
subject_org=`grep -oP '(O=).*?(?=,)' $tempdir/subject.txt | sed 's/O=/ |  /'`
subject_c=`grep -oP '(C=).*?(?=,)' $tempdir/subject.txt | sed 's/C=/ |  /'`
issuer_cn=`grep -m1 -Po 'CN=\K.*' $tempdir/issuer.txt | cut -d '=' -f 2-`
issuer_org=`grep -oP '(O=).*?(?=,)' $tempdir/issuer.txt | sed 's/O=/ |  /'`
issuer_c=`grep -oP '(C=).*?(?=,)' $tempdir/issuer.txt |  sed 's/C=/ |  /'`
verify=`grep -i 'Verification:' $tempdir/brief.txt | cut -d ' ' -f 2- | sed 's/^ *//'`
protocol=`grep -i 'Protocol version' $tempdir/brief.txt | cut -d ':' -f 2- | sed 's/^ *//'`
cipher=`grep -i -w 'Ciphersuite' $tempdir/brief.txt | cut -d ':' -f 2- | sed 's/^ *//'`
pubkey=`cat $tempdir/x509.txt | grep -i -m 1 -A 2 'public' | sed '/Info/d' |  sed '/Algorithm:/d'  | sed 's/Public-Key//' |
sed 's/ : //' | sed 's/^ *//g'`
echo -e "\n\nVerification:     $verify"
echo -e "\nIssued:           $(grep -i -w 'Not Before' $tempdir/x509.txt | cut -d ':' -f 2- | sed 's/^ *//')"
echo -e "Valid until:      $(grep -i -w 'Not After' $tempdir/x509.txt | cut -d ':' -f 2- | sed 's/^ *//')"
echo -e "\nSubject:          $subject_cn $subject_org $subject_c"
echo -e "Hash:             $(grep -i 'Hash used:' $tempdir/brief.txt | cut -d ':' -f 2- | sed 's/^ *//')"
echo -e "\nIssuer:           $issuer_cn $issuer_org $issuer_c"
echo -e "\n\nCipher            $cipher"
echo -e "\nProtocol:         $protocol"
echo -e "\nSubject PubKey:   $pubkey"
echo -e "Server TempKey:   $(grep -i -w 'Server Temp Key:' $tempdir/brief.txt | cut -d ':' -f 2- | sed 's/^ *//')"
echo '' ; grep 'Fingerprint' $tempdir/x509.txt | sed 's/=/: /' | sed 's/^ *//'
echo -e "\n---------------------------------------\n"
echo -e "OSCP:\n"
grep -w -i -o "no response sent"  $tempdir/status.txt
grep -i -w 'OCSP Response Status:' $tempdir/status.txt | sed 's/OCSP/\nOCSP/'
grep -i -w 'Cert Status:' $tempdir/status.txt | sed 's/^ *//'
echo '' ; grep 'OCSP - URI' $tempdir/x509.txt | cut -d ':' -f 2- | sed 's/^ *//'
grep 'Subject OCSP hash:' $tempdir/x509.txt | sed 's/Subject/\nSubject/' | sed 's/^ *//'
grep 'Public key OCSP hash:' $tempdir/x509.txt | sed 's/^ *//'
echo -e "\n---------------------------------------\n"
echo -e "Certificate Chain (not verified):\n"
grep -w -i -m1 -A1 '0 s:*' $tempdir/status.txt | cut -d ':' -f 2- ; echo ''
grep -w -i -m1 -A1 '1 s:*' $tempdir/status.txt| cut -d ':' -f 2- ; echo ''
grep -w -i -m1 -A1 '2 s:*' $tempdir/status.txt | cut -d ':' -f 2-
}
function f_BANNERS {
local s="$*"
curl -s https://api.hackertarget.com/bannerlookup/?q=${s}${api_key_ht} > $tempdir/banners.json
jq -r '.' $tempdir/banners.json  | tr -d '{""}' | tr -d ',[]' | sed 's/^ *//' | sed "/^[[:space:]]*$/d" |
sed '/ip:/i \\n___\n' > $tempdir/banners.txt ; echo '' >> $tempdir/banners.txt 
cat $tempdir/banners.txt 
}
function f_RevDNS {
local s="$*"
curl -s https://api.hackertarget.com/reversedns/?q=${s}${api_key_ht} > $tempdir/out_revdns.txt
cat $tempdir/out_revdns.txt | sed 's/ / => /'  | awk '{print $1 "\t" $2 "\t" $3}' > $tempdir/revdns.txt
echo '' ; cat $tempdir/revdns.txt ; echo ''
}
function f_RevIP {
local s="$*"
curl -s https://api.hackertarget.com/reverseiplookup/?q=${s}${api_key_ht} > $tempdir/out_revip.txt
sort -t ',' -k 2 -V  $tempdir/out_revip.txt | sed 's/,/ => /'  | awk '{print $3 "\t" $2 "\t" $1}' > $tempdir/revip.txt
echo '' ; cat $tempdir/revip.txt ; echo ''
}
function f_VHOSTS {
local s="$*" ; echo -e "[+] ${s} Virtual Hosts\n"
curl -s https://api.hackertarget.com/reverseiplookup/?q=${s}${api_key_ht}
echo ''
}
function f_hostSearch {
for i in `seq 1 254` ; do sublist="$sublist ${prefx}.$i" ; done
for i in $sublist ; do
ptr=`host $i $nsserv | cut -d ' ' -f 5` ; echo -e "$i\t=>\t$ptr" | sed '/NXDOMAIN/d' ; done ; echo ''
}

#******************** Webpresence *****************************
function f_headers {
local s="$*"
awk '{ IGNORECASE=1 } /HTTP|Location|Server|Cloudflare|Strict-Transport-Security|Varnish|Cache-Control|X-Powered-By|X-Generator|X-Redirect-By|X-Server-Instance-Name|X-Frame-Options|X-Content-Type-Options|X-Permitted-Cross-Domain-Policies|X-XSS-Protection|P3P/ { print }' $out/HEADERS.${s}.txt |
sed 's/HTTP/\nHTTP/' | sed '/[Ll]ink:/d' | sed '/[Rr]eport-[Tt]o:/d' | sed '/[Cc]ontent-[Ss]ecurity-[Pp]olicy:/d' | sed '/[Ff]eature-[Pp]olicy:/d' | sed '/permissions-policy:/d' |
sed '/[Ee]-[Tt]ag:/d' | sed '/expect-ct:/d' | fmt -w 70 -s
}
function f_socialLinks {
local s="$*"
if ! type lynx &> /dev/null; then
echo "Please install lynx"; else
echo -e "\n[+] ${s} LINK DUMP\n\n" > $out/LINK_DUMP.${s}.txt
timeout 3 lynx -accept_all_cookies -dump -listonly -nonumbers www.${s} > $tempdir/linkdump.txt  
sort -f -u $tempdir/linkdump.txt >> $out/LINK_DUMP.${s}.txt
grep -i -F -econtact -ediscord -ekontakt -efacebook -egithub -einstagram -elinkedin -epinterest -etwitter -exing -eyoutube  $out/LINK_DUMP.${s}.txt |
sed '/sport/d' | sed '/program/d' > $tempdir/social.txt
grep -i -F -etelefon: -etelefon -etel -etel: -efon -efon: -ephone: -ephone -emailto: $out/LINK_DUMP.${s}.txt | sed 's/mailto:/\nmailto:/' |
sed 's/mailto://' > $tempdir/contacts.txt ; fi
curl ${s}/contact -sLk > $tempdir/page.txt
curl ${s}/jobs -sLk >> $tempdir/page.txt
curl ${s}/karriere -sLk >> $tempdir/page.txt
curl ${s}/kontakt -sLk >> $tempdir/page.txt
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/src.txt | sed '/*.png/d' | sed '/*.jpg/d' | sed '/*.jpeg/d' >> $tempdir/contacts.txt
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/page.txt >> $tempdir/contacts.txt
grep -oP '(Email\[).*?(?=])' $tempdir/ww.txt | sed 's/Email\[//' | tr -d '][' | sed 's/,/\n/g' |  sed 's/^ *//' >>  $tempdir/contacts.txt
echo -e "\n\n[+] E-Mail\n"
sort -f -u $tempdir/contacts.txt
echo -e "\n\n[+] Social Media & Contact Links\n"
sort -f -u $tempdir/social.txt
}
function f_linkDump {
local s="$*"
if ! type lynx &> /dev/null; then
echo "Please install lynx" ; else
echo -e "\n[+] $s LINK DUMP\n" > $out/LINK_DUMP.${s}.txt
lynx -accept_all_cookies -dump -listonly www.${s} | tee -a $out/LINK_DUMP.$s.txt ; fi ; echo ''
}
function f_WHATWEB {
local s="$*"
if [ $option_connect = "9" ] ; then
curl -s https://api.hackertarget.com/whatweb/?q=${s}${api_key_ht} > $tempdir/ww.txt ; else
if ! type whatweb &> /dev/null; then
curl -s https://api.hackertarget.com/whatweb/?q=${s}${api_key_ht} > $tempdir/ww.txt ; else
whatweb --no-errors --color=never ${s} > $tempdir/ww.txt ; fi ; fi
}
function f_WHATWEB_REDIR {
cut -d ']' -f 1  $tempdir/ww.txt | sed '/http/ s/$/]/' | sed '/^$/d' ; echo ''
grep -oP '(IP\[).*?(?=])' $tempdir/ww.txt  | tail -1  | sed 's/^ *//' | sed 's/IP\[/  >> /' | tr -d ']['
}
function f_WHATWEB_PAGE {
echo -e "\n[+] Title\n" ; grep -oP '(Title\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/Title\[//' |
tr -d ']' | tail -1 | sed 's/^ *//'
grep -oP '(Meta-Author\[).*?(?=,)' $tempdir/ww.txt | tr -d ']' | sed 's/Meta-Author\[/\n\n [+] Author\n\n/' | sed 's/^ *//'
if ! [ $option_connect = "9" ] ; then
echo -e "\n\n[+] Description\n"
cat $tempdir/src.txt | grep -w -A 1 "meta" | sed 's/^ *//' > $tempdir/meta.txt
cat $tempdir/meta.txt | tr -d '"' | tr -d '<' | tr -d '>' | tr -d '/' |sed '/meta name=description content=/!d' |
sed 's/meta/\nmeta/g' > $tempdir/content.txt
cat $tempdir/content.txt | sed '/meta name=description content=/!d' | sed 's/meta name=description content=//' |
sed 's/&#039;s/s/' | sed 's/link//' | sed 's/meta name=twitter:card//' | sed 's/rel=canonical//' | sed 's/href/\nhref/' |
sed 's/meta property=og:type//' | sed 's/\!--/\n\!--/' | sed '/\!--/d' | sed '$!N; /^\(.*\)\n\1$/!P; D' | sed 's/^ *//' |
sed 's/title/\ntitle/' | sed '/name=theme-color/d' | sed '/href=*/d' | sed 's/&amp;/\&/' | fmt -w 70 -s ; else
echo -e "\n[+] E-Mail\n" ; grep -oP '(Email\[).*?(?=])' $tempdir/ww.txt | sed 's/Email\[//' | tr -d '][' |
sed 's/,/\n/g' |  sed 's/^ *//' ; fi
}
function f_WHATWEB_CODE {
echo ''
grep -oP '(HTTPServer\[).*?(?=,)' $tempdir/ww.txt | sort -u  | sed 's/HTTPServer\[/Server: /' | sed 's/\]/ /'
grep -oP '(Via\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/Via\[/Via:     /' | tr -d ']['
grep -oP '(Via-Proxy\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/Via-Proxy\[/Proxy: /' | tr -d ']['
echo ''
grep -oP '(Open-Graph-Protocol\[).*?(?=\])' $tempdir/ww.txt | sort -u  | sed 's/\[/: /' | tr -d ']'
grep -o -w 'HTML[4-5]' $tempdir/ww.txt | sort -u | sed '/HTML*/{x;p;x;}'
grep -o -w 'XHTML[1-4]' $tempdir/ww.txt | sort -u | sed '/XHTML*/{x;p;x;}'
grep -o -w 'Frame' $tempdir/ww.txt | tail -1
grep -o -w 'YouTube' $tempdir/ww.txt | tail -1
grep -oP '(Script\[).*?(?=\])' $tempdir/ww.txt | sed 's/Script\[//' | tr -d '][' | sed 's/^ *//'
grep -oP '(JQuery\[).*?(?=\])' $tempdir/ww.txt | sort -u | tr -d '][' | sed 's/^ *//'
grep -oP '(MetaGenerator\[).*?(?=,)' $tempdir/ww.txt | sort -u | sed 's/MetaGenerator\[//' | tr -d '][' | sed 's/^ *//'
grep -oP '(PoweredBy\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/\[/: /' | tr -d ']['
grep -oP '(X-Powered-By\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/\[/: /' | tr -d ']['
grep -oP '(probably).*?(?=,)' $tempdir/ww.txt | sort -u
grep -o -i -w -m 1 'WordPress' $tempdir/ww.txt 
grep -oP '(PasswordField\[).*?(?=\])' $tempdir/ww.txt | sed 's/PasswordField\[/PasswordField:  /' | tr -d ']' 
grep -oP '(WWW-Authenticate\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/\[/:  /' | tr -d ']['
grep -oP -m 1 '(Content-Language\[).*?(?=\])' $tempdir/ww.txt | sed 's/Content-Language\[/Language: /' | tr -d ']'
grep -oP '(Strict-Transport-Security\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/: /' | tr -d ']['
grep -oP '(X-Frame-Options\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/\[/:  /' | tr -d ']['
grep -oP '(X-XSS-Protection\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/:  /' | tr -d ']['
grep -oP '(HttpOnly\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/\[/:  /' | tr -d ']['
grep -oP '(Cookies\[).*?(?=\])' $tempdir/ww.txt | sort -u  | sed 's/\[/:  /' | tr -d ']['
grep -oP '(X-UA-Compatible\[).*?(?=\])' $tempdir/ww.txt | sort -u  | sed 's/\[/: /' | tr -d ']'
grep -oP '(UncommonHeaders\[).*?(?=,)' $tempdir/ww.txt | sort -f -u | sed 's/UncommonHeaders\[/Uncommon Headers:\n\[ /' | tr -d '][' | sed 's/^ *//'
grep -oP '(Google-Analytics\[).*?(?=,)' $tempdir/ww.txt | sed 's/Google-Analytics\[/\nGoogle-Analytics:\n\[ /' | tr -d '][' | sed 's/^ *//'
}

#********************** Blacklists & Threadfeeds  *****************************
function f_ISC_Feeds {
mindate=`grep 'mindate' $tempdir/isc.txt | cut -d ':' -f 2- | sed 's/^ *//'`
maxdate=`grep 'maxdate' $tempdir/isc.txt | cut -d ':' -f 2- | sed 's/^ *//'`
echo -e "_______________________\n" ; echo -e "[+] IP Threatfeed (ISC)\n"
echo -e "Attacks:        $(grep 'attacks' $tempdir/isc.txt | cut -d ':' -f 2- | sed 's/^ *//')"
echo -e "Time:           $mindate - $maxdate"
sed -n '/threatfeeds/,$p' $tempdir/isc.txt | sed 's/^ *//'
}
function f_BLACKLISTS {
local s="$*"
echo -e "[+] DNS Blocklists\n" ; echo -e " [ $s ] \n"
reverse=$(echo ${s} | sed -ne "s~^\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)$~\4.\3.\2.\1~p")
for i in ${blacklists} ; do
in_list="$(dig @1.1.1.1 +short -t a ${reverse}.${i}.)"
if [[ $in_list ]]; then
echo -e "${R}YES${D} (${in_list}) | ${i}" ; else
echo -e "NO | ${i}" ; fi ; done
}
function f_RIPE_BLACKLIST {
local s="$*"
f_solidShorter ; echo -e "[+]  Blacklist Info (RIPEstat)\n" ; echo -e " [ $s ] "
curl -s https://stat.ripe.net/data/blacklist/data.json?resource=${s} > $tempdir/ripestat_blackl.json
jq -r '.data.sources[]' $tempdir/ripestat_blackl.json | tr -d ']},\":[{' | sed 's/^ *//' | sed '/^$/d' |
sed '/prefix/i \\n______\n' | sed '/timelines/{x;p;x;}' | sed '/starttime/{x;p;x;}' 
}

#********************** RIPEstat API  *****************************
function f_RIPE_CHAIN {
local s="$*"
echo -e "[+] PTR & Authoritative Nameservers\n"
curl -s https://stat.ripe.net/data/dns-chain/data.json?resource=${s} > $tempdir/chain.json
jq -r '.data.forward_nodes' $tempdir/chain.json | tr -d '{}]/":[}' | sed '/^$/d' | sed 's/^[ \t]*//' | head -1
echo '-' ; jq -r '.data.authoritative_nameservers[]' $tempdir/chain.json
}
function f_DELEGATION {
local s="$*" 
echo -e "[+]  DNS Delegation  (${s})\n\n"
curl -s https://stat.ripe.net/data/reverse-dns/data.json?resource=${s} > $tempdir/revd.json
jq -r '.data.delegations[]' $tempdir/revd.json | grep -A1 'domain\|descr\|nserver' | tr -d '\":,' |
grep 'value' | sed 's/value//' | sed 's/^ *//'
}
function f_NETGEO {
local s="$*" ; curl -s https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${s} > $tempdir/netloc.json
echo '' ; jq -r '.data.located_resources[]' $tempdir/netloc.json | tr -d '[{\",}]' | sed 's/^[ \t]*//' |
sed '/./!d' | sed '/country:/i __________\n'
}
#**************************** BGP View API *********************************
function f_AS_Description {
local s="$*"
curl -s https://api.bgpview.io/asn/${s} > $tempdir/asn.json
traffic=`jq -r '.data.traffic_estimation' $tempdir/asn.json | sed 's/null/-/'`
ratio=$(jq -r '.data.traffic_ratio'  $tempdir/asn.json | sed 's/null/-/')
as_descr=` jq -r '.data.description_full' $tempdir/asn.json | tr -d '["]' | sed '/^$/d' | sed 's/^ *//'`
alloc_date=`jq -r '.data.rir_allocation.date_allocated' $tempdir/asn.json`
rir_name=`jq -r '.data.rir_allocation.rir_name' $tempdir/asn.json`
echo -e "As Num:          ${s}"
echo -e "AS Name:         $(jq -r '.data.name' $tempdir/asn.json) "
echo -e "\nDescription:     $as_descr"
echo -e "Allocation:      $alloc_date  ($rir_name)"
echo -e "AS Country:      $(jq -r '.data.country_code' $tempdir/asn.json)"
echo -e "___________\n"
echo -e "[+] Traffic\n"
echo -e "$ratio  $traffic"
echo -e "________________\n"
echo -e "[+] LookingGlass\n"
jq -r '.data.looking_glass'  $tempdir/asn.json
echo -e "\n______________\n"
echo -e "[+] AS Contact\n"
jq -r '.data.owner_address[]' $tempdir/asn.json
echo ''
jq -r '.data.email_contacts[]' $tempdir/asn.json
jq -r '.data.website'  $tempdir/asn.json
echo '' ; f_solidShort ;
echo -e "[+] IX Memberships\n"
curl -s https://api.bgpview.io/asn/${s}/ixs | jq | sed -n '/data/,/@meta/{/data/!{/@meta/!p;}}' |
tr -d ',[{"}]' | sed 's/^ *//' | sed 's/name_full/full name/' | sed 's/country_code:/country:/'
}
function f_BGPview_PEERS {
curl -s https://api.bgpview.io/asn/$as/peers > $tempdir/peers.json
echo -e "\n\n${B}AS $as IPv4 Peers${D}\n"
echo -e "\n== AS $as PEERS ==\n" >> $out/AS.$as.txt
echo -e " Date: $(date)\n" >> $out/AS.$as.txt
echo -e "\n== IPv4 PEERS ==\n" >> $out/AS.$as.txt
jq -r '.data.ipv4_peers[] | {ASN: .asn, Name: .name, Desc: .description, Loc: .country_code}' $tempdir/peers.json |
tr -d '{",}' | tee -a $out/AS.$as.txt
echo -e "\n\n${B}AS $as IPv6 Peers${D}\n" ; echo -e "\n== AS $as IPv6 PEERS ==\n" >> $out/AS.$as.txt
jq -r '.data.ipv6_peers[] | {ASN: .asn, Name: .name, Desc: .description, Loc: .country_code}' $tempdir/peers.json |
tr -d '{",}' | tee -a $out/AS.$as.txt ; echo -e "\n\n Source > bgpview.io\n" | tee -a $out/AS.$as.txt
}
function f_BGPview_UPSTREAMS {
curl -s https://api.bgpview.io/asn/$as/upstreams > $tempdir/ups.json
echo -e "\n[+] AS $as IPv4 Upstreams\n\n"
jq -r '.data.ipv4_upstreams[] | {ASN: .asn, Name: .name, Desc: .description, Loc: .country_code}' $tempdir/ups.json |
tr -d '{",}' | sed 's/^ *//' 
f_solidShorter
echo -e "[+] AS $as IPv6 Upstreams \n\n"
jq -r '.data.ipv6_upstreams[] | {ASN: .asn, Name: .name, Desc: .description, Loc: .country_code}' $tempdir/ups.json |
tr -d '{",}' | sed 's/^ *//'
}
function f_BGPview_DOWNSTREAMS {
curl -s https://api.bgpview.io/asn/${as}/downstreams > $tempdir/downs.json
echo -e "\n[+] AS $as IPv4 Downstreams\n"
jq -r '.data.ipv4_downstreams[] | {ASN: .asn, Name: .name, Desc: .description, Loc: .country_code}' $tempdir/downs.json |
tr -d '{",}' | sed 's/^ *//' 
f_solidShorter ; echo -e "[+] AS $as IPv6 Downstreams\n"
jq -r '.data.ipv6_downstreams[] | {ASN: .asn, Name: .name, Desc: .description, Loc: .country_code}' $tempdir/downs.json |
tr -d '{",}' | sed 's/^ *//'
}
function f_BGPviewPREFIXES {
curl -s https://api.bgpview.io/asn/${as}/prefixes  > $tempdir/prefixes.json
if [ $option_prefix = "1" ] ; then
echo -e "\n\n--- IPV6 ---\n" ; jq -r '.data.ipv6_prefixes[].prefix' $tempdir/prefixes.json
echo -e "\n\n--- IPV4 ---\n" ; jq -r '.data.ipv4_prefixes[].prefix' $tempdir/prefixes.json ; else 
echo -e "\n\n[+] IPv6 Prefixes\n\n"
jq -r '.data.ipv6_prefixes[] | .prefix, .name, .description, .country_code' $tempdir/prefixes.json | sed 'n;n;n;G'
echo -e "\n_________________\n" ; echo -e "[+] IPv4 Prefixes\n\n"
jq -r '.data.ipv4_prefixes[] | .prefix, .name, .description, .country_code' $tempdir/prefixes.json | sed 'n;n;n;G' ; fi
}
function f_BGPviewORG {
curl -s https://api.bgpview.io/search?query_term=$input  > $tempdir/org.json
jq -r -c '.data.asns[] | {ASN: .asn, n: .name , C: .country_code , M: .abuse_contacts[0]}' $tempdir/org.json |
tr -d '{",}' | sed 's/ASN://' | sed 's/n:/    /' | sed 's/C:/, /'|  sed 's/M:/     /'
echo -e "\n_________________\n" ; echo -e "[+] IPv6 Prefixes\n\n"
jq -r '.data.ipv6_prefixes[] | .prefix, .name, .description, .country_code' $tempdir/org.json | sed 'n;n;n;G;'
echo -e "\n_________________\n" ; echo -e "[+] IPv4 Prefixes\n\n"
jq -r '.data.ipv4_prefixes[] | .prefix, .name, .description, .country_code' $tempdir/org.json | sed 'n;n;n;G;'
}
function f_BGPviewIX {
curl -s https://api.bgpview.io/ix/${ixid} | jq | tr -d ',[{"}]' | sed 's/^ *//' > $tempdir/bgp-ix.txt
sed -n '/data:/,/members_count:/p' $tempdir/bgp-ix.txt | sed '/data:/d' | sed '/name_full/G' |
sed 's/name_full/full name/' | sed 's/country_code/country/' | sed 's/ipv4_address/ipv4/' |
sed 's/ipv6_address/ipv6/' | tee -a $out/IX.$ixid.txt
echo -e -n "\n\nShow members?  [y] | [n]  " ; read answer
if [ $answer = "y" ] ; then
sed -n '/members/,/meta/p' $tempdir/bgp-ix.txt | sed 's/members:/\n\nmembers:/' | sed '/members_count/d' |
sed '/@meta/d' | sed 's/country_code/country/' | sed 's/ipv4_address/ipv4/' | sed 's/ipv6_address/ipv6/' |
tee -a $out/IX.$ixid.txt ; else
echo '' ; fi
}
function f_ASabuseC {
local s="$*"
if [ $whois_registry = "ripencc" ] ; then 
whois -h whois.ripe.net -b as$as | grep -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" > $tempdir/abusec.txt 
elif [ $whois_registry = "afrinic" ] ; then 
whois -h whois.afrinic.net -b as$as | grep -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" > $tempdir/abusec.txt 
elif [ $whois_registry = "apnic" ] ; then 
whois -h whois.apnic.net -b as$as | grep -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" > $tempdir/abusec.txt 
elif [ $whois_registry = "lacnic" ] ; then 
whois -h whois.lacnic.net -b as$as | grep -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" > $tempdir/abusec.txt ; else 
whois -h whois.arin.net a $as > $tempdir/AS.txt
grep -m1 'OrgAbuseEmail:' $tempdir/AS.txt | grep -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" > $tempdir/abusec.txt ; fi 
}
function f_DNS_CONS4 {
local s="$*"
echo -e "[+] Reverse DNS Consistency  (${s})\n\n"
curl -s https://stat.ripe.net/data/reverse-dns-consistency/data.json?resource=${s} > $tempdir/dns.json
jq -r '.data.prefixes.ipv4' $tempdir/dns.json | grep 'complete' | tr -d ',\"' | sed 's/^ *//' | sed '/complete/G' 
jq -r '.data.prefixes.ipv4' $tempdir/dns.json | grep 'prefix\|found' | tr -d '],\"[' | cut -d ':' -f 2- | tr -d ' ' 
}
function f_DNS_CONS6 {
local s="$*"
echo -e "[+] Reverse DNS Consistency  (${s})\n\n"
curl -s https://stat.ripe.net/data/reverse-dns-consistency/data.json?resource=${s} > $tempdir/dns.json
jq -r '.data.prefixes.ipv6' $tempdir/dns.json | grep 'complete' | tr -d ',\"' | sed 's/^ *//' | sed '/complete/G' 
jq -r '.data.prefixes.ipv6' $tempdir/dns.json | grep 'prefix\|found' | tr -d '],\"[' | cut -d ':' -f 2- | tr -d ' ' 
}

function f_NETINFO {
local s="$*"
net=`echo "$s" | rev | cut -d '/' -f 2- | rev`
prefix=`cut -d '|' -f 3 $tempdir/cymru.txt | tr -d ' '`
if [ $whois_registry = "arin" ] ; then
netname=`grep -m 1 '^Net-Name:' $tempdir/p_full.txt  | cut -d ':' -f 2- | sed 's/^ *//'`
netrange=`grep -m 1 '^Net-Range:' $tempdir/p_full.txt  | cut -d ':' -f 2- | sed 's/^ *//'`
cidr=`grep -m 1 '^CIDR:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
elif [ $whois_registry = "lacnic" ] ; then
netname=`grep -m 1 '^inetrev:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'`
cidr=`grep -m 1 '^inetnum:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'`
else 
netname=`grep -m 1 '^netname:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'`
if [[ ${net} =~ $REGEX_IP4 ]] ; then
inetnum=`grep -m 1 '^inetnum:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'` ; else 
cidr=`grep -m 1 '^inet6num:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'` ; fi ; fi
if [ $type_net = "false" ] ; then
if cat $tempdir/p_full.txt | grep -q -E "^Geo-"; then
city="Geo-City:"
cc="Geo-Country-Code:" ; else
city="City:"
cc="Country-Code:" ; fi
org_cc=`grep -m1 -E "${cc}" $tempdir/p_full.txt | cut -d ':' -f 2- | sed 's/^ //'`
org_city=`grep -m1 -E "${city}" $tempdir/p_full.txt | cut -d ':' -f 2- | sed 's/^ //'` ; fi 
if [ $type_net = "true" ] ; then
echo -e "[+] ${s}\n\n" ; else 
echo -e "[+] Network \n\n" ; fi 
echo -e "Net-Name:       $netname"
if [[ ${net} =~ $REGEX_IP4 ]] ; then
if [ $whois_registry = "arin" ] ; then
echo -e "Net-Range       $netrange" 
echo -e "CIDR:           $cidr"
elif [ $whois_registry = "lacnic" ] ; then
echo -e "CIDR:           $cidr" ; else 
echo -e "Net-Range       $inetnum" ; fi ; else 
echo -e "CIDR:           $cidr" ; fi
echo -e "\nAllocated:      $(cut -d '|' -f 6 $tempdir/cymru.txt | sed 's/^ *//' | tr -d ' ') ($whois_registry)"
echo -e "BGP Prefix:     $(cut -d '|' -f 3 $tempdir/cymru.txt | tr -d ' ')"
echo -e "__________\n" ; echo -e "[+] Owner\n"
if [ $whois_registry = "arin" ] ; then
orgname=`grep -m 1 '^Org-Name:' $tempdir/p_full.txt  | cut -d ':' -f 2- | sed 's/^ *//'`
orgid=`grep -m1 '^Org-ID:' $tempdir/p_full.txt  | cut -d ':' -f 2- | sed 's/^ *//'`
abuse_contact=`grep -m 1 '^Abuse-0-Email:' $tempdir/p_full.txt  | cut -d ':' -f 2- | sed 's/^ *//'` ; fi 
if [ $type_net = "false" ] ; then
jq -r '.org' $tempdir/geo.json > $tempdir/org.txt 
grep '^org-name:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//' >> $tempdir/org.txt 
grep -m 1 '^Organization:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//' >> $tempdir/org.txt 
grep -m 1 '^owner:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//' >> $tempdir/org.txt 
grep -w -m 1 '^Org-Name:' $tempdir/p_full.txt | cut -d ':' -f 2- | sed 's/^ *//' >> $tempdir/org.txt 
sort -f -u $tempdir/org.txt | sed '/^$/d'
if [ $whois_registry = "arin" ] ; then
echo "$orgid" ; fi 
echo -e "Branch: $org_city $org_cc" ; else 
if [ $whois_registry = "arin" ] ; then
echo "$orgname" ; echo "orgid" 
elif [ $whois_registry = "lacnic" ] ; then
grep -m 1 '^owner:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//' ; else
grep '^org-name:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//' > $tempdir/org.txt 
grep -w -m 1 '^Org-Name:' $tempdir/p_full.txt | cut -d ':' -f 2- | sed 's/^ *//' >> $tempdir/org.txt 
sort -f -u $tempdir/org.txt
grep '^org:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'
grep -m 1 '^country:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//' ; fi ; fi 
if [ $whois_registry = "arin" ] ; then
echo "$abuse_contact"
elif [ $whois_registry = "lacnic" ] ; then
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt | grep 'abuse\|noc' | sort -f -u
else 
grep -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt ; fi
}

function f_DRWHO {
local s="$*"
net=`echo "$s" | rev | cut -d '/' -f 2- | rev`
f_REGISTRY "${s}" ; echo -e "\n\n[+] ${s}\n" >> $out/WHOIS.txt
f_revWHOIS > $tempdir/who.txt ; f_revWHOIS >> $out/WHOIS.txt ; f_solidLong >> $out/WHOIS.txt
whois -h whois.pwhois.org type=all ${s} > $tempdir/p_full.txt
prefix=`cut -d '|' -f 3 $tempdir/cymru.txt | tr -d ' '`
as=`cut -d '|' -f 1 $tempdir/cymru.txt | sed 's/^ *//' | tr -d ' '`
if [ $type_net = "false" ] ; then
curl -s https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${s} > $tempdir/ac.json
if [ $whois_registry = "ripencc" ] ; then
less_sp=$(jq -r '.data.less_specifics[0]' $tempdir/ac.json)
curl -s https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${less_sp} > $tempdir/lsloc.json ; fi 
if [ $option_server = "y" ] ; then
echo -e "\n__________\n"
echo -e "[+] Server\n"
echo -e "IP:          $(jq -r '.query' $tempdir/geo.json)"
echo -e "PTR:         $(jq -r '.reverse' $tempdir/geo.json)"
echo -e "\nProxy:       $(jq -r '.proxy' $tempdir/geo.json)" ; else
echo -e "\n_________\n"
echo -e "[+] Host\n"
echo -e "IP:          $(jq -r '.query' $tempdir/geo.json)"
echo -e "PTR:         $(jq -r '.reverse' $tempdir/geo.json)"
echo -e "\nMobile:      $(jq -r '.mobile' $tempdir/geo.json)"
echo -e "Proxy:       $(jq -r '.proxy' $tempdir/geo.json)" ; fi
if [[ ${s} =~ $REGEX_IP4 ]] ; then
curl -s -L https://isc.sans.edu/api/ip/${s}?text | tr -d '(][)' | sed 's/ =>/: /' | sed 's/Array//' | sed 's/^[ \t]*//' | sed '/^$/d' |
sed '1,1d' > $tempdir/isc.txt
echo -e "Cloud:       $(grep -s 'cloud:' $tempdir/isc.txt | cut -d ':' -f 2- | sed 's/^ *//')" ; fi
echo -e "Hosting:     $(jq -r '.hosting' $tempdir/geo.json)"
echo -e "\n_____________\n"
echo -e "[+] Location\n"
echo -e "Country:      $(jq -r '.country' $tempdir/geo.json) ($(jq -r '.countryCode' $tempdir/geo.json))"
echo -e "City:         $(jq -r '.city' $tempdir/geo.json)"
echo -e "\nRegion:       $(jq -r '.regionName' $tempdir/geo.json)"
echo -e "Timezone:     $(jq -r '.timezone' $tempdir/geo.json)"
echo -e "Lat.,Lon.:    $(jq -r '.lat' $tempdir/geo.json), $(jq -r '.lon' $tempdir/geo.json)"
echo -e "\n________\n"
echo -e "[+] ISP\n"
jq -r '.isp' $tempdir/geo.json
if [[ ${s} =~ $REGEX_IP4 ]] ; then
f_ISC_Feeds ; echo -e "\n\n[+] Network Blacklist Summary (uceprotect)\n"
jq -r '.data.blacklist_info[] | .list, .entries' $tempdir/ac.json ; else 
echo -e "\n____________________________________\n" ; f_RIPE_CHAIN "${s}"
echo -e "\n___________________\n" ; f_DELEGATION "${s}" ; fi 
f_solidShort ; fi ; f_NETINFO ${s}
if [ $type_net = "false" ] && [ $whois_registry = "ripencc" ] ; then
echo -e "\n__________________\n" ; echo -e "[+] Less specifics\n"
echo "$less_sp"
curl -s https://stat.ripe.net/data/reverse-dns-consistency/data.json?resource=${less_sp} > $tempdir/nets.json
if [[ ${s} =~ $REGEX_IP4 ]]; then
jq -r '.data.prefixes.ipv4' $tempdir/nets.json | grep 'prefix' | tr -d ',\"' | cut -d ':' -f 2- | tr -d ' ' ; else
jq -r '.data.prefixes.ipv6' $tempdir/nets.json | grep 'prefix' | tr -d ',\"' | cut -d ':' -f 2- | tr -d ' ' ; fi
fi
f_solidShort ; echo -e "[+] Origin AS \n\n"
whois -h whois.cymru.com -- "-v -f as$as" > $tempdir/cymru_as.txt 
echo -e "AS Num:        $as" 
echo -e "AS Name:       $(cut -d '|' -f 5 $tempdir/cymru_as.txt | sed 's/^ *//')" 
echo -e "\nAllocated:     $(cut -d '|' -f 4 $tempdir/cymru_as.txt | sed 's/^ *//' | tr -d ' ') ($whois_registry)"
if [ $type_net = "false" ] ; then 
echo -e "AS Org:        $(jq -r '.as' $tempdir/geo.json | cut -d ' ' -f 2- | sed 's/^ *//')" ; fi 
if [[ ${s} =~ $REGEX_IP4 ]] ; then
echo -e "AS Size:       $(grep -w 'assize' $tempdir/isc.txt | cut -d ':' -f 2- | sed 's/^ *//' | sed -e :a -e 's/\(.*[0-9]\)\([0-9]\{3\}\)/\1,\2/;ta')"
echo -e "Contact:       $(grep -w 'asabusecontact:' $tempdir/isc.txt | cut -d ':' -f 2- | sed 's/^ *//')" ; else 
f_ASabuseC "${as}" ; echo -e "Contact:       $(cat $tempdir/abusec.txt)" ; fi 
if  [ $option_details = "2" ] ; then 
if [ $type_net = "false" ] && [[ ${s} =~ $REGEX_IP4 ]]; then
f_solidShort; echo -e "[+] Host Details\n"
if [ $option_banners = "y" ] ; then 
echo -e "\n[+] Banners" ; f_BANNERS "${s}"
if cat $tempdir/banners.txt | grep -q -E "http*"  &&  [ $option_ww = "y" ] ; then
curl -s https://api.hackertarget.com/whatweb/?q=${s}${api_key_ht} > $tempdir/ww.txt
echo -e "\n[+] Status\n" ; f_WHATWEB_REDIR
f_solidShorter ; echo -e "[+] Website & Web-Tech\n"
grep -oP '(Title\[).*?(?=\])' $tempdir/ww.txt | tr -d '][' | tail -1 | sed 's/^ *//' | sed 's/Title/\[+] Title\n\n/'
grep -oP '(Meta-Author\[).*?(?=,)' $tempdir/ww.txt | tr -d ']' | sed 's/Meta-Author\[/\n[+] Author\n\n/' | sed 's/^ *//'
grep -oP '(Email\[).*?(?=])' $tempdir/ww.txt | tr -d '][' |  sed 's/Email/\n[+] E-Mail\n/' | sed 's/,/\n/g' |  sed 's/^ *//'
f_WHATWEB_CODE ; fi ; echo -e "\n____________________________________\n" ; fi
f_RIPE_CHAIN "${s}" ; echo -e "\n__________________\n" ; f_DELEGATION "${s}" ; fi
f_solidShort ; echo -e "[+] Network Details\n"
if [[ ${s} = ${prefix} ]] ; then 
curl -s https://api.bgpview.io/prefix/${s} > $tempdir/pfx.json
prefix_upstreams=`jq -r '.data.asns[].prefix_upstreams[] | {ASN: .asn, Name: .name, Loc: .country_code}' $tempdir/pfx.json | tr -d '}{\",' | sed 's/^ *//'`
echo -e "\n[+] Prefix Country Codes \n"
echo -e "Whois:         $(jq -r '.data.country_codes.whois_country_code' $tempdir/pfx.json)"
echo -e "Allocation:    $(jq -r '.data.country_codes.rir_allocation_country_code' $tempdir/pfx.json)"
echo -e "_____________________" ; fi 
echo -e "\n[+] Owner Contact\n"
if [ $whois_registry = "arin" ] ; then
if [[ ${s} = ${prefix} ]] ; then 
jq -r '.data.description_full[]' $tempdir/pfx.json
jq -r '.data.owner_address[]' $tempdir/pfx.json ; else 
zip=`grep "PostalCode:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
state=`grep "StateProv:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' `
arin_country=`grep 'Country:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
arin_city=`grep 'City:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
grep "Address:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'
echo "$state - $zip" ; echo "$arin_city, $arin_country"
grep -w 'OrgAbusePhone:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt > $tempdir/mailboxes.txt ; fi 
elif [ $whois_registry = "lacnic" ] ; then 
if [[ ${s} = ${prefix} ]] ; then 
jq -r '.data.description_full[]' $tempdir/pfx.json
jq -r '.data.owner_address[]' $tempdir/pfx.json
jq -r '.data.email_contacts[]' $tempdir/pfx.json > $tempdir/mailboxes.txt ; else 
grep "responsible:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'
grep "owner:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' ; fi ; else 
sed -n 'H; /^organisation/h; ${g;p;}' $tempdir/whois.txt  | sed -n '/organisation/,/source/p' | grep -s 'organisation\|address' | cut -d ':' -f 2- |
sed 's/^ *//' | sed '/organisation/{x;p;x;}'
sed -n 'H; /^role/h; ${g;p;}' $tempdir/whois.txt  | sed -n '/role/,/source/p' | grep 'role\|address' | sed '/role/{x;p;x}'  | cut -d ':' -f 2- | sed 's/^ *//'
sed -n 'H; /^person/h; ${g;p;}' $tempdir/whois.txt  | sed -n '/person/,/source/p' | grep 'person\|address' | sed '/person/{x;p;x}' |
cut -d ':' -f 2- | sed 's/^ *//' ; fi 
if [[ ${s} = ${prefix} ]] ; then 
jq -r '.data.email_contacts[]' $tempdir/pfx.json > $tempdir/mailboxes.txt
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt >> $tempdir/mailboxes.txt ; else 
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt > $tempdir/mailboxes.txt ; fi
echo '' ; sort -f -u $tempdir/mailboxes.txt ; f_solidShorter
echo -e "[+] Owner Handles\n"
if [ $whois_registry = "arin" ] ; then
grep -w 'NetHandle:' $tempdir/whois.txt | sed 's/NetHandle:/Net: /'
grep -w 'OrgAbuseHandle:' $tempdir/whois.txt | sed 's/OrgAbuseHandle:/Abuse: /'
grep -w 'OrgNOCHandle:' $tempdir/whois.txt | sed 's/OrgNOCHandle:/NOC: /'
elif [ $whois_registry = "lacnic" ] ; then
echo -e "[owner-c]"
grep -w 'owner-c:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' 
echo -e "[tech-c]"
grep -w 'tech-c:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' ; else 
echo -e "\n[abuse-c]"
grep -w 'abuse-c:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' > $tempdir/abuse_c.txt
sort $tempdir/abuse_c.txt | uniq
echo -e "\n[admin-c]"
grep -w 'admin-c:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' > $tempdir/admins.txt
grep -w 'nic-hdl:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' >> $tempdir/admins.txt
sort $tempdir/admins.txt | uniq
echo -e "\n[mnt-by]"
mnt_by=`grep -w 'mnt-by:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
echo "$mnt_by" | sort -u ; fi
if [[ ${s} = ${prefix} ]] ; then 
f_solidShort  ; echo -e "[+] Network Upstreams\n" ; echo "$prefix_upstreams" ; fi 
fi
}
function f_PREFIX {
local s="$*"
curl -s https://api.bgpview.io/prefix/${s} > $tempdir/pfx.json
prefix_upstreams=`jq -r '.data.asns[].prefix_upstreams[] | {ASN: .asn, Name: .name, Loc: .country_code}' $tempdir/pfx.json | tr -d '}{\",' | sed 's/^ *//'`
rir=`jq -r '.data.rir_allocation.rir_name' $tempdir/pfx.json`
alloc=`jq -r '.data.rir_allocation.date_allocated' $tempdir/pfx.json`
echo -e "[+] Prefix - $prefix\n\n"
net=`echo "$s" | rev | cut -d '/' -f 2- | rev`
if [[ ${s} =~ $REGEX_IP4 ]] || [[ ${net} =~ $REGEX_IP4 ]] ; then
ipcalc -b -n ${s} | sed '/Address:/d' | sed '/Network:/d' | sed '/Broadcast/d' ; else 
sipcalc ${s} > $tempdir/scalc.txt
grep -w 'Compressed'    $tempdir/scalc.txt ; echo '' 
grep -w 'Expanded'      $tempdir/scalc.txt ; echo '' 
grep -w 'Subnet prefix' $tempdir/scalc.txt ; echo ''
grep -w 'Address ID (masked)' $tempdir/scalc.txt 
grep -w 'Prefix address' $tempdir/scalc.txt ; echo -e '' 
grep -A 1 'Network range' $tempdir/scalc.txt ; fi
f_solidShorter ; echo -e "[+] Net-Name\n"
jq -r '.data.name' $tempdir/pfx.json
echo -e "\n\n[+] Owner\n"
jq -r '.data.description_full[]' $tempdir/pfx.json
jq -r '.data.owner_address[]' $tempdir/pfx.json ; echo ''
jq -r '.data.email_contacts[]' $tempdir/pfx.json
f_solidShorter ; echo -e "[+] Prefix Country Codes \n"
echo -e "Whois:         $(jq -r '.data.country_codes.whois_country_code' $tempdir/pfx.json)"
echo -e "Allocation:    $(jq -r '.data.country_codes.rir_allocation_country_code' $tempdir/pfx.json)"
f_solidShort ; echo -e "[+] Prefix Upstreams\n"
echo "$prefix_upstreams" ; f_solidShort
echo -e "[+] Prefix Geographic Distribution (${prefix})\n" ; f_NETGEO "${prefix}" 
}
function f_NET_WHOIS {
local s="$*"
net=`echo "$s" | rev | cut -d '/' -f 2- | rev`
whois -h whois.cymru.com -- "-v -f ${s}" > $tempdir/cymru.txt
f_REGISTRY "${s}" ; whois -h whois.pwhois.org type=all ${s} > $tempdir/p_full.txt
f_NETINFO ${s}
as=`cut -d '|' -f 1 $tempdir/cymru.txt | sed 's/^ *//' | tr -d ' '`
echo -e "______________\n" ; echo -e "[+]  AS $as\n" 
f_ASabuseC "${as}" ; whois -h whois.cymru.com -- "-v -f as$as" > $tempdir/cymru_as.txt 
reg_date=`cut -d '|' -f 4 $tempdir/cymru_as.txt | sed 's/^ *//' | tr -d ' '`
cut -d '|' -f 5 $tempdir/cymru_as.txt | sed 's/^ *//'
echo -e "$reg_date ($whois_registry)"
cat $tempdir/abusec.txt
}
function f_certSpotter {
local s="$*"
echo -e "[+]  Certificate Subject, Fingerprint (SHA256) & Issuer\n"
curl -s  "https://api.certspotter.com/v1/issuances?domain=${s}&expand=dns_names&expand=issuer&expand=cert" > $tempdir/cert.json
jq -r '.[] | .dns_names[], .cert.sha256, .not_before, .not_after, .issuer.name' $tempdir/cert.json | sed '/CN=*/G' 
echo -e "\nSource > https://api.certspotter.com" 
}
function f_WriteOut {
local s="$*"
curl ${curl_array[@]} ${x} 2>$tempdir/curl.txt -D $tempdir/headers.txt -o $tempdir/src.txt -w \
"
URL:              %{url_effective}
IP:               %{remote_ip}
Port:             %{remote_port}\n
Status            %{response_code}, HTTP %{http_version}
Content:          %{content_type}\n
Num Redirects:    %{num_redirects}
Redirects:        %{time_redirect} s \n
SSL Handshake:    %{time_appconnect} s
DNS Lookup:       %{time_namelookup} s
———\n
Time Total:       %{time_total} s
" > $tempdir/response.txt
}
function f_curlHandshake {
awk '{ IGNORECASE=1 } /connected|connection|trying|HTTP|ALPN|host|location|certificate:|subject:|issuer:|expire date|certificate verify ok.|cipher|handshake/ { print }' $tempdir/curl.txt |
sed '/^$/d' | sed '/TCP_NODELAY/d' | sed '/[Aa]ccept:/d' | sed '/left intact/d' | sed '/response-body/d' | sed '/verify locations:/d' |
sed '/CApath/d' | sed '/CAfile:/d' | sed '/Policy/d' |  sed '/old SSL session/d' | sed '/permissions-policy:/d' | sed '/state changed/d' |
sed '/Trying/i -------------' | sed '/Connected to/a -------------' | sed '/Server certificate:/i \\n------------------------------------------\n' |
sed '/SSL certificate verify ok./a \\n------------------------------------------\n' | sed '/expect-ct:/d' | sed '/content-security-policy:/d' |
sed -e :a -e 's/\(.*[0-9]\)\([0-9]\{4\}\)/\1/;ta'
}

#*************** SUBMENUS *******************************
function f_options_SERVERS {
echo -e "\n ${B}22)${D}  Shared Name Servers"             
echo -e " ${B}23)${D}  Zone Transfer"                   
echo -e " ${B}24)${D}  MX- & NS- Server Enumeration & Blacklist Check "
}
function f_optionsWhois {
echo -e "\n ${B}33)${D}  whois"                        
echo -e " ${B}34)${D}  Search by Handle, Org- or AS-Name"
echo -e " ${B}35)${D}  Search by AS Number"
echo -e " ${B}36)${D}  Prefixes, Peering & IX Memberships"            
echo -e " ${B}37)${D}  IX Information"
echo -e " ${B}38)${D}  RIPESTAT Looking Glass"
}
function f_optionsIPV4 {
echo -e "\n ${B}44)${D}  IPv4 Address Details, Virtual Hosts"
echo -e " ${B}45)${D}  IPv4 Network Details"
echo -e " ${B}46)${D}  Reverse DNS, Service Banners & VHosts (IPv4 Networks)"
echo -e " ${B}47)${D}  NMAP Ping Sweep (IPv4)"
}
function f_optionsIPV6 {
echo -e "\n ${B}61)${D}  Dump Router, DHCP6"  
echo -e " ${B}62)${D}  ICMPv6"
echo -e " ${B}63)${D}  MAC/IPv4 to IPv6 Conversion" 
echo -e " ${B}64)${D}  Extract Network & Host Portions" 
echo -e " ${B}65)${D}  Subdomains (IPv6)" 
echo -e " ${B}66)${D}  IPv6 Address & - Network Details" 
echo -e " ${B}67)${D}  IPv6 Reverse DNS"
}
function f_optionsWEBSERVERS {
echo -e "\n ${B}111)${D}  HTTP Headers, Link Dump, robots.txt"               
echo -e " ${B}112)${D}  Web Server RT-, Response- & Loading Times"                 
echo -e " ${B}113)${D}  SSL/TLS- & Web Server Security"

}
function f_options_T {
echo -e "\n ${B}t1)${D}  Nmap Geo Traceroute (TCP)"
echo -e " ${B}t2)${D}  Nmap path-mtu.nse (TCP)"          
echo -e " ${B}t3)${D}  MTR Traceroute (TCP,UDP,ICMP)"              
echo -e " ${B}t4)${D}  Dublin Traceroute (NAT aware, multipath tracerouting, ICMP)"
echo -e " ${B}t5)${D}  Tracepath (non-root, MTU discovery, ICMP)"
echo -e " ${B}t6)${D}  atk-trace6 (ICMPv6 traceroute, MTU- & tunnel-discovery)"
}
function f_options_P {
echo -e "\n ${B}p1)${D}  Port- & Version Scans        ${B}p5)${D} IPv4 Ping Sweep (Nmap)"    
echo -e " ${B}p2)${D}  Port Scan (API)              ${B}p6)${D}  ICMPv6"  
echo -e " ${B}p3)${D}  Banner Grabbing (API)       ${B}p11)${D}  ARP Scan"
echo -e " ${B}p4)${D}  Nping (API)                 ${B}p12)${D}  DHCP Discover"
}

#***************************** main program loop *****************************
while true
do
echo -e -n "\n  ${B}?${D}  " ; read choice
case $choice in
m)
f_startMenu
;;
c | clear)
clear
f_Menu
;;
o)
f_Menu
;;
p)
f_options_P
;;
a)
#************** ADD Permanent Folder  ********************
f_makeNewDir ; f_dashedGrey
echo -e -n "\n${B} Set folder > ${D}HOME/${B}dir_name >>${D} " ; read dirname
mkdir $HOME/$dirname
out="$HOME/$dirname"
report="true"
echo -e "\n ${B}Option > Safe Mode > ${D}"
echo -e "\n ${B}>${D} Send packets to target systems ?"
echo -e -n "\n ${B}>${D} ${GREEN}[1]${B} yes | ${R}[9]${B} no ?${D}  " ; read option_connect
if [ $option_connect = "9" ] ; then
conn="${R}false${D}" ; else
conn="${GREEN}true${D}" ; fi
echo -e -n "\n${B} > ${D}Set target?  ${B}[y]${D} yes ${B}| [n]${D} later ${B}?${D} " ; read option_target
if [ $option_target = "y" ] ; then
echo -e -n "\n ${B}Target >  ${D}DOMAIN ${B} >>${D}  " ; read target
if [ $option_connect = "9" ] ; then
if [[ $target =~ $REGEX_IP4 ]]; then
address_ipv4=`echo $target`
target_ip=`echo $target` ; else
target_ip='' ; host_ip=''
target_dom=`echo $target` ; fi ; else
if [[ $target =~ $REGEX_IP4 ]]; then
target_ip=`echo $target` ; else
target_ip=`dig +short $target | head -1`
host_ip="-  ${target_ip}" ; fi ; fi
fi ; f_Menu
;;
s)
f_makeNewDir
echo -e -n "\n ${B}Target >  ${D}DOMAIN / IPv4 ${B} >>${D}  " ; read target
echo -e "\n ${B}Option > Safe Mode > ${D}"
echo -e "\n ${B}>${D} Send packets to target systems ?"
echo -e -n "\n ${B}>${D} ${GREEN}[1]${B} yes | ${R}[9]${B} no ?${D}  " ; read option_connect
if [ $option_connect = "9" ] ; then
conn="${R}false${D}" ; else
conn="${GREEN}true${D}" ; fi
if [ $option_connect = "1" ] ; then
conn="${GREEN}true${D}"
if [[ $target =~ $REGEX_IP4 ]]; then
target_ip=`echo $target` ; else
target_ip=`dig +short $target | head -1`
host_ip="-  ${target_ip}" ; fi ; else
conn="${R}false${D}"
if [[ $target =~ $REGEX_IP4 ]]; then
address_ipv4=`echo $target`
target_ip=`echo $target` ; else
target_ip='' ; host_ip=''
target_dom=`echo $target` ; fi ; fi ; f_Menu
;;
t)
f_options_T
;;
i)
f_makeNewDir ; f_dashedGrey
echo -e "\n ${B}Option > Safe Mode > ${D}"
echo -e "\n ${B}>${D} Send packets to target systems ?"
echo -e -n "\n ${B}>${D} ${GREEN}[1]${B} yes | ${R}[9]${B} no ?${D}  " ; read option_connect
if [ $option_connect = "1" ] ; then
conn="${GREEN}true${D}"
if [[ $target =~ $REGEX_IP4 ]]; then
target_ip=`echo $target` ; else
target_ip=`dig +short $target | head -1`
host_ip="-  ${target_ip}" ; fi
else
conn="${R}false${D}"
if [[ $target =~ $REGEX_IP4 ]]; then
address_ipv4=`echo $target`
target_ip=`echo $target` ; else
target_ip=''
host_ip=''
target_dom=`echo $target` ; fi
fi ; echo'' ; f_removeDir ; f_Menu
;;
1)
f_makeNewDir ; f_dashedGrey
touch $tempdir/hosts.list ; option_server="y" ; option_details="2"
option_banners="n" ; option_ww="n" ; type_net="false"
if [[ $target =~ ${REGEX_IP4} ]]; then
echo -e -n "\n${B}Target > [1]${D} set target domain ${B}| [2]${D} Target List  ${B}?${D}  " ; read option_target ; else
echo -e -n "\n${B}Target > [1]${D} set target domain ${B}| [2]${D} Target List ${B}| [3] current > ${D} $target  ${B}?${D}  " ; read option_target ; fi
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D}DOMAIN  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/hosts.list
hosts=" $tempdir/hosts.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}  " ; read input
hosts="${input}"
elif [ $option_target = "3" ] ; then
echo "$target" > $tempdir/hosts.list
hosts="$tempdir/hosts.list" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
echo -e -n "\n${B}Option >${D} Search for virtual hosts on target server  ${B}[y] | [n] ?${D}  " ; read option_vhosts
echo -e -n "\n${B}Option >${D} Show BGP Prefix - Details ${B}[y] | [n] ?${D}  " ; read option_prefix
if ! [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Option >${D} List supported ciphersuites  ${B}[y] | [n] ?${D}  " ; read option_ciphers ; fi
for x in $(cat $hosts) ; do
f_textfileBanner >> $out/${x}.txt
f_solidLong | tee -a $out/${x}.txt ; echo -e "\n == ${x} == \n" >> $out/${x}.txt ; echo ''
f_whoisLOOKUP "${x}"
echo -e "\n == ${x} WHOIS == \n\n" >> $out/WHOIS.txt
cat $tempdir/host-whois2.txt >> $out/WHOIS.txt ; f_solidShort >> $out/WHOIS.txt
if [ $option_connect = "9" ] ; then
curl -s https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht} > $tempdir/ww.txt
ip4=`grep -oP '(IP\[).*?(?=])' $tempdir/ww.txt | tail -1 | sed 's/IP\[//' | grep -E -o "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"`
f_BOX_BANNER "${ip4}" ; echo -e "\n${B}Website & Server${D}\n\n"
echo -e "[+] Status & Redirects\n" ; f_WHATWEB_REDIR
echo -e "\n\n[+] Website\n" | tee -a $out/${x}.txt ; f_WHATWEB_PAGE | tee -a $out/${x}.txt
f_solidShort | tee -a $out/${x}.txt
echo -e "[+] Web-Tech" | tee -a $out/${x}.txt ; f_WHATWEB_CODE | tee -a $out/${x}.txt
f_solidShort | tee -a $out/${x}.txt ; echo -e "[+]  Service Banners" | tee -a $out/${x}.txt
f_BANNERS "${ip4}" | tee -a $out/${x}.txt
f_DRWHO "${ip4}" | tee -a $out/${x}.txt
else
error_code=6
curl -s -f -L -k ${x} > /dev/null
if [ $? = ${error_code} ];then
echo -e "\n${R} $x WEBSITE CONNECTION: FAILURE${D}\n\n"
echo -e "\n $x WEBSITE CONNECTION: FAILURE\n" >> $out/${x}.txt
exit 1 ; else
echo -e "\n  ${B}WEBSITE STATUS: ${GREEN}ONLINE${D}"
echo -e "\n WEBSITE STATUS: ONLINE\n" >> $out/${x}.txt ; fi
declare -a curl_array=() ; curl_array+=(-sLk4) ; f_WriteOut "${x}" 
ip4="$(egrep -m 1 -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/response.txt)"
f_BOX_BANNER "${ip4}" ; echo '' ; cat $tempdir/headers.txt > $out/HEADERS.${x}.txt
cat $tempdir/response.txt | tee -a $out/${x}.txt ; f_solidShort | tee -a $out/${x}.txt
f_headers "${x}" | tee -a $out/${x}.txt ; f_solidShort | tee -a $out/${x}.txt
echo '' ; echo -e "[+]  Domain Host A & AAAA Records\n\n" | tee -a $out/${x}.txt
f_aRecord "${x}" | tee -a $out/${x}.txt ; f_solidLong | tee -a $out/${x}.txt
echo -e "${B}Website & Server${D}\n" ; echo -e "[+] Website\n" >> $out/${x}.txt
f_WHATWEB "${x}"
f_WHATWEB_PAGE | tee -a $out/${x}.txt
f_socialLinks "${x}"  | tee -a $out/${x}.txt
f_solidShort | tee -a $out/${x}.txt ; echo -e "[+] Web-Tech" | tee -a $out/${x}.txt ; f_WHATWEB_CODE | tee -a $out/${x}.txt
f_solidShort | tee -a $out/${x}.txt ; echo -e "[+] Service Banners" | tee -a $out/${x}.txt
f_BANNERS "${ip4}" | tee -a $out/${x}.txt ; f_DRWHO "${ip4}" | tee -a $out/${x}.txt ; fi 
f_solidLong | tee -a $out/${x}.txt ; echo -e "${B}${x} SSL/TLS${D}\n"
echo -e "${x} SSL/TLS\n\n" >> $out/${x}.txt ; f_certSpotter "${x}" | tee -a $out/${x}.txt
if ! [ $option_connect = "9" ] ; then
f_solidShort | tee -a $out/${x}.txt
echo -e "[+] Certificate Status (openSSL)" | tee -a $out/${x}.txt ; f_certInfo "${x}" | tee -a $out/${x}.txt
if [ $option_ciphers = "y" ] ; then
f_solidShort | tee -a $out/${x}.txt ; echo -e "[+] Ciphersuites (Nmap)\n" | tee -a $out/${x}.txt
nmap -sT -Pn -p 443 --script sslv2,ssl-enum-ciphers,ssl-dh-params,tls-alpn ${x} | sed '/PORT/{x;p;x;G;}' | sed '/Read data files/d' |
sed '/NSE/d' | sed '/Initiating/d' | sed '/Completed/d' | sed '/Discovered/d' | sed '/Host is up/d' |
sed '/Starting Nmap/d' | fmt -w 100 -s | tee -a $out/${x}.txt ; fi ; fi
if [ $option_vhosts = "y" ] ; then
f_solidLong | tee -a $out/${x}.txt
echo -e "${B}${ip4} Virtual Hosts${D}\n\n" ; echo -e "[+] Domain Host (${ip4}) VIRTUAL HOSTS ==\n" >> $out/${x}.txt
curl -s https://api.hackertarget.com/reverseiplookup/?q=${ip4}${api_key_ht} | tee -a $out/${x}.txt ; fi 
f_solidLong | tee -a $out/${x}.txt
echo -e "${B}${x} whois${D}\n\n" ; echo -e "\n[+] ${x} WHOIS\n\n" >> $out/${x}.txt
cat $tempdir/host-whois2.txt | tee -a $out/${x}.txt
f_solidShort >> $out/${x}.txt ; echo -e "[+] ${ip4} Reverse Whois \n\n" >> $out/${x}.txt
cat $tempdir/who.txt >> $out/${x}.txt ; f_solidLong >> $out/${x}.txt
echo -e "[+] ${x} HTTP HEADERS\n\n" >> $out/${x}.txt
cat $tempdir/headers.txt >> $out/${x}.txt ; echo -e "\n[+]${x} robots.txt\n\n" > $out/ROBOTS.${x}.txt
curl -sLk4 ${x}/robots.txt >> $out/ROBOTS.${x}.txt
prefix=`cut -d '|' -f 3 $tempdir/cymru.txt | tr -d ' '`
if [ $option_prefix = "y" ] ; then 
f_solidLong | tee -a $out/${x}.txt
f_PREFIX "${prefix}" | tee -a $out/${x}.txt ; fi ;  done 
echo '' ; f_removeDir ; f_Menu
;;
2)
f_makeNewDir ; f_dashedGrey ; touch $tempdir/hosts.list ; declare dig_array=()
if [[ $target =~ ${REGEX_IP4} ]]; then
echo -e -n "\n${B}Target > [1]${D} Set target domain ${B}| [2]${D} Target List  ${B}?${D}  " ; read option_target ; else
echo -e -n "\n${B}Target > [1]${D} Set target domain ${B}| [2]${D} Target List  ${B}| [3] current >  ${D}$target  ${B}?${D}  " ; read option_target ; fi
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D}DOMAIN ${B}>>${D}  " ; read input
echo "$input" > $tempdir/hosts.list
hosts=" $tempdir/hosts.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}  " ; read input
hosts="${input}"
elif [ $option_target = "3" ] ; then
echo "$target" > $tempdir/hosts.list
hosts="${tempdir}/hosts.list" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
if [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Options > [1]${D} DNS records ${B}| [2]${D} DNS records & subdomains ${B}?${D}  " ; read option_subs ; else 
echo -e "\n${B}Options >\n"
echo -e "${B} [1]${D} DNS resource records only"
echo -e "${B} [2]${D} DNS records & subdomains (IPv4)"
echo -e "${B} [3]${D} DNS records & subdomains (IPv4, IPv6)"
echo -e -n "\n${B}  ?${D}  "  ; read option_subs
echo -e -n "\n${B}Option >${D} Customize DNS Lookup  ${B}[y] | [n]  ?${D}  " ; read answer 
if [ $answer = "n" ] ; then 
option_transfer="n" ; option_zone="n"
dig_array+=(+noall +answer +noclass +nottlid) ; else 
echo -e "\n${B}Nameservers (System Defaults)${D}\n"
cat /etc/resolv.conf | sed '/#/d' | grep 'nameserver' 
echo -e -n "\n${B}Options > ${D} Nameserver ${B}> [1]${D} Use system defaults ${B}| [2]${D} use 1.1.1.1  ${B}| [3]${D} set custom NS  ${B}?${D}  " 
read option_ns
if [ $option_ns = "2" ] ; then
dig_array+=(@1.1.1.1) ; nssrv_dig="@1.1.1.1"
elif [ $option_ns = "3" ] ; then
echo -e -n "\n${B}Set     >${D} Nameserver  ${B} >>${D}   " ; read nssrv
dig_array+=(@nssrv) ; nssrv_dig="@${nssrv}" ; else 
nssrv_dig="" ; fi 
dig_array+=(+noall +answer +noclass) 
echo -e -n "\n${B}Option > [1]${D} TTL values (ms) ${B}| [2]${D} TTL values (human readable) ${B}| [9]${D} SKIP ${B}?${D}  " ; read option_ttl
if [ $option_ttl = "1" ] ; then
dig_array+=(+ttlid)
elif [ $option_ttl = "2" ] ; then
dig_array+=(+ttlunits) ; else 
dig_array+=(+nottlid) ; fi 
echo -e -n "\n${B}Option  >${D} Print responding name server and lookup time?  ${B}[y] | [n] ?${D}  " ; read option_identify 
if [ $option_identify = "y" ] ; then
dig_array+=(+identify) ; fi
echo -e -n "\n${B}Option  >${D} Check for unauthorized zone transfers?   ${B}[y] | [n] ?${D}  " ; read option_transfer
echo -e -n "\n${B}Option  >${D} Check zone config for best practices (RFC 1912) ${B}[y] | [n] ?${D}  " ; read option_zone ; fi ; fi 
for x in $(cat $hosts) ; do
touch $tempdir/dnsrec.txt ; echo '' > $tempdir/dnsrec.txt
f_solidLong | tee -a $tempdir/dnsrec.txt
echo -e "\n === ${x} DNS RECORDS ===\n" >> $tempdir/dnsrec.txt
echo -e " Date: $(date)\n" >> $tempdir/dnsrec.txt ; f_solidShortest >> $tempdir/dnsrec.txt
if [ $option_connect = "9" ] ; then
echo -e "\n\n${B}${x} DNS Records${D}\n"
curl -s https://api.hackertarget.com/dnslookup/?q=${x}${api_key_ht} | tee -a $tempdir/dnsrec.txt
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/dnsrec.txt > $tempdir/ip_1.list
echo -e "\nSource > hackertarget.com IP Tools API" | tee -a $tempdir/dnsrec.txt
cat $tempdir/dnsrec.txt | tee -a $out/DNSrec_and_Subdomains.txt >> $out/${x}.txt ; else 
echo -e "[+] Domain Host A\n\n" >> $tempdir/dnsrec.txt
echo -e "${B}Domain Host A & AAAA Records${D}\n\n"
dig a ${dig_array[@]} ${x} | tee -a $tempdir/dnsrec.txt
echo '' ; echo -e "\n[+] AAAA\n" >> $tempdir/dnsrec.txt
dig aaaa ${dig_array[@]} ${x} | tee -a $tempdir/dnsrec.txt
f_solidShort | tee -a $tempdir/dnsrec.txt
echo -e "[+] A Record Lookup Delegation \n\n" >> $tempdir/dnsrec.txt
echo -e "${B}A Record Lookup Delegation${D}\n\n"
dig ${nssrv_dig} +trace +nodnssec +ttlunits +noclass ${x} | grep 'A\|Received' | sed 's/;;//' | sed '/A/{x;p;x;G}' | sed 's/^ *//' |
tee -a $tempdir/dnsrec.txt
f_solidShort | tee -a $tempdir/dnsrec.txt
echo -e "${B}MX Records${D}\n\n" ; echo -e "[+] MX Records \n\n" >> $tempdir/dnsrec.txt
dig mx ${dig_array[@]} ${x} | tee -a $tempdir/dnsrec.txt
echo -e "\n\n[+] MX A/AAAA\n" | tee -a $tempdir/dnsrec.txt
dig ${dig_array[@]} $(dig mx +short ${x}) | tee -a $tempdir/dnsrec.txt
echo '' | tee -a $tempdir/dnsrec.txt
dig aaaa ${dig_array[@]} $(dig mx +short ${x}) | tee -a $tempdir/dnsrec.txt
f_solidShort | tee -a $tempdir/dnsrec.txt
echo -e "${B}NS Records${D}\n\n" ; echo -e "[+] NS Records \n\n" >> $tempdir/dnsrec.txt
dig ns ${dig_array[@]} ${x} | tee -a $tempdir/dnsrec.txt
echo -e "\n\n[+] NS A/AAAA\n" | tee -a $tempdir/dnsrec.txt
dig ${dig_array[@]} $(dig ns +short ${x}) | tee -a $tempdir/dnsrec.txt
echo '' | tee -a $tempdir/dnsrec.txt
dig aaaa ${dig_array[@]} $(dig ns +short ${x}) | tee -a $tempdir/dnsrec.txt
echo -e "\n\n${B}SOA Record${D}\n\n" 
echo -e "\n\n[+] SOA Record \n\n" >> $tempdir/dnsrec.txt 
dig soa +noall +answer +noclass +ttlunits ${x} | tee -a $tempdir/dnsrec.txt
echo '' | tee -a $tempdir/dnsrec.txt
dig soa +noall +answer +multiline ${x} > $tempdir/soa.txt
awk '{ print  $1 $2,   $3, $4, $5 }' $tempdir/soa.txt | sed '1,1d' |
sed '$d'  | sed '/serial/{x;p;x;}'  | tee -a $tempdir/dnsrec.txt
f_solidShort | tee -a $tempdir/dnsrec.txt
echo -e "${B}Checking for non-matching SOA Records${D}\n"
echo -e "[+] Checking for non-matching SOA Records\n" >> $tempdir/dnsrec.txt
dig ${nssrv_dig} +nssearch ${x} | sed '/SOA/{x;p;x;}' | sed 's/from/\nfrom/' | tee -a $tempdir/dnsrec.txt
f_solidShort | tee -a $tempdir/dnsrec.txt
echo -e "${B}SRV Record(s)${D}\n"
echo -e "[+] SRV RECORDS(S) (via nmap.nse)\n" >> $tempdir/dnsrec.txt
nmap -Pn -sn --script dns-srv-enum --script-args dns-srv-enum.domain=$x | sed '/Pre-scan/d' |
tee -a $tempdir/dnsrec.txt
echo -e "\n\n[+] TXT RECORDS\n" >> $tempdir/dnsrec.txt
echo -e "\n\n${B}TXT Record(s)${D}\n"
dig +short txt ${x} | sed '/\"/{x;p;x;}' | fmt -w 100 -s > $tempdir/TXT.txt
cat $tempdir/TXT.txt | tee -a $tempdir/dnsrec.txt
echo -e "\n\n[+] IPv4 Addresses found in TXT\n" | tee -a $tempdir/dnsrec.txt
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/TXT.txt | tee -a $tempdir/dnsrec.txt
f_solidShort | tee -a $tempdir/dnsrec.txt
echo -e "${B}IPv4 PTR Records${D}\n"
echo -e "[+] PTR RECORDS\n" >> $tempdir/dnsrec.txt
cat $tempdir/dnsrec.txt | sed '/Received/d' | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' > $tempdir/ip_1.list
for i in $(cat "$tempdir/ip_1.list" | sort -u -V) ; do
ptr=`host $i | cut -d ' ' -f 5` ; echo "$i - $ptr" | sed 's/3(NXDOMAIN)/no record/' ; done | tee -a $tempdir/dnsrec.txt 
if [ $option_zone = "y" ] ; then 
f_solidShort | tee -a $tempdir/dnsrec.txt 
echo -e "${B}Zone Config Best Practice Check (RFC 1912)${D}\n\n"
echo -e "[+] Zone Config Best Practice Check (RFC 1912)\n\n" >> $tempdir/dnsrec.txt 
soa=`dig soa +short $x` ; soa_host=`echo "$soa" | cut -d ' ' -f 1`
nmap -sn -Pn ${soa_host} --script dns-check-zone --script-args=dns-check-zone.domain=$x |
sed '/Host discovery disabled /d' | sed '/Host is up/d' | sed '/Starting Nmap/d' | sed '/Other addresses/d' |
sed 's/Nmap scan report for//'  | tee -a $tempdir/dnsrec.txt ; fi 
if   [ $option_transfer = "y" ] ; then
f_solidLong | tee -a  $tempdir/dnsrec.txt 
echo -e "${B}${x} Zone Transfer${D}" ; echo -e "\n[+] ${x} ZONE TRANSFER" >>  $tempdir/dnsrec.txt 
echo '' > $tempdir/zone.txt 
curl -s https://api.hackertarget.com/zonetransfer/?q=${x}${api_key_ht} >> $tempdir/zone.txt
cat $tempdir/zone.txt | tee -a $tempdir/dnsrec.txt  ; fi
cat $tempdir/dnsrec.txt | tee -a $out/DNSrec_and_Subdomains.txt >> $out/${x}.txt ; fi 
if ! [ $option_subs = "1" ] ; then
echo '' > $tempdir/dnsrec.txt
f_solidLong | tee -a $tempdir/dnsrec.txt
touch $tempdir/subs.txt ; echo -e "${B}${x} Subdomains${D}\n\n"
echo -e "[+] ${x} SUBDOMAINS\n\n" >> $tempdir/dnsrec.txt ; echo -e "[+] ${x} Subdomains (IPv4)\n" >> $tempdir/dnsrec.txt
curl -s https://api.hackertarget.com/hostsearch/?q=${x}${api_key_ht}  > $tempdir/subs.txt
sort -t ',' -k 2 -V  $tempdir/subs.txt | cut -d ',' -f 1 | tr -d ' ' > $tempdir/hostsnames.txt 
sort -t ',' -k 2 -V  $tempdir/subs.txt | sed 's/,/ => /'  | awk '{print $3 "\t" $2 "\t" $1}' > $tempdir/subs_sorted.txt
cat $tempdir/subs_sorted.txt | tee -a $tempdir/dnsrec.txt
echo -e "\nSource > hackertarget.com IP Tools API" | tee -a $tempdir/dnsrec.txt
cat $tempdir/dnsrec.txt | tee -a $out/DNSrec_and_Subdomains.txt >> $out/${x}.txt 
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/subs_sorted.txt >> $tempdir/ip_1.list
f_solidShort | tee -a $out/${x}.txt ; f_solidShort >> $out/DNSrec_and_Subdomains.txt
echo '' > $tempdir/dnsrec.txt 
echo -e "[+] ${x} Subdomains Reverse DNS \n\n" | tee -a $tempdir/dnsrec.txt
curl -s https://dns.bufferover.run/dns?q=${x} > $tempdir/dnsbo.json 
jq -r '.RDNS[]' $tempdir/dnsbo.json | cut -d ',' -f 2- >> $tempdir/hostsnames.txt 
sed 's/^[ \t]*//;s/[ \t]*$//' $tempdir/hostsnames.txt | sed '/^$/d' | sort -f -u $tempdir/hostsnames.txt > $tempdir/hosts_ip4.txt 
jq -r '.RDNS[]' $tempdir/dnsbo.json | sort -t ',' -k 1 -V  | sed 's/,/ => /'  | awk '{print $1 "\t" $2 "\t" $3}' | tee -a $tempdir/dnsrec.txt 
echo -e "\nSource > https://dns.bufferover.run" | tee -a $tempdir/dnsrec.txt
cat $tempdir/dnsrec.txt | tee -a $out/DNSrec_and_Subdomains.txt >> $out/${x}.txt
if [ $option_subs = "3" ]; then
f_solidShort | tee -a $out/${x}.txt ; f_solidShort >> $out/DNSrec_and_Subdomains.txt
echo '' > $tempdir/dnsrec.txt 
echo -e "[+] Subdomains (AAAA)\n\n" | tee -a $tempdir/dnsrec.txt
dig @1.1.1.1 -t aaaa +noall +answer +noclass +nottlid -f $tempdir/hosts_ip4.txt | sed 's/AAAA/,/' | sed '/NS/d' > $tempdir/ipv6_hosts.txt
sed 's/^[ \t]*//;s/[ \t]*$//' $tempdir/ipv6_hosts.txt | cut -s -d ',' -f 2 - | sed '/CNAME/d'  | sort -f -u > $tempdir/ip6.txt
cat $tempdir/ipv6_hosts.txt | sed 's/,/\t/' | tee -a $tempdir/dnsrec.txt 
f_solidShorter | tee -a $tempdir/dnsrec.txt ; echo -e "\n[+] IPv6 Network Portions\n\n" | tee -a $tempdir/dnsrec.txt
/usr/bin/atk6-extract_networks6 $tempdir/ip6.txt | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -V -u | tee -a $tempdir/dnsrec.txt
cat $tempdir/dnsrec.txt | tee -a $out/DNSrec_and_Subdomains.txt >> $out/${x}.txt ; fi ; fi 
echo '' > $tempdir/dnsrec.txt ; f_solidLong | tee -a $tempdir/dnsrec.txt 
sort -t . -k 1,1n -k 2,2n -k 3,3n -u $tempdir/ip_1.list > $tempdir/ip.list
echo -e "begin\ntype=cymru" > $tempdir/ips.txt ; cat $tempdir/ip.list >> $tempdir/ips.txt ; echo "end" >> $tempdir/ips.txt
netcat whois.pwhois.org 43 < $tempdir/ips.txt  > $tempdir/pwhois_cymru.txt
echo -e "${B}pwhois.org Bulk Lookup${D}\n" ; echo -e "[+] DNS Records & Subdomains Networks & AS (pwhois.org)\n" >> $tempdir/dnsrec.txt 
cat $tempdir/pwhois_cymru.txt | cut -d '|' -f 1,2,3,4,6 | sed '/Bulk mode; one IP/d' | sed '/ORG NAME/{x;p;x;G;}' > $tempdir/whois_table.txt
cat $tempdir/whois_table.txt | tee -a $tempdir/dnsrec.txt ; echo '' | tee -a $tempdir/dnsrec.txt 
echo "begin" > $tempdir/ips.txt ; cat $tempdir/ip.list >> $tempdir/ips.txt ; echo "end" >> $tempdir/ips.txt
netcat whois.pwhois.org 43 < $tempdir/ips.txt > $tempdir/pwhois_bulk.txt
cat $tempdir/pwhois_bulk.txt | sed '/IP:/i \\n____________________\n' | sed '/AS-Path:/d' |
sed '/Cache-Date:/d' | sed '/Latitude:/d' | sed '/Longitude:/d' | sed '/Region:/d' | sed '/Country-Code:/d' |
sed '/Route-Originated-Date:/d' | sed '/Route-Originated-TS:/d' | tee -a $tempdir/dnsrec.txt 
cat $tempdir/dnsrec.txt | tee -a $out/${x}.txt >> $out/DNSrec_and_Subdomains.txt  ; done 
echo '' ; f_Menu  ; f_removeDir
;;
3) f_optionsWhois ;;
4) f_optionsIPV4 ;;
5)
#************** 5) SSL/TLS & WEBSERVER SECURITY *******************
f_makeNewDir ; f_dashedGrey
option_server="y" ; option_banners="n" ; option_ww="n" ; type_net="false"
if [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Options > [1]${D} SSL/TLS Status  ${B}| [2]${D} Webserver/ Website Information ${B}?${D}  " ; read answer ; else 
echo -e -n "\n${B}Options > [1]${D} SSL/TLS Status / Analysis  ${B}| [2]${D} Webserver & SSL/TLS Security ${B}?${D}  " ; read answer 
if [ $answer = "2" ] ; then 
option_server="y" ; option_banners="n" ; type_net="false"
echo -e "\n${B}Options > Webserver Enumeration & Security ${D}"
echo -e -n "\n${B}Options >${D} Network, whois & geolocation info ${B} > [1]${D} Summary ${B}| [2]${D} Details ${B}| [9]${D} SKIP  ${B}?${D}  " ; read option_details
echo -e -n "\n${B}Options > Nmap > [1]${D} Safe Mode ${B}| [2]${D} Intrusive Mode ${B}| [9]${D} SKIP  ${B}?${D}  " ; read option_nmap 
if ! [ $option_nmap = "9" ] ; then
declare -a nmap_array=() ; declare -a script_array=() ; declare -a port_array=() ; nmap_array+=(-sV -O -Pn)
if [ $option_nmap = "2" ] ; then
script_array+=(banner,http-server-header,ajp-headers,http-chrono,https-redirect,http-php-version,http-affiliate-id,http-referer-checker,http-auth,http-auth-finder,http-csrf,http-phpself-xss,http-dombased-xss,http-unsafe-output-escaping,http-rfi-spider,mysql-info,mysql-empty-password,ftp-anon,rpcinfo,ssh-auth-methods,ssh2-enum-algos,sshv1,http-sql-injection,http-malware-host,http-open-proxy,http-enum,http-phpmyadmin-dir-traversal,http-slowloris-check,smtp-strangeport,ssl-poodle,ssl-heartbleed,sslv2,ssl-enum-ciphers,ssl-dh-params,tls-alpn,vulners,http-methods)
else
script_array+=(banner,http-server-header,ajp-headers,http-chrono,https-redirect,http-php-version,http-affiliate-id,http-referer-checker,mysql-info,sslv2,ssl-enum-ciphers,ssl-dh-params,tls-alpn,vulners) ; fi 
echo -e "\n${B}Ports   > Current target ports > ${D}\n"
echo -e "${B} >${D} $web_ports"
echo -e -n "\n${B}Ports   >${D}  Customize ports? ${B} [y] | [n] ?${D}  " ; read option_ports
if [ $option_ports = "y" ] ; then
echo -e -n "\n${B}Set     > Ports  ${D}- e.g. 636,989-995  ${B}>>${D} " ; read add_ports
port_array+=(${add_ports}) ; else 
port_array+=(${web_ports}) ; fi ; fi
echo -e "\n${B}Options > \n"
echo -e "${B} [1]${D} Display Security Headers & HTML Comments" 
echo -e "${B} [2]${D} Check for Black-/Blocklisting" 
echo -e "${B} [3]${D} BOTH" 
echo -e "${B} [9]${D} SKIP" 
echo -e -n "\n${B}  ? ${D}  " ; read option_web_additional ; fi 
echo -e "\n${B}Options > SSL/TLS${D}"
echo -e "\n${B}Options > \n"
echo -e "${B} [1]${D} Certificate Status (Certspotter API & openSSL)"
echo -e "${B} [2]${D} openSSL filedump"
echo -e "${B} [3]${D} BOTH" 
echo -e "${B} [9]${D} SKIP" 
echo -e -n "\n${B}  ? ${D}  " ; read option_ssl_1
if [ $answer = "1" ] ; then 
echo -e -n "\n${B}Options >${B} Nmap > [1]${D} SSL/TLS Cipher Enum  ${B}| [2]${D} SSH Cipher Enum ${B}| [3]${D} BOTH  ${B}| [9]${D} SKIP ${B}?${D}  "
read option_ssl_2
if ! [ $option_ssl_2 = "9" ] ; then
if [ $option_ssl_2 = "2" ] ; then
echo -e -n "\n${B}Ports  > [1]${D} Port 22  ${B}| [2]${D} Custom Ports  ${B}?${D}  " ; read portChoice
if   [ $portChoice = "1" ] ; then
p="22" ; else
echo -e -n "\n${B}Ports  >  Ports  ${D}- e.g. 636,989-995  ${B}>>${D}  " ; read p ; fi
elif [ $option_ssl_2 = "3" ] ; then
echo -e -n "\n${B}Ports  > [1]${D} Ports 22, 443  ${B}| [2]${D} Custom Ports  ${B}?${D}  " ; read portChoice
if   [ $portChoice = "1" ] ; then
p="22,443" ; else
echo -e -n "\n${B}Ports  >  Ports  ${D}- e.g. 636,989-995  ${B}>>${D}  " ; read p ; fi ; else
echo -e -n "\n${B}Ports  > [1]${D} Port 443  ${B}| [2]${D} Custom Ports  ${B}?${D}  " ; read portChoice
if   [ $portChoice = "1" ] ; then
p="443" ; else
echo -e -n "\n${B}Ports  >  Ports  ${D}- e.g. 636,989-995  ${B}>>${D}  " ; read p ; fi ; fi
fi ; fi
echo -e -n "\n${B}Options >${D} SSL/TLS ${B} > [1]${D} testssl  ${B}| [2]${D} curl handshake analysis ${B}| [3]${D} BOTH  ${B}| [9]${D} SKIP  ${B}?${D}  "
read option_ssl_3 
fi ; f_solidLong ; touch $tempdir/hosts.list
if [[ $target =~ ${REGEX_IP4} ]]; then
echo -e -n "\n${B}Target > [1]${D} set target domain ${B}| [2]${D} Target List  ${B}?${D}  " ; read option_target ; else
echo -e -n "\n${B}Target > [1]${D} set target domain ${B}| [2]${D} Target List ${B}| [3] current > ${D} $target  ${B}?${D}  " ; read option_target ; fi
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D}Domain ${B}|${D} Hostname ${B}>>${D}  " ; read input
echo "$input" > $tempdir/hosts.list
hosts="$tempdir/hosts.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}  " ; read input
hosts="${input}"
elif [ $option_target = "3" ] ; then
echo "$target" > $tempdir/hosts.list
hosts="$tempdir/hosts.list" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
f_solidLong
for x in $(cat $hosts) ; do
if [ $answer = "1" ] ; then 
output="$out/TLS_SSH.${x}.txt" ; else 
output="$out/WEB.${x}.txt" ; fi 
if [ $option_connect = "9" ] ; then
echo -e "\n${B}$x Certificate Status ${D}\n"
echo -e "\n\n == $x SSL/TLS STATUS  == \n" >> ${output}
f_certSpotter "${x}" | tee -a ${output} ; f_solidShort | tee -a ${output}
if [ $answer = "2" ] ; then 
option_details="2" ; f_WHATWEB "${x}"
ip4=`grep -oP '(IP\[).*?(?=])' $tempdir/ww.txt | tail -1 | sed 's/IP\[//' | grep -E -o "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"`
f_BOX_BANNER "${ip4}" ; echo '' | tee -a ${output}
f_WHATWEB_REDIR | tee -a ${output} ; f_WHATWEB_PAGE | tee -a ${output}
echo -e "[+] Server & Web-Tech" | tee -a ${output}
f_BANNERS "${ip4}" | tee -a ${output} ; f_WHATWEB_CODE | tee -a ${output}
f_solidShort | tee -a ${output} ; f_DRWHO  "${ip4}" | tee -a ${output} ; fi ; else 
if [ $answer = "2" ] ; then 
if [ $option_ssl_3 = "2" ] || [ $option_ssl_3 = "3" ] ; then 
curl_array+=(-sLk4v --trace-time) ; else 
curl_array+=(-sLk4) ; fi 
f_WriteOut "${x}" 
ip4="$(egrep -m 1 -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/response.txt)"
if ! [ $option_details = "9" ] ; then 
f_BOX_BANNER "${ip4}" ; echo '' ; else 
f_BOX "${x}" ; echo '' ; fi
cat $tempdir/response.txt | tee -a ${output} ; f_solidShort | tee -a ${output}
f_WHATWEB "${x}" ; echo -e "\n[+] Web Site\n" | tee -a ${output}
f_WHATWEB_PAGE | tee -a ${output} ; f_socialLinks "${x}"  | tee -a ${output}
f_solidShort | tee -a ${output} ; echo -e "[+] Web-Tech" | tee -a ${output} 
f_WHATWEB_CODE | tee -a ${output} ; echo -e "\n\n[+] Service Banners" | tee -a ${output}
f_BANNERS "${ip4}" | tee -a ${output}
if ! [ $option_details = "9" ] ; then 
f_DRWHO "${ip4}" | tee -a ${output}
f_solidShort | tee -a ${output}
if [ $option_details = "2" ] ; then 
prefix=`cut -d '|' -f 3 $tempdir/cymru.txt | tr -d ' '`
f_PREFIX "${prefix}" | tee -a ${output} ; f_solidShort | tee -a ${output} ; fi ; fi
if [ $option_web_additional = "2" ] || [ $option_web_additional = "3" ] ; then 
f_BLACKLISTS "${ip4}" | tee -a ${output} ; f_solidShort | tee -a ${output} ; fi ; fi 
if [ $option_ssl_1 = "1" ] || [ $option_ssl_1 = "3" ]; then
echo -e "\n${B}$x Certificate Status ${D}\n"
echo -e "\n\n == $x SSL/TLS STATUS  == \n" >> ${output}
f_certSpotter "${x}" | tee -a ${output} ; f_solidShort | tee -a ${output}
f_certInfo "${x}" | tee -a ${output} ; f_solidLong | tee -a ${output} ; fi 
if [ $option_ssl_1 = "2" ] ; then
f_certInfo "${x}" | tee -a ${output} ; f_solidShort | tee -a ${output}
echo | timeout 3 openssl s_client -connect ${x}:443 2>/dev/null | openssl x509 -text -fingerprint | fmt -w 80 -s 
echo '' | tee -a ${output} ; f_solidLong | tee -a ${output} ; fi
if [ $option_ssl_1 = "3" ] ; then
f_solidShort | tee -a ${output}
echo | timeout 3 openssl s_client -connect ${x}:443 2>/dev/null | openssl x509 -text -fingerprint | fmt -w 80 -s 
echo '' | tee -a ${output} ; f_solidLong | tee -a ${output} ; fi 
if [ $answer = "1" ] ; then 
if ! [ $option_ssl_2 = "9" ] ; then
echo -e "\n${B}${x} NMAP Cipher Enumeration ${D}\n\n" 
echo -e "\n == $x NMAP CIPHER ENUMERATION == \n" >> ${output} 
if [ $option_ssl_2 = "1" ] ; then
nmap -sT -Pn -p ${p} ${x} -oA ${out}/CIPHERS.${x} --script sslv2,ssl-enum-ciphers,ssl-dh-params,tls-alpn > $tempdir/nmap.txt 
elif [ $option_ssl_2 = "2" ] ; then
sudo nmap -sV -Pn -p ${p} ${x} -oA ${out}/CIPHERS.${x} --script banner,ssh-auth-methods,ssh2-enum-algos,sshv1,vulners  > $tempdir/nmap.txt 
elif [ $option_ssl_2 = "3" ] ; then
sudo nmap -sV -Pn -p ${p} -oA ${out}/SSH.${x} --script ${SSL_enum},${SSL_vulners},ssh-auth-methods,ssh2-enum-algos,sshv1 ${x} > $tempdir/nmap.txt ; fi 
cat $tempdir/nmap.txt | sed '/PORT/{x;p;x;G;}' | sed '/Read data files/d' | sed '/Starting Nmap/d' | tee -a ${output}
f_solidLong | tee -a ${output} ; fi ; fi
if [ $option_ssl_3 = "2" ] || [ $option_ssl_3 = "3" ] ; then
echo -e "\n${B}$x SSL/TLS Handshake (curl)${D}\n"
echo -e "\n\n == $x SSL/TLS HANDSHAKE (curl) == \n" >> ${output}
if [ $answer = "2" ] ; then
f_curlHandshake | tee -a ${output} ; f_solidLong | tee -a ${output} ; else 
curl_array+=(-sLk4v --trace-time) ; f_WriteOut "${x}" 
cat $tempdir/response.txt | tee -a ${output} ; f_solidShort | tee -a ${output} 
f_curlHandshake | tee -a ${output} ; f_solidLong | tee -a ${output} ; fi ; fi 
if [ $option_ssl_3 = "1" ] || [ $option_ssl_3 = "3" ] ; then
echo -e "${B}${x} Testssl ${D}\n\n" ; echo -e " == ${x} TESTSSL == \n\n" >> ${output}
testssl --quiet --phone-out --ids-friendly --color 0 ${x} | tee -a ${output}
f_solidLong | tee -a ${output} ; fi
if [ $answer = "2" ] ; then
if ! [ $option_nmap = "9" ] ; then 
echo -e "\n${B}${x} Server Enum & Vulnerabilities${D}\n\n"
echo -e "\n== ${x} NMAP RESULTS (SERVER ENUM / VULNERABILITIES) == \n" >> ${output} 
if [ $option_nmap = "2" ] ; then
sudo nmap ${nmap_array[@]} -p ${port_array[@]} ${x} -oA ${out}/WEB.${x} --script ${script_array[@]} --script-args http-methods.test-all > $tempdir/nmap.txt ; else 
sudo nmap ${nmap_array[@]} -p ${port_array[@]} ${x} -oA ${out}/WEB.${x} --script ${script_array[@]} > $tempdir/nmap.txt ; fi 
cat $tempdir/nmap.txt | sed '/PORT/{x;p;x;}' | sed '/Starting Nmap/d' | sed '/Read data files/d' | sed '/NSE/d' |
sed '/Nmap scan report/{x;p;x;}' | sed '/Initiating/d' | sed '/Completed/d' | sed '/Discovered/d' | sed '/\/tcp /{x;p;x;G;}' |
sed '/Service detection/d' | sed '/Aggressive OS guesses:/{x;p;x;}' | sed '/Uptime guess:/{x;p;x;}' | sed '/Network Distance:/{x;p;x;}' |
fmt -s -w 120 | tee -a ${output} ; f_solidLong | tee -a ${output} ; fi
echo -e "\n${B}${x} HTTP Headers ${D}\n\n"
echo -e "\n == ${x} HTTP HEADERS == \n" >> ${output} 
curl -sILk --max-time 3 ${x} | fmt -s -w 80 | tee -a $out/Headers.${x}.txt
echo -e "\n${IT}Dumping robots.txt to output folder...${D}\n"
curl -sLk ${x}/robots.txt | fmt -s -w 100 > $out/ROBOTS.${x}.txt
if [ $option_web_additional = "2" ] || [ $option_web_additional = "3" ] ; then 
echo -e "\n\n[+] HTML Comments & Security Headers\n\n" | tee -a ${output}
sudo nmap -sS -Pn -p 80,443,8009 -oA ${out}/COMMENTS.${x} --script http-security-headers,http-comments-displayer ${x} | sed '/PORT/{x;p;x;G;}' | sed '/Read data files/d' |
sed '/NSE/d' | sed '/Initiating/d' | sed '/Completed/d' | sed '/Discovered/d' | sed '/Host is up/d' |
sed '/Starting Nmap/d' | fmt -w 100 -s | tee -a ${output} ; fi ; fi 
fi ; done 
echo '' ; f_Menu ; f_removeDir
;;
6) f_optionsIPV6 ;;
7)
f_makeNewDir ; f_dashedGrey
echo -e -n "${B}\nTarget > ${D} e.g. UA-123456 ${B}>>${D}  " ; read ua
echo -e "\n[+] $ua REVERSE ANALYTICS LOOKUP \n\n" >> $out/Rev_GoogleAnalytics.txt
curl -s https://api.hackertarget.com/analyticslookup/?q=${ua} | tee -a $out/Rev_GoogleAnalytics.txt
f_solidShort >> $out/Rev_GoogleAnalytics.txt
echo '' ; f_Menu ; f_removeDir
;;
11) f_optionsWEBSERVERS ;;
12) f_options_SERVERS ;;
13)
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}pwhois.org Bulk Lookup (IPv4/IPv6)\n"
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}   " ; read input
echo -e -n "\n${B}Option > Output > [1]${D} type pwhois default  ${B}| [2]${D} type cymru (table layout)  ${B}?${D}  " ; read option_pwhois
touch $tempdir/ips.txt
if [ $option_pwhois = "2" ]; then
echo -e "begin\ntype=cymru" > $tempdir/iplist.txt ; else
echo "begin" > $tempdir/iplist.txt ; fi
cat $input >> $tempdir/iplist.txt ; echo "end" >> $tempdir/ips.txt
netcat whois.pwhois.org 43 < $tempdir/iplist.txt > $tempdir/pwhois_bulk.txt
if [ $option_pwhois = "1" ]; then
cat $tempdir/pwhois_bulk.txt | sed '/IP:/i \\n____________________\n' | tee -a $out/pwhois_bulk.txt ; else
cat $tempdir/pwhois_bulk.txt | sed '/ORG NAME/{x;p;x;G;}' | tee -a $out/pwhois_bulk.txt ; fi
echo '' | tee -a $out/pwhois_bulk.txt ; f_solidLong >> $out/pwhois_bulk.txt
f_Menu ; f_removeDir
;;
14)
f_makeNewDir ; f_dashedGrey
echo -e "\n\n${B}Options > Set > DNS Query / Record Type  >\n "
echo -e -n " > ${B} [1]${D} A  ${B}| [2]${D} AAAA  ${B}| [3]${D} SRV  ${B}| [4]${D} Delegation Tracing & DNSSEC  ${B}?${D}  " ; read option_record
echo -e "\n${B}Nameservers (System Defaults)${D}\n"
cat /etc/resolv.conf | sed '/#/d' | grep 'nameserver' 
echo -e -n "\n${B}Options > ${D} Nameserver ${B}> [1]${D} Use system defaults ${B}| [2]${D} use 1.1.1.1  ${B}| [3]${D} set custom NS  ${B}?${D}  " 
read option_ns
if [ $option_ns = "2" ] ; then
dig_array+=(@1.1.1.1) ; nssrv_dig="@1.1.1.1"
elif [ $option_ns = "3" ] ; then
echo -e -n "\n${B}Set     >${D} Nameserver  ${B} >>${D}   " ; read nssrv
dig_array+=(@nssrv) ; nssrv_dig="@${nssrv}" ; else 
nssrv_dig="" ; fi 
if [ $option_record = "2" ] ; then
dig_array+=(aaaa)
elif [ $option_record = "3" ] ; then 
dig_array+=(srv) ; else 
: ; fi 
if [ $option_record = "4" ] ; then
echo -e -n "\n${B}Option > ${D} DNS Delegation Tracing  >  Show DNSSEC Records   ${B}[y] | [n] ?${D}  " ; read option_dnssec
if [ $option_dnssec = "y" ] ; then
dig_array+=(+nocmd +noall +answer +trace +noclass +dnssec +split=4) ; else 
dig_array+=(+nocmd +noall +answer +trace +noclass +nodnssec) ; fi ; else 
echo -e -n "\n${B}Option > Output > [1]${D} Short Mode  ${B}| [2]${D} Record Type & Query Address / URL ${B}?${D}  " ; read option_short
if [ $option_short = "2" ] ; then 
dig_array+=(+noall +answer +noclass +nottlid) ; else 
dig_array+=(+short) ; fi ; fi 
if [ $report = "true" ] ; then
echo -e -n "\n${B}Set     >  ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename
output="$out/${filename}.txt" ; else
output="$tempdir/out14" ; fi
f_solidShort | tee -a ${output}
echo -e "[+] dig Batch Mode - Type > $record\n\n" | tee -a ${output}
${dig_array[@]} -f ${input} | tee -a ${output}
echo '' | tee -a ${output}
f_Menu ; f_removeDir
;;
22)
#****** 22) DISCOVER DOMAINS SHARING A COMMON WEBSERVER ******
f_makeNewDir ; f_dashedGrey
if ! [[ $target =~ ${REGEX_IP4} ]]; then
echo -e "\n${B}Shared DNS Server (via hackertarget.com)${D}\n"
echo -e "${B}Domain NS Records${D}\n"
dig ns +short $target | rev | cut -c 2- | rev ; fi
echo -e -n "\n${B}Target >${D} Nameserver ${B}>>${D}  " ; read targetNS ; echo ''
echo -e "\n== DOMAINS SHARING $targetNS (via hackertarget.com) == \n" >> $out/Domains_sharing_$targetNS.txt
curl -s https://api.hackertarget.com/findshareddns/?q=${targetNS}${api_key_ht} | tee -a $out/Domains_sharing_$targetNS.txt
echo '' | tee -a $out/Domains_sharing_$targetNS.txt
f_solidLong >> $out/Domains_sharing_$targetNS.txt ; f_Menu ; f_removeDir
;;
23)
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}Zone Transfer"
echo -e -n "\n${B}Target >${D} DOMAIN ${B}>>${D}  " ; read target_dom
if [ $option_connect = "9" ] ; then
echo -e "\n\n == $target_dom ZONETRANSFER (via hackertarget.com) ==\n\n" >> $out/NS.$target_dom.txt
curl -s https://api.hackertarget.com/zonetransfer/?q=${target_dom}${api_key_ht}  | tee -a $out/NS.$target_dom.txt
echo '' | tee -a $out/NS.$target_dom.txt ; else
echo -e -n "\n${B}Tools  > [1]${D} dig  ${B}|  [2]${D}  hackertarget.com API  ${B}?${D}  "  ; read source
if   [ $source = "2" ] ; then
curl -s https://api.hackertarget.com/zonetransfer/?q=${target_dom}${api_key_ht}  | tee -a $out/NS.$target_dom.txt ; else
echo -e -n "\n${B}Server > [1]${D} All NS records ${B}| [2]${D} specific name server  ${B}?${D}  " ; read option_ns
if   [ $option_ns = "2" ] ; then
echo -e -n "\n${B}Target >${D} NAME SERVER ${B}>>${D}  " ; read target_ns ; echo ''
dig axfr @${target_ns} $target_dom | tee -a $out/NS.$target_dom.txt ; else
dig ns +short $target_dom | rev | cut -c  2- | rev > $tempdir/ns.txt
for i in $(cat $tempdir/ns.txt); do
dig axfr @${i} $target_dom | tee -a $out/NS.$target_dom.txt ; done ; fi
fi ; echo '' | tee -a $out/NS.$target_dom.txt ; fi
f_solidLong >> $out/NS.$target_dom.txt ; f_removeDir ; f_Menu
;;
24)
f_makeNewDir ; f_dashedGrey ; option_server="y" ; option_banners="n" ; type_net="false" ; option_ww="n"
if ! [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Options  >${D} Targets ${B}> [1]${D} Domain Name Servers  ${B}| [2]${D} Domain MX Servers  ${B}| [3]${D} MX Servers List  ${B}?${D}  "  ; read option_target
if [ $option_target = "3" ] ; then
echo -e -n "\n${B}Target   > ${D}PATH TO FILE ${B}>>${D}  " ; read input ; else 
if [[ $target =~ ${REGEX_IP4} ]]; then
echo -e -n "\n${B}Target   > ${D}DOMAIN  ${B} >>${D}   " ; read dom ; else
echo -e -n "\n${B}Target   > [1]${D} new target ${B}| [2] current > ${D} $target  ${B}?${D}  " ; read answer 
if [ $answer = "2" ] ; then
dom=`echo $target` ; else
echo -e -n "\n${B}Target   > ${D}DOMAIN  ${B} >>${D}   " ; read dom ; fi ; fi ; fi
echo -e -n "\n${B}Options  >${D} whois & geolocation ${B} > [1]${D} Summary ${B}| [2]${D} Details, incl. DNS Consistency & Delegation ${B}| [9]${D} SKIP  ${B}?${D}  "
read option_details
echo -e -n "\n${B}Option   >${D} Check for Black-/Blocklisting?  ${B} [y] | [n]  ${B}?${D}  " ; read option_blacklist
echo -e "\n${B}Options > Nmap Port- & Service-Scans\n" 
echo -e "${B} [1]${D} NS Servers (DNSid, Bind-version, Path-mtu, CVE Vulners)"   
echo -e "${B} [2]${D} NS- & MX Servers ([1], SSH Algos, SMTP Methods & Users)"  
echo -e "${B} [3]${D} NS- & MX Servers (Above, including Open Relay & Open Proxy Checks)" 
echo -e "${B} [9]${D} SKIP"
echo -e -n "\n${B}  ?${D}  " ; read option_nmap
if [ $option_nmap = "1" ] ; then 
nmap_array+=(-Pn -sU -sT -sV --version-intensity 2)
port_array+=(U:53,T:53,T:25,T:443,T:853)
scripts="path-mtu,dns-nsid,vulners"
elif [ $option_nmap = "2" ] ; then 
nmap_array+=(-Pn -sU -sT -sV --version-intensity 3)
scripts="http-server-header,https-redirect,ssl-enum-ciphers,ssl-dh-params,tls-alpn,ssh2-enum-algos,banner,smtp-commands,smtp-ntlm-info,smtp-enum-users.nse,imap-capabilities,imap-ntlm-info,pop3-capabilities,pop3-ntlm-info,path-mtu,dns-nsid,vulners"
port_array+=(U:53,T:53,T:22,T:25,T:80,T:143,T:443,T:465,T:587,T:691,T:853)
elif [ $option_nmap = "3" ] ; then 
nmap_array+=(-Pn -sU -sT -sV -O --version-intensity 5)
port_array+=(U:53,T:53,T:22,T:25,T:80,T:143,T:443,T:465,T:587,T:691,T:853)
scripts="http-server-header,https-redirect,ssl-enum-ciphers,ssl-dh-params,tls-alpn,ssh2-enum-algos,smtp-open-relay,http-open-proxy,http-malware-host,path-mtu,dns-nsid,vulners"
else 
: ; fi 
echo -e -n "\n${B}Options  >${D} MTR Mode ${B}> [1]${D} TCP ${B}| [2]${D} ICMP ${B}| [3]${D} BOTH ${B}| [9]${D} SKIP  ${B}?${D}  "
read option_mtr
if [ $option_mtr = "2" ] ; then
mtr_protocol='icmp' 
elif [ $option_mtr = "1" ] || [ $option_mtr = "3" ] ; then
if [ $option_target = "2" ] || [ $option_target = "3" ] ; then 
echo -e -n "\n${B}Options  >${D} MTR Target Port ${B}> [1]${D} tcp/25 (SMTP) ${B}| [2]${D} tcp/143 (IMAP)  ${B}?${D}  " ; read mtr_tport 
if [ $mtr_tport = "2" ] ; then
tport="143" ; else 
tport="25" ; fi ; else 
echo -e -n "\n${B}Options  >${D} MTR Target Port ${B}> [1]${D} tcp/53 (DNS) ${B}| [2]${D} tcp/853 (DNS/TLS)  ${B}?${D}  " ; read mtr_tport 
if [ $mtr_tport = "2" ] ; then
tport="853" ; else 
tport="53" ; fi ; fi 
else 
: ; fi 
if [ $option_target = "1" ] ; then 
echo -e "\n\n${B}Nameservers (System Defaults)${D}\n"
cat /etc/resolv.conf | sed '/#/d'
echo -e -n "\n${B}Option > [1]${D} Select custom nameserver ${B}| [2]${D} use 1.1.1.1  ${B}?${D}  " ; read option_ns_choice
if [ $option_ns_choice = "1" ] ; then
echo -e -n "\n${B}Set    > Default Nameserver  ${B} >>${D}   " ; read nssrv ; else
nssrv="1.1.1.1" ; fi 
echo -e -n "\n${B}Option  >${D} Zonetransfer ${B}> [1]${D} dig  ${B}|  [2]${D}  hackertarget.com API ${B}| [9]${D} SKIP  ${B}?${D}  "  ; read option_transfer
echo -e "$(dig ns +short $dom)" > $tempdir/targets.list ; input="$tempdir/targets.list"
output="$out/NS.${dom}.txt" ; f_solidShort ; echo -e " [ $dom A, MX & NS Records ] \n\n" > ${output}
echo -e "\n[+] Domain Host A\n"
dig @${nssrv} +trace +nodnssec +ttlunits +noclass ${dom} | grep 'A\|Received' | sed 's/;;//' | sed '/A/{x;p;x;G}' | sed 's/^ *//' | tee -a ${output}
f_solidShort | tee -a ${output}
echo -e "[+] MX\n" | tee -a ${output}
dig @${nssrv}  mx +noall +answer +ttlunits +noclass +stats ${dom} | grep -A 2 -w 'MX' | sed 's/;; Query time:/Time:/' |  sed -n '/;;/!p' |
sed '/Time:/{x;p;x;}' | tee -a ${output}
f_solidShort | tee -a ${output} ; echo -e "[+] NS\n" | tee -a ${output}
dig @${nssrv} ns +noall +answer +ttlunits +noclass +stats ${dom} | grep -A 2 -w 'NS' | sed 's/;; Query time:/Time:/' |  sed -n '/;;/!p' |
sed '/Time:/{x;p;x;}' | tee -a ${output}
echo -e "\n\n[+] NS A\n" | tee -a ${output}
dig @${nssrv} +noall +answer +ttlunits +noclass +stats $(dig ns +short ${dom}) | sed 's/;; Query time:/Time:/' | grep -A 1 -w 'A' |
sed '/Time:/{x;p;x;G;}' | tee -a $tempdir/ns_ip4.txt ; cat $tempdir/ns_ip4.txt >> ${output}
echo -e "\n\n[+] NS A PTR-Records\n" | tee -a ${output}
for i in $(grep -w 'A' $tempdir/ns_ip4.txt | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}') ; do
dig @${nssrv}  +noall +answer +ttlunits +noclass -x ${i} | sed '/PTR/{x;p;x;}' | tee -a ${output} ; done
echo -e "\n\n[+] NS AAAA\n" | tee -a ${output}
dig @${nssrv} aaaa +noall +answer +ttlunits +noclass +stats $(dig ns +short ${dom}) | sed 's/;; Query time:/Time:/' | grep -A 1 -w 'AAAA' |
sed '/Time:/{x;p;x;G;}' | tee -a ${output}
f_solidShort | tee -a ${output} ; echo -e "[+] SOA Record\n\n" | tee -a ${output}
dig @${nssrv} soa +noall +answer +ttlunits +noclass $dom | tee -a ${output}
dig @${nssrv} soa +noall +answer +multiline ${dom} > $tempdir/soa.txt
awk '{ print  $1 $2,   $3, $4, $5 }' $tempdir/soa.txt | sed '1,1d' |
sed '$d'  | sed '/serial/{x;p;x;}'  | tee -a  ${output} ; f_solidShort | tee -a ${output}
dig @${nssrv} +nssearch ${dom} | sed '/SOA/{x;p;x;}' | sed 's/from/\nfrom/' | tee -a ${output}
f_solidShort | tee -a ${output} 
echo -e "[+] Zone Config Best Practice Check (nmap)\n\n" | tee -a ${output} 
soa=`dig soa +short $dom` ; soa_host=`echo "$soa" | cut -d ' ' -f 1`
nmap -sn -Pn ${soa_host} --script dns-check-zone --script-args=dns-check-zone.domain=$dom |
sed '/Host discovery disabled /d' | sed '/Host is up/d' | sed '/Starting Nmap/d' |
sed '/Nmap done/d' | sed '/Other addresses/d' | sed 's/Nmap scan report for//'  | tee -a ${output}
if ! [ $option_transfer = "9" ] ; then
f_solidLong | tee -a ${output} ; echo '' > $tempdir/zone.txt
echo -e "${B}Zone Transfer${D}" ; echo -e "\n == ZONE TRANSFER  ==\n" >> ${output}
if   [ $option_transfer = "1" ] ; then
ns=$(dig ns +short ${dom}) ;
for i in $(echo "$ns"); do
echo '' > $tempdir/zone.txt 
dig axfr @${i} $dom >> $tempdir/zone.txt ; done ; else 
curl -s https://api.hackertarget.com/zonetransfer/?q=${dom}${api_key_ht} >> $tempdir/zone.txt ; fi
echo '' >> $tempdir/zone.txt ; cat $tempdir/zone.txt | tee -a ${output} ; fi
elif [ $option_target = "2" ] ; then
echo -e "$(dig mx +short $dom | cut -d ' ' -f 2)" > $tempdir/targets.list 
input="$tempdir/targets.list" ; output="$out/MX.${dom}.txt"
f_solidShort ; echo -e " [ $dom MX Records ] \n\n" > ${output}
echo -e "[+] MX\n" | tee -a ${output}
dig mx +noall +answer +ttlunits +noclass +stats ${dom} | grep -A 2 -w 'MX' | sed 's/;; Query time:/Time:/' |  sed -n '/;;/!p' |
sed '/Time:/{x;p;x;}' | tee -a ${output}
echo -e "________\n" | tee -a ${output} ; echo -e "[+] MX A\n" | tee -a ${output}
dig +noall +answer +ttlunits +noclass +stats $(dig mx +short ${dom}) | sed 's/;; Query time:/Time:/' | grep -A 1 -w 'A' |
sed '/Time:/{x;p;x;G;}' | tee -a $tempdir/mx_ip4.txt ; cat $tempdir/mx_ip4.txt >> ${output}
f_solidShorter | tee -a ${output} ; echo -e "[+] MX A PTR-Records\n" | tee -a ${output}
for i in $(grep -w 'A' $tempdir/mx_ip4.txt | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}') ; do
dig +noall +answer +ttlunits +noclass -x ${i} | sed '/PTR/{x;p;x;}' | tee -a ${output} ; done
echo -e "___________\n" | tee -a ${output} ; echo -e "[+] MX AAAA\n" | tee -a ${output}
dig -t aaaa +noall +answer +ttlunits +noclass +stats $(dig mx +short ${dom}) | sed 's/;; Query time:/Time:/' | grep -A 1 -w 'AAAA' |
sed '/Time:/{x;p;x;G;}' | tee -a ${output} ; else 
: ; fi 
for x in $(cat ${input}) ; do
f_solidLong | tee -a ${output}
if [[ $x =~ ${REGEX_IP4} ]]; then
ip4=`echo $x` ; else 
ip4=`dig +short $x | head -1` ; fi
f_OUTPUT_HEADER "${x}"
if ! [ $option_details = "9" ]  ; then
f_BOX_BANNER "${ip4}" ; else 
f_BOX " ${x} " ; fi ; echo '' | tee -a ${output}
if ! [ $option_nmap = "9" ] ; then
sudo nmap ${nmap_array[@]} -p ${port_array[@]} ${ip4} -oA ${out}/NS_MX.${ip4} --script $scripts | sed '/PORT/{x;p;x;G;}' | sed '/\/tcp /{x;p;x;}' |
sed '/Read data files/d' | sed '/NSE/d' | sed '/Initiating/d' | sed '/Completed/d' | sed '/Discovered/d' | sed '/Service detection/d' | 
sed '/Aggressive OS guesses:/{x;p;x;}' | sed '/Uptime guess:/{x;p;x;}' | sed '/Nmap scan report/{x;p;x;}' |
sed '/Network Distance:/{x;p;x;}' | fmt -w 120 -s | tee -a ${output} ; fi
if [ $option_blacklist = "y" ] ; then
f_solidShort | tee -a ${output} 
f_BLACKLISTS "${ip4}" | tee -a ${output} ; fi 
if ! [ $option_details = "9" ] ; then
f_solidShort | tee -a ${output}
echo -e "${B} $x Geolocation $ whois${D}\n"
f_DRWHO "${ip4}" | tee -a $output 
if [ $option_details = "2" ] ; then
prefix=`cut -d '|' -f 3 $tempdir/cymru.txt | tr -d ' '`
f_solidShort | tee -a ${output} 
f_PREFIX "${prefix}" | tee -a ${output}
f_solidShort | tee -a ${output} ; f_BOX " ${prefix} - Details "
echo -e "\n\n == BGP- PREFIX DETAILS  ($prefix) ==\n\n" >> ${output}
echo -e "\n"
f_DELEGATION "${prefix}" | tee -a ${output}
echo -e "\n___________________________\n" | tee -a ${output}
echo -e "[+] Reverse DNS Consistency\n" | tee -a ${output}
curl -s https://stat.ripe.net/data/reverse-dns-consistency/data.json?resource=${prefix} > $tempdir/dns.json
jq -r '.data.prefixes.ipv4' $tempdir/dns.json | grep 'complete' | tr -d ',\"' |
sed 's/^ *//' | sed '/complete/G' | tee -a ${output}
jq -r '.data.prefixes.ipv4' $tempdir/dns.json | grep 'prefix\|found' | tr -d '],\"[' | cut -d ':' -f 2- | tr -d ' ' | tee -a ${output}
f_solidShorter | tee -a ${output}
echo -e "[+] Prefix Geographic Distribution\n" | tee -a ${output}
f_NETGEO "${prefix}" | tee -a ${output} ; fi ; fi 
if ! [ $option_mtr = "9" ] ; then
f_solidShort | tee -a ${output}
echo -e "${B}$x MTR ${D}"
echo -e " == ${x} MTR == " >> ${output}
if [ $option_mtr = "1" ] ||  [ $option_mtr = "3" ] ; then
echo -e "\n\n[+] TCP, Port > $tport, Mode > IPv4" | tee -a ${output}
sudo mtr -4 -T -b -c4 -w -z -P ${tport} -o "  L  S D  A BW  X  M" ${x} | sed '/Start:/{x;p;x;}'  | sed '/HOST:/G' |
tee -a ${output}
echo -e "\n\n[+] TCP, Port > $tport, Mode > Auto" | tee -a ${output}
sudo mtr -T -b -c2 -w -z -P ${tport} -o "  L  S D  A BW  X  M" ${x} | sed '/Start:/{x;p;x;}'  | sed '/HOST:/G' |
tee -a ${output} ; fi 
if [ $option_mtr = "2" ] ||  [ $option_mtr = "3" ] ; then
echo -e "\n\n[+] ICMP, Mode > IPv4" | tee -a ${output}
sudo mtr -4 -b -c4 -w -z -o "  L  S D  A BW  X  M" ${x} | sed '/Start:/{x;p;x;}'  | sed '/HOST:/G' |
tee -a ${output} ; fi 
echo '' | tee -a ${output}
f_solidShort | tee -a ${output}
echo -e "Snt = packages sent;  Wrst = worst RTT in ms; \nJavg = average jitter" | tee -a ${output}
fi ; done ; else 
f_WARNING ; fi ; echo '' ; f_Menu  ; f_removeDir
;;
33)
#************** 33-38) WHOIS & BPG OPTIONS ********************
f_makeNewDir ; f_dashedGrey
echo -e -n "\n${B}Target > [1]${D} new target   ${B}| [2] current target > ${D}  $target  ${B}?${D}  " ; read option_target
if   [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D}DOMAIN${B} | ${D}IP${B}  >>${D}   " ; read input ; else
input=`echo $target` ; fi
if [[ $input =~ ${REGEX_IP4} ]]; then
f_REGISTRY "${input}" ; echo -e "\n\n${B}$input reverse whois${D}\n\n"
f_revWHOIS | tee $tempdir/revWHOIS.txt
if [ $option_target = "2" ] ; then
echo -e "\n == $input REVERSE WHOIS  ==\n\n" | tee -a $out/WHOIS.txt >> $out/$target.txt
cat $tempdir/revWHOIS.txt >> $out/$target.txt ; cat $tempdir/revWHOIS.txt >> $out/WHOIS.txt ; else
echo -e "\n == $input REVERSE WHOIS  ==\n\n" >> $out/WHOIS.txt
cat $tempdir/revWHOIS.txt >> $out/WHOIS.txt ; fi
else
rev_whois_target=`host -t A $input | head -1 | cut -d " " -f 4` ; f_REGISTRY "$rev_whois_target"
echo -e "\n\n${B}$input whois lookup${D}\n\n" ; f_whoisLOOKUP "${input}"
if [ $option_target = "2" ] ; then
echo -e "\n== $whois_target WHOIS SUMMARY ==\n" | tee -a $out/WHOIS.txt >> $out/$target.txt
cat $tempdir/host-whois2.txt | tee -a $out/$target.txt
cat $tempdir/host-whois2.txt >> $out/WHOIS.txt
f_solidShort >> $out/WHOIS.txt ; f_solidShort >> $out/$target.txt ; else
echo -e "\n== $whois_target WHOIS SUMMARY ==\n"  >> $out/WHOIS.txt
cat $tempdir/host-whois2.txt | tee -a $out/WHOIS.txt ; f_solidShort >> $out/WHOIS.txt ; fi
echo -e "\n\n${B}$rev_whois_target reverse whois${D}\n\n"
f_revWHOIS | tee $tempdir/revWHOIS.txt
if [ $option_target = "2" ] ; then
echo -e "\n== $input ($rev_whois_target) REVERSE WHOIS ==\n\n" | tee -a $out/WHOIS.txt >> $out/$target.txt
cat $tempdir/revWHOIS.txt >> $out/$target.txt
cat $tempdir/revWHOIS.txt >> $out/WHOIS.txt ; else
echo -e "\n== $input ($rev_whois_target) REVERSE WHOIS ==\n\n" >> $out/WHOIS.txt
cat $tempdir/revWHOIS.txt >> $out/WHOIS.txt ; fi
fi
if [ $option_target = "2" ] ; then
f_solidLong  >> $out/$target.txt ; f_solidLong >> $out/WHOIS.txt ; else
f_solidLong >> $out/WHOIS.txt ; fi
echo '' ; f_Menu ; f_optionsWhois ; f_removeDir
;;
34)
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}Options >\n"
echo -e "${B} [1]${D} Search by AS- / Org-Name (bgpview.io)"
echo -e "${B} [2]${D} Search by Organisation Common Name (Registry Servers)"
echo -e "${B} [3]${D} RIPE whois Inverse Search"
echo -e -n "\n${B}  ?${D}  " ; read option_whois_1
if  [ $option_whois_1 = "1" ] ; then
echo -e -n "\n${B}Target  >  ${D}Name  ${B}>>${D} " ; read input
f_solidShort 
echo -e "\n${B}$input Results${D}\n\n"
echo -e "\n\n\n == $input SEARCH RESULTS (via bgpview.org) ==\n\n" >> $out/WHOIS.txt
f_BGPviewORG | tee -a $out/WHOIS.txt ; f_solidLong >> $out/WHOIS.txt
elif  [ $option_whois_1 = "2" ] ; then
echo -e -n "\n${B}Set     >   RIR > [1]${D} ARIN  ${B}| [2]${D} RIPE ORG SEARCH   ${B}| [3]${D} RIPE AS OR PERSON SEARCH  ${B}| [4]${D} OTHER  ${B}?${D} " ;
read option_whois_2
echo -e -n "\n${B}Target  >  ${D}Name  ${B}>>${D} " ; read input
if  [ $option_whois_2 = "1" ] ; then
echo -e "\n== $input SEARCH RESULTS (via whois.arin.net) ==\n\n" >> $out/WHOIS.txt
echo -e "\n"
whois -h whois.arin.net o ${input}
elif  [ $option_whois_2 = "2" ] ; then
echo -e "\n == $input SEARCH RESULTS (via whois.ripe.net) ==\n" >> $out/WHOIS.txt
whois -h whois.ripe.net -- " -B -T organisation ${input}" | sed 's/% Information related/Information related /'  | sed 's/% Abuse contact/Abuse contact/' |
sed '/%/d' | sed '/Information related/i \\n________________________________\n' > $tempdir/org.txt
cat $tempdir/org.txt | tee -a $out/WHOIS.txt
echo -e "\n________________\n" | tee -a $out/WHOIS.txt ; echo -e "[+] BGP Prefixes\n" | tee -a $out/WHOIS.txt
grep -w "^route:" $tempdir/org.txt | cut -d ':' -f 2- | sed 's/^ *//' | tee -a $out/WHOIS.txt
echo -e "\n___________________\n" | tee -a $out/WHOIS.txt ; echo -e "[+] E-Mail Contacts\n" | tee -a $out/WHOIS.txt
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/org.txt | sort -u | tee -a $out/WHOIS.txt
f_solidLong >> $out/WHOIS.txt
elif  [ $option_whois_2 = "3" ] ; then
echo -e "\n == $input SEARCH RESULTS (via whois.ripe.net) ==\n" >> $out/WHOIS.txt
echo -e "\n"
whois -h whois.ripe.net -- " -B ${input}" | sed 's/% Information related/Information related /'  | sed 's/% Abuse contact/Abuse contact/' |
sed '/%/d' | sed '/Information related/i \\n________________________________\n' | tee -a $out/WHOIS.txt
f_solidLong >> $out/WHOIS.txt ; else
echo -e -n "\n${B}Set     >${D} Registry, e.g. apnic ${B}>>${D} " ; read rir ; echo ''
whois -h whois.${rir}.net ${input} | tee -a $out/WHOIS.txt
f_solidLong >> $out/WHOIS.txt ; fi
elif  [ $option_whois_1 = "3" ] ; then
echo -e "\n${B}Options >\n"
echo -e " ${B}[1]${D} abuse-c  ${B}|  [3]${D} mnt-by"
echo -e " ${B}[2]${D} admin-c  ${B}|  [4]${D} origin"
echo -e -n "\n ${B} ?${D}  "  ; read option_whois_3
if  [ $option_whois_3 = "1" ] ; then
query_type="abuse-c"
elif  [ $option_whois_3 = "2" ] ; then
query_type="admin-c"
elif  [ $option_whois_3 = "3" ] ; then
query_type="mnt-by"
elif  [ $option_whois_3 = "4" ] ; then
query_type="origin" ; else
: ; fi
if  [ $option_whois_3 = "4" ] ; then
echo -e -n "\n${B}Target > ${D}Origin-AS, e.g. AS553 ${B}>>${D}  " ; read query_object ; else
echo -e -n "\n${B}Target > ${D}Object ${B}>>${D}  " ; read query_object ;  fi
echo -e "\n == INVERSE SEARCH RESULTS (via whois.ripe.net) ==\n" >> $out/WHOIS.txt
echo -e "Type > $query_type   Object > $query_object\n" >> $out/WHOIS.txt
whois -h whois.ripe.net -- " -B -i ${query_type} ${query_object}" | sed 's/% Information related/Information related /'  | sed 's/% Abuse contact/Abuse contact/' |
sed '/%/d' | sed '/Information related/i \\n________________________________\n' > $tempdir/inv.txt
echo -e "\n\n[+] $query_object Regular Search (whois.ripe.net)\n" | tee -a $out/WHOIS.txt
whois -h whois.ripe.net -B $query_object | sed '/^%/d' | tee -a $out/WHOIS.txt
f_solidShort | tee -a $out/WHOIS.txt ; echo -e "[+] $query_object Inverse Search Summary\n" | tee -a $out/WHOIS.txt
echo -e "[+] Networks\n" | tee -a $out/WHOIS.txt
grep -w -A 2 '^inetnum:' $tempdir/inv.txt | cut -d ':' -f 2- | tr -d ' ' | tee -a $out/WHOIS.txt
f_solidShorter | tee -a $out/WHOIS.txt
grep -w '^inetnum:' $tempdir/inv.txt | cut -d ':' -f 2- | tr -d ' ' > $tempdir/netranges.txt
declare -a ip_array=()
ip_array+=($(cut -d '-' -f 2 $tempdir/netranges.txt))
for i in "${ip_array[@]}" ; do
echo ''
curl -s https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=$i > $tempdir/ac.json
jq -r '.data.less_specifics[0]' $tempdir/ac.json  | tee -a $out/WHOIS.txt
jq -r '.data.less_specifics[1]' $tempdir/ac.json  | tee -a $out/WHOIS.txt; done
echo -e "\n___________________\n" | tee -a $out/WHOIS.txt ; echo -e "[+] E-Mail Contacts\n" | tee -a $out/WHOIS.txt
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/inv.txt | sort -u | tee -a $out/WHOIS.txt
echo '' | tee -a $out/WHOIS.txt ; cat $tempdir/inv.txt | tee -a $out/INVERSE_WHOIS.${query_object}.txt
f_solidLong >> $out/WHOIS.txt ; f_solidLong >> $out/INVERSE_WHOIS.${query_object}.txt ; else 
: ; fi
echo '' ; f_Menu ; f_optionsWhois ; f_removeDir
;;
35)
f_makeNewDir ; f_dashedGrey
touch $tempdir/targets.list
echo -e -n "\n${B}Target > [1]${D} Set target AS ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target  > ${D}AS Number (ASN) -e.g. ${B}AS${D}36459 ${B}>> AS${D}" ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e "${R}ERROR!${D}" ; exit 0
fi
echo -e -n "\n${B}Option > ${D} List BGP Prefixes (IPv4)  ${B} [y] | [n]  ${B}?${D}  " ; read option_as
for as in $(cat "$targets" | tr -d ' ') ; do
output="$out/AS.${as}.txt" ; f_solidLong
whois -h whois.cymru.com -- "-v -f as${as}" > $tempdir/cymru_asn.txt
as_country=`cut -d '|' -f 2  $tempdir/cymru_asn.txt | tr -d ' '`
echo '' ; f_BOX " AS ${as} - ${as_country} " 
echo '' | tee -a ${output} ; f_OUTPUT_HEADER "AS $as" ; f_AS_Description "${as}" | tee -a ${output}
if [ $option_as = "y" ] ; then
echo -e "\n_________________\n" | tee -a ${output} ; echo -e "[+] IPv4 Prefixes\n\n" | tee -a ${output}
whois -h asn.shadowserver.org prefix ${as} | tee -a ${output} ; fi 
done
f_solidLong >> ${output}
echo'' ; f_removeDir ; f_Menu ; f_optionsWhois
;;
36)
f_makeNewDir ; f_dashedGrey
echo -e -n "\n${B}Target > ${D} AS number -e.g. ${B}AS${D}36459 ${B}>> AS${D}" ; read as
echo -e "${B}Options > \n"
echo -e " ${B}[1]${D} BGP Prefixes   ${B}|  [3]${D} Up- & Downstream Transit"
echo -e " ${B}[2]${D} IX Membership  ${B}|  [4]${D} Peers"
echo -e -n "\n  ${B}?${D}  " ; read option_as
echo ''
if [ $option_as = "1" ] ; then 
echo -e -n "\n${B}Options > [1]${D} Prefixes only ${B}| [2]${D} Prefixes (incl. Netname, Description & Country)  ${B}?${D}  " ; read option_prefix
f_solidShort | tee -a $out/AS.$as.txt ; echo -e "\n\n${B} AS $as Prefixes${D}\n"
echo -e "\n == AS $as PREFIXES == \n\n"  >> $out/AS.$as.txt ; f_BGPviewPREFIXES | tee -a $out/AS.$as.txt
elif [ $option_as = "2" ] ; then
f_solidShort | tee -a $out/AS.$as.txt ; echo -e "[+] IX Memberships\n" | tee -a $out/AS.$as.txt
curl -s https://api.bgpview.io/asn/${s}/ixs | jq | sed -n '/data/,/@meta/{/data/!{/@meta/!p;}}' | tr -d ',[{"}]' 
sed 's/^ *//' | sed 's/name_full/full name/' | sed 's/country_code:/country:/' | tee -a $out/AS.$as.txt
elif [ $option_as = "3" ] ; then
f_solidShort | tee -a $out/AS.$as.txt
echo -e "${B} AS $as Upstream Transit ${D}\n"
echo -e "\n[+] AS $as UPSTREAM TRANSIT \n" >> $out/AS.$as.txt
f_BGPview_UPSTREAMS | tee -a $out/AS.$as.txt
f_solidShort | tee -a $out/AS.$as.txt
echo -e "\n[+] AS $as DOWNSTREAM TRANSIT \n" >> $out/AS.$as.txt
echo -e "${B} AS $as Downstream Transit ${D}\n"
f_BGPview_DOWNSTREAMS | tee -a $out/AS.$as.txt
elif [ $option_as = "4" ] ; then
echo '' ; f_solidShort | tee -a $out/AS.$as.txt
f_BGPview_PEERS ; else
: ; fi
echo'' ; f_removeDir ; f_Menu ; f_optionsWhois
;;
37)
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}IX Information \n\n"
echo -e -n "Target > ${D} IX ID - e.g. 25  ${B}>>${D}  " ; read ixid
echo -e "\n\n${B}IX $ixid Profile & Members${D}\n\n"
echo -e "\n\n==IX $ixid BGPVIEW QUERY RESULT == \n" >> $out/IX.$ixid.txt
f_BGPviewIX ; f_solidLong >> $out/IX.$ixid.txt ; echo '' ; f_Menu ; f_optionsWhois ; f_removeDir
;;
38)
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}Looking Glass (RIPESTAT DATA API)\n"
echo -e -n "Target > ${D}Network ${B}|${D} IP ${B}>>${D}  " ; read input
echo -e "\n== LOOKING GLASS (RIPESTAT API)==\n" > $out/LookingGlass.$input.txt
echo -e "Target > $input | Date > $(date)\n\n" >> $out/LookingGlass.$input.txt
curl -s https://stat.ripe.net/data/looking-glass/data.json?resource=${input} > $tempdir/lg.json
echo -e "\n"
jq -r '.data.rrcs[] | .rrc, .location, .peers' $tempdir/lg.json | sed 's/\]/\n/' | sed 's/\[/\n/' |
tr -d '{,;"}' | tee -a $out/LookingGlass.$input.txt
f_solidLong >> $out/LookingGlass.$input.txt ; echo '' ; f_Menu ; f_optionsWhois ; f_removeDir
;;
44)
#************** 44-47) IPV4 OPTIONS *******************
f_makeNewDir ; f_dashedGrey ; touch $tempdir/targets.list
option_server="n" ; type_net="false"
echo -e "\n${B}Options > IPv4 Addresses >\n"
echo -e " ${B}[1]${D} Address Info          ${B}|  [11]${D} Address Info   (target list)"
echo -e " ${B}[2]${D} Address Virtual Hosts ${B}|  [12]${D} Address VHosts (target list)"
echo -e -n "\n ${B} ?${D}  "  ; read option_ipv4_1
if [ $option_ipv4_1 = "1" ] || [ $option_ipv4_1 = "2" ]   ; then
echo -e -n "\n${B}Target > ${D}  IPV4 ADDRESS ${B} >>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_ipv4_1 = "11" ] || [ $option_ipv4_1 = "12" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
if [ $option_ipv4_1 = "1" ] || [ $option_ipv4_1 = "11" ]  ; then
echo -e -n "\n${B}Option > geolocation & whois > [1]${D}  Summary  ${B}| [2]${D}  Details ${B}?${D}  " ; read option_details
if [ $option_details = "2" ] ; then
echo -e -n "\n${B}Option > geolocation & whois > ${D} Show BGP prefix details  ${B}[y] | [n] ?${D}  "  ; read option_prefix ; fi 
echo -e -n "\n${B}Option > [1]${D} IP, network blacklist info ${B}| [2]${D} Target server virtual hosts ${B}| [3]${D} BOTH ${B}| [9] ${D}SKIP ${B}?${D}  " ; read option_ipv4_2
if [ $option_details = "2" ] ; then
option_banners="y"
echo -e -n "\n${B}Option >${D} If banner grab indicates webserver > get WhatWeb results ${B}[y] | [n] ?${D}  "  ; read option_ww ; fi
for x in $(cat "$targets") ; do
f_solidLong | tee -a ${output}
output="$out/${x}.txt" ; f_BOX_BANNER "${x}" ; f_OUTPUT_HEADER "${x}"
f_DRWHO "${x}" | tee -a ${output}
if [ $option_details = "2" ] ; then
prefix=`cut -d '|' -f 3 $tempdir/cymru.txt | tr -d ' '`
f_solidShort | tee -a ${output} 
f_PREFIX "${prefix}" | tee -a ${output} ; fi 
if [ $option_ipv4_2 = "1" ] || [ $option_ipv4_2 = "3" ] ; then
f_solidShort | tee -a ${output} 
f_BLACKLISTS "${x}" | tee -a ${output} ; f_RIPE_BLACKLIST "${x}" | tee -a ${output} ; fi
if [ $option_ipv4_2 = "2" ] || [ $option_ipv4_2 = "3" ] ; then
f_solidShort | tee -a ${output} ; f_VHOSTS "${x}" | tee -a ${output} ; fi
if [ $option_details = "2" ] ; then
if [ $option_prefix = "y" ] ; then 
f_solidShort | tee -a ${output} ; f_BOX " ${prefix} - Details "
echo -e "\n\n == BGP- PREFIX DETAILS  ($prefix) ==\n\n" >> ${output}
f_DNS_CONS4 "${prefix}" | tee -a ${output} ; f_solidShort | tee -a ${output}
f_DELEGATION "${prefix}" | tee -a ${output}
if [ $option_ipv4_2 = "1" ] || [ $option_ipv4_2 = "3" ] ; then
f_solidShort | tee -a ${output}
f_RIPE_BLACKLIST "${prefix}" | tee -a ${output} ; echo '' ; fi ; fi 
fi ; done ; fi
if [ $option_ipv4_1 = "2" ] || [ $option_ipv4_1 = "12" ] ; then
for x in $(cat "$targets") ; do
f_solidLong | tee -a ${output} ; f_VHOSTS "${x}" | tee -a ${output}
done ; fi ; echo '' ; f_Menu ; f_optionsIPV4 ; f_removeDir
;;
45)
f_makeNewDir ; f_dashedGrey ; touch $tempdir/targets.list
type_net="true" ; option_details="2"
echo -e -n "\n${B}Target > [1]${D} Set target Network  ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D} Network (CIDR)  ${B}>>${D}   " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e "${R}ERROR!${D}" ; exit 0
fi
if [ $report = "true" ] ; then
echo -e -n "\n${B}Set   > ${D}OUTPUT - FILE NAME ${B}>>${D}  " ; read filename
output="$out/${filename}.txt" ; else
output="$tempdir/out46.txt" ; fi
echo -e -n "\n${B}Option > ${D} Show Network & BGP prefix details  ${B}[y] | [n]  ?${D}  " ; read option_prefix
echo -e -n "\n${B}Option > ${D} Show network blacklist info  ${B}[y] | [n]  ?${D}  " ; read option_blacklist
for x in $(cat "$targets") ; do
f_solidLong | tee -a ${output} ; whois -h whois.cymru.com -- "-v -f ${x}" > $tempdir/cymru.txt
as=`cut -d '|' -f 1 $tempdir/cymru.txt | sed 's/^ *//'`
echo '' ; f_BOX " ${x} - AS $as " ; f_OUTPUT_HEADER "${x}"
echo -e "\n" | tee -a ${output}
ipcalc -b -n ${x} | sed '/Address:/d' | tee -a ${output} ; f_solidShort | tee -a ${output}
f_DRWHO "${x}" | tee -a ${output} ; f_solidShort | tee -a ${output}
echo -e "[+] Geographic Distribution (${x}) ${D}\n" | tee -a ${output}
f_NETGEO "${x}" | tee -a ${output}
if [ $option_prefix = "y" ] ; then
f_solidShort | tee -a ${output}
f_DNS_CONS4 "${x}" | tee -a ${output} ; f_solidShort | tee -a ${output}
f_DELEGATION "${x}" | tee -a ${output} ; fi 
prefix=`cut -d '|' -f 3 $tempdir/cymru.txt | tr -d ' '`
if [ $option_blacklist = "y" ] ; then
f_solidLong | tee -a ${output}
f_RIPE_BLACKLIST "${x}" | tee -a ${output} ; fi
if ! [[ ${x} = ${prefix} ]] ; then 
if [ $option_prefix = "y" ] ; then
f_solidLong | tee -a ${output}
f_PREFIX "${prefix}" | tee -a ${output}
f_solidShort | tee -a ${output}
f_DNS_CONS4 "${prefix}" | tee -a ${output}
f_solidShort | tee -a ${output}
f_DELEGATION "${prefix}" | tee -a ${output} ; fi ; fi
done ; echo '' ; f_Menu ; f_optionsIPV4 ; f_removeDir
;;
46)
f_makeNewDir ; f_dashedGrey ; type_net="true"
echo -e -n "\n${B}Target  > Max. Size: /24 > [1]${D} Single target network ${B}| [2]${D} Target list ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target  > ${D}Network (CIDR)  ${B}>>${D}   " ; read input
echo "$input" > $tempdir/nets.list
nets="$tempdir/nets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE  ${B}>>${D}   " ; read input
nets="${input}" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
echo -e -n "\n${B}Options >  [1]${D} Reverse DNS  ${B}| [2]${D} Reverse IP  ${B}| [3]${D} Both ${B}| [9]${D} SKIP ${B}?${D}  " ; read option_net_1
if ! [ $option_connect = "1" ] ; then
echo -e -n "\n${B}Options >${D}  Service banners ${B}>  [1]${D} hackertarget.com API  ${B}| [9]${D} SKIP  ${B}?${D}  " ; read option_net_2
option_nmap="0" ; else 
echo -e -n "\n${B}Options >${D}  Service banners ${B}>  [1]${D} hackertarget.com API  ${B}| [2] tool >${D} Nmap  ${B}| [9]${D} SKIP  ${B}?${D}  " ; read option_net_2 ; fi 
if [ $option_net_1 = "1" ] || [ $option_net_1 = "3" ] ; then
if ! [ $option_connect = "1" ] ; then
option_source="1" ; option_ip="n" ; else 
echo -e "\n${B}Nameservers (System Defaults)${D}\n"
cat /etc/resolv.conf | sed '/#/d' | grep 'nameserver' 
echo -e "\n${B}Option  > Reverse DNS >" 
echo -e -n "\n${B}Source  > [1]${D}  hackertarget.com API  ${B}| [2] tool >${D} host (default NS) ${B}| [3] tool >${D} host (custom NS)  ${B}?${D}  " 
read option_source
if [ $option_source = "3" ] ; then 
echo -e -n "\n${B}Options > ${D} Nameserver ${B}> [1]${D} Set custom NS ${B}| [2]${D} use 1.1.1.1  ${B}?${D}  " ; read option_ns
if [ $option_ns = "1" ] ; then
echo -e -n "\n${B}Set     >${D} Nameserver  ${B} >>${D}   " ; read nameserver
nssrv="$nameserver" ; nssrv_dig="@${nameserver}" ; else 
nssrv="1.1.1.1" ; nssrv_dig="@1.1.1.1" ; fi ; fi 
echo -e -n "\n${B}Option  >${D} Reverse DNS  ${B}>${D} Look up IPv6 addresses for PTR records? ${B}(tool >${D} dig ${B}) [y] | [n]  ?${D}  " ; read option_ip
if [ $option_ip = "y" ] ; then
if [ $option_source = "3" ] ; then 
nssrv_dig=`echo $nssrv_dig` ; else 
nssrv_dig="@1.1.1.1" ; fi ; fi
fi ; fi
if [ $option_net_2 = "2" ] ; then
echo -e "\n${B}Options > Nmap > ${D}\n"
echo -e " ${B}[1]${D} Run Nmap service scan (root) with host discovery (ICMP echo)"
echo -e " ${B}[2]${D} Run Nmap service scan (root), skip host discovery"
echo -e -n "\n ${B} ? ${D}  " ; read option_nmap ; fi
echo -e -n "\n${B}Options >  whois > [1]${D} whois summary  ${B}| [9]${D} SKIP  ${B}?${D}  " ; read option_whois 
if [ $report = "true" ] ; then
echo -e -n "\n${B}Set   > ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename
output="$out/${filename}.txt" ; else
output="$tempdir/out46.txt" ; fi
for x in $(cat ${nets}) ; do
if [ $option_whois = "1" ] ; then 
f_solidLong | tee -a ${output} ; f_NET_WHOIS "${x}" | tee -a ${output} ; fi 
if [ $option_net_1 = "1" ] || [ $option_net_1 = "3" ] ; then
f_solidLong | tee -a ${output} ; echo -e "[+] ${x} IPv4 Hosts (PTRs)\n" | tee -a ${output}
if [ $option_source = "1" ] ; then
f_RevDNS "${x}" | tee $tempdir/ipv4_hosts.txt  ; else 
echo '' | tee -a ${output} ; prefx=`echo $x | cut -d '.' -f -3` ; f_hostSearch | tee -a $tempdir/ipv4_hosts.txt ; fi
cat $tempdir/ipv4_hosts.txt >> ${output}
if [ $option_ip = "y" ] ; then
awk '{print $3}' $tempdir/ipv4_hosts.txt | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/hosts.txt
f_solidShort | tee -a ${output} ; echo -e "[+]  IPv6 Hosts \n" | tee -a ${output}
dig ${nssrv_dig} aaaa +noall +answer +noclass +nottlid -f $tempdir/hosts.txt | sed 's/AAAA/,/' | sed '/NS/d' | sed '/CNAME/d' > $tempdir/ipv6_hosts.txt
cut -d ',' -f 2- $tempdir/ipv6_hosts.txt | tr -d ' ' > $tempdir/ip6.txt
cat $tempdir/ipv6_hosts.txt | sed 's/,/\t/' | tee -a ${output}
f_solidShort | tee -a ${output} ; echo -e "[+]  IPv6 Network Portions\n" | tee -a ${output}
/usr/bin/atk6-extract_networks6 $tempdir/ip6.txt | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -V -u | tee -a ${output}
fi ; fi
if ! [ $option_net_2 = "9" ] ; then
f_solidLong | tee -a ${output} ; echo -e "[+] ${x} Service Banners" | tee -a ${output}
f_solidLong >> $out/BANNERS.txt ; echo -e "\n == ${x} SERVICE BANNERS ==\n" >> $out/BANNERS.txt
if [ $option_net_2 = "2" ] ; then
if [ $option_nmap  = "1" ] ; then
echo '' | tee -a ${output}
sudo nmap -n -sV --top-ports 100 --script banner,http-server-header,https-redirect,http-title,mysql-info,ms-sql-info ${x} > $tempdir/nmap.txt ; else
sudo nmap -n -sV -Pn --top-ports 100 --script banner,http-server-header,https-redirect,http-title,mysql-info,ms-sql-info ${x} > $tempdir/nmap.txt ; fi
cat $tempdir/nmap.txt | sed '/PORT/{x;p;x;}' | sed '/\/tcp /{x;p;x;}' | sed '/Nmap scan report/i ____\n' | sed '/Read data files/d' |
sed '/NSE/d' | sed '/Initiating/d' | sed '/Completed/d' | sed '/Discovered/d' | sed '/Uptime guess:/{x;p;x;}' | sed '/Network Distance:/{x;p;x;}' |
fmt -w 120 -s | tee $tempdir/services.txt ; else 
f_BANNERS "${x}" > $tempdir/services.txt ; fi 
cat $tempdir/services.txt | tee -a ${output} ; cat $tempdir/services.txt >> $out/BANNERS.txt ; fi
if [ $option_net_1 = "2" ] || [ $option_net_1 = "3" ] ; then
f_solidLong | tee -a ${output} ; echo -e "[+] ${x} Reverse IP (Virtual Hosts)\n" | tee -a ${output}
f_solidLong >> $out/VHOSTS.txt ; echo -e "\n == ${x} VIRTUAL HOSTS ==\n" >> $out/VHOSTS.txt
f_RevIP "${x}" | tee $tempdir/vhosts.txt ; cat $tempdir/vhosts.txt | tee -a ${output} >> $out/VHOSTS.txt ; fi
done ; echo '' ; f_Menu ; f_optionsIPV4 ; f_removeDir
;;
47 | p5)
#************** 47) NMAP PING SWEEP ********************
f_makeNewDir ; f_dashedGrey
echo -e "\n\n${B}Ping Sweep (Nmap)${D}\n"
echo -e -n "\n${B}Target Network (CIDR) >>${D}   " ; read input
netw=`echo "$input" | cut -d '.' -f -3`
echo -e "\n == $input PING SWEEP ==${D}\n" >>  $out/PING.${netw}.txt
echo -e "\n"
nmap -sn $input | fmt -s -w 80 | tee -a  $out/PING.${netw}.txt
f_solidLong >>  $out/PING.${netw}.txt
echo '' ; f_Menu ; f_optionsIPV4 ; f_removeDir
;;
61)
#************** 61-69) IPv6 OPTIONS ********************
f_makeNewDir ; f_dashedGrey
echo -e -n "\n${B}Option > [1]${D} Dump Router6  ${B}| [2]${D} Dump DHCP6  ${B}| [3] ${D} BOTH  ${B}?${D}  " ; read answer
echo -e "\n${B}Active Network Interfaces${D}\n"
ip -6 addr show | grep 'state UP' | cut -d ':' -f 2 | sed 's/^ *//'
echo -e -n "\n${B}Set  >  ${D}Network Interface -e.g. eth0  ${B}>>${D}  " ; read interface
echo -e "\n"
if [ $answer = "1" ] || [ $answer = "3" ] ; then 
echo -e "\n == atk6-dump_router6  ==\n" >> $out/ATK6-Dump_Router6.txt
echo '' ; echo -e "    Interface > $interface  Date > $(date) \n\n" >> $out/ATK6-Dump_Router6.txt
sudo atk6-dump_router6 ${interface} | tee -a $out/ATK6-Dump_Router6.txt ; fi
if [ $answer = "2" ] || [ $answer = "3" ] ; then 
echo -e -n "\n${B}Target > ${D} DHCP Server   ${B}>>${D}   " ; read dhcp_target 
echo '' ; echo -e "\n == atk6-dump_dhcp6  ==\n" >> $out/ATK6-Dump_DHCP6.txt
echo '' ; echo -e "    Interface > $interface  Date > $(date) \n\n" >> $out/ATK6-Dump_DHCP6.txt
sudo atk6-dump_dhcp6 ${interface} ${dhcp_target} | tee -a $out/ATK6-Dump_DHCP6.txt ; fi
echo '' ; f_removeDir ; f_Menu ; f_optionsIPV6
;;
62 | p6)
f_makeNewDir ; f_dashedGrey
if ! [ $option_connect = "9" ] ; then
touch $tempdir/targets.list ; output="$out/ICMPv6.txt" 
echo -e -n "\n${B}Target > [1]${D} Set target IPv6 Address  ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D} IPv6 Address   ${B}>>${D}   " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE  ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
echo -e "\n${B}Active Network Interfaces${D}\n"
ip -6 addr show | grep -w 'state UP' | cut -d ' ' -f 2 | tr -d ':'
echo -e -n "\n${B}Set >${D} Network interface (e.g. eth0)  ${B}>>${D} "; read n_interface
declare -a v6_array=()
v6_array+=(${n_interface})
echo -e -n "\n${B}Set >${D} Number of packets (default:1)  ${B}>>${D} "; read packets
v6_array+=(-n ${packets})
echo -e -n "\n${B}Option >${D} Set custom ICMPv6 type (default: 128 = ping) ${B} [y] | [n] ? ${D} " ; read answer
if  [ $answer = "y" ] ; then
echo -e -n "\n${B}Set >${D} ICMPv6 type ${B}>>${D} "; read option_type
v6_array+=(-T ${option_type}) ; fi
echo -e -n "\n${B}Option >${D} Set custom ICMPv6 code (default: 0) ${B} [y] | [n] ? ${D} " ; read answer
if  [ $answer = "y" ] ; then
echo -e -n "\n${B}Set >${D} ICMPv6 code  ${B}>>${D} "; read option_code
v6_array+=(-C ${option_code}) ; fi 
for x in $(cat "$targets") ; do
f_solidShort | tee -a ${output} ; echo -e "\n[+] ${x} ICMPv6\n" | tee -a ${output}
echo '' | tee -a ${output}
sudo atk6-thcping6 ${v6_array[@]} ${x} | sed '/packet sent/{x;p;x;G;}' | tee -a ${output}
echo ' ' | tee -a ${output} ; done
else
f_WARNING ; fi ; f_Menu ; f_optionsIPV6 ; f_removeDir
;;
63)
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}Convert to IPv6\n"
echo -e -n "\n${B}Target > MAC or IPv4 or IPv6  >>${D}  " ; read input ;
echo -e -n "\n${B}Option >${D} Set IPv6 Prefix  ${B}[y] | [n] ?${D}  "  ; read answer
declare -a v6_conversion=()
if  [ $answer = "y" ] ; then
echo -e -n "\n${B}Set >${D} IPv6 prefix  ${B}>>${D} "; read v6_prefix
v6_conversion+=(${v6_prefix}) ; fi ; echo -e "\n"
atk6-address6 ${input} ${v6_conversion[@]} ; echo '' ; f_removeDir ; f_Menu ; f_optionsIPV6
;;
64)
f_makeNewDir ; f_dashedGrey
echo -e -n "\n${B}Options > [1]${D} Single Input ${B}| [2]${D} Read from File ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D}IPV6 ADDRESS  ${B}>>${D}  " ; read address
echo "$address" > $tempdir/list.txt ; input='$tempdir/list.txt' ; else 
echo -e -n "\n${B}Target  >  ${D}PATH TO FILE ${B}>>${D}  " ; read input ; fi
if [ $report = "true" ] && [ $option_target = "2" ] ; then
echo -e -n "\n${B}Set     >  ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename
output="$out/${filename}.txt" ; else
output="$tempdir/out62" ; fi
f_solidShort | tee -a ${output}
echo -e "\n[+] IPv6 Network Portions\n\n" | tee -a ${output}
/usr/bin/atk6-extract_networks6 ${input} | sort -V -u | tee -a ${output}
echo '' | tee -a ${output} 
f_solidShorter | tee -a ${output}
echo -e "\n[+] IPv6 Host Portions\n\n" | tee -a ${output}
/usr/bin/atk6-extract_hosts6 ${input} | sort -V -u  | tee -a ${output} 
echo '' | tee -a ${output} ; f_removeDir ; f_Menu ; f_optionsIPV6
;;
65)
f_makeNewDir ; f_dashedGrey
if ! [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Target > [1]${D} set target domain ${B}| [2]${D} Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D}DOMAIN  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/doms.list
doms=" $tempdir/doms.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}  " ; read input
doms="${input}" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi 
for x in $(cat $doms) ; do
f_solidLong | tee $tempdir/subs.txt
echo -e "\n === ${x} SUBDOMAINS (IPv6) ===\n\n" >> $tempdir/subs.txt
echo -e "Date: $(date)\n" >> $tempdir/subs.txt
echo -e "\n${B}${x} Subdomains (IPv6)${D}\n\n"
atk6-dnsdict6 -d -l ${x} | sed '/Estimated time/G' | tee -a $tempdir/v6subs.txt
cat $tempdir/v6subs.txt >> $tempdir/subs.txt
cut -s -d '>' -f 2- $tempdir/v6subs.txt | tr -d ' ' > $tempdir/v6addresses.txt 
f_solidShorter | tee -a $tempdir/subs.txt
echo -e "[+] Networks \n\n" | tee -a $tempdir/subs.txt
/usr/bin/atk6-extract_networks6 $tempdir/v6addresses.txt | sort -u | tee -a $tempdir/subs.txt
f_solidShorter | tee -a $tempdir/subs.txt
cat $tempdir/subs.txt | tee -a $out/${x}.txt >> $out/DNSrec_and_Subdomains.txt ; done
else
f_WARNING ; fi ; echo '' ; f_Menu ; f_optionsIPV6 ; f_removeDir
;;
66)
f_makeNewDir ; f_dashedGrey
touch $tempdir/targets.list ; option_server="n" 
echo -e "\n${B}Options > IPv6 Addresses >\n"
echo -e " ${B}[1]${D} Set target IPv6 Address  ${B}|  [11]${D} Set target IPv6 Network"
echo -e " ${B}[2]${D} Read Addresses from file ${B}|  [12]${D} Read networks from file"
echo -e -n "\n ${B} ?${D}  "  ; read option_ipv6_1
if [ $option_ipv6_1 = "1" ] ; then
echo -e -n "\n${B}Target > ${D}  IPV6 ADDRESS ${B} >>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
type_net="false"
elif [ $option_ipv6_1 = "11" ] ; then
echo -e -n "\n${B}Target > ${D}  IPV6 NETWORK ADDRESS (CIDR) ${B} >>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
type_net="true"
elif [ $option_ipv6_1 = "2" ] || [ $option_ipv6_1 = "12" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}  " ; read input
targets="$input" ;
if [ $report = "true" ] ; then
echo -e -n "\n${B}Set   > ${D}OUTPUT - FILE NAME ${B}>>${D}  " ; read filename
output="$out/${filename}.txt" ; fi 
if [ $option_ipv6_1 = "12" ] ; then
type_net="true" ; else
type_net="false" ; fi ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
echo -e "\n${B}Options >${D} (GLOBAL scope addresses only)\n"
echo -e "${B} [1]${D} geolocation, whois info"
echo -e "${B} [2]${D} geolocation, whois & BGP prefix details"
echo -e "${B} [9]${D} SKIP "
echo -e -n "\n${B}  ? ${D}  " ; read option_details
for x in $(cat "$targets") ; do
if [ $report = "true" ] ; then
if [ $option_ipv6_1 = "1" ] ; then
output="$out/${x}.txt"
elif [ $option_ipv6_1 = "11" ] ; then
net=`echo $x | rev | cut -d '/' -f 2- | rev`
output="$out/NET.${net}.txt" ; else
output="$output" ; fi ; else 
output="$tempdir/out6.txt" ; fi
f_solidLong | tee -a ${output} ; f_OUTPUT_HEADER "${x}"
sipcalc ${x} > $tempdir/sc.txt ; f_BOX " ${x} "
if [ $option_ipv6_1 = "1" ] || [ $option_ipv6_1 = "2" ] ; then
echo -e "\n\n[+] Address Type\n\n" | tee -a ${output}
grep -w 'Address type'  $tempdir/sc.txt | tee -a ${output}
echo '' | tee -a ${output}
grep -w 'Compressed' $tempdir/sc.txt | tee -a ${output} ; echo '' | tee -a ${output}
grep -w 'Expanded' $tempdir/sc.txt | tee -a ${output} ; echo '' | tee -a ${output}
grep -w 'Address ID' $tempdir/sc.txt | tee -a ${output} 
echo '' | tee -a ${output} ; f_solidShorter | tee -a ${output} ; echo "$x" > $tempdir/list.txt
echo -e "\nNetwork:   $(/usr/bin/atk6-extract_networks6 $tempdir/list.txt)" | tee -a ${output}
echo -e "\nHost:      $(/usr/bin/atk6-extract_hosts6 $tempdir/list.txt)" | tee -a ${output}
echo -e "\n\n[+] Encoded MAC / IPv4 Address\n"  | tee -a ${output}
atk6-address6 ${x} | tee -a ${output} ; else
echo -e "\n" | tee -a ${output}
grep -w 'Address type' $tempdir/sc.txt | tee -a ${output} ; echo '' | tee -a ${output}
grep -w 'Compressed' $tempdir/sc.txt | tee -a ${output} ; echo '' | tee -a ${output}
grep -w 'Expanded' $tempdir/sc.txt | tee -a ${output} ; echo '' | tee -a ${output}
grep -w 'Subnet prefix' $tempdir/sc.txt | tee -a ${output} ; echo '' | tee -a ${output}
grep -w 'Address ID (masked)' $tempdir/sc.txt | tee -a ${output}
grep -w 'Prefix address' $tempdir/sc.txt | tee -a ${output} ; echo '' | tee -a ${output}
grep -A 1 'Network range' $tempdir/sc.txt | tee -a ${output}
echo '' | tee -a ${output} ; f_solidShort | tee -a ${output} ; fi
if [[ $(grep -w 'Address type' $tempdir/sc.txt | grep -c -i -w 'Global Unicast') -ge "1" ]] && ! [ $option_details = "9" ] ; then
if [ $type_net = "false" ] ; then
echo '' ; f_BOX_BANNER "${x}" ; else
whois -h whois.cymru.com -- "-v -f ${x}" > $tempdir/cymru.txt ; fi
f_DRWHO "${x}" | tee -a ${output}
prefix=`cut -d '|' -f 3 $tempdir/cymru.txt | tr -d ' '`
if [ $type_net = "true" ] ; then
f_solidLong | tee -a ${output}
echo -e "[+] ${x} Geographic Distributon\n" | tee -a ${output}
f_NETGEO "${x}" | tee -a ${output} ; f_solidLong | tee -a ${output}
f_DELEGATION "${x}" | tee -a ${output} ; f_solidLong | tee -a ${output}
f_DNS_CONS6 "${prefix}" | tee -a ${output} ; fi 
if  [ $option_details = "2" ] ; then 
if ! [ $x = $prefix ] ; then 
f_solidLong | tee -a ${output} ; f_PREFIX "${prefix}" | tee -a ${output} 
f_solidLong | tee -a ${output} ; f_DELEGATION "${prefix}" | tee -a ${output}
f_solidLong | tee -a ${output} ; f_DNS_CONS6 "${prefix}" | tee -a ${output} ; fi ; fi 
fi ; done ; echo '' ; f_removeDir ; f_Menu ; f_optionsIPV6
;;
67)
f_makeNewDir ; f_dashedGrey
if ! [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Target > ${D}IPv6 NETWORK ${B}|${D} REVERSE IP / NETWORK ADDRESS  ${B}>>${D}  " ; read address
echo -e -n "\n${B}Target > ${D}NAME SERVER ${B}>>${D}  " ; read target_ns
echo -e -n "\n${B}Option > [1] ${D} UDP  ${B} | [2] ${D} TCP  ${B}?${D}  " ; read input_protocol
if [ $input_protocol = "2" ] ; then 
protocol="-t" ; else 
protocol="" ; fi 
net=`echo $x | rev | cut -d '/' -f 2- | rev`
output="$out/REVERSE_DNS.${net}.txt"
f_solidLong | tee -a ${output} ; f_OUTPUT_HEADER "${address}"
f_BOX " ${x} " ; echo '' | tee -a ${output}
sudo atk6-dnsrevenum6 ${protocol} ${target_ns} ${address} | tee -a ${output} ; else
f_WARNING ; fi ; echo '' ; f_Menu ; f_optionsIPV6 ; f_removeDir
;;
111)
f_makeNewDir ; f_dashedGrey ; touch $tempdir/hosts.list ; declare dig_array=()
if [[ $target =~ ${REGEX_IP4} ]]; then
echo -e -n "\n${B}Target > [1]${D} Set target host ${B}| [2]${D} target list  ${B}?${D}  " ; read option_target ; else
echo -e -n "\n${B}Target > [1]${D} Set target host ${B}| [2]${D} target list  ${B}| [3] current >  ${D}$target  ${B}?${D}  " ; read option_target ; fi
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D}HOSTNAME ${B}>>${D}  " ; read input
echo "$input" > $tempdir/hosts.list
hosts=" $tempdir/hosts.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}  " ; read input
hosts="${input}"
elif [ $option_target = "3" ] ; then
echo "$target" > $tempdir/hosts.list
hosts="${tempdir}/hosts.list" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
if [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Options  > [1]${D} HTTP headers ${B}| [2]${D} link dump  ${B}| [3]${D} BOTH ${B}?${D}  " ; read option_dump ; else 
echo -e "\n${B}Options  >${D}\n"
echo -e -n "${B} > [1]${D} HTTP headers  ${B}| [2] ${D} link dump  ${B}| [3]${D} robots.txt  ${B}| [4]${D} ALL  ${B}?${D}  " ; read option_dump
echo -e -n "\n${B}Source  > ${D} HTTP headers/ link dump ${B} > [1]${D} curl/ lynx  ${B}| [2]${D} hackertarget.com API   ${B}?${D}  " ; read option_source ; fi 
for x in $(cat $hosts) ; do
if [ $option_connect = "9" ] ; then
if [ $option_dump = "1" ] || [ $option_dump = "3" ] ; then
echo '' > $out/Headers.${x}.txt ; f_solidLong 
echo -e "\n[+] ${x} HTTP Headers (Source > hackertarget.com)\n\n" | tee -a $out/Headers.${x}.txt
curl -s https://api.hackertarget.com/httpheaders/?q=${x}${api_key_ht} |
fmt -s -w 80 | tee -a $out/Headers.${x}.txt ; echo '' ; fi 
if [ $option_dump = "2" ] || [ $option_dump = "3" ] ; then
echo '' > $out/LINK_DUMP.${x}.txt ; f_solidLong
echo -e "\n[+] ${x} Link Dump (Source > hackertarget.com)\n" | tee -a $out/LINK_DUMP.${x}.txt
echo -e "    Date > $(date)\n" >> $out/LINK_DUMP.${x}.txt
curl -s https://api.hackertarget.com/pagelinks/?q=${x}${api_key_ht} | tee -a $out/LINK_DUMP.${x}.txt ; echo '' ; fi ; else 
if [ $option_dump = "1" ] || [ $option_dump = "4" ] ; then
echo '' > $out/Headers.${x}.txt ; f_solidLong 
echo -e "\n[+] ${x} HTTP Headers\n\n    (Date > $(date))\n"| tee -a $out/Headers.${x}.txt
if [ $option_source = "1" ] ; then
curl -sILk --max-time 3 ${x} | fmt -s -w 80 | tee -a $out/Headers.${x}.txt ; echo '' ; else
curl -s https://api.hackertarget.com/httpheaders/?q=${x}${api_key_ht} |
fmt -s -w 80 | tee -a $out/HEADERS.$address.txt ; echo '' ; fi ; fi
if [ $option_dump = "2" ] || [ $option_dump = "4" ] ; then
echo '' > $out/LINK_DUMP.${x}.txt ; f_solidLong
echo -e "\n[+] ${x} Link Dump\n\n    (Date > $(date))\n" | tee -a $out/LINK_DUMP.${x}.txt
if [ $option_source = "1" ] ; then
f_linkDump "${x}" | tee -a $out/LINK_DUMP.$page.txt ; echo '' ; else
curl -s https://api.hackertarget.com/pagelinks/?q=${x}${api_key_ht} | tee -a $out/LINK_DUMP.$page.txt ; echo '' ; fi ; fi 
if [ $option_dump = "3" ] || [ $option_dump = "4" ] ; then
echo '' > $out/ROBOTS.${x}.txt ; f_solidLong
echo -e "\n[+] ${x} robots.txt\n\n    (Date > $(date))\n" | tee -a $out/ROBOTS.${x}.txt
curl -sLk --max-time 3 ${x}/robots.txt | fmt -s -w 80 | tee -a $out/ROBOTS.${x}.txt ; echo '' ; fi ; fi 
done ; f_removeDir ; f_Menu ; f_optionsWEBSERVERS  
;;
112)
f_makeNewDir ; f_dashedGrey
if ! [ $option_connect = "9" ] ; then
declare -a nmap_array=() ; declare -a curl_array=() ; declare -a mtr_array=() ; declare -a ping_array=() 
echo -e "\n${B}RT-, Response- & Page-Loading Times${D}"
echo -e "\n${B}Options > Target Type >\n"
echo -e "${B} [1]${D} Server- Hostname(s) (IPv4 Mode) ${B}| [11]${D} Server IPv4 Address(es)"
echo -e "${B} [2]${D} Server- Hostname(s) (IPv6 Mode) ${B}| [12]${D} Server IPv6 Address(es)"
echo -e -n "\n${B}  ?${D}  " ; read option_ipv
echo -e -n "\n${B}Target  >${D} Source > ${B}[1]${D} new target ${B}| [2]${D} Target List (.txt) ${B}| [3] current > ${D} $target  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D}HOSTNAME(s) ${B}| ${D}IP(s) ${B}>>${D}   " ; read input
echo "$input" > $tempdir/servers.txt
servers="$tempdir/servers.txt"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}   " ; read input
servers="${input}"
elif [ $option_target = "3" ] ; then
echo "$target" > $tempdir/servers.txt
servers="${tempdir}/servers.txt" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
echo -e -n "\n${B}Option > Set  > ${D} MTR Target TCP Port ${B}> [1]${D} 80 ${B}| [2]${D} set port ${B}| [9] SKIP  ${B}?${D}  " ; read option_mtr
if [ $option_mtr = "1" ] ; then
tport="80"
elif [ $option_mtr = "2" ] ; then
echo -e -n "\n${B}Set       >${D}  Target Port - e.g. 8080  ${B}>>${D}  " ; read tport ; else
: ; fi
if [ $option_ipv = "2" ] || [ $option_ipv = "12" ] ; then
mtr_array+=(--tcp -P ${tport} -6 -c4 -w -b -z) ; ping_array+=(-6 -c 4) ; t='aaaa'
curl_array+=(-sLk6v) ; nmap_array+=(-sS -Pn -6 -p 80,443) ; else 
mtr_array+=(--tcp -P ${tport} -4 -c4 -w -b -z) ; ping_array+=(-c 4) ; t='a'
curl_array+=(-sLk4v) ; nmap_array+=(-sS -Pn -p 80,443) ; fi
for x in $(cat ${servers}) ; do
output="$out/WEB.${x}.txt"  ;  f_solidLong | tee -a ${output}
echo -e "\n == ${x} RT- SERVER RESPONSE- & PAGE LOADING TIMES ==\n"  >> ${output}
touch $tempdir/response.txt
date_time=$(date)
curl ${curl_array[@]} ${x} --trace-time 2>$tempdir/curl.txt -D $tempdir/headers.txt -o $tempdir/src.txt -w \
"
URL:              %{url_effective}
IP:               %{remote_ip}
Port:             %{remote_port}\n
Status            %{response_code}, HTTP %{http_version}
Content:          %{content_type}\n\n
DNS Lookup:       %{time_namelookup} s \n
Redirects:        %{time_redirect} s
Num Redirects:    %{num_redirects}\n
TCP Handshake:    %{time_connect} s
SSL Handshake:    %{time_appconnect} s
———\n
Time Total:       %{time_total} s
___________________________________\n
Download Size:    %{size_download} bytes
Download Speed:   %{speed_download} bytes/s\n
" > $tempdir/response.txt
if [ $option_ipv = "2" ] ; then 
ipaddr="$(grep -w 'IP:' $tempdir/response.txt | rev | cut -d ' ' -f 1 | rev)"
elif [ $option_ipv = "12" ] ; then 
ipaddr=`echo $x` ; else 
ipaddr="$(egrep -m 1 -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/response.txt)" ; fi 
echo '' ; f_BOX_BANNER "${ipaddr}" ; echo ''
f_solidShort >> ${output}
echo -e "${B}${x} Response-Times${D}\n" ; echo -e "[+] ${x} RESPONSE-TIMES\n\n"  >> ${output}
cat $tempdir/response.txt | tee -a ${output}
f_solidShort | tee -a ${output}
if ! [ $option_mtr = "9" ] ; then
echo -e "\n[+] $x MTR (TCP, Port > $tport)\n" >> ${output}
echo -e "\n${B}Round Trip Times & MTR Traceroute (TCP, Port > $tport)${D}\n"
sudo mtr ${mtr_array[@]} -o "  L  S D  A BW  M" ${x} | sed '/HOST:/G' |
tee -a ${output}
f_solidShorter | tee -a ${output}
echo -e "Snt = packages sent; Wrst = worst RTT in ms; \nJavg = average jitter" | tee -a ${output} ; echo '' ; fi
f_solidShort | tee -a ${output} ; echo -e "[+] httping\n" | tee -a ${output}
timeout 10 httping ${ping_array[@]} ${x} | sed '/---/{x;p;x;G;}' | sed '/round-trip/{x;p;x;G;}' |
sed '/PING/G' | tee -a ${output}
echo -e "_______________\n" | tee -a ${output} ; echo -e "[+] ping [icmp]\n" | tee -a ${output}
ping -c 4 -W 20 ${ipaddr} | sed '/---/G' | sed '/PING/G' | sed '/rtt/{x;p;x;}' | tee -a ${output}
f_solidLong | tee -a ${output} 
echo -e "[+] ${x} Website Request Times\n\n" | tee -a ${output}
timeout 10 sudo nmap ${nmap_array[@]} --script path-mtu,http-chrono ${x} | sed '/PORT/{x;p;x;G;}' | sed '/Read data files/d' |
sed '/NSE/d' | sed '/Initiating/d' | sed '/Completed/d' | sed '/Discovered/d' | sed '/Host is up/d' |
sed '/Starting Nmap/d' | fmt -w 80 -s  | tee -a ${output} ; f_solidLong | tee -a ${output} 
echo -e "${B}${x} Response-Times - Details ${D}\n" ; echo -e " == ${x} RESPONSE-TIMES - DETAILS ==\n\n"  >> ${output}
echo -e "[+] DNS Lookup Time (curl)\n\n" | tee -a ${output}
echo -e "$(grep -w 'DNS Lookup:' $tempdir/response.txt | cut -d ':' -f 2- |  sed 's/^[ \t]*//') (total lookup time)" |
tee -a ${output}
f_solidShorter | tee -a  ${output}
echo -e "[+] Lookup Delegation (dig)\n\n" | tee -a ${output}
dig @1.1.1.1 ${t} +noall +answer +trace +noclass +nodnssec ${x} > $tempdir/trace.txt
cat $tempdir/trace.txt | grep ';; Received' | sed 's/;;//' | sed 's/^ *//' | sed '$d' | tee -a ${output}
sed -e '/./{H;$!d;}' -e 'x;/A/!d;' $tempdir/trace.txt | sed 's/;;//' | sed 's/^ *//' |
sed '/NS/d' | sed '/Received/{x;p;x;}' | tee -a ${output}
f_solidShort | tee -a ${output}
as=`cut -d '|' -f 1 $tempdir/cymru.txt | sed 's/^ *//' | tr -d ' '`
echo -e "[+] Redirects\n" | tee -a ${output}
echo -e "\n[+] Server Location & Timezone \n" | tee -a ${output}
echo -e "Timezone:     $(jq -r '.timezone' $tempdir/geo.json), CET $(expr $(jq -r '.offset' $tempdir/geo.json) / 3600 )h" |
tee -a ${output} ; echo '' | tee -a ${output}
echo -e "Country:      $(jq -r '.country' $tempdir/geo.json) ($(jq -r '.countryCode' $tempdir/geo.json))" | tee -a ${output}
echo -e "City:         $(jq -r '.city' $tempdir/geo.json)\n" | tee -a ${output}
echo -e "Hosting:      $(jq -r '.hosting' $tempdir/geo.json)" | tee -a ${output}
echo -e "ISP:          $(jq -r '.isp' $tempdir/geo.json)" | tee -a ${output}
echo -e "AS:           AS $as, $(cut -d '|' -f 7 $tempdir/cymru.txt | sed 's/^ *//')" | tee -a ${output}
f_solidShorter | tee -a ${output} ; echo -e "[+] Local Time \n" | tee -a ${output}
offset=$(date +"%Z %z")
echo -e "SYSTEM TIME:      $date_time" | tee -a ${output}
echo -e "CET OFFSET:       $offset" | tee -a ${output}
f_solidShorter | tee -a ${output}
grep -w 'Redirects:' $tempdir/response.txt | tee -a ${output}
f_solidShorter | tee -a ${output}
sed -n '/HTTP/p; /[Ll]ocation:/p; /[Dd]ate:/p; /[Ss]erver:/p' $tempdir/headers.txt | sed '/HTTP/{x;p;x;}' | tee -a ${output}
echo '' | tee -a ${output} ; f_solidLong | tee -a ${output}
echo -e "[+] Handshake \n\n" | tee -a ${output} ; grep -w 'Redirects:' $tempdir/response.txt | tee -a ${output} ; echo '' | tee -a ${output}
grep -w '^TCP Handshake:' $tempdir/response.txt | tee -a ${output}
grep -w '^SSL Handshake:' $tempdir/response.txt | tee -a  ${output}
echo -e "_____________\n" | tee -a ${output} ; echo -e '' | tee -a ${output}
f_curlHandshake | tee -a ${output} ; f_solidLong | tee -a ${output}
done ; else
f_WARNING ; fi ; f_removeDir ; echo '' ; f_Menu ; f_optionsWEBSERVERS 
;;
p1)
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}Nmap Port & Service Version Scan"
if ! [ $option_connect = "9" ] ; then
declare -a nmap_array=() ; declare -a port_array=()
echo -e -n "\n${B}Mode    >  [1]${D}  IPv4   ${B}|  [2]${D}  IPv6  ${B}?${D}  " ; read option_ipv
echo -e -n "\n${B}Target  >  [1]${D} Set new target  ${B}| [2]${D} Read targets from list ${B}| [3] current > ${D} $target  ${B}?${D}  " ; read option_target
if [ $option_target = "3" ] ; then
scan_target=`echo $target` 
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}  " ; read input
scan_target="-iL ${input}"
else 
if [ $option_ip_version = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}Hostname(s)   ${B}|${D} IPv6 Address(es)  ${B}>>${D}  " ; read scan_target ; else 
echo -e -n "\n${B}Target  > ${D}Hostname(s)   ${B}|${D} IPv4 Address(es)  ${B}|${D} Network(s)  ${B}>>${D}  " ; read scan_target
fi ; fi
echo -e "\n${B}Options >\n" 
echo -e "${B} [1]${D} TCP Connect Scan (non-root)"
echo -e "${B} [2]${D} Basic SYN Scan"   
echo -e "${B} [3]${D} Service Version Scan (optional: vulners)"
echo -e "${B} [4]${D} Service- & OS- Version Scan (optional: vulners)"
echo -e "${B} [5]${D} Alternative Scan Flags"
echo -e -n "\n${B}  ?${D}  " ; read scan_type
if   [ $scan_type = "1" ] ; then
nmap_array+=(-sT -Pn) ; scripts_1="banner,ajp-headers,http-server-header,ms-sql-info,mysql-info"
elif [ $scan_type = "2" ] ; then
nmap_array+=(-Pn -sS) ; scripts_1="banner"
elif [ $scan_type = "3" ] ; then
nmap_array+=(-Pn -sV) ; scripts_1="banner,ajp-headers,http-server-header,ms-sql-info,mysql-info"
elif [ $scan_type = "4" ] ; then
nmap_array+=(-Pn -sV -O)
scripts_1="banner,ajp-headers,http-server-header,ms-sql-info,mysql-info,smb-protocols,smb-os-discovery,vmware-version"
elif [ $scan_type = "5" ] ; then
echo -e -n "\n\n${B}Flags   >  [1]${D} ACK ${B}| [2]${D} FIN ${B}| [3]${D} WINDOW SCAN  ${B}?${D}  " ; read scan_flag
if [ $scan_flag = "1" ] ; then
     nmap_array+=(-sA -Pn --reason)
elif [ $scan_flag = "3" ] ; then
     nmap_array+=(-sW -Pn --reason) ; else 
     nmap_array+=(-sF -Pn --reason) ; fi
echo -e -n "\n\n${B}Options >  [1]${D} Packet Fragmentation ${B}| [2]${D} Source Port Spoofing ${B}| [3]${D} BOTH ${B}| [9]${D} IGNORE ${B}?${D}  " ; read option_extra
if   [ $option_extra = "1" ] ; then
     nmap_array+=(-f)
elif [ $option_extra = "2" ] ; then
     echo -e -n "\n\n${B}Set     >${D}  Source Port${B}>>${D}  " ; read source_port
     nmap_array+=(-g ${source_port})
elif [ $option_extra = "3" ] ; then
     echo -e -n "\n\n${B}Set     >${D}  Source Port${B}>>${D}  " ; read source_port
     nmap_array+=(-f -g ${source_port}) ; else 
     : ; fi
else
echo -e "\n ${R}Error! ${D} \n" ; exit 0 ; fi
if [ $report = "true" ] ; then
echo -e -n "\n${B}Set   > ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename ; else
filename="nmap" ; fi 
if [ $option_ipv = "2" ] ; then 
nmap_array+=(-6) ; fi
if [ $scan_type = "3" ] || [ $scan_type = "4" ] ; then
echo -e -n "\n${B}Option  > [1]${D} Scan for CVE Vulners  ${B}| [2]${D} CVE Vulners & empty mySQL/MS-SQL root passwords  ${B}| [9] SKIP  ${B}?${D}  " ; read option_vulners
if   [ $option_vulners = "1" ] ; then
scripts_2="http-malware-host,smtp-strangeport,vulners"
elif   [ $option_vulners = "2" ] ; then
scripts_2="mysql-empty-password,ms-sql-empty-password,ms-sql-ntlm-info,http-malware-host,smtp-strangeport,vulners,ftp-anon" ; else
: ; fi ; fi
echo -e "\n\n${B}Ports   > [1]${D} nmap Top 100 Ports   ${B}|  [4]${D} nmap Top 5000 Ports"
echo -e "          ${B}[2]${D} nmap Top 500 Ports   ${B}|  [5]${D} Custom Port List"
echo -e "          ${B}[3]${D} nmap Top 1000 Ports  ${B}|  [6]${D} All TCP Ports"
echo -e -n "\n           ${B}?${D}  " ; read portChoice
if   [ $portChoice = "1" ] ; then
port_array+=(--top-ports 100)
elif [ $portChoice = "2" ] ; then
port_array+=(--top-ports 500)
elif [ $portChoice = "3" ] ; then
port_array+=(--top-ports 1000)
elif [ $portChoice = "4" ] ; then
port_array+=(--top-ports 5000)
elif [ $portChoice = "5" ] ; then
echo -e -n "\n${B}Ports  > ${D} e.g. 636,989-995  ${B}>>${D}  " ; read ports
port_array+=(-p ${ports}) ; else 
port_array+=(-p-) ; fi
echo -e "\n == NMAP PORT SCAN (root)== \n" >> $out/PORTSCANS.txt
echo -e "Date : $(date), Type: $scan_type $scan_flag\n" >> $out/PORTSCANS.txt
echo -e "Target: $scan_target\n\n" >> $out/PORTSCANS.txt ; echo ''
f_solidShort
if [ $scan_type = "1" ] ; then
nmap ${nmap_array[@]} -oA ${out}/${filename} ${port_array[@]} ${scan_target} --script ${scripts_1} > $tempdir/nmap.txt 
elif [ $scan_type = "4" ] ; then
sudo nmap ${nmap_array[@]} -oA ${out}/${filename} ${port_array[@]} ${scan_target} > $tempdir/nmap.txt ; else 
sudo nmap ${nmap_array[@]} ${port_array[@]} ${scan_target} -oA ${out}/${filename} --script ${scripts_1},${scripts_2} > $tempdir/nmap.txt ; fi
cat $tempdir/nmap.txt | sed '/PORT/{x;p;x;}' | sed '/\/tcp /{x;p;x;}' |
sed '/Read data files/d' | sed '/NSE/d' | sed '/Initiating/d' | sed '/Completed/d' | sed '/Discovered/d' |
sed '/Aggressive OS guesses:/{x;p;x;}' | sed '/Uptime guess:/{x;p;x;}' | sed '/Nmap scan report/{x;p;x;}' |
sed '/Network Distance:/{x;p;x;}' | fmt -w 120 -s | tee -a $out/PORTSCANS.txt
f_solidLong >> $out/PORTSCANS.txt ; echo ; else
f_WARNING ; fi ; f_removeDir ; f_Menu ; f_options_P
;;
p2)
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}Nmap TCP Port Scan (via hackertarget.com)\n"
echo -e -n "\n${B}Target  >  IP  >>${D}  " ; read scan_target
echo -e "\n== $scan_target TCP PORT SCAN (via hackertarget.com) == ${D} \n" >> $out/PORTSCANS.txt
echo -e "Date: $(date) \n" >> $out/PORTSCANS.txt
echo '' ; curl -s https://api.hackertarget.com/nmap/?q=${scan_target}${api_key_ht} | tee -a $out/PORTSCANS.txt
f_solidLong >> $out/PORTSCANS.txt 
echo '' ; f_removeDir ; f_Menu ; f_options_P
;;
p3)
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}Banner Grabbing"
echo -e -n "\n${B}Target >${D} Network (CIDR) ${B}|${D} IPv4 ${B} >>${D}  " ; read scan_target ; echo ''
echo -e "\n[+]  $scan_target SERVICE BANNERS\n" >> $out/Banners.txt
f_BANNERS "${scan_target}" | tee -a $out/Banners.txt
f_solidLong >> $out/Banners.txt
echo ''; f_removeDir ; f_Menu ; f_options_P
;;
p4)
f_makeNewDir ; f_dashedGrey
echo -e -n "\n${B}Target  >  IP  >>${D}  " ; read scan_target
echo -e "\n[+] $scan_target Nping (via hackertarget.com API)\n"
echo '' ; curl -s https://api.hackertarget.com/nping/?q=${scan_target}${api_key_ht}  | tee -a $out/PORTSCANS.txt
f_solidShort >> $out/PORTSCANS.txt
echo '' ; f_removeDir ; f_ Menu ; f_options_P
;;
p11)
#************** p11) ARP SCAN ********************
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}ARP Scan${D}\n"
echo -e "${B}Active Network Interfaces${D}\n"
ip -4 addr show | awk '/inet.*brd/{print $NF}'
echo -e -n "\n${B}Set  >  ${D}Network Interface -e.g. eth0  ${B}>>${D}  " ; read interface
echo -e "\n == $interface ARP SCAN ==\n" >> $out/ARP_$interface.txt
echo -e " Date: $(date) " >> $out/ARP_$interface.txt
echo '' ; sudo arp-scan -I ${interface} -l | sed '/Interface:/{x;p;x;}' |
sed '/Starting arp-scan/{x;p;x;G;}' | tee -a $out/ARP_$interface.txt
f_solidLong >> $out/ARP_$interface.txt ; echo '' ; f_removeDir ; f_Menu ; f_options_P
;;
p12)
#************** p12) DHCP Discover Broadcast (NMAP) ********************
f_makeNewDir ; f_dashedGrey
echo -e -n "\n${B}Mode    > [1]${D} IPv4   ${B}| [2]${D} IPv6  ${B}?${D}  " ; read option_ip_version
echo -e "\n\n${B}Nmap DHCP Discover${D}\n\n"
echo -e "\n == NMAP DHCP DISCOVER ==\n" >> $out/DHCP.txt
echo -e " Date: $(date) " >> $out/DHCP.txt
if [ $option_ip_version = "2" ] ; then
script="broadcast-dhcp6-discover" ; ipv='-6' ; else 
script="broadcast-dhcp-discover" ; ipv=''  ; fi
echo '' ; sudo nmap ${ipv} -v --script ${script} | sed '/NSE/d' | sed '/Initiating/d' |
sed '/Completed/d' | sed '/Read data files/d' | tee -a $out/DHCP.txt
f_solidLong >> $out/DHCP.txt; echo '' ; f_removeDir ; f_menuP
;;
t1)
#************** t) TRACEROUTE OPTIONS  ********************
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}NMAP NSE Geo Traceroute${D}"
echo -e -n "\n${B}Target > ${D}HOSTNAME(s)${B} | ${D}IP(s)${B}  >>${D}   " ; read address
echo -e "\n\n == $address NMAP GEO TRACEROUTE ==" >> $out/ROUTES.${address}.txt
echo -e "\n" | tee -a $out/ROUTES.${address}.txt
sudo nmap -sn --traceroute --script traceroute-geolocation $address | sed '/Read data files/d' | tee -a $out/ROUTES.${address}.txt
f_solidLong >> $out/ROUTES.${address}.txt ; echo '' ; f_removeDir ; f_Menu ; f_options_T
;;
t2)
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}NMAP Path MTU Discovery (TCP)${D}"
echo -e -n "\n${B}Target > ${D}HOSTNAME(s)${B} | ${D}IP(s)${B}  >>${D}   " ; read address
echo -e -n "\n${B}Ports  > ${D} e.g. 636,989-995  ${B}>>${D}  " ; read ports
echo -e "\n == NMAP MTU DISCOVERY ==\n" >> $out/MTU.${address}.txt
echo -e " Target > ${address}, Date > $(date)\n\n" >> $out/MTU.${address}.txt
echo -e "\n" ; sudo nmap -sS -Pn -p ${ports} --script path-mtu $address | tee -a $out/MTU.${address}.txt
echo '' ; f_removeDir ; f_Menu; f_options_T
;;
t3)
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}MTR Traceroute${D}"
echo -e -n "\n${B}Target    >  ${D}Hostname ${B}|${D} URL ${B}|${D} IP  ${B}>>${D}  " ; read address
echo -e -n "\n${B}Source    > [1] ${D}App (local inst.) ${B}| [2] ${D} hackertarget.com API  ${B}?${D}  " ; read option_source
if [ $option_source = "2" ] ; then
echo -e -n "\n${B}Target  >  ${D}Hostname ${B}|${D} IPv4 Address ${B}>>${D}  " ; read address
echo -e "\n == $address MTR TRACEROUTE (via hackertarget.com) == ${D} \n" >> $out/ROUTES.${address}.txt
echo -e " Date: $(date) \n" >> $out/ROUTES.${address}.txt ; echo -e "\n"
curl -s https://api.hackertarget.com/mtr/?q=${address}${api_key_ht}  | tee -a $out/ROUTES.${address}.txt
echo '' | tee -a $out/ROUTES.${address}.txt ; else
echo -e -n "\n${B}Target > [1]${D} Set target  ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target  >  ${D}Hostname ${B}|${D} IPv4 / IPv6 Address ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
declare -a mtr_array=()
echo -e -n "\n${B}Options   > [4]${D} IPV4 MODE  ${B}| [6]${D}  IPV6 MODE ${B}| [9]${D}  AUTO (DEFAULT)  ${B}?${D}  " ; read IPvChoice
if  [ $IPvChoice = "4" ] ; then
mtr_array+=(-4)
elif  [ $IPvChoice = "6" ] ; then
mtr_array+=(-6) ; else
: ; fi
echo -e -n "\n${B}Set       >${D}  Max. hops (default 30): ${B}max hops  >>${D}  " ; read hops
mtr_array+=(-m ${hops})
echo -e -n "\n${B}Option    >${D}  No of pings - e.g. 5  ${B}>>${D}  " ; read pingcount
mtr_array+=(-c ${pingcount})
echo -e -n "\n${B}Protocols > [1]${D}  TCP  ${B}| [2]${D}  UDP  ${B}| [3]${D}  ICMP  ${B}?${D}  " ; read protocol_input
if  [ $protocol_input = "1" ] ; then
mtr_array+=(--tcp)
echo -e -n "\n${B}Set       >${D}  Target Port - e.g. 25  ${B}>>${D}  " ; read t_port
mtr_array+=(-P ${t_port}) ; echo ''
elif   [ $protocol_input = "2" ] ; then
mtr_array+=(--udp) ; else
:; fi
for x in $(cat "$targets") ; do
output="$out/ROUTES.${x}.txt"
echo -e "\n\n[+] ${x} MTR\n" | tee -a ${output}
sudo mtr -w -b -z ${mtr_array[@]} -o "  L  S D  A BW  M" $address | sed '/HOST:/G' | tee -a ${output}
echo '' | tee -a ${output} ; f_solidShorter | tee -a ${output}
echo -e "Snt = packages sent; Javg = average jitter\n" | tee -a ${output} ; done ; fi 
echo '' ; f_removeDir ; f_Menu ; f_options_T
;;
t4)
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}Dublin Traceroute"
echo -e -n "\n${B}Target > [1]${D} new target ${B}| [2] current > ${D}$target  ${B}?${D}  " ; read answer
if [ $answer = "2" ] ; then
address=`echo $target` ; else
echo -e -n "\n${B}Target >  ${D}Hostname ${B}|${D}  URL ${B}|${D}  IP  ${B}>>${D}  " ; read address ; fi
echo -e "\n" ; sudo dublin-traceroute -n 12 $address | sed '/Flow ID/{x;p;x;G;}' |
tee -a $out/ROUTES.${address}.txt
f_solidLong >> $out/ROUTES.${address}.txt
echo '' ; f_removeDir ; f_Menu ; f_options_T
;;
t5)
f_makeNewDir ; f_dashedGrey ; declare -a path_array=()
echo -e "\n${B}Tracepath (non root)${D}\n"
if ! [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Target  > [1]${D} new target ${B}| [2] current >  ${D}$target ${B}?${D}  " ; read answer
if [ $answer = "2" ] ; then
address=`echo $target` ; else
echo -e -n "\n ${B}Hostname | URL | IP >>  " ; read address ; fi
echo -e -n "\n${B}Options > [4]${D} IPv4 Mode  ${B}| [6]${D} IPv6 Mode | ${B}[b]${D} both ${B}?${D} " ; read IPvChoice
echo -e -n "\n${B}Set     >${D} Max. amount of hops (default: 30) ${B} >>${D}  " ; read hops
if   [ $IPvChoice = "6" ] ; then
ipv="6" ; path_array+=(-6 -b) ; else 
ipv="4" ; path_array+=(-4 -b) ; fi 
f_solidLong | $out/ROUTES.${address}.txt
if   [ $IPvChoice = "b" ] ; then
ipv="4" ; path_array+=(-4 -b)
echo -e "[+] $address Tracepath Results (IP$ipv)\n\n"  | tee -a $out/ROUTES.${address}.txt
tracepath  ${path_array[@]} -m ${hops} $address | tee -a $out/ROUTES.${address}.txt 
f_solidShort | tee -a $out/ROUTES.${address}.txt ; ipv="6" ; path_array+=(-6 -b) 
echo -e "[+] $address Tracepath Results (IP$ipv)\n\n"  | tee -a $out/ROUTES.${address}.txt
tracepath  ${path_array[@]} -m ${hops} $address | tee -a $out/ROUTES.${address}.txt ; else 
echo -e "[+] $address Tracepath Results (IP$ipv)\n\n"  | tee -a $out/ROUTES.${address}.txt
tracepath  ${path_array[@]} -m ${hops} $address | tee -a $out/ROUTES.${address}.txt ; fi ; else 
f_WARNING ; fi ; echo '' ; f_removeDir ; f_Menu; f_options_T
;;
t6)
f_makeNewDir ; f_dashedGrey
echo -e -n "\n${B}Target > [1]${D} Set target IPv6 Address  ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D} IPv6 Address   ${B}>>${D}   " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE  ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
echo -e "\n${B}Active Network Interfaces${D}\n"
ip -6 addr show | grep 'state UP' | cut -d ':' -f 2 | sed 's/^ *//'
echo -e -n "\n${B}Set  >  ${D}Network Interface -e.g. eth0  ${B}>>${D}  " ; read interface
for x in $(cat "$targets") ; do
output="$out/ROUTES.${x}.txt"
echo -e "\n[+] ${x} trace6\n" | tee -a ${output}
echo '' | tee -a ${output}
sudo atk6-trace6 -t -d ${interface} ${x} | tee -a ${output}
echo '' | tee -a ${output} ; f_solidLong >> ${output} ; done
f_removeDir ; f_Menu; f_options_T
;;
q)
echo -e "\n${B}----------------------------------- Done -------------------------------------\n"
echo -e "                       ${BDim}Author - Thomas Wy, Mar 2021${D}\n\n"
f_removeDir
break
;;
esac
done

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
#************ NMAP SCRIPT COLLECTIONS ***********
mx_safe="banner,smtp-commands,smtp-ntlm-info,imap-capabilities,imap-ntlm-info,pop3-capabilities,pop3-ntlm-info"
mx_ext_1="smtp-enum-users.nse"
mx_ext_2="smtp-enum-users.nse,smtp-open-relay"
mx_ext_root="smtp-strangeport,vulners"
SSL_enum="sslv2,ssl-enum-ciphers,ssl-dh-params,tls-alpn"
SSL_vulners="ssl-poodle,ssl-heartbleed"
http_safe="banner,http-server-header,ajp-headers,http-chrono,https-redirect,http-php-version,http-generator,http-affiliate-id,http-referer-checker,mysql-info"
http_safe_ext_1="http-auth,http-auth-finder"
http_safe_ext_2="http-security-headers,http-comments-displayer,http-robots.txt"
http_safe_ext_root="vulners"
http_intrusive="http-csrf,http-phpself-xss,http-dombased-xss,mysql-empty-password,http-unsafe-output-escaping,http-rfi-spider,http-sql-injection,http-malware-host,ftp-anon,http-enum,http-phpmyadmin-dir-traversal,smtp-strangeport,rpcinfo,ssh-auth-methods,ssh2-enum-algos,sshv1,http-methods --script-args http-methods.test-all"
sql_ftp_passwd_vulners="mysql-info,mysql-empty-password,ms-sql-empty-password,ms-sql-info,ms-sql-ntlm-info,ftp-anon"
vulners_1="http-malware-host,smtp-strangeport,vulners"
vulners_2="mysql-empty-password,ms-sql-empty-password,ms-sql-ntlm-info,http-malware-host,smtp-strangeport,vulners,ftp-anon"
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

#************ menus *************
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
curl -s http://ip-api.com/json/${s}?fields=21118939 > $tempdir/geo.json
whois -h whois.cymru.com -- "-v -f ${s}" > $tempdir/cymru.txt
country=`jq -r '.country' $tempdir/geo.json`
as=`cut -d '|' -f 1 $tempdir/cymru.txt | sed 's/^ *//'`
echo '' ; f_BOX " ${s} - $country - AS $as " ; echo ''
}
function f_OUTPUT_HEADER {
local s="$*"
echo -e "   \n  [ ${s} ] \n" >> ${output}
echo -e "_____________________________________\n" >> ${output}
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
sed '/Parent:/d' | sed '/[Rr]emarks/d' | sed '/admin-c/d' | sed '/[Ff]ax/d' | sed '/PostalCode:/d' |
sed '/mnt-irt:/d' | sed '/irt:/d' | sed '/tech-c:/d' | sed '/StateProv:/d' | sed '/OrgNOCHandle:/d' |
sed '/OrgTech/d' | sed '/OrgAbuseHandle/d' | sed "/^[[:space:]]*$/d" | sed 's/inetnum/\ninetnum/' |
sed 's/organisation/\norganisation/' | sed 's/role/\nrole/' | sed 's/person/\nperson/' | sed 's/route/\nroute/' |
sed 's/OrgName/\nOrgName/' | sed 's/OrgNOCName:/\nOrgNOCName:/' |
sed 's/OrgAbuseName:/\nOrgAbuseName:/' > $tempdir/rev_whois.txt
if [ $whois_registry = "arin" ] ; then
sed -n '/NetRange/,/Updated/p'  $tempdir/rev_whois.txt | sed 's/OriginAS/\nOriginAS/'
echo -e "\n---------------------------------------------\n"
sed -n '/OrgName/,/Updated/p' $tempdir/rev_whois.txt
echo -e "\n---------------------------------------------\n"
sed -e '/./{H;$!d;}' -e 'x;/OrgNOCName:/!d;' $tempdir/rev_whois.txt
sed -e '/./{H;$!d;}' -e 'x;/OrgAbuseName:/!d;' $tempdir/rev_whois.txt
else
sed -n '/inetnum/,/source/{/source/!p}' $tempdir/rev_whois.txt | sed '/netname/G' | sed '/org:/d'
sed -n '/source/,/route/{/route/!p}' $tempdir/rev_whois.txt | sed '/abuse-c:/d' | sed '/tech-c:/d' |
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
function f_certInfo_Curl {
#First certificate
grep -w -i -m 1 'subject:' $tempdir/curl.txt > $tempdir/subject1.txt
grep -w -i -m 1 'issuer:' $tempdir/curl.txt > $tempdir/issuer1.txt
s_cn=`cat $tempdir/subject1.txt | sed 's/^.*CN=/CN=/' | sed 's/CN=//' | sed 's/^ *//'`
s_org=`grep -oP '(O=).*?(?=;)' $tempdir/subject1.txt | sed 's/O=/| Org: /' | sed 's/^ *//'`
s_country=`grep -oP '(C=).*?(?=;)' $tempdir/subject1.txt | sed 's/^ *//' | sed 's/C=/\| /'`
s_city=`grep -oP '(L=).*?(?=;)' $tempdir/subject1.txt | sed 's/^ *//' | sed 's/L=/\| /'`
i_cn=`cat $tempdir/issuer1.txt | sed 's/^.*CN=/CN=/' | sed 's/CN=//' | sed 's/^ *//'`
i_org=`grep -oP '(O=).*?(?=;)' $tempdir/issuer1.txt | sed 's/O=/| Org: /' | sed 's/^ *//'`
i_country=`grep -oP '(C=).*?(?=;)' $tempdir/issuer1.txt | sed 's/C=/\| /'  | sed 's/^ *//'`
i_city=`grep -oP '(L=).*?(?=;)' $tempdir/issuer1.txt | sed 's/L=/\| /' | sed 's/^ *//'`
verify=`grep -m 1 'SSL certificate verify' $tempdir/curl.txt | rev | cut -d ' ' -f1 | rev | tr -d '.'`
echo -e "\nVerification:      $verify"
echo -e "\nIssued:            $(grep -m 1 -oP '(start date:).*' $tempdir/curl.txt | cut -d ':' -f 2- | sed 's/^ *//')"
echo -e "Valid until:       $(grep -m 1 -oP '(expire date:).*' $tempdir/curl.txt | cut -d ':' -f 2- | sed 's/^ *//')"
echo -e "\nSubject:           $s_cn $s_org $s_city $s_country"
echo -e "\nCA:                $i_cn $i_org $i_country $i_city"
echo -e "\nCipher:            $(grep -m 1 'SSL connection using' $tempdir/curl.txt  | grep -o TLS.*)"
#2nd or last certificate
if [[ $(grep -w -i -c 'Server certificate:' $tempdir/curl.txt) -gt "1" ]] ; then
tac $tempdir/curl.txt | sed -n '/SSL certificate verify/,/SSL certificate verify/p' | sed '$d' > $tempdir/cert2.txt
grep -w -i -m 1 'subject:' $tempdir/cert2.txt > $tempdir/subject2.txt
grep -w -i -m 1 'issuer:' $tempdir/cert2.txt > $tempdir/issuer2.txt
s_cn=`cat $tempdir/subject2.txt | sed 's/^.*CN=/CN=/' | sed 's/CN=//' | sed 's/^ *//'`
s_org=`grep -oP '(O=).*?(?=;)' $tempdir/subject2.txt | sed 's/O=/| Org: /' | sed 's/^ *//'`
s_country=`grep -oP '(C=).*?(?=;)' $tempdir/subject2.txt | sed 's/^ *//' | sed 's/C=/\| /'`
s_city=`grep -oP '(L=).*?(?=;)' $tempdir/subject2.txt | sed 's/^ *//' | sed 's/L=/\| /'`
i_cn=`cat $tempdir/issuer2.txt | sed 's/^.*CN=/CN=/' | sed 's/CN=//' | sed 's/^ *//'`
i_org=`grep -oP '(O=).*?(?=;)' $tempdir/issuer2.txt | sed 's/O=/| Org: /' | sed 's/^ *//'`
i_country=`grep -oP '(C=).*?(?=;)' $tempdir/issuer2.txt | sed 's/C=/\| /'  | sed 's/^ *//'`
i_city=`grep -oP '(L=).*?(?=;)' $tempdir/issuer2.txt | sed 's/L=/\| /' | sed 's/^ *//'`
verify=`grep 'SSL certificate verify' $tempdir/cert2.txt | rev | cut -d ' ' -f1 | rev | tr -d '.'`
echo -e "\n----------------------------------------------------\n"
echo -e "Verification:      $verify"
echo -e "\nIssued:            $(grep -m 1 -oP '(start date:).*' $tempdir/cert2.txt | cut -d ':' -f 2- | sed 's/^ *//')"
echo -e "Valid until:       $(grep -m 1 -oP '(expire date:).*' $tempdir/cert2.txt | cut -d ':' -f 2- | sed 's/^ *//')"
echo -e "\nSubject:           $s_cn $s_org $s_city $s_country"
echo -e "\nCA:                $i_cn $i_org $i_country $i_city"
echo -e "\nCipher:            $(sed '/SSL connection using/!d' $tempdir/cert2.txt | grep -o TLS.*)\n"
fi
}

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
sed '/ip:/i \\n___\n' > $tempdir/banners.txt
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
awk '{ IGNORECASE=1 } /HTTP|Location|Server|Cloudflare|Strict-Transport-Security|Varnish|X-Powered-By|X-Generator|X-Server-Instance-Name|X-Content-Type-Options|X-Permitted-Cross-Domain-Policies|X-XSS-Protection/ { print }' $out/HEADERS.${s}.txt |
sed 's/HTTP/\nHTTP/' | sed '/[Ll]ink:/d' | sed '/[Rr]eport-[Tt]o:/d' | sed '/[Cc]ontent-[Ss]ecurity-[Pp]olicy:/d' | sed '/[Ff]eature-[Pp]olicy:/d' | sed '/permissions-policy:/d' |
sed '/[Ee]-[Tt]ag:/d' | sed '/expect-ct:/d' | fmt -w 70 -s
}
function f_socialLinks {
local s="$*"
if ! type lynx &> /dev/null; then
echo "Please install lynx"; else
timeout 3 lynx -accept_all_cookies -dump -listonly -nonumbers www.${s} > $out/LINK_DUMP.${s}.txt
grep -i -F -econtact -ediscord -ekontakt -efacebook -egithub -einstagram -elinkedin -epinterest -etwitter -exing -eyoutube  $out/LINK_DUMP.${s}.txt |
sed '/sport/d' | sed '/program/d' > $tempdir/social.txt
grep -i -F -etel: -efon: -ephone -emailto: $out/LINK_DUMP.${s}.txt | sed 's/mailto:/\nmailto:/' |
sed 's/mailto://' > $tempdir/contacts.txt ; fi
curl ${s}/kontakt -sLk > $tempdir/page.txt
curl ${s}/contact -sLk >> $tempdir/page.txt
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/src.txt >> $tempdir/contacts.txt
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/page.txt >> $tempdir/contacts.txt
grep -oP '(Email\[).*?(?=])' $tempdir/ww.txt | sed 's/Email\[//' | tr -d '][' | sed 's/,/\n/g' |  sed 's/^ *//' >>  $tempdir/contacts.txt
echo -e "\n\n[+] E-Mail\n"
sort $tempdir/contacts.txt | uniq
echo -e "\n\n[+] Social Media & Contact Links\n"
sort $tempdir/social.txt | uniq
}
function f_linkDump {
local s="$*"
if ! type lynx &> /dev/null; then
echo "Please install lynx" ; else
echo -e "\n== $s LINK DUMP ==\n" >> $out/LINK_DUMP.$s.txt
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
echo -e "[+] Status & Redirects\n" 
cut -d ']' -f 1  $tempdir/ww.txt | sed '/http/ s/$/]/' | sed '/^$/d'
grep -oP '(IP\[).*?(?=])'  $tempdir/ww.txt  | tail -1 | sed 's/IP\[/ > /' | tr -d '][' | sed 's/^ *//'
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
grep -oP '(Via\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/Via\[/\nVia:     /' | tr -d ']['
grep -oP '(Via-Proxy\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/Via-Proxy\[/\nProxy: /' | tr -d ']['
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
grep -oP '(PasswordField\[).*?(?=\])' $tempdir/ww.txt | sed 's/PasswordField\[/PasswordField:  /' | tr -d ']' 
grep -oP '(WWW-Authenticate\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/\[/:  /' | tr -d ']['
grep -oP -m 1 '(Content-Language\[).*?(?=\])' $tempdir/ww.txt | sed 's/Content-Language\[/Language: /' | tr -d ']'
grep -oP '(Strict-Transport-Security\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/: /' | tr -d ']['
grep -oP '(X-Frame-Options\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/\[/:  /' | tr -d ']['
grep -oP '(X-XSS-Protection\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/:  /' | tr -d ']['
grep -oP '(HttpOnly\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/\[/:  /' | tr -d ']['
grep -oP '(Cookies\[).*?(?=\])' $tempdir/ww.txt | sort -u  | sed 's/\[/:  /' | tr -d ']['
grep -oP '(X-UA-Compatible\[).*?(?=\])' $tempdir/ww.txt | sort -u  | sed 's/\[/: /' | tr -d ']'
grep -oP '(UncommonHeaders\[).*?(?=,)' $tempdir/ww.txt | sort -u | sed 's/UncommonHeaders\[/Uncommon Headers:\n\[ /' | tr -d '][' | sed 's/^ *//'
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
f_solidShort ;  echo -e "[+] DNS Blocklists\n" ; echo -e " [ $s ] \n"
reverse=$(echo ${s} | sed -ne "s~^\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)$~\4.\3.\2.\1~p")
for i in ${blacklists} ; do
in_list="$(dig @1.1.1.1 +short -t a ${reverse}.${i}.)"
if [[ $in_list ]]; then
echo -e "${R}YES${D} (${in_list}) | ${i}" ; else
echo -e "NO | ${i}" ; fi ; done
}
function f_RIPE_BLACKLIST {
local s="$*"
f_solidShorter ; echo -e "[+] Blacklist Info (RIPEstat)\n" ; echo -e " [ $s ] "
curl -s https://stat.ripe.net/data/blacklist/data.json?resource=${s} > $tempdir/ripestat_blackl.json
jq -r '.data.sources[]' $tempdir/ripestat_blackl.json | tr -d ']},\":[{' | sed 's/^ *//' | sed '/^$/d' |
sed '/prefix/i \\n______\n' | sed '/timelines/{x;p;x;}' | sed '/starttime/{x;p;x;}' 
}

#********************** RIPEstat API  *****************************
function f_RIPE_CHAIN {
local s="$*"
echo -e "\n___________________________________\n" ; echo -e "[+] PTR & Authoritative Nameservers\n"
curl -s https://stat.ripe.net/data/dns-chain/data.json?resource=${s} > $tempdir/chain.json
jq -r '.data.forward_nodes' $tempdir/chain.json | tr -d '{}]/":[}' | sed '/^$/d' | sed 's/^[ \t]*//' | head -1
echo '-' ; jq -r '.data.authoritative_nameservers[]' $tempdir/chain.json
}
function f_DELEGATION {
echo -e "[+] Delegation\n"
local s="$*" ; curl -s https://stat.ripe.net/data/reverse-dns/data.json?resource=${s} > $tempdir/revd.json
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
echo -e "\n[+] AS ${s}\n"
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
tr -d '{",}' | tee -a $out/AS.$as.txt
echo "\n________\n" >> $out/AS.$as.txt
}
function f_BGPview_UPSTREAMS {
curl -s https://api.bgpview.io/asn/$as/upstreams > $tempdir/ups.json
echo -e "\n${B}AS $as IPv4 Upstreams${D}\n"
echo -e "\n== AS $as IPv4 UPSTREAMS ==\n" >> $out/AS.$as.txt
jq -r '.data.ipv4_upstreams[] | {ASN: .asn, Name: .name, Desc: .description, Loc: .country_code}' $tempdir/ups.json |
tr -d '{",}' | sed 's/^ *//' | tee -a $out/AS.$as.txt
echo -e "\n${B}AS $as IPv6 Upstreams${D}\n"
echo -e "\n== AS $as IPv6 UPSTREAMS ==\n" >> $out/AS.$as.txt
jq -r '.data.ipv6_upstreams[] | {ASN: .asn, Name: .name, Desc: .description, Loc: .country_code}' $tempdir/ups.json |
tr -d '{",}' | sed 's/^ *//' | tee -a $out/AS.$as.txt
}
function f_BGPviewPREFIXES {
curl -s https://api.bgpview.io/asn/${as}/prefixes  > $tempdir/prefixes.json
echo -e "\n[+] IPv6 Prefixes\n"
jq -r '.data.ipv6_prefixes[] | .prefix, .description, .country_code' $tempdir/prefixes.json | sed 'n;n;G;'
echo -e "\n\n_________________\n" ; echo -e "[+] IPv4 Prefixes\n\n"
jq -r '.data.ipv4_prefixes[] | .prefix, .description, .country_code' $tempdir/prefixes.json | sed 'n;n;G;'
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

function f_DRWHO {
local s="$*"
net=`echo "$s" | rev | cut -d '/' -f 2- | rev`
f_REGISTRY "${s}" ; echo -e "\n\n[+] ${s}\n" >> $out/WHOIS.txt
f_revWHOIS >> $out/WHOIS.txt ; f_solidLong >> $out/WHOIS.txt
prefix=`cut -d '|' -f 3 $tempdir/cymru.txt | tr -d ' '`
as=`cut -d '|' -f 1 $tempdir/cymru.txt | sed 's/^ *//' | tr -d ' '`
if [ $whois_registry = "arin" ] ; then
netname=`grep -m 1 '^NetName:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'`
netrange=`grep -m 1 '^NetRange:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'`
cidr=`grep -m 1 '^CIDR:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
elif [ $whois_registry = "lacnic" ] ; then
netname=`grep -m 1 '^inetrev:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'`
cidr=`grep -m 1 '^inetnum:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'`
else 
netname=`grep -m 1 '^netname:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'`
if [[ ${s} =~ $REGEX_IP4 ]] || [[ ${net} =~ $REGEX_IP4 ]] ; then
inetnum=`grep -m 1 '^inetnum:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'` ; else 
cidr=`grep -m 1 '^inet6num:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'` ; fi
fi
if [ $type_net = "false" ] ; then
whois -h whois.pwhois.org type=all ${s} > $tempdir/p_full.txt
if cat $tempdir/p_full.txt | grep -q -E "^Geo-"; then
city="Geo-City:"
cc="Geo-Country-Code:" ; else
city="City:"
cc="Country-Code:" ; fi
org_cc=`grep -m1 -E "${cc}" $tempdir/p_full.txt | cut -d ':' -f 2- | sed 's/^ //'`
org_city=`grep -m1 -E "${city}" $tempdir/p_full.txt | cut -d ':' -f 2- | sed 's/^ //'`
if [ $whois_registry = "ripencc" ] ; then
curl -s https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${s} > $tempdir/ac.json
less_sp=$(jq -r '.data.less_specifics[0]' $tempdir/ac.json)
curl -s https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${less_sp} > $tempdir/lsloc.json
fi
if [ $option_server = "y" ] ; then
echo -e "\n__________\n"
echo -e "[+] Server\n"
echo -e "IP:          $(jq -r '.query' $tempdir/geo.json)"
echo -e "PTR:         $(jq -r '.reverse' $tempdir/geo.json)"
echo -e "\nProxy:       $(jq -r '.proxy' $tempdir/geo.json)" ; else
echo -e "\n________\n"
echo -e "[+] Host\n"
echo -e "IP:          $(jq -r '.query' $tempdir/geo.json)"
echo -e "PTR:         $(jq -r '.reverse' $tempdir/geo.json)"
echo -e "\nMobile:      $(jq -r '.mobile' $tempdir/geo.json)"
echo -e "Proxy:       $(jq -r '.proxy' $tempdir/geo.json)" ; fi
if [[ ${s} =~ $REGEX_IP4 ]] ; then
curl -s -L https://isc.sans.edu/api/ip/${s}?text | tr -d '(][)' | sed 's/ =>/: /' | sed 's/Array//' | sed 's/^[ \t]*//' | sed '/^$/d' |
sed '1,1d' > $tempdir/isc.txt
echo -e "\nCloud:       $(grep -s 'cloud:' $tempdir/isc.txt | cut -d ':' -f 2- | sed 's/^ *//')" ; fi
echo -e "Hosting:     $(jq -r '.hosting' $tempdir/geo.json)"
echo -e "\n\n_____________\n"
echo -e "[+] Location\n"
echo -e "Country:      $(jq -r '.country' $tempdir/geo.json) ($(jq -r '.countryCode' $tempdir/geo.json))"
echo -e "City:         $(jq -r '.city' $tempdir/geo.json)"
echo -e "\nRegion:       $(jq -r '.regionName' $tempdir/geo.json)"
echo -e "Timezone:     $(jq -r '.timezone' $tempdir/geo.json)"
echo -e "Lat.,Lon.:    $(jq -r '.lat' $tempdir/geo.json), $(jq -r '.lon' $tempdir/geo.json)"
echo -e "\n_______\n"
echo -e "[+] ISP\n"
jq -r '.isp' $tempdir/geo.json
if [[ ${s} =~ $REGEX_IP4 ]] ; then
echo '' ;  f_ISC_Feeds
echo -e "\n[+] Network Blacklist Info\n"
jq -r '.data.blacklist_info[] | .list, .entries' $tempdir/ac.json ; fi
if ! [[ ${s} =~ $REGEX_IP4 ]] ; then
f_RIPE_CHAIN "${s}" ; echo -e "\n______________\n" ; f_DELEGATION "${s}" ; fi 
f_solidShort ; else 
echo '' ; fi 
echo -e "[+] Network \n\n"
echo -e "Net-Name:       $netname"
if [[ ${s} =~ $REGEX_IP4 ]] || [[ ${net} =~ $REGEX_IP4 ]] ; then
if [ $whois_registry = "arin" ] || [ $whois_registry = "lacnic" ] ; then
echo -e "CIDR:           $cidr" ; else 
echo -e "Net-Range       $inetnum" ; fi ; else 
echo -e "CIDR:           $cidr" ; fi
echo -e "\nRegistry:       $whois_registry"
echo -e "BGP Prefix:     $prefix"
if [ $type_net = "false" ] ; then
echo -e "\n\n_________\n" ; echo -e "[+] Owner\n"
jq -r '.org' $tempdir/geo.json
echo -e "Branch:  $org_city $org_cc"
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt | grep 'abuse\|noc' | sort -f -u  ; else 
if [ $whois_registry = "arin" ] ; then
echo -e "\n\n_________\n" ; echo -e "[+] Owner\n"
grep -m 1 '^Organization:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'
echo ''
grep -m 1 '^OrgAbuseEmail:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'
elif [ $whois_registry = "lacnic" ] ; then
echo -e "\n\n_________\n" ; echo -e "[+] Owner\n"
grep -m 1 '^owner:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'
echo ''
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt | grep 'abuse\|noc' | sort -f -u
else
echo -e "\n\n________________\n" 
echo -e "[+] Organisation\n"
grep '^org-name:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'
grep '^org:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'
grep '^country:' $tempdir/whois.txt  | cut -d ':' -f 2- | sed 's/^ *//'
echo ''
grep -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt
fi ; fi
if [ $type_net = "false" ] && [ $whois_registry = "ripencc" ] ; then
echo -e "\n__________________\n" ; echo -e "[+] Less specifics\n"
echo "$less_sp"
curl -s https://stat.ripe.net/data/reverse-dns-consistency/data.json?resource=${less_sp} > $tempdir/nets.json
if [[ ${s} =~ $REGEX_IP4 ]]; then
jq -r '.data.prefixes.ipv4' $tempdir/nets.json | grep 'prefix' | tr -d ',\"' | cut -d ':' -f 2- | tr -d ' ' ; else
jq -r '.data.prefixes.ipv6' $tempdir/nets.json | grep 'prefix' | tr -d ',\"' | cut -d ':' -f 2- | tr -d ' ' ; fi
fi
f_solidShort ; echo -e "[+] Origin AS \n"
echo -e "AS Num:        $as" 
echo -e "AS Name:       $(cut -d '|' -f 7 $tempdir/cymru.txt | sed 's/^ *//')" 
if [ $type_net = "false" ] ; then 
echo -e "AS Org:        $(jq -r '.as' $tempdir/geo.json | cut -d ' ' -f 2- | sed 's/^ *//')"
if [[ ${s} =~ $REGEX_IP4 ]] ; then
echo -e "\nAS Size:       $(grep -w 'assize' $tempdir/isc.txt | cut -d ':' -f 2- | sed 's/^ *//' | sed -e :a -e 's/\(.*[0-9]\)\([0-9]\{3\}\)/\1,\2/;ta')"
echo -e "Contact:       $(grep -w 'asabusecontact:' $tempdir/isc.txt | cut -d ':' -f 2- | sed 's/^ *//')" ; fi ; fi
if  [ $option_details = "2" ] ; then 
if [ $type_net = "false" ] && [[ ${s} =~ $REGEX_IP4 ]]; then
f_solidShort; echo -e "[+] Host Details"
if [ $option_banners = "y" ] ; then 
f_BANNERS "${s}"
if cat $tempdir/banners.txt | grep -q -E "http*"  &&  [ $option_ww = "y" ] ; then
curl -s https://api.hackertarget.com/whatweb/?q=${s}${api_key_ht} > $tempdir/ww.txt
f_solidShortest ; f_WHATWEB_REDIR ; f_WHATWEB_CODE
echo -e "\n\n[+] Title\n" ; grep -oP '(Title\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/Title\[//' |
tr -d ']' | tail -1 | sed 's/^ *//'
grep -oP '(Meta-Author\[).*?(?=,)' $tempdir/ww.txt | tr -d ']' | sed 's/Meta-Author\[/\n[+] Author\n\n/' | sed 's/^ *//'
grep -oP '(Email\[).*?(?=])' $tempdir/ww.txt | tr -d '][' |  sed 's/Email/\n[+] E-Mail\n/' | sed 's/,/\n/g' |  sed 's/^ *//'
fi ; fi
f_RIPE_CHAIN "${s}" ; echo -e "\n______________\n" ; f_DELEGATION "${s}"
fi
f_solidShort ; echo -e "[+] Network Details\n"
echo -e "\n[+] Owner Contact\n"
if [ $whois_registry = "lacnic" ] ; then
grep "responsible:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'
grep "owner:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'
elif [ $whois_registry = "arin" ] ; then
zip=`grep "PostalCode:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
state=`grep "StateProv:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' `
arin_country=`grep 'Country:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
arin_city=`grep 'City:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
grep "Address:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'
echo "$state - $zip"
echo "$arin_city, $arin_country" ; echo ''
grep -w 'OrgAbusePhone:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' ; else
sed -n 'H; /^organisation/h; ${g;p;}' $tempdir/whois.txt  | sed -n '/organisation/,/source/p' | grep -s 'organisation\|address' | cut -d ':' -f 2- |
sed 's/^ *//' | sed '/organisation/{x;p;x;}'
sed -n 'H; /^role/h; ${g;p;}' $tempdir/whois.txt  | sed -n '/role/,/source/p' | grep 'role\|address' | sed '/role/{x;p;x}'  | cut -d ':' -f 2- | sed 's/^ *//'
sed -n 'H; /^person/h; ${g;p;}' $tempdir/whois.txt  | sed -n '/person/,/source/p' | grep 'person\|address' | sed '/person/{x;p;x}' |
cut -d ':' -f 2- | sed 's/^ *//' ; echo '' ; fi
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt | sort -f -u
f_solidShorter
echo -e "[+] Owner Handles\n"
if [ $whois_registry = "arin" ] ; then
grep -w 'NetHandle:' $tempdir/whois.txt
grep -w 'OrgAbuseHandle:' $tempdir/whois.txt
grep -w 'OrgNOCHandle:' $tempdir/whois.txt
elif [ $whois_registry = "lacnic" ] ; then
echo -e "[+] owner-c:\n"
grep -w 'owner-c:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' 
echo -e "\n[+] tech-c:\n"
grep -w 'tech-c:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' ; else 
echo -e "[+] abuse-c:\n"
grep -w 'abuse-c:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' > $tempdir/abuse_c.txt
sort $tempdir/abuse_c.txt | uniq
echo -e "\n[+] admin-c:\n"
grep -w 'admin-c:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' > $tempdir/admins.txt
grep -w 'nic-hdl:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' >> $tempdir/admins.txt
sort $tempdir/admins.txt | uniq
echo -e "\n[+] mnt-by:\n"
mnt_by=`grep -w 'mnt-by:' $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
echo "$mnt_by" | sort -u ; fi
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
ipcalc -b -n ${s} | sed '/Address:/d' | sed '/Network:/d' | sed '/Broadcast/d'
else 
sipcalc ${s} > $tempdir/scalc.txt
grep -w 'Compressed'    $tempdir/scalc.txt ; echo '' 
grep -w 'Expanded'      $tempdir/scalc.txt ; echo '' 
grep -w 'Subnet prefix' $tempdir/scalc.txt ; echo ''
grep -w 'Address ID (masked)' $tempdir/scalc.txt 
grep -w 'Prefix address' $tempdir/scalc.txt ; echo -e '' 
grep -A 1 'Network range' $tempdir/scalc.txt
fi
echo -e "\n_________\n"
echo -e "[+] Owner\n"
jq -r '.data.name' $tempdir/pfx.json
jq -r '.data.description_full[]' $tempdir/pfx.json ; echo ''
jq -r '.data.owner_address[]' $tempdir/pfx.json ; echo ''
jq -r '.data.email_contacts[]' $tempdir/pfx.json
echo -e "__________________\n"
echo -e "[+] Country Codes \n"
echo -e "Whois:         $(jq -r '.data.country_codes.whois_country_code' $tempdir/pfx.json)"
echo -e "Allocation:    $(jq -r '.data.country_codes.rir_allocation_country_code' $tempdir/pfx.json)"
echo -e "_____________________\n"
echo -e "[+] Network Upstreams\n"
echo "$prefix_upstreams"
}

function f_options_SERVERS {
echo -e "\n ${B}22)${D}  Shared Name Servers             ${B}24)${D}  DNS Zone & Nameservers"
echo -e " ${B}23)${D}  Zone Transfer                   ${B}25)${D}  Mail Server Info & Blacklisting"
}
function f_optionsWhois {
echo -e "\n ${B}33)${D}  whois                          ${B}36)${D}  Prefixes, Peering & IX Memberships"
echo -e " ${B}34)${D}  Search by Org-/ AS-Name        ${B}37)${D}  IX Information"
echo -e " ${B}35)${D}  Search by AS Number            ${B}38)${D}  RIPESTAT Looking Glass"
}
function f_optionsIPV4 {
echo -e "\n ${B}44)${D}  IPv4 Address Information, Virtual Hosts"
echo -e " ${B}45)${D}  IPv4 Network Information"
echo -e " ${B}46)${D}  IPv4 Network Reverse DNS, Service Banners & VHosts"
echo -e " ${B}47)${D}  NMAP Ping Sweep (IPv4)"
}
function f_optionsIPV6 {
echo -e "\n ${B}61)${D}  Dump Router6 / Dump DHCP6"  
echo -e " ${B}62)${D}  ICMPv6"
echo -e " ${B}63)${D}  MAC/IPv4 to IPv6 Conversion" 
echo -e " ${B}64)${D}  IPv6 Network / Host Portions (bulk)" 
echo -e " ${B}65)${D}  Subdomains (IPv6)" 
echo -e " ${B}66)${D}  IPv6 Address & - Network Information" 
echo -e " ${B}67)${D}  IPv6 Reverse DNS"
}
function f_optionsWEBSERVERS {
echo -e "\n ${B}111)${D}  HTTP Headers                ${B}113)${D}  Web Server Status & Response Times"
echo -e " ${B}112)${D}  robots.txt                  ${B}115)${D}  Web Server Security"
echo -e " ${B}113)${D}  Link Dump"
}
function f_options_T {
echo -e "\n ${B}t1)${D}  Nmap Geo Traceroute           ${B}t3)${D}  Dublin Traceroute"
echo -e " ${B}t2)${D}  MTR Traceroute                ${B}t4)${D}  Tracepath (non-root)"
}
function f_options_P {
echo -e "\n ${B}p1)${D}  Port- & Version Scans        ${B}p4)${D}  Nping (API)"
echo -e " ${B}p2)${D}  Port Scan (API)              ${B}p5)${D}  Ping Sweep (Nmap)"
echo -e " ${B}p3)${D}  Banner Grabbing (API)        ${B}p6)${D}  ARP Scan"
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
conn="${R}false${D}"
else
conn="${GREEN}true${D}"
fi
echo -e -n "\n${B} > ${D}Set target?  ${B}[y]${D} yes ${B}| [n]${D} later ${B}?${D} " ; read option_target
if [ $option_target = "y" ] ; then
echo -e -n "\n ${B}Target >  ${D}DOMAIN ${B} >>${D}  " ; read target
if [ $option_connect = "9" ] ; then
if [[ $target =~ $REGEX_IP4 ]]; then
address_ipv4=`echo $target`
target_ip=`echo $target` ; else
target_ip=''
host_ip=''
target_dom=`echo $target` ; fi
else
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
conn="${R}false${D}"
else
conn="${GREEN}true${D}"
fi
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
fi
f_Menu
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
touch $tempdir/hosts.list ; option_server="y" ; option_details="2" ;
option_banners="y" ; option_ww="n" ; type_net="false"
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
echo -e -n "\n${B}Option >${D} Search for virtual hosts on target server  ${B}[y] | [n] ?${D}  " ; read option_vhosts ; echo ''
if ! [ $option_connect = "9" ] ; then
echo -e -n "${B}Option >${D} List supported ciphersuites  ${B}[y] | [n] ?${D}  " ; read option_ciphers ; echo ''
fi
for x in $(cat $hosts) ; do
f_textfileBanner >> $out/${x}.txt
f_solidLong | tee -a $out/${x}.txt ; echo -e "\n == ${x} == \n" >> $out/${x}.txt ; echo ''
f_whoisLOOKUP "${x}"
echo -e "\n== ${x} WHOIS == \n\n" >> $out/WHOIS.txt
cat $tempdir/host-whois2.txt >> $out/WHOIS.txt
#********
if [ $option_connect = "9" ] ; then
#********
curl -s https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht} > $tempdir/ww.txt
ip4=`grep -oP '(IP\[).*?(?=])' $tempdir/ww.txt | tail -1 | sed 's/IP\[//' | grep -E -o "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"`
f_BOX_BANNER "${ip4}" ; echo -e "\n${B}Website${D}\n" ; echo -e "\n == WEBSITE ==\n" >> $out/${x}.txt
f_WHATWEB_REDIR | tee -a $out/${x}.txt
f_WHATWEB_PAGE | tee -a $out/${x}.txt
f_solidShort | tee -a $out/${x}.txt ; echo -e "${B}Web- Technologies${D}"
echo -e "\n == WEB- TECHNOLOGIES == " >> $out/${x}.txt
f_WHATWEB_CODE | tee -a $out/${x}.txt
f_solidShort | tee -a $out/${x}.txt ; echo -e "${B}Domain Host${D}\n"
echo -e "\n == DOMAIN HOST == \n" >> $out/${x}.txt
f_DRWHO "${ip4}" | tee -a $out/${x}.txt
#********
else
#********
error_code=6
curl -s -f -L -k ${x} > /dev/null
if [ $? = ${error_code} ];then
echo -e "\n${R} $x WEBSITE CONNECTION: FAILURE${D}\n\n"
echo -e "\n $x WEBSITE CONNECTION: FAILURE\n" >> $out/${x}.txt
exit 1 ; else
echo -e "\n  ${B}WEBSITE STATUS: ${GREEN}ONLINE${D}"
echo -e "\n WEBSITE STATUS: ONLINE\n" >> $out/${x}.txt ; fi
curl -4 -s -v -L ${x} 2>$tempdir/curl.txt -D $out/HEADERS.${x}.txt -o $tempdir/src.txt -w \
"
URL:               %{url_effective}\n
IP:                %{remote_ip}
Port:              %{remote_port}\n
DNS_Lookup:        %{time_namelookup} s
Redirects:         %{time_redirect} s, (%{num_redirects})\n
SSL Handshake:     %{time_appconnect} s\n
———\n
Time Total:        %{time_total} s\n
" > $tempdir/response.txt
ip4="$(egrep -m 1 -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/response.txt)"
f_BOX_BANNER "${ip4}" ; echo ''
cat $tempdir/response.txt | tee -a $out/${x}.txt
f_solidShorter | tee -a $out/${x}.txt
f_headers "${x}" | tee -a $out/${x}.txt
f_solidShort | tee -a $out/${x}.txt
echo -e "${B}Website${D}\n" ; echo -e " == WEBSITE ==\n" >> $out/${x}.txt
f_WHATWEB "${x}"
f_WHATWEB_PAGE | tee -a $out/${x}.txt
f_socialLinks "${x}"  | tee -a $out/${x}.txt
f_solidShort | tee -a $out/${x}.txt ; echo -e "${B}Web- Technologies${D}\n"
echo -e " == WEB- TECHNOLOGIES == \n" >> $out/${x}.txt
f_WHATWEB_CODE | tee -a $out/${x}.txt
f_solidShort | tee -a $out/${x}.txt ; echo -e "${B}Domain Host${D}\n\n"
echo -e " == DOMAIN HOST == \n\n" >> $out/${x}.txt
echo -e "[+] A & AAAA Records\n\n" | tee -a $out/${x}.txt
f_aRecord "${x}" | tee -a $out/${x}.txt
f_DRWHO "${ip4}" | tee -a $out/${x}.txt
f_solidShort | tee -a $out/${x}.txt ; echo -e "${B}Certificate Status (curl)${D}\n"
echo -e "== CERTIFICATE STATUS (curl) ==\n" >> $out/${x}.txt
f_certInfo_Curl | tee -a $out/${x}.txt
echo '' | tee -a $out/${x}.txt
f_solidShorter | tee -a $out/${x}.txt
echo -e "${B}Certificate Status (openSSL)${D}"
echo -e "== CERTIFICATE STATUS (openSSL) ==" >> $out/${x}.txt
f_certInfo "${x}" | tee -a $out/${x}.txt
if [ $option_ciphers = "y" ] ; then
f_solidShort | tee -a $out/${x}.txt
echo -e "${B}Ciphersuites${D}\n" ; echo -e "\n== CIPHERSUITES ==\n\n"  >> $out/${x}.txt
nmap -sT -Pn -p 443 --script ${SSL_enum} ${x} | sed '/PORT/{x;p;x;G;}' | sed '/Read data files/d' |
sed '/NSE/d' | sed '/Initiating/d' | sed '/Completed/d' | sed '/Discovered/d' | sed '/Host is up/d' |
sed '/Starting Nmap/d' | fmt -w 100 -s | tee -a $out/${x}.txt ; fi
#********
fi
#********
f_solidShort | tee -a $out/${x}.txt
echo -e "${B}${x} whois${D}\n\n" ; echo -e "\n== ${x} WHOIS == \n\n" >> $out/${x}.txt
cat $tempdir/host-whois2.txt | tee -a $out/${x}.txt
if [ $option_vhosts = "y" ] ; then
f_solidShort | tee -a $out/${x}.txt
echo -e "${B}${ip4} Virtual Hosts${D}\n\n" ; echo -e "== ${ip4} VIRTUAL HOSTS ==\n\n" >> $out/${x}.txt
curl -s https://api.hackertarget.com/reverseiplookup/?q=${ip4}${api_key_ht} | tee -a $out/${x}.txt
echo -e "\n" | tee -a $out/${x}.txt ; fi ; done
f_solidLong >> $out/${x}.txt ;
echo '' ; f_removeDir ; f_Menu
;;
2)
f_makeNewDir ; f_dashedGrey ; touch $tempdir/hosts.list
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
echo -e -n "\n${B}Option > [1]${D} Show TTL values   ${B}| [2]${D} Show TTL values (human readable)  ${B}| [9]${D} SKIP  ${B}?${D}  " ; read option_ttl
if [ $option_ttl = "1" ] ; then
ttl="+ttlid"
elif [ $option_ttl = "2" ] ; then 
ttl="+ttlunits" ; else 
ttl="+nottlid" ; fi
echo -e -n "\n${B}Option > [1]${D} DNS records & subdomains  ${B}| [2]${D} DNS records only  ${B}?${D}  " ; read option_subs
for x in $(cat $hosts) ; do
#********
if [ $option_connect = "9" ] ; then
#********
echo -e "\n=== ${x} DNS RECORDS ===\n\n" >> $out/${x}.txt
echo -e "Date: $(date)\n" >> $out/${x}.txt
echo -e "\n\n${B}${x} DNS Records${D}\n"
curl -s https://api.hackertarget.com/dnslookup/?q=${x}${api_key_ht} | tee -a $out/${x}.txt
echo -e "\n\n${B}Source >${D} hackertarget.com IP Tools API"
echo -e "\n\nSource > hackertarget.com IP Tools API" >> $out/${x}.txt
f_solidLong >> $out/${x}.txt
#********
else
#********
f_solidLong
echo -e "\n${B}${x} A & AAAA Records${D}\n"
touch $tempdir/dnsrec.txt ; echo -e "\n === ${x} DNS RECORDS ===\n" > $tempdir/dnsrec.txt
echo -e "Date: $(date)\n" >> $tempdir/dnsrec.txt ; f_solidShortest >> $tempdir/dnsrec.txt
echo -e "\n == A & AAAA ==\n" >> $tempdir/dnsrec.txt
soa=`dig soa +short ${x}`
dig +noall +answer +noclass ${ttl} ${x} | tee -a $tempdir/dnsrec.txt
dig aaaa +noall +answer +noclass ${ttl} ${x} | tee -a $tempdir/dnsrec.txt
echo -e "\n\n == NS ==\n\n" >> $tempdir/dnsrec.txt
echo -e "\n\n${B}NS & MX Records${D}\n"
dig ns +noall +answer +noclass ${ttl} ${x} | tee -a $tempdir/dnsrec.txt
echo -e "\n\n == MX ==\n\n" >> $tempdir/dnsrec.txt ; echo ''
dig mx +noall +answer +noclass ${ttl} ${x} | tee -a $tempdir/dnsrec.txt
echo -e "\n\n${B}MX A/AAAA${D}\n"
echo -e "\n\n == MX A/AAAA == \n\n" >> $tempdir/dnsrec.txt
dig +noall +answer +noclass ${ttl} $(dig mx +short ${x}) | tee -a $tempdir/dnsrec.txt
echo '' | tee -a $tempdir/dnsrec.txt
dig aaaa +noall +answer ${ttl} +noclass $(dig mx +short ${x}) | tee -a $tempdir/dnsrec.txt
echo -e "\n${B}NS A/AAAA Records${D}\n"
echo -e "\n\n == NS A/AAAA == \n" >> $tempdir/dnsrec.txt
dig +noall +answer +noclass ${ttl} $(dig ns +short ${x}) | tee -a $tempdir/dnsrec.txt
echo '' | tee -a $tempdir/dnsrec.txt
dig aaaa +noall +answer +noclass ${ttl} $(dig ns +short ${x}) | tee -a $tempdir/dnsrec.txt
soa=`dig soa +short ${x}`
echo -e "\n\n${B}SOA:${D}  $soa"
echo -e "\n\n == SOA ==\n\n" >> $tempdir/dnsrec.txt ; echo ''
echo -e "$soa"  >> $tempdir/dnsrec.txt
dig soa +noall +answer +multiline ${x} > $tempdir/soa.txt
awk '{ print  $1 $2,   $3, $4, $5 }' $tempdir/soa.txt | sed '1,1d' |
sed '$d'  | sed '/serial/{x;p;x;}'  | tee -a $tempdir/dnsrec.txt
echo -e "\n\n${B}IPv4 PTR Records${D}\n"
echo -e "\n\n == PTR RECORDS ==\n" >> $tempdir/dnsrec.txt
ip_addr=`egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/dnsrec.txt`
for i in $(echo "$ip_addr"); do
ptr=`host $i | cut -d ' ' -f 5` ; echo "$i - $ptr" | sed '/NXDOMAIN/d'
done | tee -a $tempdir/dnsrec.txt
f_solidShort | tee -a  $tempdir/dnsrec.txt
echo -e "${B}SRV Record(s)${D}\n"
echo -e " == SRV RECORDS(S) (via nmap.nse)  ==\n" >> $tempdir/dnsrec.txt
nmap -Pn -sn --script dns-srv-enum --script-args dns-srv-enum.domain=$target_dom | sed '/Nmap/d' |
sed '/Pre-scan/d' | tee -a $tempdir/dnsrec.txt
echo -e "\n\n == TXT RECORDS ==\n" >> $tempdir/dnsrec.txt
echo -e "\n\n${B}TXT Record(s)${D}\n"
dig +short txt ${x} | sed '/\"/{x;p;x;}' | fmt -w 100 -s > $tempdir/TXT.txt
cat $tempdir/TXT.txt | tee -a $tempdir/dnsrec.txt
echo -e "\n${B}IPv4 Addresses found in TXT:${D}\n"
echo -e "\n == IPv4 ADDRESSES FOUND IN TXT RECORDS ==\n" >> $tempdir/dnsrec.txt
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/TXT.txt | tee -a $tempdir/dnsrec.txt
f_solidLong | tee -a $tempdir/dnsrec.txt
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/dnsrec.txt  > $tempdir/ip_1.list
cat $tempdir/dnsrec.txt | tee -a $out/DNSrec_and_Subdomains.txt >> $out/${x}.txt
#********
fi
#********
if [ $option_subs = "1" ]; then
touch $tempdir/subs.txt ; echo -e "${B}${x} Subdomains${D}\n\n"
echo -e "== ${x} SUBDOMAINS == \n\n" | tee -a $out/DNSrec_and_Subdomains.txt >> $out/${x}.txt
curl -s https://api.hackertarget.com/hostsearch/?q=${x}${api_key_ht}  > $tempdir/subs.txt
sort -t ',' -k 2 -V  $tempdir/subs.txt | sed 's/,/ => /'  | awk '{print $3 "\t" $2 "\t" $1}' > $tempdir/subs_sorted.txt
cat $tempdir/subs_sorted.txt | tee -a $out/${x}.txt ; cat $tempdir/subs_sorted.txt >> $out/DNSrec_and_Subdomains.txt
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/subs_sorted.txt >> $tempdir/ip_1.list
f_solidLong | tee -a $out/${x}.txt ; f_solidLong >> $out/DNSrec_and_Subdomains.txt ; fi
sort -t . -k 1,1n -k 2,2n -k 3,3n -u $tempdir/ip_1.list > $tempdir/ip.list
echo -e "begin\ntype=cymru" > $tempdir/ips.txt
cat $tempdir/ip.list >> $tempdir/ips.txt
echo "end" >> $tempdir/ips.txt
netcat whois.pwhois.org 43 < $tempdir/ips.txt  > $tempdir/pwhois_cymru.txt
echo -e "${B}Networks & AS${D}\n" ; echo -e "== NETWORKS & AS ==\n" | tee -a $out/${x}.txt >> $out/DNSrec_and_Subdomains.txt
cat $tempdir/pwhois_cymru.txt | cut -d '|' -f 1,2,3,4,6 | sed '/Bulk mode; one IP/d' | sed '/ORG NAME/{x;p;x;G;}' > $tempdir/whois_table.txt
cat $tempdir/whois_table.txt | tee -a $out/${x}.txt ; cat $tempdir/whois_table.txt >> $out/DNSrec_and_Subdomains.txt
echo '' | tee -a $out/${x}.txt ; echo '' >> $out/DNSrec_and_Subdomains.txt
echo "begin" > $tempdir/ips.txt
cat $tempdir/ip.list >> $tempdir/ips.txt
echo "end" >> $tempdir/ips.txt
netcat whois.pwhois.org 43 < $tempdir/ips.txt > $tempdir/pwhois_bulk.txt
cat $tempdir/pwhois_bulk.txt | sed '/IP:/i \\n____________________\n' | sed '/AS-Path:/d' |
sed '/Cache-Date:/d' | sed '/Latitude:/d' | sed '/Longitude:/d' | sed '/Region:/d' | sed '/Country-Code:/d' |
sed '/Route-Originated-Date:/d' | sed '/Route-Originated-TS:/d' | tee -a $tempdir/pw.txt
cat $tempdir/pw.txt | tee -a $out/${x}.txt >> $out/DNSrec_and_Subdomains.txt
f_solidLong >> $out/${x}.txt ; f_solidLong >> $out/DNSrec_and_Subdomains.txt ; done
echo '' ; f_Menu  ; f_removeDir
;;
3) f_optionsWhois ;;
4) f_optionsIPV4 ;;
5)
#************** 5) SSL/TLS OPTIONS *******************
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}Options - SSL/TLS & SSH${D}"
#********
if ! [ $option_connect = "9" ] ; then
#********
echo -e "\n${B}Options >\n"
echo -e "${B} [1]${D} SSL Status (curl)"
echo -e "${B} [2]${D} Status & File Dump (openSSL)"
echo -e "${B} [3]${D} Supported SSL/TLS Ciphers (Nmap)"
echo -e "${B} [4]${D} SSH Auth Methods & Ciphers"
echo -e -n "\n${B}  ?${D}  " ; read option_ssl
if [ $option_ssl = "2" ]; then
echo -e -n "\n${B}Option > [1]${D} Show status & certificate File ${B}| [2]${D} Show status & dump cert file  ${B}?${D} " ; read option_cert
fi
if [ $option_ssl = "3" ]; then
echo -e -n "\n${B}Ports  > [1]${D} Port 443  ${B}| [2]${D} Custom Ports  ${B}?${D}  " ; read portChoice
if   [ $portChoice = "1" ] ; then
p='443' ; else
echo -e -n "\n${B}Ports  >  Ports  ${D}- e.g. 636,989-995  ${B}>>${D}  " ; read p ; fi
echo '' ; fi
if [ $option_ssl = "4" ]; then
echo -e -n "\n${B}Ports  > [1]${D} Port 22  ${B}| [2]${D} Custom Ports  ${B}?${D}  " ; read portChoice
if   [ $portChoice = "1" ] ; then
p='22' ; else
echo -e -n "\n${B}Ports  >  Ports  ${D}- e.g. 636,989-995  ${B}>>${D}  " ; read p ; fi
echo '' ; fi
f_solidShort ; touch $tempdir/hosts.list
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
for x in $(cat $hosts) ; do
f_solidShort | tee -a $out/TLS_SSH.txt
if [ $option_ssl = "1" ]; then
curl -sLkv ${x} 2>$tempdir/curl.txt -o /dev/null
echo -e "\n\n== ${x} SSL/TLS STATUS (curl) == \n" >> $out/TLS_SSH.txt
echo -e "Date: $(date)\n\n" >> $out/TLS_SSH.txt
echo -e "\n${B}${x} Certificate Status (source: curl)${D}"
f_certInfo_Curl "${x}" | tee -a $out/TLS_SSH.txt
f_solidLong >> $out/TLS_SSH.txt
elif [ $option_ssl = "2" ]; then
echo -e "\n${B}$x Certificate Status (source: openSSL)${D}"
echo -e "\n\n== $x SSL/TLS STATUS (openSSL) == \n" >> $out/TLS_SSH.txt
echo -e "Date: $(date)\n\n" >> $out/TLS_SSH.txt
if [ $option_cert = "1" ]; then
f_certInfo "${x}" | tee -a $out/TLS_SSH.txt
echo '' ; f_solidShort
echo | timeout 3 openssl s_client -connect ${x}:443 2>/dev/null | openssl x509 -text -fingerprint | fmt -w 80 -s ; else
f_certInfo "${x}" | tee -a $out/TLS_SSH.txt
f_solidLong >> $out/TLS_SSH.txt ; fi
elif [ $option_ssl = "3" ] ; then
echo -e "\n== $x SSL/TLS ENUMERATION == \n" >> $out/TLS_SSH.txt
echo -e "Date: $(date)\n\n" >> $out/TLS_SSH.txt
nmap -sT -Pn -p ${p} --script ${SSL_enum} ${x} | sed '/PORT/{x;p;x;G;}' | sed '/Read data files/d' |
sed '/Starting Nmap/d' | tee -a $out/TLS_SSH.txt
f_solidLong  >> $out/TLS_SSH.txt
elif [ $option_ssl = "4" ] ; then
echo -e "\n== $scan_target SSH ENUMERATION == \n" >> $out/TLS_SSH.txt
echo -e "Date: $(date)\n\n" >> $out/TLS_SSH.txt
nmap -sT -Pn -p ${p} --script ${SSH_enum} ${address} | sed '/PORT/{x;p;x;G;}' | sed '/Read data files/d' |
sed '/Starting Nmap/d' | tee -a $out/TLS_SSH.txt
f_solidLong  >> $out/TLS_SSH.txt ; else
echo -e "\n${R}Unexpected input${D}\n" ; fi
done
#********
else
#********
f_WARNING
#********
fi
#********
echo '' ; f_Menu ; f_removeDir
;;
6) f_optionsIPV6 ;;
7)
f_makeNewDir ; f_dashedGrey
echo -e -n "${B}\nTarget > ${D} e.g. UA-123456 ${B}>>${D}  " ; read ua
echo -e "\n== $ua REVERSE ANALYTICS LOOKUP ==\n\n" >> $out/Rev_GoogleAnalytics.txt
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
echo -e "\n\n${B}Options > Set > DNS Record Type  >\n "
echo -e -n " > ${B} [1]${D}  A   ${B}| [2]${D}  AAAA   ${B}|  [3]${D}  SRV   ${B}?${D}  " ; read option_record
if [ $option_record = "2" ] ; then
record="aaaa"
elif [ $option_record = "3" ] ; then
record="srv" ; else 
record="a" ; fi
echo -e -n "\n${B}Option > [1]${D} Short Mode  ${B}| [2]${D} Record Type & Query ${B}?${D}  " ; read option_short
if [ $option_short = "2" ] ; then 
dig_option="+noall +answer +noclass +nottlid" ; else 
dig_option="+short" ; fi
echo -e "\n${B}Nameservers (System Defaults)${D}\n"
cat /etc/resolv.conf | sed '/#/d'
echo -e -n "\n${B}Options > [1]${D} Use system defaults ${B}| [2]${D} 1.1.1.1  ${B}| [3]${D} set custom NS  " ; read option_ns_choice
if [ $option_ns_choice = "1" ] ; then
nssrv=`grep -w '^nameserver' /etc/resolv.conf | cut -d ' ' -f 2- | tr -d ' '`
elif [ $option_ns_choice = "3" ] ; then
echo -e -n "\n${B}Set     >${D} Default Nameserver  ${B} >>${D}   " ; read nssrv ; else
nssrv="1.1.1.1" ; fi
echo -e -n "\n${B}Target  >  ${D}PATH TO FILE ${B}>>${D}  " ; read input
if [ $report = "true" ] ; then
echo -e -n "\n${B}Set     >  ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename
output="$out/${filename}.txt" ; else
output="$tempdir/out14" ; fi
f_solidShort | tee -a ${output}
echo -e "[+] dig Batch Mode - Type > $record\n\n" | tee -a ${output}
dig @${nssrv} -t ${record} ${dig_option} -f ${input} | tee -a ${output}
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
f_makeNewDir ; f_dashedGrey ; option_server="y" ; option_banners="n" ; type_net="false"
if [[ $target =~ ${REGEX_IP4} ]]; then
echo -e -n "\n${B}Target  > ${D}DOMAIN  ${B} >>${D}   " ; read dom ; else
echo -e -n "\n${B}Target  > [1]${D} new target ${B}| [2] current > ${D} $target  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
dom=`echo $target` ; else
echo -e -n "\n${B}Target  > ${D}DOMAIN  ${B} >>${D}   " ; read dom
fi ; fi
output="$out/NS.${dom}.txt"
if [ $option_connect = "1" ] ; then
echo -e "\n\n${B}Nameservers (System Defaults)${D}\n"
cat /etc/resolv.conf | sed '/#/d'
echo -e -n "\n${B}Option > [1]${D} Use system defaults ${B}| [2]${D} 1.1.1.1  ${B}| [3]${D} set custom NS  ${B}?${D}  " ; read option_ns_choice
if [ $option_ns_choice = "1" ] ; then
nssrv=`grep -w '^nameserver' /etc/resolv.conf | cut -d ' ' -f 2- | tr -d ' '`
elif [ $option_ns_choice = "2" ] ; then
nssrv="1.1.1.1"
elif [ $option_ns_choice = "3" ] ; then
echo -e -n "\n${B}Set    > Default Nameserver  ${B} >>${D}   " ; read nssrv ; else
: ; fi
echo -e -n "\n${B}Option > [1]${D} TTL values (seconds) ${B}| [2]${D} TTL values (human readable)  ${B}?${D}  " ; read option_ttl
if [ $option_ttl = "1" ] ; then
ttl="+ttlid" ; else 
ttl="+ttlunits" ; fi
echo -e -n "\n${B}Option > ${D} DNS Delegation Tracing  >  Show DNSSEC Records   ${B}[y] | [n] ?${D}  " ; read option_dnssec
if [ $option_dnssec = "y" ] ; then
dig_options="+nocmd +noall +answer +trace +noclass +ttlunits +dnssec +split=4" ; else
dig_options="+nocmd +noall +answer +trace +noclass +ttlunits +nodnssec" ; fi
echo -e "\n\n == $dom ZONE CONFIGURATIONS & NAME SERVER ==\n" >> ${output}
echo -e "Date   >  $(date)" >> ${output}
f_solidShort >> ${output} ; echo '' >> ${output}
echo -e "_________________\n" ; echo -e "[+] Domain Host A\n" | tee -a ${output}
dig @${nssrv} +noall +answer ${ttl} +noclass +stats ${dom} | sed 's/;; Query time:/Time:/' | sed 's/;; SERVER/Server/' |  grep -w 'A\|Time:\|Server' |
sed '/Time:/{x;p;x;G;}' | sed '/Server:/G' | tee -a ${output}
echo -e "\n________\n" | tee -a ${output}; echo -e "[+] AAAA\n" | tee -a ${output}
dig @${nssrv} -t aaaa +noall +answer ${ttl} +noclass +stats ${dom} | sed 's/;; Query time:/Time:/' | grep -w 'AAAA\|Time:' |
sed '/Time:/{x;p;x;G;}' | tee -a ${output}
echo -e "_______\n" | tee -a ${output}
echo -e "[+] MX \n" | tee -a ${output}
dig @${nssrv} -t mx +noall +answer ${ttl} +noclass +stats ${dom} | sed 's/;; Query time:/Time:/' |  grep -w 'MX\|Time:' | sed '/Time:/{x;p;x;G;}' |
tee -a ${output}
echo -e "________\n" | tee -a ${output}
echo -e "[+] MX A\n" | tee -a ${output}
dig @${nssrv} +noall +answer ${ttl} +noclass +stats $(dig @${nssrv} mx +short ${dom}) | sed 's/;; Query time:/Time:/' |  grep -A 1 -w 'A' |
sed '/Time:/{x;p;x;G;}' | tee -a ${output}
echo -e "___________\n" | tee -a ${output}
echo -e "[+] MX AAAA\n" | tee -a ${output}
dig @${nssrv} -t aaaa +noall +answer ${ttl} +noclass +stats $(dig @${nssrv} mx +short ${dom}) | sed 's/;; Query time:/Time:/' | grep -A 1 -w 'AAAA' |
sed '/Time:/{x;p;x;G;}' | tee -a ${output}
f_solidShort | tee -a ${output}
echo -e "[+] NS \n" | tee -a ${output}
dig @${nssrv} -t ns +noall +answer ${ttl} +noclass +stats $dom  | sed 's/;; Query time:/Time:/' |  grep -w 'NS\|Time:' | sed '/Time:/{x;p;x;G;}' |
tee -a ${output}
echo -e "________\n" | tee -a ${output}
echo -e "[+] NS A \n" | tee -a ${output}
dig @${nssrv} +noall +answer ${ttl} +noclass +stats $(dig @${nssrv} ns +short $dom) | sed 's/;; Query time:/Time:/' | grep -A 1 -w 'A'  |
sed '/Time:/{x;p;x;G;}' | tee -a ${output}
echo -e "\n___________\n" | tee -a ${output}
echo -e "[+] NS AAAA\n" | tee -a ${output}
dig @${nssrv} -t aaaa +noall +answer ${ttl} +noclass +stats $(dig @${nssrv} ns +short $dom) | sed 's/;; Query time:/Time:/' | grep -A 1 -w 'AAAA' |
sed '/Time:/{x;p;x;G;}' | tee -a ${output}
f_solidShort | tee -a ${output}
echo -e "[+] IPv4 PTR Records\n" | tee -a ${output}
ip_addr=`egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' ${output} | sed '/1.1.1.1./d'`
for i in $(echo "$ip_addr"); do
dig @${nssrv} +noall +answer ${ttl} +noclass -x ${i} |  sed '/one.one.one.one./d' | sed '/PTR/{x;p;x;}' |
tee -a ${output} ; done 
f_solidShort | tee -a ${output}
echo -e "[+] TXT\n" | tee -a ${output}
dig @${nssrv} -t txt +noall +answer ${ttl} +noclass +stats ${dom} | sed 's/;; Query time:/Time:/' | grep -w 'TXT\|Time:' | sed '/Time:/{x;p;x;G;}' |
tee -a ${output}
f_solidShort | tee -a ${output}
soa=`dig @${nssrv} soa +short $dom`
echo -e "[+] SOA \n\n" | tee -a ${output}
dig @${nssrv} -t soa +noall +answer ${ttl} +noclass $dom  | tee -a ${output}
dig @${nssrv} soa +noall +answer +multiline $dom > $tempdir/soa.txt
awk '{ print  $1 $2,   $3, $4, $5 }' $tempdir/soa.txt | sed '1,1d' |
sed '$d'  | sed '/serial/{x;p;x;}'  | tee -a ${output}
f_solidLong | tee -a ${output}
echo -e "${B}SOA Records Comparison${D}\n"
echo -e "== $dom SOA RECORDS COMPARISON==\n" >> ${output}
dig @${nssrv} +nssearch $dom | sed '/SOA/{x;p;x;}' | sed 's/from/\nfrom/' |
tee -a ${output}
f_solidLong | tee -a ${output}
echo -e "\n== DNS ZONE CONFIGS ==\n\n"  >> ${output}
echo -e "${B}DNS Zone Configs${D}\n"
soa_host=`echo "$soa" | cut -d ' ' -f 1`
nmap -sn -Pn ${soa_host} --script dns-check-zone --script-args=dns-check-zone.domain=$dom |
sed '/Host discovery disabled /d' | sed '/Host is up/d' | sed '/Starting Nmap/d' |
sed '/Nmap done/d' | sed '/Other addresses/d' | sed 's/Nmap scan report for//'  |  tee -a ${output}
f_solidLong | tee -a ${output}
echo -e "${B}Lookup Delegation (Domain Host A Record)${D}\n\n"
echo -e "== LOOKUP DELEGATION (Domain Host A Record) ==\n\n" >> ${output}
dig @${nssrv} ${dig_options} ${dom} | sed '/Received/{x;p;x;}' | fmt -s -w 120 |
tee -a ${output} ; f_solidShort | tee -a ${output}
soa_url=`host -t soa ${dom} | cut -d ' ' -f 5`
soa_ip=`host $soa_url | rev | cut -d ' ' -f 1 | rev | tr -d ' '`
echo -e "${B}Reverse DNS Lookup Time & Delegation (Domain Primary Name Server)${D}\n\n"
echo -e " == DNS LOOKUP- TIME & DELEGATION (Domain Primary Name Server) ==\n\n" >> ${output}
dig @${nssrv} ${dig_options} -x  ${soa_ip} | sed '/Received/{x;p;x;}'  | fmt -s -w 120 | tee -a ${output}
f_solidShort | tee -a ${output} 
echo -e -n "${B}Option >${D} Check for unauthorized zone transfers?  ${B}[y] | [n] ?${D}  " ; read option_ns_1
echo -e "${B}\nOptions >\n"
echo -e "${B}[1]${D} BIND version & NS ID (nmap, root only)"
echo -e "${B}[2]${D} Run MTR (Mode > TCP, Port > 53, root only)"
echo -e "${B}[3]${D} BOTH"
echo -e "${B}[9]${D} SKIP"
echo -e -n "\n${B} ? ${D}  " ; read option_ns_2
echo -e -n "\n${B}Option  >${D} Network, whois & geolocation info ${B} > [1]${D} Summary ${B}| [2]${D} Details ${B}| [9]${D} SKIP  ${B}?${D}  " ; read option_details
if [ $option_ns_1 = "y" ] ; then
echo '' > $tempdir/zone.txt
echo -e -n "\n${B}Source  >${D} Zonetransfer ${B}> [1]${D} dig  ${B}|  [2]${D}  hackertarget.com API  ${B}?${D}  "  ; read option_source
f_solidShort
echo -e "${B}Zone Transfer${D}" ; echo -e "\n == ZONE TRANSFER  ==\n" >> ${output}
if   [ $option_source = "2" ] ; then
curl -s https://api.hackertarget.com/zonetransfer/?q=${dom}${api_key_ht} >> $tempdir/zone.txt ; else
ns=$(dig ns +short ${dom}) ;
for i in $(echo "$ns"); do
dig axfr @${i} $dom >> $tempdir/zone.txt
done ; fi
echo '' >> $tempdir/zone.txt ; cat $tempdir/zone.txt | tee -a ${output} ; fi
if ! [ $option_ns_2 = "9" ] || ! [ $option_details = "9" ] ; then
ns=`dig ns +short ${dom}`
for x in $(echo "$ns") ; do
ns_ip=`dig +short ${x} | head -1`
f_solidLong | tee -a ${output} ; echo '' | tee -a ${output}
if ! [ $option_details = "9" ]  ; then
f_BOX_BANNER "${ns_ip}" ; f_OUTPUT_HEADER "${x}" ; else 
f_BOX " ${x} " ; f_OUTPUT_HEADER "${x}" ; fi
if [ $option_ns_2 = "1" ] || [ $option_ns_2 = "3" ] ; then
echo -e "\n[+] BIND Version & NS ID\n" | tee -a ${output}
sudo nmap -sSU -p 53 -Pn --script dns-nsid $x > $tempdir/nmap.txt
cat $tempdir/nmap.txt | sed '/Host discovery disabled /d' | sed '/Host is up/d' | sed '/Starting Nmap/d' |
sed '/Nmap done/d' | tee -a ${output} ; echo '' | tee -a ${output} ; fi
if ! [ $option_details = "9" ]  ; then
f_DRWHO "${ns_ip}" | tee -a ${output} ; fi
if [ $option_ns_2 = "2" ] || [ $option_ns_2 = "3" ] ; then
f_solidShort | tee -a ${output}
echo -e "${B}$x MTR ${D}\n"
sudo mtr -T -b -c4 -w -z -P 53 -o "  L  S D  A BW  X  M" ${x} | sed '/Start:/{x;p;x;}'  | sed '/HOST:/G' |
tee -a ${output}
f_solidShort | tee -a ${output}
echo -e "Snt = packages sent;  Wrst = worst RTT in ms; \nJavg = average jitter" | tee -a ${output} ; fi
done ; fi
else
f_WARNING ; fi
echo '' ; f_Menu ; f_removeDir
;;
25)
f_makeNewDir ; f_dashedGrey ; option_server="y" ; option_banners="n" ; type_net="false"
echo -e "\n${B}Mail Server Configs & Blacklist Check${D}\n"
if ! [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Target  > [1]${D} Set target mail server ${B}| [2]${D} Domain MX records ${B}| [3]${D} Target list  ${B}?${D} " ; read option_target
if   [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target  > IPV4 ADDRESS ${B}>>${D}   " ; read input
echo "$input" > $tempdir/servers.txt
servers="$tempdir/servers.txt"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}DOMAIN  ${B} >>${D}   " ; read dom
dig +short $(dig mx +short ${dom}) > $tempdir/servers.txt
output="$out/MX.${dom}.txt"
servers="$tempdir/servers.txt"
elif [ $option_target = "3" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE ${B}>>${D}   " ; read input
servers="${input}" ; else 
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
echo -e -n "\n${B}Option  > [1] ${D}Geolocation & whois info ${B}| [2]${D} Blacklist info ${B}| [3]${D} BOTH ${B}| [9]${D} SKIP  ${B}?${D}  " ; read option_mx_1
if [ $option_mx_1 = "1" ] || [ $option_mx_1 = "3" ] ; then
echo -e -n "\n${B}Option  >${D} Network, whois & geolocation info ${B} > [1]${D} Summary ${B}| [2]${D} Details ${B}| [9]${D} SKIP  ${B}?${D}  " ; read option_details
fi
echo -e -n "\n${B}Option  > [1] ${D}Run MTR (port 25) ${B}| [2]${D} Run MTR (port 143)  ${B}| [9]${D} SKIP ${B}?${D}  " ; read option_mtr
if   [ $option_mtr = "1" ] ; then
t_port="25" 
elif   [ $option_mtr = "2" ] ; then
t_port="143" ; else
: ; fi
echo -e -n "\n${B}Option  > ${D} Run Nmap scan ${B}[y] | [n] ${B}?${D} " ; read option_nmap
if   [ $option_nmap = "y" ] ; then
echo -e -n "\n${B}Option  >${D} Do you have superuser privileges  ${B}[y] | [n] ?${D}  " ; read option_root
echo -e "\n\n${B}Options >  [1]${D} MX Commands ${B}| [2]${D} MX Commands & SMTP Users"
echo -e "${B}        >  [3]${D} Option 1,2 & Open Relay Check"
echo -e -n "\n${B}            ?${D}  " ; read  option_mx_2
if [ $option_root = "y" ] ; then
if   [ $option_mx_2 = "2" ] ; then
scripts="${mx_safe},${mx_ext_1},${mx_ext_root}"
elif [ $option_mx_2 = "3" ] ; then
scripts="${mx_safe},${mx_ext_2},${mx_ext_root}" ; else 
scripts="${mx_safe},${mx_ext_root}" ; fi
else
if   [ $option_mx_2 = "2" ] ; then
scripts="${mx_safe},${mx_ext_1}"
elif [ $option_mx_2 = "3" ] ; then
scripts="${mx_safe},${mx_ext_2}" ; else 
scripts="${mx_safe}" ; fi
fi
fi
if [ $option_target = "2" ] ; then
f_solidShort ; f_OUTPUT_HEADER "${dom} MX Records"
echo -e "${B}${dom} A & MX- Records${D}\n"
echo -e "\n[+] Domain A- Records\n"
dig +noall +answer +ttlunits +noclass +stats ${dom} | sed 's/;; Query time:/Time:/' | sed 's/;; SERVER/Server/' |
sed -n '/;;/!p'  | sed '/Time:/{x;p;x;}' | tee -a ${output} 
echo -e "______\n"
echo -e "[+] MX\n" | tee -a ${output}
dig mx +noall +answer +ttlunits +noclass +stats ${dom} | grep -A 2 -w 'MX' | sed 's/;; Query time:/Time:/' |  sed -n '/;;/!p' |
sed '/Time:/{x;p;x;}' | tee -a ${output}
echo -e "\n_________\n" | tee -a ${output}
echo -e "[x] MX  A\n" | tee -a ${output}
dig +noall +answer +noclass +ttlunits $(dig mx +short ${dom}) | tee -a ${output}
echo -e "\n____________\n" | tee -a ${output}
echo -e "[x] MX  AAAA\n" | tee -a ${output}
dig aaaa +noall +answer +noclass +ttlunits $(dig mx +short ${dom}) | tee -a ${output} ; fi
for x in $(cat ${servers}) ; do
f_solidLong | tee -a ${output}
if  [ $option_target = "2" ] ; then
output="$out/MX.${dom}.txt" ; else 
output="$out/MX.${x}.txt" ; fi
f_OUTPUT_HEADER "${x}"
if [ $option_mx_1 = "1" ] || [ $option_mx_1 = "3" ] ; then
f_BOX_BANNER "${x}" ; f_DRWHO "${x}" ; else 
f_BOX "${x}" ; fi
if  [ $option_nmap = "y" ] ; then
f_solidShort | tee -a ${output}
echo -e "[+] Nmap Results\n"  | tee -a ${output}
if [ $option_root = "y" ] ; then
sudo nmap -sV -O -Pn -p 22,25,143,443,465,587,993 --script ${scripts} ${x} > $tempdir/nmap.txt ; else 
nmap -sT -Pn -p 22,25,143,443,465,587,993 --script ${scripts} ${x} > $tempdir/nmap.txt  ; fi
cat $tempdir/nmap.txt | sed '/PORT/{x;p;x;}' | sed '/Starting Nmap/d' | sed '/Read data files/d' | sed '/NSE/d' |
sed '/Nmap scan report/{x;p;x;}' | sed '/Initiating/d' | sed '/Completed/d' | sed '/Discovered/d' | sed '/\/tcp /{x;p;x;G;}' |
sed '/Service detection/d' | sed '/Nmap done/d' | fmt -s -w 100 | tee -a ${output}
fi
if  [ $option_mtr = "1" ] || [ $option_mtr = "2" ] ; then
f_solidShort | tee -a ${output}
echo -e "${B}${x} MTR (TCP, Port > $t_port)${D}\n"
echo -e " == ${x} MTR TCP, PORT >  $t_port) == \n" >> ${output} 
sudo mtr -T -b -c4 -w -z -P ${t_port} -o "  L  S D  A BW  X  M" ${x} | sed '/Start:/{x;p;x;}'  | sed '/HOST:/G' |
tee -a ${output} ; echo '' | tee -a ${output}  ; f_solidShort | tee -a ${output} 
echo -e "Snt = packages sent;  Wrst = worst RTT in ms; \nJavg = average jitter" | tee -a ${output} ; fi
if [ $option_mx_1 = "2" ] || [ $option_mx_1 = "3" ] ; then
f_BLACKLISTS "${x}" | tee -a ${output} ; f_RIPE_BLACKLIST "${x}" | tee -a ${output} ; fi
done ; else
f_WARNING ; fi ; f_Menu ; f_options_SERVERS ;  f_removeDir
;;
33)
#************** 33) WHOIS  ********************
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
echo -e "${B} [1]${D} Search by AS Name (bgpview.io)"
echo -e "${B} [2]${D} Search by Organisation Common Name (Registry Servers)"
echo -e "${B} [3]${D} RIPE inverse search"
echo -e -n "\n${B}  ?${D}  " ; read option_whois_1
if  [ $option_whois_1 = "1" ] ; then
echo -e -n "\n${B}Target  >  ${D}Name  ${B}>>${D} " ; read input
echo -e "\n\n${B}$input Results${D}\n"
echo -e "\n== $input SEARCH RESULTS (via bgpview.org) ==\n\n" >> $out/WHOIS.txt
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
echo -e -n "\n${B}Set     >${D} Registry, e.g. apnic ${B}>>${D} " ; read rir
echo ''
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
echo -e "\n== INVERSE SEARCH RESULTS (via whois.ripe.net) ==\n" >> $out/WHOIS.txt
echo -e "Type > $query_type   Object > $query_object\n" >> $out/WHOIS.txt
whois -h whois.ripe.net -- " -B -i ${query_type} ${query_object}" | sed 's/% Information related/Information related /'  | sed 's/% Abuse contact/Abuse contact/' |
sed '/%/d' | sed '/Information related/i \\n________________________________\n' > $tempdir/inv.txt
cat $tempdir/inv.txt | tee -a $out/WHOIS.txt
echo -e "____________\n" | tee -a $out/WHOIS.txt ; echo -e "[+] Networks\n" | tee -a $out/WHOIS.txt
grep -w -A 2 '^inetnum:' $tempdir/inv.txt | cut -d ':' -f 2- | tr -d ' ' > $tempdir/netnames.txt
cat $tempdir/netnames.txt
echo ''
grep -w '^inetnum:' $tempdir/inv.txt | cut -d ':' -f 2- | tr -d ' ' > $tempdir/netranges.txt
declare -a ip_array=()
ip_array+=($(cut -d '-' -f 2 $tempdir/netranges.txt))
for i in "${ip_array[@]}" ; do
echo ''
curl -s https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=$i > $tempdir/ac.json
jq -r '.data.less_specifics[0]' $tempdir/ac.json
jq -r '.data.less_specifics[1]' $tempdir/ac.json ; done
echo -e "____________\n" | tee -a $out/WHOIS.txt ; echo -e "[+] Prefixes\n" | tee -a $out/WHOIS.txt
grep -w "^route:" $tempdir/inv.txt | cut -d ':' -f 2- | sed 's/^ *//' | tee -a $out/WHOIS.txt
echo -e "\n___________________\n" | tee -a $out/WHOIS.txt ; echo -e "[+] E-Mail Contacts\n" | tee -a $out/WHOIS.txt
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/inv.txt | sort -u | tee -a $out/WHOIS.txt
f_solidLong >> $out/WHOIS.txt
elif  [ $option_whois_1 = "4" ] ; then
echo -e -n "\n${B}Target > ${D}SEARCHTERM ${B}>>${D}  " ; read st
curl -s https://stat.ripe.net/data/searchcomplete/data.json?resource=${st} > $tempdir/sug.json
echo '' ; jq -r '.data' $tempdir/sug.json ; else
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
echo '' ; f_BOX " AS ${as} - ${as_country} " ; echo ''
f_OUTPUT_HEADER "AS $as"
f_AS_Description "${as}" | tee -a ${output}
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
echo -e "\n ${B}[1]${D} BGP Prefixes      ${B}|  [4]${D} IX Memberships "
echo -e " ${B}[2]${D} IPv6 Netblocks    ${B}|  [5]${D} Peering"
echo -e " ${B}[3]${D} Upstream Transit" 
echo -e -n "\n  ${B}?${D}  " ; read option_as
if [ $option_as = "1" ] ; then 
echo -e "\n\n == AS $as PREFIXES (bgpview.io) ==\n" >> $out/AS.$as.txt
f_BGPviewPREFIXES | tee -a $out/AS.$as.txt
elif [ $option_as = "2" ] ; then 
f_solidShort | tee -a $out/AS.$as.txt
echo -e "[+] AS $as - Assigned IPV6 Address Blocks \n\n" | tee -a $out/AS.$as.txt
whois -h whois.pwhois.org "netblock6 source-as=${as}" | grep 'Net-Range:\|Net-Handle:' | cut -d ':' -f 2- | sed 's/^ *//' | sed 'n;G;' |
tee -a $out/AS.$as.txt
elif [ $option_as = "3" ] ; then
echo '' ; f_solidShort | tee -a $out/AS.$as.txt
echo -e "[+] AS $as Upstreams\n" | tee -a $out/AS.$as.txt
f_BGPview_UPSTREAMS
elif [ $option_as = "4" ] ; then
echo '' ; f_solidShort | tee -a $out/AS.$as.txt
echo -e "[+] IX Memberships\n" | tee -a $out/AS.$as.txt
curl -s https://api.bgpview.io/asn/${s}/ixs | jq | sed -n '/data/,/@meta/{/data/!{/@meta/!p;}}' |
tr -d ',[{"}]' | sed 's/^ *//' | sed 's/name_full/full name/' | sed 's/country_code:/country:/' | tee -a $out/AS.$as.txt
elif [ $option_as = "5" ] ; then
f_BGPview_PEERS ; else
: ; fi
echo'' ; f_removeDir ; f_Menu ; f_optionsWhois
;;
37)
#************** 37) IX INFORMATION *******************
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}IX Information \n\n"
echo -e -n "Target > ${D} IX ID - e.g. 25  ${B}>>${D}  " ; read ixid
echo -e "\n\n${B}IX $ixid Profile & Members${D}\n\n"
echo -e "\n\n==IX $ixid BGPVIEW QUERY RESULT == \n" >> $out/IX.$ixid.txt
f_BGPviewIX ; f_solidLong >> $out/IX.$ixid.txt ; echo '' ; f_Menu ; f_optionsWhois ; f_removeDir
;;
38)
#************** 38) RIPESTAT API LOOKING GLASS *******************
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
echo -e -n "\n${B}Option > [1]${D} whois summary ${B}| [2]${D} whois & BGP prefix details ${B}?${D}  " ; read option_details
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
f_BLACKLISTS "${x}" | tee -a ${output} ; f_RIPE_BLACKLIST "${x}" | tee -a ${output} ; fi
if [ $option_ipv4_2 = "2" ] || [ $option_ipv4_2 = "3" ] ; then
f_solidShort | tee -a ${output} ; f_VHOSTS "${x}" | tee -a ${output} ; fi
if [ $option_details = "2" ] ; then
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
f_NETGEO "${prefix}" | tee -a ${output}
if [ $option_ipv4_2 = "1" ] || [ $option_ipv4_2 = "3" ] ; then
f_RIPE_BLACKLIST "${prefix}" | tee -a ${output} ; echo '' ; fi
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
echo -e -n "\n${B}Option > ${D} Show BGP prefix  details  ${B}[y] | [n] ?${D}  " ; read option_prefix
echo -e -n "\n${B}Option > ${D} Show network blacklist info  ${B}[y] | [n] ?${D}  " ; read option_blacklist
for x in $(cat "$targets") ; do
f_solidLong ; whois -h whois.cymru.com -- "-v -f ${x}" > $tempdir/cymru.txt
echo '' ; f_BOX " ${x} - AS $as " ; f_OUTPUT_HEADER "${x}"
echo -e "\n${B}Size & Netmask${D}\n\n" ; echo -e " == SIZE & NETMASK == \n\n" >> ${output}
ipcalc -b -n ${x} | tee -a ${output}
f_solidShort
f_DRWHO "${x}" | tee -a ${output}
f_solidShort | tee -a ${output}
echo -e "${B}${x}  Geographic Distribution ${D}\n" ; echo -e " == ${x} GEOGRAPHIC DISTRIBUTION == \n" >> ${output}
f_NETGEO "${x}" | tee -a ${output}
f_solidShort | tee -a ${output}
echo -e "${B}DNS Delegation & Reverse DNS Consistency${D}\n"
echo -e " == DNS DELEGATION & REVERSE DNS CONSISTENCY ==\n\n" >> ${output}
f_DELEGATION "${x}" | tee -a ${output}
echo -e "\n_______________\n" | tee -a ${output}
echo -e "[+] Consistency\n" | tee -a ${output}
curl -s https://stat.ripe.net/data/reverse-dns-consistency/data.json?resource=$x > $tempdir/dns.json
jq -r '.data.prefixes.ipv4' $tempdir/dns.json | grep 'complete' | tr -d ',\"' |
sed 's/^ *//' | sed '/complete/G' | tee -a ${output}
jq -r '.data.prefixes.ipv4' $tempdir/dns.json | grep 'prefix\|found' | tr -d '],\"[' | cut -d ':' -f 2- | tr -d ' ' > $tempdir/prefixes.txt
cat $tempdir/prefixes.txt | tee -a ${output}
prefix=`cut -d '|' -f 3 $tempdir/cymru.txt | tr -d ' '`
f_solidShorter | tee -a ${output}
echo -e "${B}Networks\n${D}" ; echo -e "\n\n== NETWORKS ==\n" >> ${output}
jq -r '.data.prefixes.ipv4' $tempdir/dns.json | grep 'prefix' | tr -d ',\"' | cut -d ':' -f 2- | tr -d ' '
if [ $option_blacklist = "y" ] ; then
f_RIPE_BLACKLIST "${x}" | tee -a ${output} ; fi
f_solidShort | tee -a ${output}
f_PREFIX "${prefix}" | tee -a ${output}
if ! [[ ${x} = ${prefix} ]] && [ $option_prefix = "y" ] ; then
f_solidShort | tee -a ${output}
f_DELEGATION "${prefix}" | tee -a ${output}
echo -e "\n___________________________\n" | tee -a ${output}
echo -e "[+] Reverse DNS Consistency\n" | tee -a ${output}
curl -s https://stat.ripe.net/data/reverse-dns-consistency/data.json?resource=${prefix} > $tempdir/dns.json
jq -r '.data.prefixes.ipv4' $tempdir/dns.json | grep 'complete' | tr -d ',\"' |
sed 's/^ *//' | sed '/complete/G' | tee -a ${output}
jq -r '.data.prefixes.ipv4' $tempdir/dns.json | grep 'prefix\|found' | tr -d '],\"[' | cut -d ':' -f 2- | tr -d ' ' | tee -a ${output}
f_solidShorter | tee -a ${output}
echo -e "[+] Prefix Geographic Distribution \n" | tee -a ${output}
f_NETGEO "${prefix}" | tee -a ${output}
f_solidShorter | tee -a ${output}
echo -e "[+] Networks \n\n" | tee -a ${output}
jq -r '.data.prefixes.ipv4' $tempdir/dns.json | grep 'prefix' | tr -d ',\"' | cut -d ':' -f 2- | tr -d ' ' | tee -a ${output} ; fi
done
f_solidLong >> ${output} ; echo '' ; f_Menu ; f_optionsIPV4 ; f_removeDir
;;
46)
f_makeNewDir ; f_dashedGrey
echo -e -n "\n${B}Target  > Max. Size: /24 > [1]${D} Single target network ${B}| [2]${D} Target list ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target  > ${D}Network (CIDR)  ${B}>>${D}   " ; read input
echo "$input" > $tempdir/nets.list
nets="$tempdir/nets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE  ${B}>>${D}   " ; read input
nets="${input}" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
echo -e -n "\n${B}Options > [1]${D} Reverse DNS  ${B}| [2]${D} Reverse IP  ${B}| [3]${D} Both ${B}| [9]${D} SKIP ${B}?${D}  " ; read option_net_1
if [ $option_net_1 = "1" ] || [ $option_net_1 = "3" ] ; then
echo -e -n "\n${B}Source  >${D} Reverse DNS ${B}> [1]${D} dnsutils (host) ${B}| [2]${D} hackertarget.com API  ${B}?${D}  "  ; read option_source
if [ $option_source = "1" ] ; then
echo -e "\n${B}Nameservers (System Defaults)${D}\n"
cat /etc/resolv.conf | sed '/#/d'
echo -e -n "\n${B}Options > [1]${D} Use system defaults ${B}| [2]${D} 1.1.1.1  ${B}| [3]${D} set custom NS  " ; read option_ns_choice
if [ $option_ns_choice = "1" ] ; then
nssrv=`grep -w '^nameserver' /etc/resolv.conf | cut -d ' ' -f 2- | tr -d ' '`
elif [ $option_ns_choice = "3" ] ; then
echo -e -n "\n${B}Set     >${D} Default Nameserver  ${B} >>${D}   " ; read nssrv ; else
nssrv="1.1.1.1" ; fi
fi ; fi
echo -e -n "\n${B}Options >${D} Service banners ${B}> [1]${D} Nmap  ${B}| [2]${D} hackertarget.com API  ${B}| [9]${D} SKIP  ${B}?${D}  " ; read option_net_2
if [ $option_net_2 = "1" ] ; then
echo -e "\n${B}Options >${D}\n"
echo -e " ${B}[1]${D} Run Nmap service scan (root) with host discovery (ICMP echo)"
echo -e " ${B}[2]${D} Run Nmap service scan (root), skip host discovery"
echo -e " ${B}[3]${D} Run Nmap port scan (non root) with host discovery"
echo -e " ${B}[4]${D} Run Nmap port scan (non root), skip host discovery"
echo -e -n "\n ${B} ? ${D}  " ; read option_nmap ; fi
if [ $report = "true" ] ; then
echo -e -n "\n${B}Set   > ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename
output="$out/${filename}.txt" ; else
output="$tempdir/out46.txt" ; fi
for x in $(cat ${nets}) ; do
f_solidLong | tee -a ${output}
echo '' ; f_BOX " ${x} " ; f_OUTPUT_HEADER "${x}" ;  echo ''
if [ $option_net_1 = "1" ] || [ $option_net_1 = "3" ] ; then
echo -e "\n${B}${x} Reverse DNS${D}\n" ; echo -e "== ${x} REVERSE DNS ==\n\n" >> ${output}
if [ $option_source = "1" ] ; then
prefx=`echo $x | cut -d '.' -f -3`
f_hostSearch | tee -a ${output} ; else
f_RevDNS "${x}" | tee -a ${output} ; fi ; fi
if [ $option_net_2 = "1" ] || [ $option_net_2 = "2" ]  ; then
f_solidShort | tee -a ${output}
echo -e "\n${B} Service Banners ${D}"
echo -e "\n== ${x} SERVICE BANNERS ==\n" | tee -a  $out/BANNERS.txt >> ${output}
echo -e "Date >  $(date)\n" >> $out/BANNERS.txt ; fi
if [ $option_net_2 = "1" ] ; then
if [ $option_nmap  = "1" ] ; then
sudo nmap -n -sV --top-ports 100 --script banner,http-server-header,https-redirect,http-title,mysql-info,ms-sql-info ${x} > $tempdir/nmap.txt
elif [ $option_nmap = "2" ] ; then
sudo nmap -n -sV -Pn --top-ports 100 --script banner,http-server-header,https-redirect,http-title,mysql-info,ms-sql-info ${x} > $tempdir/nmap.txt
elif [ $option_nmap = "3" ] ; then
nmap -n -sT --top-ports 100 --script banner,http-server-header,https-redirect,http-title,mysql-info,ms-sql-info ${x} > $tempdir/nmap.txt
elif [ $option_nmap = "4" ] ; then
nmap -n -sT -Pn --top-ports 100 --script banner,http-server-header,https-redirect,http-title,mysql-info,ms-sql-info ${x} > $tempdir/nmap.txt ; else
: ; fi
cat $tempdir/nmap.txt | sed '/PORT/{x;p;x;}' | sed '/\/tcp /{x;p;x;}' | sed '/Nmap scan report/i ____\n' | sed '/Read data files/d' |
sed '/NSE/d' | sed '/Initiating/d' | sed '/Completed/d' | sed '/Discovered/d' | sed '/Uptime guess:/{x;p;x;}' | sed '/Network Distance:/{x;p;x;}' |
fmt -w 120 -s | tee $tempdir/services.txt
cat $tempdir/services.txt | tee -a $out/BANNERS.txt >> ${output} ; fi
if [ $option_net_2 = "2" ] ; then
f_BANNERS "${x}" | tee $tempdir/services.txt
echo '' | tee -a $tempdir/services.txt
cat $tempdir/services.txt | tee -a $out/BANNERS.txt >> ${output} ; fi
if [ $option_net_1 = "2" ] || [ $option_net_1 = "3" ] ; then
f_solidShort | tee -a ${output}
echo -e "\n${B}${x} Reverse IP${D}\n" ; echo -e "\n== ${x} REVERSE IP ==\n" >> ${output}
f_RevIP "${x}" | tee -a ${output} ; fi ; f_solidLong >> ${output} ; done
echo '' ; f_Menu ; f_optionsIPV4 ; f_removeDir
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
f_solidLong >>  $out/PING.${netw}.txt ; echo '' ; f_removeDir
echo '' ; f_Menu ; f_optionsIPV4 ; f_removeDir
;;
61)
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
echo '' ; f_Menu ; f_removeDir
;;
62)
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
f_solidLong | tee -a ${output} ; f_OUTPUT_HEADER "${x}" ; f_BOX " ${x} " 
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
atk6-address6 ${input} ${v6_conversion[@]} ; echo '' ; f_Menu ; f_removeDir
;;
64)
f_makeNewDir ; f_dashedGrey
echo -e -n "\n${B}Options > [1]${D} Extract Network Portions  ${B}| [2]${D} Extract Host Portions  ${B}| [3]${D} BOTH  ${B}| [9]${D} CANCEL ${B}?${D}  " ; read answer
echo -e -n "\n${B}Target  >  ${D}PATH TO FILE ${B}>>${D}  " ; read input
if [ $report = "true" ] ; then
echo -e -n "\n${B}Set     >  ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename
output="$out/${filename}.txt" ; else
output="$tempdir/out62" ; fi
if ! [ $answer = "9" ] ; then 
if [ $answer = "1" ] || [ $answer = "3" ] ; then 
f_solidShort | tee -a ${output}
echo -e "\n[+] IPv6 Network Portions\n\n" | tee -a ${output}
/usr/bin/atk6-extract_networks6 ${input} | sort -V -u | tee -a ${output}
echo '' | tee -a ${output} ; fi 
if [ $answer = "2" ] || [ $answer = "3" ] ; then 
f_solidShort | tee -a ${output}
echo -e "\n[+] IPv6 Host Portions\n\n" | tee -a ${output}
/usr/bin/atk6-extract_hosts6 ${input} | sort -V -u  | tee -a ${output} 
echo '' | tee -a ${output} ; fi 
fi ; f_Menu ; f_removeDir
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
f_BOX " ${x} " ; echo -e "\n${B}${x} Subdomains (IPv6)${D}\n\n"
atk6-dnsdict6 -l ${x} | sed '/Estimated time/G' | tee -a $tempdir/v6subs.txt
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
echo -e "${R}ERROR!${D}" ; exit 0
fi
echo -e "\n${B}Options >${D} (GLOBAL scope addresses only)\n"
echo -e "${B} [1]${D} geolocation, whois info"
echo -e "${B} [2]${D} geolocation, whois & BGP prefix details, IP Address/Network Blacklist Info"
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
sipcalc ${x} > $tempdir/scalc.txt
f_BOX " ${x} "
if [ $option_ipv6_1 = "1" ] || [ $option_ipv6_1 = "2" ] ; then
echo -e "\n\n[+] Address Type\n\n" | tee -a ${output}
grep -w 'Address type'  $tempdir/scalc.txt | tee -a ${output}
echo '' | tee -a ${output}
grep -w 'Compressed' $tempdir/scalc.txt | tee -a ${output}
echo '' | tee -a ${output}
grep -w 'Expanded' $tempdir/scalc.txt | tee -a ${output}
echo '' | tee -a ${output}
grep -w 'Address ID' $tempdir/scalc.txt | tee -a ${output}
echo '' | tee -a ${output} ; f_solidShorter | tee -a ${output} ; echo "$x" > $tempdir/list.txt
echo -e "\nNetwork:   $(/usr/bin/atk6-extract_networks6 $tempdir/list.txt)" | tee -a ${output}
echo -e "\nHost:      $(/usr/bin/atk6-extract_hosts6 $tempdir/list.txt)" | tee -a ${output}
echo -e "\n\n[+] Encoded MAC / IPv4 Address\n"  | tee -a ${output}
atk6-address6 ${x} | tee -a ${output} ; else
echo -e "\n\n[+] Network Range\n\n" | tee -a ${output}
grep -w 'Address type'  $tempdir/scalc.txt | tee -a ${output}
echo '' | tee -a ${output}
grep -w 'Compressed'    $tempdir/scalc.txt | tee -a ${output}
echo '' 
grep -w 'Expanded'      $tempdir/scalc.txt | tee -a ${output}
echo '' 
grep -w 'Subnet prefix' $tempdir/scalc.txt | tee -a ${output}
echo -e ''
grep -w 'Address ID (masked)' $tempdir/scalc.txt | tee -a ${output}
grep -w 'Prefix address' $tempdir/scalc.txt | tee -a ${output}
echo -e '' 
grep -A 1 'Network range' $tempdir/scalc.txt | tee -a ${output}
echo '' | tee -a ${output} ; f_solidShort | tee -a ${output}
fi
if [[ $(grep -w 'Address type' $tempdir/scalc.txt | grep -c -i -w 'Global Unicast') -ge "1" ]] && ! [ $option_details = "9" ] ; then
if [ $type_net = "false" ] ; then
f_BOX_BANNER "${x}" ; else
whois -h whois.cymru.com -- "-v -f ${x}" > $tempdir/cymru.txt ; fi
f_DRWHO "${x}" | tee -a ${output}
f_solidShort | tee -a ${output}
prefix=`cut -d '|' -f 3 $tempdir/cymru.txt | tr -d ' '`
if [ $type_net = "true" ] ; then
f_DELEGATION "${x}" | tee -a ${output}
echo -e "\n___________________________\n" | tee -a ${output}
echo -e "[+] Reverse DNS Consistency\n" | tee -a ${output}
curl -s https://stat.ripe.net/data/reverse-dns-consistency/data.json?resource=${x} > $tempdir/rdns.json
jq -r '.data.prefixes.ipv6' $tempdir/rdns.json | grep 'complete' | tr -d ',\"' |
sed 's/^ *//' | sed '/complete/G' | tee -a ${output}
jq -r '.data.prefixes.ipv6' $tempdir/rdns.json | grep 'prefix\|found' | tr -d '],\"[' | cut -d ':' -f 2- |
tr -d ' ' | tee -a ${output}
echo -e "\n\n__________________________________\n" | tee -a ${output}
echo -e "[+] Network Geographic Distributon\n" | tee -a ${output}
f_NETGEO "${x}" | tee -a ${output} ; fi
if  [ $option_details = "2" ] ; then 
f_PREFIX "${prefix}" | tee -a ${output}
if ! [ $x = $prefix ] ; then 
f_solidShort | tee -a ${output}
f_DELEGATION "${prefix}" | tee -a ${output}
echo -e "\n__________________________________\n" | tee -a ${output}
echo -e "[+] Prefix Reverse DNS Consistency\n" | tee -a ${output}
curl -s https://stat.ripe.net/data/reverse-dns-consistency/data.json?resource=${prefix} > $tempdir/dns.json
jq -r '.data.prefixes.ipv6' $tempdir/dns.json | grep 'complete' | tr -d ',\"' |
sed 's/^ *//' | sed '/complete/G' | tee -a ${output}
jq -r '.data.prefixes.ipv6' $tempdir/dns.json | grep 'prefix\|found' | tr -d '],\"[' | cut -d ':' -f 2- |
tr -d ' ' | tee -a ${output}
echo -e "[+] Prefix Geographic Distributon\n" | tee -a ${output}
f_NETGEO "${prefix}" | tee -a ${output} ; fi 
fi ; fi
done ; echo '' ; f_Menu ; f_removeDir
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
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}HTTP Headers${D}\n"
echo -e -n "\n${B}Target > [1]${D} new target ${B}| [2] current > ${D}  $target  ${B}?${D}  " ; read answer
if [ $answer = "2" ] ; then
address=`echo $target` ; else
echo -e -n "\n${B}Target > ${D}HOSTNAME  ${B}| ${D}IP${B} >>${D}   " ; read address ; fi
if ! [ $option_connect = "9" ] ; then
echo -e "\n== $address HTTP HEADERS ==\n\n" > $out/HEADERS.$address.txt
echo -e "\n" ; curl -s https://api.hackertarget.com/httpheaders/?q=${address}${api_key_ht} |
fmt -s -w 80 | tee -a $out/Headers.$address.txt
else
echo -e -n "\n${B}Source > [1]${D} curl  ${B}|  [2]${D} hackertarget.com WW API  ${B}?${D}  "  ; read source
echo -e "\n== $address HTTP HEADERS ==\n\n" > $out/HEADERS.$address.txt
echo -e "\n" ; if [ $source = "1" ] ; then
curl -sILk --max-time 3 $address | fmt -s -w 80 | tee -a $out/HEADERS.$address.txt ; else
curl -s https://api.hackertarget.com/httpheaders/?q=${address}${api_key_ht} |
fmt -s -w 80 | tee -a $out/HEADERS.$address.txt ; fi
fi
echo '' | tee -a $out/HEADERS.$address.txt
f_Menu ; f_optionsWEBSERVERS  ; f_removeDir
;;
112)
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}robots.txt${D}\n"
if ! [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Target > [1]${D} new target ${B}| [2] current > ${D}  $target  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
address=`echo $target` ; else
echo -e -n "\n${B}Target > ${D}HOSTNAME${B} | ${D}IP${B} >>${D}  " ; read address ; fi
echo -e "\n== $address robots.txt ==\n" >> $out/ROBOTS.$address.txt
echo -e "Date: $(date) \n\n" >> $out/ROBOTS.$address.txt
curl -sLk --max-time 3 $address/robots.txt | fmt -s -w 80 | tee -a $out/ROBOTS.$address.txt
echo '' | tee -a $out/ROBOTS.$address.txt ; else
f_WARNING ; fi ; f_Menu ; f_optionsWEBSERVERS ;  f_removeDir
;;
113)
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}Link Dump${D}"
echo -e -n "\n${B}Target > [1]${D} new target ${B}| [2] current > ${D}  $target  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
page=`echo $target` ; else
echo -e -n "\n${B}Target ${D}HOSTNAME${B} | ${D}IP${B} >>${D}  " ; read page ; fi
if [ $option_connect = "9" ] ; then
echo -e "\n\n== ${page} LINK DUMP (source > hackertarget.com) ==\n" >> $out/LINK_DUMP.$page.txt
echo -e "Date: $(date)\n\n" >> $out/LINK_DUMP.$page.txt
echo -e "\n" ; curl -s https://api.hackertarget.com/pagelinks/?q=${page}${api_key_ht} | tee -a  $out/LINK_DUMP.$page.txt
else
echo -e -n "\n${B}Source > [1]${D} lynx   ${B}|  [2]${D} hackertarget.com WW API  ${B}?${D}  "  ; read source
echo -e "\n" ; if [ $source = "1" ] ; then
echo -e "\n\n== ${page} LINK DUMP (source > lynx) ==\n" >> $out/LINK_DUMP.$page.txt
echo -e "Date: $(date)\n\n" >> $out/LINK_DUMP.$page.txt
f_linkDump "${page}" ; else
echo -e "\n\n== ${page} LINK DUMP (source > hackertarget.com) ==\n" >> $out/LINK_DUMP.$page.txt
echo -e "Date: $(date)\n\n" >> $out/LINK_DUMP.$page.txt
curl -s https://api.hackertarget.com/pagelinks/?q=${page}${api_key_ht} | tee -a $out/LINK_DUMP.$page.txt ; fi
fi
echo '' | tee -a $out/LINK_DUMP.$page.txt
f_Menu ; f_optionsWEBSERVERS  ; f_removeDir
;;
114)
f_makeNewDir ; f_dashedGrey
if ! [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Target > [1]${D} new target ${B}| [2]${D} Target List (.txt) ${B}| [3] current > ${D} $target  ${B}?${D}  " ; read option_target
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
echo -e -n "\n${B}Set       >${D}  Target Port - e.g. 25  ${B}>>${D}  " ; read tport ; else
: ; fi
for x in $(cat ${servers}) ; do
output="$out/WEB.${x}.txt"  ;  f_solidLong | tee -a ${output}
echo -e "\n == ${x} SERVER RESPONSE & REQUEST TIMES ==\n"  >> ${output}
touch $tempdir/response.txt
date_time=$(date)
curl -sLk4v ${x} --trace-time 2>$tempdir/curl.txt -D $tempdir/headers.txt -o $tempdir/src.txt -w \
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
ip4="$(egrep -m 1 -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/response.txt)"
curl -s https://ipapi.co/${ip4}/json/ > $tempdir/timezone.json
s_city=$(jq -r '.city' $tempdir/timezone.json)
s_country=$(jq -r '.country_name' $tempdir/timezone.json)
s_as=$(jq -r '.asn' $tempdir/timezone.json | sed 's/AS/AS /')
echo '' ; f_BOX " ${x} - ${s_country} - ${s_as} " ; echo ''
f_solidShort >> ${output}
if ! [ $option_mtr = "9" ] ; then
echo -e "\n\n${B}Round Trip Times & MTR Traceroute (TCP, Port > $tport)${D}\n\n"
echo -e " == ROUND TRIP TIMES & MTR TRACEROUTE (TCP, PORT >  $tport) == \n\n" >> ${output}
echo -e "[+] Mode > IPv4" | tee -a ${output}
sudo mtr -4 -T -b -c4 -w -z -P ${tport} -o "  L  S D  A BW  X  M" ${x} | sed '/Start:/{x;p;x;}'  | sed '/HOST:/G' |
tee -a ${output}
echo -e "\n\n[+] Mode > Auto" | tee -a ${output}
sudo mtr -T -b -c2 -w -z -P ${tport} -o "  L  S D  A BW  X  M" ${x} | sed '/Start:/{x;p;x;}'  | sed '/HOST:/G' |
tee -a ${output}
echo '' | tee -a ${output}
f_solidShort | tee -a ${output}
echo -e "Snt = packages sent;  Wrst = worst RTT in ms; \nJavg = average jitter" | tee -a ${output}
fi
echo -e "\n___________\n" | tee -a ${output}
echo -e "[+] httping\n" | tee -a ${output}
timeout 10 httping ${x} -c 5 | sed '/---/{x;p;x;G;}' | sed '/round-trip/{x;p;x;G;}' |
sed '/PING/G' | tee -a ${output}
echo -e "\n_______________\n" | tee -a ${output}
echo -e "[+] ping [icmp]\n" | tee -a ${output}
ping -c 5 -W 20 ${ip4} | sed '/---/G' | sed '/PING/G' | sed '/packet loss/{x;p;x;G;}' |
sed '/Paketverlust/{x;p;x;G;}' | tee -a ${output}
f_solidShort | tee -a ${output}
echo -e "${B}${x} Response-Times${D}\n" ; echo -e " == ${x} RESPONSE-TIMES ==\n\n"  >> ${output}
cat $tempdir/response.txt | tee -a ${output}
f_solidShort | tee -a ${output}
echo -e "== DNS LOOKUP TIME & - DELEGATION == \n" >> ${output}
echo -e "${B}DNS Lookup Time & - Delegation ${D}\n\n"
echo -e "[+] Time\n" | tee -a ${output}
echo -e "$(grep -w 'DNS Lookup:' $tempdir/response.txt | cut -d ':' -f 2- |  sed 's/^[ \t]*//') (total lookup time)" |
tee -a ${output}
f_solidShorter | tee -a  ${output}
echo -e "[+] Delegation\n" | tee -a ${output}
dig @1.1.1.1 +noall +answer +trace +noclass +nodnssec ${x} > $tempdir/trace.txt
cat $tempdir/trace.txt | grep ';; Received' | sed 's/;;//' | sed 's/^ *//' | sed '$d' | tee -a ${output}
sed -e '/./{H;$!d;}' -e 'x;/A/!d;' $tempdir/trace.txt | sed 's/;;//' | sed 's/^ *//' |
sed '/NS/d' | sed '/Received/{x;p;x;}' | tee -a ${output}
f_solidShort | tee -a ${output}
echo -e "${B}Redirects & Handshake ${D}\n"
echo -e " == REDIRECTS & HANDSHAKE ==\n" >> ${output}
echo -e "\n[+] Server Timezone \n" | tee -a ${output}
echo -e "Timezone:         $(jq -r '.timezone' $tempdir/timezone.json), CET $(jq -r '.utc_offset' $tempdir/timezone.json)" |
tee -a ${output}
echo -e "Location,ASN:     $s_city, $s_country, $s_as " | tee -a ${output}
echo -e "_______________\n" | tee -a  ${output}
echo -e "[+] Local Time \n" | tee -a ${output}
offset=$(date +"%Z %z")
echo -e "SYSTEM TIME:      $date_time" | tee -a ${output}
echo -e "UTC OFFSET:       $offset" | tee -a ${output}
f_solidShorter | tee -a ${output}
grep -w 'Redirects:' $tempdir/response.txt | tee -a ${output}
f_solidShorter | tee -a ${output}
sed -n '/HTTP/p; /[Ll]ocation:/p; /[Dd]ate:/p; /[Ss]erver:/p' $tempdir/headers.txt | sed '/HTTP/{x;p;x;}' |
tee -a ${output}
echo '' | tee -a ${output}
f_solidShort | tee -a ${output}
echo -e "[+] Handshake \n\n" | tee -a ${output}
grep -w 'Redirects:' $tempdir/response.txt | tee -a ${output}
echo ''
grep -w '^TCP Handshake:' $tempdir/response.txt | tee -a ${output}
grep -w '^SSL Handshake:' $tempdir/response.txt | tee -a  ${output}
echo -e "_____________\n" | tee -a ${output}
echo -e '' | tee -a ${output}
awk '{ IGNORECASE=1 } /connected|connection|trying|HTTP|ALPN|host|location|certificate:|subject:|issuer:|expire date|certificate verify ok.|cipher|handshake/ { print }' $tempdir/curl.txt |
sed '/^$/d' | sed '/TCP_NODELAY/d' | sed '/[Aa]ccept:/d' | sed '/left intact/d' | sed '/response-body/d' | sed '/verify locations:/d' |
sed '/CApath/d' | sed '/CAfile:/d' | sed '/Policy/d' |  sed '/old SSL session/d' | sed '/permissions-policy:/d' | sed '/state changed/d' |
sed '/Trying/i -------------' |
sed '/Connected to/a -------------' |
sed '/Server certificate:/i \\n------------------------------------------\n' |
sed '/SSL certificate verify ok./a \\n------------------------------------------\n' | sed -e :a -e 's/\(.*[0-9]\)\([0-9]\{4\}\)/\1/;ta' |
tee -a ${output}
f_solidLong | tee -a ${output}
echo -e "${B}${x} Page Request Times${D}\n\n"
echo -e "== ${x} PAGE REQUEST TIMES ==\n\n" >> ${output}
timeout 10 nmap -sT -Pn -p 80,443 --script http-chrono ${x} | sed '/PORT/{x;p;x;G;}' | sed '/Read data files/d' |
sed '/NSE/d' | sed '/Initiating/d' | sed '/Completed/d' | sed '/Discovered/d' | sed '/Host is up/d' |
sed '/Starting Nmap/d' | fmt -w 80 -s  | tee -a ${output} ; done
else
f_WARNING ; fi ; f_Menu ; f_optionsWEBSERVERS ;  f_removeDir
;;
115)
f_makeNewDir ; f_dashedGrey ; declare -a script_array=() ; declare -a port_array=()
option_server="y" ; option_banners="n" ; type_net="false"
if ! [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Target  > [1]${D} new target ${B}| [2]${D} Target List ${B}| [3] current > ${D}$target  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target  > ${D}HOSTNAME ${B}| ${D}IP  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/servers.txt
servers="$tempdir/servers.txt"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE  ${B}>>${D}  " ; read input
servers="${input}"
elif [ $option_target = "3" ] ; then
echo "$target" > $tempdir/servers.txt
servers="${tempdir}/servers.txt" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
echo -e "\n${B}Ports   > Current target ports > ${D}\n"
echo -e "${B} >${D} $web_ports"
echo -e -n "\n${B}Ports   >${D}  Customize ports? ${B} [y] | [n] ?${D}  " ; read option_ports
if [ $option_ports = "y" ] ; then
echo -e -n "\n${B}Set     > Ports  ${D}- e.g. 636,989-995  ${B}>>${D} " ; read add_ports
port_array+=(${add_ports}) ; else 
port_array+=(${web_ports}) ; fi
echo -e -n "\n${B}Options >${D} Network, whois & geolocation info ${B} > [1]${D} Summary ${B}| [2]${D} Details ${B}| [9]${D} SKIP  ${B}?${D}  " ; read option_details
echo -e -n "\n${B}Options >${D} Certificate status ${B} > [1]${D} curl  ${B}| [2]${D} openssl ${B}| [3]${D} BOTH  ${B}?${D}  " ; read option_web_1
echo -e -n "\n${B}Option  > ${D} Run testssl  ${B}[y] | [n] ?${D}  " ; read option_web_2
echo -e -n "\n${B}Option  > ${D} Display security headers & HTML comments ${B}[y] | [n] ?${D} " ; read option_web_3
echo -e -n "\n${B}Option  >${D} Do you have superuser privileges  ${B}[y] | [n] ?${D}  " ; read option_root
echo -e "\n\n${B}Nmap Mode > [1]${D} Safe Mode   ${B}|  [2]${D} Intrusive Mode"
echo -e -n "\n             ${B}?${D}  "  ; read option_web_4
if [ $option_root = "y" ] ; then
if [ $option_web_4 = "2" ] ; then
script_array+=(${http_safe},${http_safe_ext_1},${http_safe_ext_root},${SSL_enum},${http_intrusive}) ; else
script_array+=(${http_safe},${http_safe_ext_1},${http_safe_ext_root},${SSL_enum}) ; fi ; else 
if [ $option_web_4 = "2" ] ; then
script_array+=(${http_safe},${http_safe_ext_1},${SSL_enum},${http_intrusive}) ; else 
script_array+=(${http_safe},${http_safe_ext_1},${SSL_enum}) ; fi ; fi
for x in $(cat ${servers}) ; do
output="$out/WEB.${x}.txt" 
f_solidLong | tee -a ${output}
curl -sLk4v ${x} --trace-time 2>$tempdir/curl.txt -D $tempdir/headers.txt -o $tempdir/src.txt -w \
"
URL:              %{url_effective}
IP:               %{remote_ip}
Port:             %{remote_port}\n
Status            %{response_code}, HTTP %{http_version}\n
Time Total:       %{time_total} s
" > $tempdir/response.txt
ip4="$(egrep -m 1 -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/response.txt)" 
cat $tempdir/headers.txt | fmt -w 100 -s > $out/HEADERS.${x}.txt
f_OUTPUT_HEADER "${x}" 
if ! [ $option_details = "9" ] ; then 
f_BOX_BANNER "${ip4}" ; echo '' ; else 
f_BOX "${x}" ; echo '' ; fi
cat $tempdir/response.txt | tee -a ${output} ; echo ''
f_WHATWEB "${x}" ; f_solidShorter | tee -a ${output}
echo -e "[+] Web Site\n"  | tee -a ${output}
f_WHATWEB_PAGE | tee -a ${output} ; f_socialLinks "${x}"  | tee -a ${output}
echo -e "\n_______________________\n" | tee -a ${output} ; echo -e "[+] Web Tech & Services\n"  | tee -a ${output}
f_WHATWEB_CODE | tee -a ${output} ; f_BANNERS "${ip4}" | tee -a ${output} ; echo -e "\n" | tee -a ${output}
if ! [ $option_details = "9" ] ; then 
f_DRWHO "${ip4}" | tee -a ${output} ; fi
f_BLACKLISTS "${ip4}" | tee -a ${output} 
f_solidShort | tee -a ${output}  ; echo -e "${B}Certificate Status${D}\n"
echo -e "== CERTIFICATE STATUS ==\n" >> ${output} 
if [ $option_web_1 = "1" ] ; then 
f_certInfo_Curl | tee -a ${output} ; else 
f_certInfo_Curl | tee -a ${output} 
f_solidShorter | tee -a ${output} 
f_certInfo "${x}" | tee -a ${output} ; fi 
if [ $option_web_2 = "y" ] ; then
f_solidShort | tee -a ${output}
echo -e "${B}${x} Testssl ${D}\n\n" ; echo -e " == ${x} TESTSSL == \n\n" >> ${output}
testssl --quiet --phone-out --ids-friendly --color 0 ${x} | tee -a ${output} ; fi
f_solidShort | tee -a ${output}
echo -e "\n${B}${x} Server Enum & Vulnerabilities${D}\n\n"
echo -e "\n== ${x} NMAP RESULTS (SERVER ENUM / VULNERABILITIES) == \n" >> ${output} 
if [ $option_root = "y" ] ; then
sudo nmap -sV -O -Pn -p ${port_array[@]} ${x} --script ${script_array[@]} > $tempdir/nmap.txt ; else
nmap -sT -Pn -p ${port_array[@]} ${x} --script ${script_array[@]} > $tempdir/nmap.txt ; fi
cat $tempdir/nmap.txt | sed '/PORT/{x;p;x;}' | sed '/Starting Nmap/d' | sed '/Read data files/d' | sed '/NSE/d' |
sed '/Nmap scan report/{x;p;x;}' | sed '/Initiating/d' | sed '/Completed/d' | sed '/Discovered/d' | sed '/\/tcp /{x;p;x;G;}' |
sed '/Service detection/d' | sed '/Aggressive OS guesses:/{x;p;x;}' | sed '/Uptime guess:/{x;p;x;}' | sed '/Network Distance:/{x;p;x;}' |
fmt -s -w 120 | tee -a ${output} 
if [ $option_web_3 = "y" ] ; then
f_solidShort | tee -a ${output}
echo -e "${B}${x} Security Headers, robots.txt & HTML Comments${D}\n\n" 
echo -e " == SECURITY HEADERS, HTML COMMENTS & robots.txt == \n\n" >> ${output} 
nmap -sT -Pn -p 80,443,8009 --script ${http_safe_ext_2} ${x} | sed '/PORT/{x;p;x;G;}' | sed '/Read data files/d' |
sed '/NSE/d' | sed '/Initiating/d' | sed '/Completed/d' | sed '/Discovered/d' | sed '/Host is up/d' |
sed '/Starting Nmap/d' | fmt -w 100 -s | tee -a ${output} ; fi
f_solidShort | tee -a ${output}
echo -e "${B}HTTP Headers ${D}\n" ; echo -e "== HTTP HEADERS == \n\n" >> ${output} 
cat $out/HEADERS.${x}.txt | tee -a  ${output}
curl -sLk --max-time 3 ${x}/robots.txt | fmt -s -w 100 > $out/ROBOTS.${x}.txt ; done
else
f_WARNING ; fi
f_Menu ; f_optionsWEBSERVERS ;  f_removeDir
;;
p1)
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}Nmap Port & Service Version Scan"
if ! [ $option_connect = "9" ] ; then
declare -a nmap_array=() ; declare -a port_array=()
echo -e -n "\n${B}Target  > [1]${D} new target ${B}| [2] current > ${D} $target  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
scan_target=`echo $target` ; else
echo -e -n "\n${B}Target  > ${D}HOSTNAME   ${B}|${D} IP(s)  ${B}|${D} Network  ${B}>>${D}  " ; read scan_target ; fi
echo -e -n "\n${B}Option  >${D} Do you have superuser privileges  ${B}[y] | [n] ?${D}  " ; read option_root
if [ $option_root = "n" ] ; then
nmap_array+=(-sT -Pn)
scripts="banner,ajp-headers,http-server-header,ms-sql-info,mysql-info" ; else
echo -e "\n${B}Options >\n" 
echo -e "${B} [1]${D} Basic SYN Scan"   
echo -e "${B} [2]${D} Service Versions Scan"  
echo -e "${B} [3]${D} Service- & OS- Version Scan"
echo -e -n "\n${B}  ?${D}  " ; read scan_type
if   [ $scan_type = "1" ] ; then
nmap_array+=(-Pn -sS) 
scripts="banner"
elif [ $scan_type = "2" ] ; then
nmap_array+=(-Pn -sV)
scripts="banner,ajp-headers,http-server-header,ms-sql-info,mysql-info"
elif [ $scan_type = "3" ] ; then
nmap_array+=(-Pn -sV -O)
scripts_1="banner,ajp-headers,http-server-header,ms-sql-info,mysql-info,smb-protocols,smb-os-discovery,vmware-version"
else
echo -e "\n ${R}Error! ${D} \n" ; exit 0 ; fi
if ! [ $scan_type = "1" ] ; then
echo -e -n "\n${B}Option  > [1]${D} Scan for CVE Vulners  ${B}| [2]${D} CVE Vulners & empty mySQL/MS-SQL root passwords  ${B}| [9] SKIP  ${B}?${D}  " ; read option_vulners
if   [ $option_vulners = "1" ] ; then
scripts_2="http-malware-host,smtp-strangeport,vulners"
elif   [ $option_vulners = "2" ] ; then
scripts_2="mysql-empty-password,ms-sql-empty-password,ms-sql-ntlm-info,http-malware-host,smtp-strangeport,ftp-anon,vulners" ; else
: ; fi ; fi
fi
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
echo -e "\n== NMAP PORT SCAN (root)== \n" >> $out/PORTSCANS.txt
echo -e "Date : $(date), Type: $scan_type $scan_flag\n" >> $out/PORTSCANS.txt
echo -e "Target: $scan_target\n\n" >> $out/PORTSCANS.txt ; echo ''
f_solidShort
if [ $option_root = "y" ] ; then
sudo nmap ${nmap_array[@]} ${port_array[@]} ${scan_target} --script ${scripts_1},${scripts_2} > $tempdir/nmap.txt ; else 
nmap ${nmap_array[@]} ${port_array[@]} ${scan_target} --script ${scripts_1},${scripts_2} > $tempdir/nmap.txt ; fi
cat $tempdir/nmap.txt | sed '/PORT/{x;p;x;G;}' | sed '/\/tcp /{x;p;x;}' |
sed '/Read data files/d' | sed '/NSE/d' | sed '/Initiating/d' | sed '/Completed/d' | sed '/Discovered/d' |
sed '/Aggressive OS guesses:/{x;p;x;}' | sed '/Uptime guess:/{x;p;x;}' | sed '/Nmap scan report/{x;p;x;}' |
sed '/Network Distance:/{x;p;x;}' | fmt -w 120 -s | tee -a $out/PORTSCANS.txt
f_solidLong >> $out/PORTSCANS.txt ; echo ; else
f_WARNING ; fi ; f_removeDir ; f_Menu ; f_options_P
;;
p2)
#************** p2) nmap port scan (via hackertarget.com) ******
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
#************** p3) Banner Grabbing (via hackertarget.com) ******
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}Banner Grabbing"
echo -e -n "\n${B}Target >${D} Network (CIDR) ${B}|${D} IPv4 ${B} >>${D}  " ; read scan_target ; echo ''
echo -e "\n== $scan_target SERVICE BANNERS ==\n" >> $out/Banners.txt
f_BANNERS "${scan_target}" | tee -a $out/Banners.txt
f_solidLong >> $out/Banners.txt
echo ''; f_removeDir ; f_Menu ; f_options_P
;;
p4)
#************** p4) nping (via hackertarget.com) ******
f_makeNewDir ; f_dashedGrey
echo -e -n "\n${B}Target  >  IP  >>${D}  " ; read scan_target
echo -e "\n == $scan_target Nping (via hackertarget.com API) == \n"
echo '' ; curl -s https://api.hackertarget.com/nping/?q=${scan_target}${api_key_ht}  | tee -a $out/PORTSCANS.txt
f_solidShort >> $out/PORTSCANS.txt
echo '' ; f_removeDir ; f_ Menu ; f_options_P
;;
p6)
#************** p6) ARP SCAN ********************
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}ARP Scan${D}\n"
echo -e "${B}Active Network Interfaces${D}\n"
ip -4 addr show | awk '/inet.*brd/{print $NF}'
echo -e -n "\n${B}Set  >  ${D}Network Interface -e.g. eth0  ${B}>>${D}  " ; read interface
echo -e "\n== $interface ARP SCAN ==\n" >> $out/ARP_$interface.txt
echo -e "Date: $(date) " >> $out/ARP_$interface.txt
echo '' ; sudo arp-scan -I ${interface} -l | sed '/Interface:/{x;p;x;}' |
sed '/Starting arp-scan/{x;p;x;G;}' | tee -a $out/ARP_$interface.txt
f_solidLong >> $out/ARP_$interface.txt ; echo '' ; f_removeDir ; f_Menu ; f_options_P
;;
t1)
#************** t1) Nmap Geo Traceroute  ********************
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}NMAP NSE Geo Traceroute${D}"
echo -e -n "\n${B}Target > ${D}HOSTNAME(s)${B} | ${D}IP(s)${B}  >>${D}   " ; read address
echo -e "\n\n== $address NMAP GEO TRACEROUTE ==" >> $out/ROUTES.${address}.txt
echo -e "\n" | tee -a $out/ROUTES.${address}.txt
sudo nmap -sn --traceroute --script traceroute-geolocation $address | sed '/Read data files/d' | tee -a $out/ROUTES.${address}.txt
f_solidLong >> $out/ROUTES.${address}.txt ; echo '' ; f_removeDir ; f_Menu ; f_options_T
;;
t2)
#************** t2) MTR Traceroute  ********************
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}MTR Traceroute${D}"
echo -e -n "\n${B}Target    >  ${D}Hostname ${B}|${D} URL ${B}|${D} IP  ${B}>>${D}  " ; read address
echo -e -n "\n${B}Source    > [1] ${D}App (local inst.) ${B}| [2] ${D} hackertarget.com API  ${B}?${D}  " ; read option_source
if [ $option_source = "2" ] ; then
echo -e "\n== $address MTR TRACEROUTE (via hackertarget.com) == ${D} \n" >> $out/ROUTES.${address}.txt
echo -e "    Date: $(date) \n" >> $out/ROUTES.${address}.txt ; echo -e "\n"
curl -s https://api.hackertarget.com/mtr/?q=${address}${api_key_ht}  | tee -a $out/ROUTES.${address}.txt ; else
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
echo -e "\n== MTR Traceroute (Target: $address) == \n\n"  >> $out/ROUTES.${address}.txt
echo -e "\n"
sudo mtr -w -b -z ${mtr_array[@]} -o "  L  S D  A BW  M" $address | sed '/HOST:/G' |
tee -a $out/ROUTES.${address}.txt
echo '' | tee -a $out/ROUTES.${address}.txt
f_solidShort | tee -a $out/ROUTES.${address}.txt
echo -e "Snt = packages sent; Javg = average jitter\n" | tee -a $out/ROUTES.${address}.txt ; fi
f_solidLong >> $out/ROUTES.${address}.txt ; f_removeDir ; f_Menu ; f_options_T
;;
t3)
#************** t3) Dublin Traceroute  ********************
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
t4)
#************** t4) Tracepath (non root)  ********************
f_makeNewDir ; f_dashedGrey
echo -e "\n${B}Tracepath (non root)${D}\n"
#********
if ! [ $option_connect = "9" ] ; then
#********
echo -e -n "\n${B}Target  > [1]${D} new target ${B}| [2] current >  ${D}$target ${B}?${D}  " ; read answer
if [ $answer = "2" ] ; then
address=`echo $target` ; else
echo -e -n "\n ${B}Hostname | URL | IP >>  " ; read address
fi
echo -e -n "\n${B}Options > [4]${D} IPv4 Mode  ${B}| [6]${D} IPv6 Mode | ${B}[b]${D} both ${B}?${D} " ; read IPvChoice
echo -e -n "\n${B}Set     >${D} Max. amount of hops (default: 30) ${B} >>${D}  " ; read hops
if   [ $IPvChoice = "4" ] ; then
    echo -e "\n\n${B}Tracepath Results (IPv4) ${D}\n\n"
    echo -e "\n\n== TRACEPATH RESULTS (IPv4) == \n\n" >> $out/ROUTES.${address}.txt
    tracepath -4 -b -m ${hops} $address | tee -a $out/ROUTES.${address}.txt
elif [ $IPvChoice = "6" ] ; then
    echo -e "\n\n${B}Tracepath Results (IPv6) ${D}\n\n"
    echo -e "\n\n== TRACEPATH RESULTS (IPv6) == \n\n" >> $out/ROUTES.${address}.txt
    tracepath -6 -b -m ${hops} $address | tee -a $out/ROUTES.${address}.txt
elif [ $IPvChoice = "b" ] ; then
    echo -e "\n\n== TRACEPATH RESULTS (IPv4) == \n\n" >> $out/ROUTES.${address}.txt
    echo -e "\n\n${B}Tracepath Results (IPv4) ${D}\n\n"
    tracepath -4 -b -m ${hops} $address | tee -a $out/ROUTES.${address}.txt
    echo -e "\n\n${B}Tracepath Results (IPv6) ${D}\n\n"
    echo -e "\n\n== TRACEPATH RESULTS (IPv6) == \n\n" >> $out/ROUTES.${address}.txt
    tracepath -6 -b -m ${hops} $address | tee -a $out/ROUTES.${address}.txt
else
    echo -e "\n${R}Please choose IPv4 or IPv6 mode${D}\n"
fi
f_solidLong >> $out/ROUTES.${address}.txt
#********
else
f_WARNING ; fi
#********
echo '' ; f_removeDir ; f_Menu; f_options_T
;;
q)
echo -e "\n${B}----------------------------------- Done -------------------------------------\n"
echo -e "                       ${BDim}Author - Thomas Wy, Feb 2021${D}\n\n"
f_removeDir
break
;;
esac
done

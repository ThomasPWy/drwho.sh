#!/bin/bash
function f_error_message {
local s="$*"
echo -e "\nERROR: $s is not installed on your system. Please make sure that at least the essential dependencies are satisfied."
echo -e "\nDependencies (essential): curl, dnsutils (installs dig & host), jq, lynx, nmap, openssl, whois"
echo -e "\nDependencies (recommended): dublin-traceroute, mtr, testssl, thc-ipv6, tracepath, wfuzz, whatweb\n"
}
if ! type curl &> /dev/null; then
f_error_message "curl" ; exit 1 ; fi 
if ! type dig &> /dev/null; then
f_error_message "dig (dnsutils)" ; exit 1 ; fi 
if ! type jq &> /dev/null; then
f_error_message "jq" ; exit 1 ; fi 
if ! type whois &> /dev/null; then
f_error_message "whois" ; exit 1 ; fi 
#####################################
#************ Variables  ***********
#************ API KEYS ***********
#hackertarget.com
api_key_ht=''
# project honeypot
honeykey=''
#************ COLORS & TEXT FORMATTING ***********
B='\e[34m' ; D='\e[0m' ; GREEN='\e[32m' ; GREEN2='\e[38;5;035m' ; R='\e[31m' 
#************ TEMPORARY WORKING DIRECTORY ***********
tempdir="${PWD}/drwho_temp" ; outdir="${PWD}/drwho_temp"
#************ REGEX ***********
REGEX_IP4="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
#************ USER AGENTS ***********
ua_moz="Mozilla/5.0"
#************ OTHER ***********
option_connect="1" ; conn="${GREEN}true${D}" ; report="false" ; quiet_dump="false" ; ssl_details="true"
#************ NMAP ***********
ports_net_services="21,22,23,25,53,80,110,143,179,443,445,465,587,1025,1434,3306,5060,5900,8080"
web_ports="22,80,443,3306,8080,9800"
web_ports_xl="21,22,23,80,111,135,443,1025,1434,3306,8000,8009,8080,9800,10000"
nmap_mx="smtp-commands,ssl-cert,smtp-ntlm-info,smtp-enum-users.nse,imap-capabilities,imap-ntlm-info,pop3-capabilities,pop3-ntlm-info,path-mtu,dns-nsid,vulners"
nmap_http_safe="banner,http-server-header,http-generator,http-title,ajp-headers,http-chrono,https-redirect,http-php-version,http-affiliate-id,http-referer-checker,sslv2,vulners"
nmap_web="http-server-header,ajp-headers,https-redirect,http-generator,http-php-version,http-affiliate-id,http-referer-checker,http-auth,http-auth-finder,http-csrf,http-phpself-xss,http-dombased-xss,http-stored-xss,http-unsafe-output-escaping,http-rfi-spider,http-apache-negotiation,mysql-empty-password,rpcinfo,ssh2-enum-algos,http-sql-injection,http-malware-host,http-open-proxy,http-enum,http-phpmyadmin-dir-traversal,http-backup-finder,unusual-port,vulners,sslv2,http-methods"
#************ BLOCKLISTS ***********
blocklists_regular="
all.bl.blocklist.de
all.s5h.net
all.spamrats.com
b.barracudacentral.org
dnsbl.darklist.de
dnsbl-1.uceprotect.net
dnsbl-2.uceprotect.net
dnsbl-3.uceprotect.net
dyn.nszones.com
ips.backscatterer.org
netscan.rbl.blockedservers.com
phishing.rbl.msrbl.net
relays.dnsbl.sorbs.net
recent.spam.dnsbl.sorbs.net
rep.mailspike.net
spam.pedantic.org
talosintelligence.com
tor.dan.me.uk
torexit.dan.me.uk
zen.spamhaus.org
zombie.dnsbl.sorbs.net
"
blocklists_small="
all.bl.blocklist.de
all.s5h.net
b.barracudacentral.org
dnsbl-1.uceprotect.net
dnsbl-2.uceprotect.net
dnsbl-3.uceprotect.net
dyn.nszones.com
ips.backscatterer.org
recent.spam.dnsbl.sorbs.net
relays.dnsbl.sorbs.net
rep.mailspike.net
talosintelligence.com
tor.dan.me.uk
zen.spamhaus.org
"
blocklists_tiny="
all.bl.blocklist.de
all.s5h.net
dyn.nszones.com
zen.spamhaus.org
"
#************* startmenu with global options  ******************
function f_startMenu {
echo -e "\n  a)  SHOW ALL OPTIONS"
echo "  c)  CLEAR SCREEN"
echo "  i)  MANAGE TARGET INTERACTION"
echo "  o)  OPTIONS"
echo "  s)  SAVE RESULTS"
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
#*********** banners, headers & output  *************
function f_OutFile {
local s="$*"
if [ $report = "true" ] ; then
echo -e "${B}Output-File(s) >${D}\n" ; echo -e "${s}\n" ; fi
}
function f_WARNING {
echo -e "\n${R} Warning >${D} This option requires sending packets to target systems!"
echo -e "\nPlease deactivate safe mode via options a) or s)." ; echo -e "\n${R}${IT}Aborting...${D}"
}
function f_textfileBanner {
echo -e "\n ---------------" ; echo -e "  drwho.sh" ; echo -e " ---------------"
echo -e "\nAuthor - Thomas Wy, Apr 2021" ; echo -e "https://github.com/ThomasPWy/drwho.sh \n"
echo -e "\nDate   - $(date)"
}
function f_REPORT {
echo -e -n "\n${B} Set folder > ${D}HOME/${B}dir_name >>${D} " ; read dirname
mkdir $HOME/$dirname ; outdir="$HOME/$dirname" ; report="true"
echo -e "\n ${B}Option > Target Connect > ${D}" ; echo -e "\n ${B}>${D} Send packets to target systems ?"
echo -e -n "\n ${B}>${D} ${GREEN}[1]${B} yes | ${R}[9]${B} no ?${D}  " ; read option_connect
if [ $option_connect = "9" ] ; then
conn="${R}false${D}" ; else
conn="${GREEN}true${D}" ; fi
export outdir ; export report
export option_connect ; export conn
}
#************ separators  *************
function f_Long {
echo -e "______________________________________________________________________________\n"
}
function f_Short {
echo -e "___________________________________________________________\n"
}
function f_Shorter {
echo -e "_________________________________________\n"
}
function f_Shortest {
echo -e "________________________\n"
}
#************ menu *************
function f_Menu {
f_Long ; echo -e "\n  ${B}Connect >  $conn"
echo -e "  ${B}Folder  >  $dirname${D}\n"
echo -e "  ${B}1)${D}  Domain Enumeration           ${B} 7)${D}  Webservers"
echo -e "  ${B}2)${D}  DNS                          ${B} p)${D}  Port Scans & Ping"
echo -e "  ${B}3)${D}  whois                        ${B} t)${D}  Traceroute"
echo -e "  ${B}4)${D}  IPv4                         ${B} i)${D}  Manage target interaction"
echo -e "  ${B}5)${D}  Rev_GoogleAnalytics Search   ${B} m)${D}  MAIN MENU"
echo -e "  ${B}6)${D}  IPv6"
}
#************ curl writeout / SSL handshake details *************
function f_writeOUT {
local s="$*"
curl ${curl_array[@]} ${curl_ua} ${s} --trace-time 2>$tempdir/curl -D $tempdir/headers -o $tempdir/${s}.html -w \
"
URL:             %{url_effective}
IP:              %{remote_ip} (%{remote_port})
Status:          %{response_code} 
\nRedirects:       %{time_redirect} s  (%{num_redirects})
DNS Lookup:      %{time_namelookup} s
\nSSL Handshake:   %{time_appconnect} s
TCP Handshake:   %{time_connect} s
———
Time Total:      %{time_total} s
____________________________________\n
Download Size:  %{size_download} bytes
Download Speed: %{speed_download} bytes/s\n
" > $tempdir/response ; cat $tempdir/${s}.html > $tempdir/src
sed -n '/<head/,/<\/head>/p' $tempdir/src > $tempdir/src_head
cat $tempdir/curl | cut -d ' ' -f 3- | sed 's/^ *//' > $tempdir/curl_trimmed
f_Long > ${outdir}/HANDSHAKE.${s}.txt ; echo -e "[+] $s | RESPONSE TIMES & SSL HANDSHAKE" >> ${outdir}/HANDSHAKE.${s}.txt
f_Long >> ${outdir}/HANDSHAKE.${s}.txt  ; cat $tempdir/response >> ${outdir}/HANDSHAKE.${s}.txt
f_curlHandshake >>  ${outdir}/HANDSHAKE.${s}.txt 
}
function f_curlHandshake {
f_Long ; echo '' ; cat $tempdir/curl | sed '/^$/d' |
grep -s -E -i "Trying|Connected to|< HTTP*|GET|TCP_NODELAY|Mark bundle|< Date:|< Server:|ALPN|handshake|Server certificate:|subject:|date:|issuer:|SSL|ID" |
sed '/CApath:/d' | sed '/CAfile:/a \---------------------------------------------------------------------' |
sed '/SSL connection using/i \---------------------------------------------------------------------' |
sed '/Connected to /i \n\---------------------------------------------------------------------' |
sed '/Connected to /a \---------------------------------------------------------------------\n' |
sed '/Server [Cc]ertificate:/i \---------------------------------------------------------------------\n' | 
sed '/SSL [Cc]ertificate verify/a \\n---------------------------------------------------------------------\n' |
sed -e :a -e 's/\(.*[0-9]\)\([0-9]\{4\}\)/\1/;ta' |
sed '/[Cc]ontent-[Ss]ecurity-[Pp]olicy:/d' | sed '/[Ff]eature-[Pp]olicy:/d' | sed '/[Pp]ermissions-[Pp]olicy:/d' |
sed '/[Cc]ontent-[Ll]anguage/d' | sed '/P3P:/d' | sed '/[Cc]ache-[Cc]ontrol:/d' | fmt -w 100 -s
}
#************ check for bogons, tor-nodes, spamhaus domain blocklist *************
function f_BOGON {
local s="$*" ; reverse=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
bogon="$(dig @1.1.1.1 +short -t a ${reverse}.bogons.cymru.com.)"
if [[ $bogon ]]; then
is_bogon="TRUE" ; else 
is_bogon="FALSE" ; fi 
export is_bogon=`echo $is_bogon`
}
function f_TOR {
local s="$*" ; reverse=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
is_tor="$(dig @1.1.1.1 +short -t a ${reverse}.tor.dan.me.uk.)"
if [[ $is_tor ]]; then
echo -e "| TOR: true (${is_tor})" ; else 
echo -e "| TOR: false" ; fi 
}
function f_DBL {
local s="$*" ; dbl_listed="$(dig @1.1.1.1 +short ${s}.dbl.spamhaus.org)"
if [[ $dbl_listed ]]; then
is_listed="$s is listed in Spamhaus DBL; return code: ${dbl_listed}" ; else 
is_listed="not listed in spamhaus.org Domain BL" ; fi 
echo -e "\nDBL:          $is_listed"
}
#************ look up abuse-contacts via abusix, ripeSTAT or whois.lacnic.net  *************
function f_ABX {
local s="$*"
if [[ ${s} =~ $REGEX_IP4 ]] ; then
reverse=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
abx=$(dig +short $reverse.abuse-contacts.abusix.zone txt | tr -d '/"') ; else
nibble=$(host $s | cut -d ' ' -f 1 | rev | cut -d '.' -f 3- | rev)
abx=$(dig +short $nibble.abuse-contacts.abusix.zone txt | tr -d '/"') ; fi
export abx=`echo $abx`
}
function f_abxHEADER {
local s="$*" ; reg=`jq -r '.data.authorities[0]' $tempdir/ac.json`
if [ $reg = "ripe" ] ; then
abx=$(jq -r '.data.anti_abuse_contacts.abuse_c[] | .email' $tempdir/ac.json)
elif [ $reg = "lacnic" ] ; then
abx=$(whois -h whois.lacnic.net $s | grep -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b") ; else  
if [[ ${s} =~ $REGEX_IP4 ]] ; then
f_ABX "${s}" ; else 
if [ $domain_enum = "true" ] ; then
whois -h whois.$reg.net ${s} > $tempdir/whois ; fi 
abx=$(cat $tempdir/whois | grep -E -i -m 1 "^OrgAbuseEmail:|^% Abuse|^abuse-mailbox:|^e-mail:" | grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b")
fi ; fi ; echo -e "[@]: $abx" ; echo -e "___\n"
}
#************ prefixes, as & RPKI validation *************
function f_PREFIX {
local s="$*" ; net=`echo "$s" | cut -d '/' -f 1` ; touch $tempdir/asnums.list ; touch $tempdir/asnums1.list
if [[ ${net} =~ $REGEX_IP4 ]] ; then
reverse=$(echo ${net} | awk -F'.' '{print $4 "." $3 "." $2 "." $1}')
dig +short $reverse.origin.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/cym ; else
whois -h whois.cymru.com -- "-v -f ${s}"  > $tempdir/cym ; fi
while read -r line;
do
asno=`echo "$line" | cut -d '|' -f 1 | sed 's/^[ \t]*//;s/[ \t]*$//'`
if [[ ${net} =~ $REGEX_IP4 ]] ; then
prefix=`echo $line | awk -F'|' '{print $2}' | tr -d ' '` ; in_reg=`echo $line | awk -F'|' '{print $4}' | tr -d ' '`
ctry=`echo $line | awk -F'|' '{print $3}' | tr -d ' '` ; else
prefix=`echo $line | awk -F'|' '{print $3}' | tr -d ' '` ; in_reg=`echo $line | awk -F'|' '{print $5}' | tr -d ' '`
ctry=`echo $line | awk -F'|' '{print $4}' | tr -d ' '` ; fi
curl -s "https://stat.ripe.net/data/rpki-validation/data.json?resource=$asno&prefix=$prefix" > $tempdir/roa.json
valid=`jq -r '.data.validating_roas[0].validity' $tempdir/roa.json`
echo -e "\nPrefix:      $prefix  | $ctry | $in_reg |  ROA: $valid"
asn=$(dig +short as$asno.asn.cymru.com TXT | cut -d '|' -f 1,5 | tr -d '"' | sed 's/^ *//')
echo -e "\nAS           $asn" 
echo "$prefix" >> $tempdir/netlist
echo "$line" | cut -d '|' -f 1 | sed 's/^[ \t]*//;s/[ \t]*$//' >> $tempdir/asnums1.list
echo "$line" | cut -d '|' -f 1 | sed 's/^[ \t]*//;s/[ \t]*$//' >> $tempdir/asnums.list
echo "$line" >> $tempdir/prefixes.list
done < $tempdir/cym ; echo ''
}
#************  server/'hop' summary *************
function f_serverINFO {
local s="$*"
if [ $type_hop = "true" ] ; then
curl -s http://ip-api.com/json/${s}?fields=16985627  > $tempdir/geo.json
proxy=`jq -r '.proxy' $tempdir/geo.json` ; hosting=`jq -r '.hosting' $tempdir/geo.json`
curl -s "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${s}" > $tempdir/ac.json ; fi
reg=`jq -r '.data.authorities[0]' $tempdir/ac.json` ; org=`jq -r '.org' $tempdir/geo.json`
if ! [[ ${s} =~ $REGEX_IP4 ]] ; then
whois -h whois.$reg.net ${s} > $tempdir/whois
netname=$(grep -i -m 1 "^netname:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//')
orgname=$(grep -i -E -m 1 "^organization:|^orgname:|^org-name:|^owner:|^descr:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//') ; fi
if [[ ${s} =~ $REGEX_IP4 ]] ; then
echo -e "begin" > $tempdir/address.txt
echo $s >> $tempdir/address.txt ; echo "end" >> $tempdir/address.txt
netcat whois.pwhois.org 43 < $tempdir/address.txt > $tempdir/pwho
orgname=`grep -w "^Org-Name:" $tempdir/pwho | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//'`
if [ -n "$orgname" ] ; then
netname=`grep "^Net-Name:" $tempdir/pwho | cut -d ' ' -f 2- | sed 's/^ *//'`
if cat $tempdir/pwho | grep -q -E "^Geo-"; then
cc="Geo-CC:" ; else
cc="Country-Code:" ; fi ; ctry=$(cat $tempdir/pwho  | grep -m 1 "^${cc}" | cut -d ':' -f 2 | sed 's/^ //') ; else
whois -h whois.$reg.net ${s} > $tempdir/whois
netname=`grep -i -m 1 "^netname:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//'`
orgname=`grep -i -E -m 1 "^organization:|^orgname:|^org-name:|^owner:|^descr:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//'`
ctry=`grep -i -m 1 "^country:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//'` ; fi ; fi
if [ -n "$org" ] ; then
organ="$org" ; else
if [ "$netname" = "$orgname" ] ; then
organ=`grep "^AS-Org-Name:"  $tempdir/pwho | cut -d ' ' -f 2- | sed 's/^ *//'` ; else
organ="$orgname" ; fi ; fi
if [ $reg = "ripe" ] ; then
less_sp=$(jq -r '.data.less_specifics[0]' $tempdir/ac.json | head -1); netname=`jq -r '.data.holder_info.name' $tempdir/ac.json` ; fi
if [ $type_hop = "true" ] ; then
if [[ ${s} =~ $REGEX_IP4 ]] ; then
f_ABX "${s}" ; else
abx=$(cat $tempdir/whois | grep -E -i -m 1 "^OrgAbuseEmail:|^% Abuse|^abuse-mailbox:|^e-mail:" | grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b") ; fi
asnumber=$(curl -s "https://stat.ripe.net/data/network-info/data.json?resource=${s}" | jq -r '.data.asns[0]')
f_Long ; echo -e "HOP $hopnum | $s | AS $asnumber | $abx" ; f_Long
curl -s https://stat.ripe.net/data/reverse-dns-ip/data.json?resource=${s} > $tempdir/ptr.json
ptr=$(jq -r '.data.result[]?' $tempdir/ptr.json | sed 's/null/no ptr record/' | tr '[:space:]' ' ' ; echo '')
echo -e "\nrDNS:        $ptr" ; fi
echo -e "\nGEO:         $(jq -r '.regionName' $tempdir/geo.json), $(jq -r '.country' $tempdir/geo.json)"
echo -e "\nORG:         $organ | ISP: $(jq -r '.isp' $tempdir/geo.json)\n"
if [ $domain_enum = "false" ] ; then
if [[ ${s} =~ $REGEX_IP4 ]] ; then
if [ -f $tempdir/iscip.json ] ; then
cloudip=`jq -r '.ip.cloud' $tempdir/iscip.json` ; mobile=`jq -r '.mobile' $tempdir/geo.json`
echo -e "             Mobile:  $mobile  | Proxy: $(jq -r '.proxy' $tempdir/geo.json) $tor_node"
echo -e "             Hosting: $hosting  | Cloud: $cloudip\n"
elif [ $type_hop = "true" ] ; then
echo -e "             Proxy: $proxy $tor_node | Hosting: $hosting\n" ; fi ; else 
echo -e "             Proxy: $proxy | Hosting: $hosting\n" ; fi ; fi 
if [ $reg = "ripe" ] ; then
echo -e "NET:         $netname | $less_sp | $ctry\n" ; else
echo -e "NET:         $netname | $ctry\n" ; fi 
f_PREFIX "${s}"
if [ $reg = "ripe" ] && [[ ${net} =~ $REGEX_IP4 ]] ; then
echo "$less_sp" >> $tempdir/nets.list
ucelist=$(jq -r '.data.blocklist_info[] | .list' $tempdir/ac.json)
if [ -n "$ucelist" ] ; then
echo -e "\nuceprotect Listings\n____________________\n" ; jq -r '.data.blocklist_info[] | .list, .entries' $tempdir/ac.json ; fi ; fi
}

#*****************  SSL/TLS  *****************
function f_certINFO {
local s="$*"
echo '' ; echo | timeout 3 openssl s_client -connect ${s}:443 -brief 2> $tempdir/brief.txt
echo | timeout 3 openssl s_client -connect ${s}:443 2>/dev/null |
openssl x509 -text -ocspid --ocsp_uri -fingerprint -serial -subject -issuer -dates -nameopt multiline | sed 's/^ *//' > $tempdir/x509.txt
if [ $ssl_details = "true" ] ; then
echo | timeout 3 openssl s_client -connect ${s}:443 2>/dev/null -showcerts > $tempdir/chain.txt
echo | timeout 3 openssl s_client -connect ${s}:443 2>/dev/null -status > $tempdir/status.txt ; fi
subject=`sed -n '/subject=/,/issuer=/p' $tempdir/x509.txt`
verify=`grep -s -i -w "Verification:" $tempdir/brief.txt | cut -d ' ' -f 2- | sed 's/^ *//'`
protocol=`grep -s -i 'Protocol version' $tempdir/brief.txt | cut -d ':' -f 2- | sed 's/^ *//'`
cipher=`grep -s -i -w 'Ciphersuite' $tempdir/brief.txt | cut -d ':' -f 2- | sed 's/^ *//'`
pubkey_algo=`grep -w -i "Public Key Algorithm:" $tempdir/x509.txt | cut -d ':' -f 2- | sed 's/^ *//'`
pubkey_length=`grep -A 1 "Public Key Algorithm:" $tempdir/x509.txt | tail -1 | cut -d ':' -f 2- | tr -d '()' | sed 's/^[ \t]*//;s/[ \t]*$//'`
sign_algo=`grep -w -i -m 1 "Signature Algorithm:" $tempdir/x509.txt | cut -d ':' -f 2- | sed 's/^ *//'`
start_date=$(grep 'notBefore=' $tempdir/x509.txt | cut -s -d '=' -f 2- | sed 's/^ *//')
ex_date=$(grep 'notAfter=' $tempdir/x509.txt | cut -s -d '=' -f 2- | sed 's/^ *//')
s_cc=`sed -n '/subject=/,/commonName/p' $tempdir/x509.txt | grep -m 1 'countryName' | cut -d '=' -f 2- | sed 's/^ *//'`
s_org=`sed -n '/subject=/,/commonName/p' $tempdir/x509.txt | grep -m 1 'organizationName' | cut -d '=' -f 2- | sed 's/^ *//'`
s_cn=`sed -n '/subject=/,/commonName/p' $tempdir/x509.txt | grep -m 1 'commonName' | cut -d '=' -f 2- | sed 's/^ *//'`
ca_cc=`sed -n '/issuer=/,/commonName/p' $tempdir/x509.txt | grep -m 1 'countryName' | cut -d '=' -f 2- | sed 's/^ *//'`
ca_org=`sed -n '/issuer=/,/commonName/p' $tempdir/x509.txt | grep -m 1 'organizationName' | cut -d '=' -f 2- | sed 's/^ *//'`
ca_cn=`sed -n '/issuer=/,/commonName/p' $tempdir/x509.txt | grep -m 1 'commonName' | cut -d '=' -f 2- | sed 's/^ *//'`
if [ $ssl_details = "true" ] ; then
f_Long >> $outdir/CERT.${s}.txt
echo "[+] $s | CERTIFICATE FILE DUMP | $(date)" >> ${outdir}/CERT.${s}.txt ; f_Long >> $outdir/CERT.${s}.txt
echo -e "[*] PEER CERTIFICATE\n"  >> ${outdir}/CERT.${s}.txt
echo -e "Verification:   $verify"  >> ${outdir}/CERT.${s}.txt
echo -e "Issued:         $start_date" >> ${outdir}/CERT.${s}.txt
echo -e "Expires:        $ex_date" >> ${outdir}/CERT.${s}.txt
echo -e "Signature:      $sign_algo" >> ${outdir}/CERT.${s}.txt
echo -e "Subject CN:     $s_cn" >> ${outdir}/CERT.${s}.txt
echo -e "\n-----------------------------------------\n" >> ${outdir}/CERT.${s}.txt
cat $tempdir/x509.txt | grep -E "^serial.=|^SHA1 Fingerprint=" | sed 's/serial=/Serial:\n/' |
sed 's/SHA1 Fingerprint=/SHA1 Fingerprint:\n/' | sed '/SHA1/{x;p;x}' >> ${outdir}/CERT.${s}.txt
echo -e "\n-----------------------------------------\n" >> ${outdir}/CERT.${s}.txt
sed -n '/Certificate chain/,/Server certificate/p' $tempdir/chain.txt | sed 's/s:/Holder: /g' | sed 's/i:/Issuer: /g' | sed '/END/G' |
sed '/BEGIN/{x;p;x}' | sed '$d' >> ${outdir}/CERT.${s}.txt ; fi
if [ $quiet_dump = "false" ] ; then
f_Long ; echo "[+] $s | CERTIFICATE | STATUS: $verify" ; f_Long
echo -e "\nVerification:     $verify"
echo -e "Issued:           $(grep -m 1 'notBefore=' $tempdir/x509.txt | cut -s -d '=' -f 2- | sed 's/^ *//')"
echo -e "Expires:          $(grep -m 1 'notAfter=' $tempdir/x509.txt | cut -s -d '=' -f 2- | sed 's/^ *//')"
echo -e "\nSubject:          $s_cn $s_org $s_c"
echo -e "Issuer:           $ca_cn $ca_org $ca_c"
echo -e "-----------------------------------------\n"
echo -e "Cipher:           $cipher | $protocol"
echo -e "PubKey:           $pubkey_algo $pubkey_length"
echo -e "Signature:        $sign_algo"
if [ $ssl_details = "true" ] ; then
echo -e "-----------------------------------------\n" ; echo -e "Serial Number:"
sed -n '/Serial [Nn]umber:/{n;p;}' $tempdir/x509.txt | sed 's/^[ \t]*//;s/[ \t]*$//'
echo -e "\nFingerprint (SHA-1):"
grep -i "Fingerprint" $tempdir/x509.txt | cut -d '=' -f 2- | sed 's/^ *//'
echo -e "-----------------------------------------\n" ; echo -e "Subject Alternative Names:\n"
sed -e '/./{H;$!d;}' -e 'x;/Subject Alternative Name:/!d;' $tempdir/x509.txt | grep 'DNS:' | sed 's/^ *//' | fmt -w 120 -s
echo -e "-----------------------------------------\n" ; echo -e "OCSP:\n"
grep -s -w -i -o "no response sent"  $tempdir/status.txt | sed 's/^[ \t]*//'
grep -s -i -w 'OCSP Response Status:' $tempdir/status.txt | sed 's/^[ \t]*//'
grep -s -i -w 'Cert Status:' $tempdir/status.txt | sed 's/^ *//'
grep -s "OCSP - URI" $tempdir/x509.txt | cut -d ':' -f 2- | sed 's/^ *//'
grep -s 'Subject OCSP hash:' $tempdir/x509.txt | sed 's/^ *//'
grep -s 'Public key OCSP hash:' $tempdir/x509.txt | sed 's/^ *//'
echo -e "-----------------------------------------\n" ; echo -e "Certificate Chain (not verified):\n"
sed -n '/Certificate chain/,/Server certificate/p' $tempdir/status.txt  | grep -E "s:|i:" | sed '/1 s:C/{x;p;x}' |
sed '/2 s:C/{x;p;x}' | sed 's/0 s:C/0\n s:C/' | sed 's/1 s:C/1\n s:C/' | sed 's/2 s:C/2\n s:C/' | sed 's/3 s:C/3\n s:C/' | sed 's/^ *//' |
sed 's/^0 / 0 /' | sed 's/^1 / 1 /' | sed 's/^2 / 2 /' ; echo '' ; fi ; fi
}
function f_testSSL {
local s="$*"
if ! [ $option_testSSL = "9" ] ; then
declare -a ssl_array=() ; ssl_array+=(--phone-out --quiet --color 0 -S -s -p) ; f_Long; echo "[+] $x  [TESTSSL]"
if [ $option_testSSL = "1" ] ; then
ssl_array+=(--sneaky) ; testssl ${ssl_array[@]} ${s} > $tempdir/testtls
grep -E -i "Start|Common Name|Issuer|trust|certificates provided|In pwnedkeys.com|Certificate Revocation List|OCSP URI|Certificate Transparency" $tempdir/testtls |
sed '/Start/i \\n\n---------------------------' | sed '/Start/a \---------------------------\n' | sed '/Issuer/G' | sed '/In pwnedkeys.com/{x;p;x;}' | sed 's/^ *//'
elif [ $option_testSSL = "2" ] ; then
ssl_array+=(-H -T -C -R -Z --ids-friendly) ; testssl ${ssl_array[@]} ${s} > $tempdir/testtls
awk '{ IGNORECASE=1 } /Common Name|Issuer|Start|NULL|Triple DES|Strong|Trust|In pwnedkeys.com DB|Certificate Revocation|OCSP|Transparency|Session Resumption|key usage|extended key usage|SSLv2|SSLv3|TLS 1|offered|Heartbleed|Ticketbleed|CRIME|Clock skew|Renegotiation|certificates provided/  { print }' $tempdir/testtls | sed '/Start/G' |
sed '/TLS extensions/d' | sed '/Heartbleed/i \\n---------------------------------------------------------\n' |  sed '/clock skew/G' |
sed '/Common Name (CN) /i \\n---------------------------------------------------------\n' | sed '/Start/i \\n---------------------------' |
sed '/Issuer/a \\n---------------------------------------------------------\n' | sed '/Start/a \---------------------------\n' |
sed '/no encryption/i \\n---------------------------------------------------------\n' | sed '/OCSP URI /{x;p;x;}' |
sed '/Session Resumption/i \\n---------------------------------------------------------\n' | sed 's/^ *//' |
sed '/In pwnedkeys.com DB /i \\n---------------------------------------------------------\n' | sed 's/TLSv1.2:/\nTLSv1.2:\n/' | sed 's/TLSv1.3:/\nTLSv1.3:\n/' |
sed 's/^ *//' | fmt -w 100 -s ; else
ssl_array+=(-P -B -T -R -Z -C -H -c --ids-friendly) ; testssl ${ssl_array[@]} ${s} > $tempdir/testtls
awk '{ IGNORECASE=1 } /Common Name|Issuer|Certificate Validity|NULL|Triple DES|Strong|Trust|In pwnedkeys.com DB|Certificate Revocation|OCSP|Transparency|Start|Session Resumption|Server key|Server extended key|SSLv2|SSLv3|TLS 1|offered|TLS 1.2|TLS 1.3|TLSv1.2|TLSv1.3|Heartbleed|Ticketbleed|CRIME|RSA|Negotiated|AES|Signature Algorithm|Clock skew|Renegotiation|DHE|certificates provided/  { print }' $tempdir/testtls | sed '/Start/{x;p;x;G}' | sed '/Issuer/a \\n---------------------------------------------------------\n' |
sed '/Heartbleed/i \\n---------------------------------------------------------\n' | sed '/cipher order/i \\n---------------------------------------------------------\n' |
sed '/no encryption/i \\n---------------------------------------------------------\n' | sed '/Start/i \\n---------------------------' | sed '/TLS extensions/d' |
sed '/Start/a \---------------------------\n' | sed '/TLS_FALLBACK/a \\n---------------------------------------------------------\n' | sed 's/TLSv1.1:/\nTLSv1.1:\n/' |
sed '/Common Name (CN) /i \\n---------------------------------------------------------\n' | sed 's/TLSv1.2:/\nTLSv1.2:\n/' | sed 's/TLSv1.3:/\nTLSv1.3:\n/' | sed 's/^ *//' |
sed '/In pwnedkeys.com DB /i \\n---------------------------------------------------------\n' | sed '/clock skew/G' |
sed '/Session Resumption/i \\n---------------------------------------------------------\n' |
sed '/Negotiated cipher/a \\n---------------------------------------------------------\n' | sed 's/^ *//' | fmt -w 100 -s ; fi ; fi ; echo ''
}
function f_certMX {
local s="$*"
echo | timeout 3 openssl s_client -connect ${s}:25 -starttls smtp -status 2>/dev/null > $tempdir/status.txt
echo | timeout 3 openssl s_client -connect ${s}:25 -starttls smtp 2>/dev/null | openssl x509 -noout -dates -issuer -subject | sed 's/ = /=/g' > $tempdir/x509.txt
exp=$(grep 'notAfter=' $tempdir/x509.txt | cut -s -d ':' -f 2- | head -1 | sed 's/^ *//')
if [ -z "$exp" ]; then
echo | timeout 3 openssl s_client -connect ${s}:587 -starttls smtp -status 2>/dev/null > $tempdir/status.txt
echo | timeout 3 openssl s_client -connect ${s}:587 -starttls smtp 2>/dev/null | openssl x509 -noout -dates -issuer -subject | sed 's/ = /=/g' > $tempdir/x509.txt
fi ; f_Short ; echo -e "* CERTIFICATE [$s] \n\n"
exp=$(grep 'notAfter=' $tempdir/x509.txt | cut -s -d '=' -f 2- | head -1 | sed 's/^ *//')
cipher=`sed -n '/END CERTIFICATE/,$p' $tempdir/status.txt | grep 'Cipher is' | rev | cut -d ' ' -f 1 | rev`
protocol=`sed -n '/END CERTIFICATE/,$p' $tempdir/status.txt | grep 'Cipher is' | grep -E -o "(SSLv[23]|TLSv1(\.[0-3])?)"`
verify=`sed -n '/END CERTIFICATE/,$p' $tempdir/status.txt | grep 'Verification' $tempdir/status.txt | cut -d ':' -f 2- | sed 's/^ *//'`
s_cn=$(sed -n '/subject=/,/issuer=/p' $tempdir/x509.txt | grep 'commonName' | cut -d '=' -f 2- | sed 's/^ *//')
s_c=$(sed -n '/subject=/,/issuer=/p' $tempdir/x509.txt | grep 'countryName' | tr -d ' ' | sed 's/countryName=/| C: /')
s_org=$(sed -n '/subject=/,/issuer=/p' $tempdir/x509.txt | grep 'organizationName' | tr -d ' ' | sed 's/organizationName=/| Org: /')
ca_cn=$(sed -n '/issuer=/,$p' $tempdir/x509.txt | grep 'commonName' | tr -d ' ' | sed 's/commonName=/CN: /')
ca_c=$(sed -n '/issuer=/,$p' $tempdir/x509.txt | grep 'countryName' | tr -d ' ' | sed 's/countryName=/| C: /')
ca_org=$(sed -n '/issuer=/,$p' $tempdir/x509.txt | grep 'organizationName' | tr -d ' ' | sed 's/organizationName=/| Org: /')
sub_cn=`grep -E -i "^subject=" $tempdir/x509.txt | awk '{print $0","}' | grep -s -oP '(CN=).*?(?=,)' | sed 's/CN=//'`
sub_org=`grep -E -i "^subject=" $tempdir/x509.txt | awk '{print $0","}' | grep -s -oP '(O=).*?(?=,)' | sed 's/O=/| /'`
sub_cc=`grep -E -i "^subject=" $tempdir/x509.txt | awk '{print $0","}' | grep -s -oP '(C=).*?(?=,)' | sed 's/C=/| /'`
ca_cn=`grep -E -i "^issuer=" $tempdir/x509.txt | awk '{print $0","}' | grep -s -oP '(CN=).*?(?=,)' | sed 's/CN=//'`
ca_org=`grep -E -i "^issuer=" $tempdir/x509.txt | awk '{print $0","}' | grep -s -oP '(O=).*?(?=,)' | sed 's/O=/| /'`
ca_cc=`grep -E -i "^issuer=" $tempdir/x509.txt | awk '{print $0","}' | grep -s -oP '(C=).*?(?=,)' | sed 's/C=/| /'`
echo -e "Status:      $verify" ; echo -e "Expires:     $exp"
echo -e "\nSubject:     $sub_cn $sub_org $sub_cc" ; echo -e "Issuer:      $ca_cn $ca_org $ca_cc"
echo -e "\nCipher:      $cipher | $protocol\n"
}
#*****************  WHOIS, NETWORKS & AS *****************
function f_DRWHO {
local s="$*" ; net=`echo $s | cut -d '/' -f 1`
if [[ ${net} =~ $REGEX_IP4 ]] ; then
rir=$(curl -s "https://stat.ripe.net/data/rir/data.json?resource=${s}" | jq -r '.data.rirs[0].rir' | cut -d ' ' -f 1 | tr -d ' ' | tr [:upper:] [:lower:]) ; else
curl -s https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${s} > $tempdir/ac.json
rir=`jq -r '.data.authorities[0]' $tempdir/ac.json` ; fi
if [ $rir = "arin" ] ; then
whois -h whois.arin.net $s > $tempdir/whois.txt
elif [ $rir = "lacnic" ] ; then
whois -h whois.lacnic.net $s > $tempdir/whois.txt ; else
whois -h whois.$rir.net -- "-B $s" > $tempdir/whois.txt ; fi
if [[ ${net} =~ $REGEX_IP4 ]] ; then
reverse=$(echo ${net} | awk -F'.' '{print $4 "." $3 "." $2 "." $1}')
dig +short $reverse.origin.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/cym
prfx=`head -1 $tempdir/cym | awk -F'|' '{print $2}' | tr -d ' '` ; fi
if ! [[ ${net} =~ $REGEX_IP4 ]] ; then
whois -h whois.cymru.com -- "-v -f ${s}" | tail -1 > $tempdir/cym
prfx=`awk -F'|' '{print $3}' $tempdir/cym | head -1 | tr -d ' '` ; fi
as=`head -1 $tempdir/cym | awk -F'|' '{print $1}' | tr -d ' '`
netn=`grep -s -a -i -E -m 1 "^netname:|^na:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
abu=`grep -s -a -E "^OrgAbuseEmail:|^abuse-c:|^% Abuse|^abuse-mailbox:" $tempdir/whois.txt |
grep -s -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b"`
org=`grep -s -a -i -E -m 1 "^organization:|^org-name:|^owner:|^descr:|^og:|^de:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
nrange=`grep -s -a -m 1 -E -i "^netrange:^|^inetnum:|^inet6num:|^in:|^i6:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
whois_cc=`grep -E -i -a -m 1 "^country:|^cy:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt |
sort -f -u > $tempdir/whois_contacts.txt
if [ $rir = "arin" ] ; then
cidr=`grep -s -m 1 -E -i "^CIDR:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'` ; fi
if ! [ $rir = "arin" ] || ! [ $rir = "lacnic" ] ; then
grep -s -w 'abuse-c:' $tempdir/whois.txt  | tr ':' ';'  | tr -d ' ' > $tempdir/handles.txt
grep -s -w 'admin-c:' $tempdir/whois.txt | tr ':' ';' | tr -d ' ' >> $tempdir/handles.txt
grep -s -w 'mnt-by:' $tempdir/whois.txt | tr ':' ';' | tr -d ' ' >> $tempdir/handles.txt
grep -s -w 'org:' $tempdir/whois.txt | tr ':' ';'  | tr -d ' ' >> $tempdir/handles.txt
grep -s -w 'tech-c:' $tempdir/whois.txt | tr ':' ';' | tr -d ' ' >> $tempdir/handles.txt
echo -e "[+] $rir Object Handles\n" > $tempdir/rirhandles.txt ; sort -u -b $tempdir/handles.txt >> $tempdir/rirhandles.txt ; fi
echo '' >  $tempdir/revwhois_temp.txt ; f_Long >> $tempdir/revwhois_temp.txt
echo -e "[+] $s WHOIS | whois.$rir.net" >> $tempdir/revwhois_temp.txt
f_Long >> $tempdir/revwhois_temp.txt
if [ $rir = "arin" ] ; then
sed -e '/./{H;$!d;}' -e 'x;/NetRange:/!d' $tempdir/whois.txt > $tempdir/rwhois_temp.txt
echo -e "________________________________________\n"  >> $tempdir/rwhois_temp.txt
sed -e '/./{H;$!d;}' -e 'x;/OrgName:/!d' $tempdir/whois.txt >> $tempdir/rwhois_temp.txt
sed -e '/./{H;$!d;}' -e 'x;/OrgAbuseHandle:/!d' $tempdir/whois.txt |
sed '/OrgAbuseHandle:/i \________________________________________\n' >> $tempdir/rwhois_temp.txt
sed -e '/./{H;$!d;}' -e 'x;/OrgTechHandle:/!d' $tempdir/whois.txt |
sed '/OrgTechHandle:/i \________________________________________\n' >> $tempdir/rwhois_temp.txt
cat $tempdir/rwhois_temp.txt | sed '/Comment:/d' | sed '/OrgAbuseRef:/d' |
sed '/OrgTechRef:/d' >> $tempdir/revwhois_temp.txt
elif [ $rir = "lacnic" ] ; then
sed '/%/d' $tempdir/whois.txt  | sed '/inetrev:/i \________________________________________\n' |
sed '/changed:/i \________________________________________\n' >> $tempdir/revwhois_temp.txt ; else
sed -e '/./{H;$!d;}' -e 'x;/inetnum:/!d' $tempdir/whois.txt | sed '/remarks:/d' | sed '/^#/d' | sed '/^%/d' | sed '/^$/d'  >> $tempdir/rwhois_temp.txt
sed -e '/./{H;$!d;}' -e 'x;/inet6num:/!d' $tempdir/whois.txt | sed '/remarks:/d' | sed '/^#/d' | sed '/^%/d' | sed '/^$/d'  >> $tempdir/rwhois_temp.txt
sed -e '/./{H;$!d;}' -e 'x;/organisation:/!d' $tempdir/whois.txt | sed '/created:/d' | sed '/source/d' | sed '/remarks:/d' | sed '/^$/d' |
sed '/organisation:/i \_____________________\n' | sed '/^#/d' >> $tempdir/rwhois_temp.txt
sed -e '/./{H;$!d;}' -e 'x;/role/!d' $tempdir/whois.txt | sed '/created:/d' | sed '/source:/d' | sed '/remarks:/d' | sed '/^$/d' |
sed '/role:/i \____________________________________\n' | sed '/^#/d' >> $tempdir/rwhois_temp.txt
sed -e '/./{H;$!d;}' -e 'x;/person/!d' $tempdir/whois.txt |  sed '/created:/d' | sed '/source/d' | sed '/remarks:/d' | sed '/^$/d' |
sed '/person:/i \____________________________________\n' | sed '/^#/d' | sed '/^#/d' >> $tempdir/rwhois_temp.txt
sed -e '/./{H;$!d;}' -e 'x;/route/!d' $tempdir/whois.txt | sed '/remarks:/d' | sed '/^$/d' |
sed '/route:/i \____________________________________\n' | sed '/^#/d' | sed '/^#/d' >> $tempdir/rwhois_temp.txt
cat $tempdir/rwhois_temp.txt | sed '/notify:/d' | sed '/phone:/d' | sed '/fax:/d' | sed '/mnt-by/d' |
sed '/admin-c/d' | sed '/tech-c/d' | sed '/abuse-c:/d' | sed '/^mnt-ref:/d' | sed '/^mnt-routes:/d' | sed '/nic-hdl:/d' |
sed '/^mnt-domains:/d' >> $tempdir/revwhois_temp.txt ; fi
echo -e "____________________________________\n" >> $tempdir/revwhois_temp.txt
echo -e "[+] Contacts\n" >> $tempdir/revwhois_temp.txt ; cat $tempdir/whois_contacts.txt >> $tempdir/revwhois_temp.txt
if ! [ $rir = "arin" ] || ! [ $rir = "lacnic" ]; then
echo -e "____________________________________\n" >> $tempdir/revwhois_temp.txt
cat $tempdir/rirhandles.txt >> $tempdir/revwhois_temp.txt ; fi
export rir ; export as ; export org ; export netn ; export nrange ; export abu ; export whois_cc
}
function f_AS_SUMMARY {
local s="$*"
dig +short as$s.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/cyas
reg=`head -1 $tempdir/cyas | awk -F'|' '{print $3}' | tr -d ' ' | sed 's/ripencc/ripe/'`
asnum=`head -1 $tempdir/cyas | awk -F'|' '{print $1}' | tr -d ' ' | sed 's/ripencc/ripe/'`
asname=`cut -d '|' -f 5 $tempdir/cyas | sed 's/^[ \t]*//;s/[ \t]*$//'`
if [ $reg = "arin" ] ; then
whois -h whois.arin.net a $s > $tempdir/AS.txt
asabuse_c=`grep -s -m1 'OrgAbuseEmail:' $tempdir/AS.txt | grep -s -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b"`
elif [ $reg = "lacnic" ] ; then
whois -h whois.lacnic.net AS${s} > $tempdir/lacnic_as.txt
abusecon=`grep -s '^abuse-c:' $tempdir/lacnic_as.txt | cut -d ':' -f 2- | tr -d ' '`
asabuse_c=`grep -s -A 4 ${abusecon} $tempdir/lacnic_as.txt | grep -s -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b"` ; else
asabuse_c=`whois -h whois.$reg.net -- "-b as${s}" | grep -s -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b"` ; fi
curl -s "https://stat.ripe.net/data/as-overview/data.json?resource=AS${s}" > $tempdir/asov.json
f_Short ; echo -e "* AS $s\n" ; echo "Name:        $asname"
echo "BGP:         announced: $(jq -r '.data.announced' $tempdir/asov.json)"
echo "RIR:         $(echo $reg | tr [:lower:] [:upper:])"
if [ -f $tempdir/iscip.json ] ; then
echo -e "Size:        $(jq -r '.ip.assize' $tempdir/iscip.json)" ; fi
echo "ORG:         $(jq -r '.data.holder' $tempdir/asov.json) | $asabuse_c  "
}
function f_asINFO {
echo '' ; curl -s https://api.bgpview.io/asn/${asnum} > $tempdir/asn.json
curl -s "https://stat.ripe.net/data/as-overview/data.json?resource=AS${asnum}" > $tempdir/asov.json
announced=`jq -r '.data.announced' $tempdir/asov.json`
curl -s "https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS${asnum}"  > $tempdir/nb.json
traffic=`jq -r '.data.traffic_estimation' $tempdir/asn.json | sed 's/null/-/'`
ratio=`jq -r '.data.traffic_ratio'  $tempdir/asn.json | sed 's/null/-/'`
as_name=`cat "$tempdir/cy_asn" | cut -d '|' -f 5 | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//'`
echo -e "As Num:          $asnum"
echo -e "AS Name:         $as_name\n"
echo -e "Description:     $(jq -r '.data.description_full[]' $tempdir/asn.json)"
echo -e "Holder:          $(jq -r '.data.holder' $tempdir/asov.json)\n"
echo -e "Announced:       $(jq -r '.data.announced' $tempdir/asov.json)"
echo -e "LookingGl:       $(jq -r '.data.looking_glass'  $tempdir/asn.json)"
echo -e "Website:         $(jq -r '.data.website'  $tempdir/asn.json)"
curl -s "https://stat.ripe.net/data/ris-prefixes/data.json?resource=${asnum}" > $tempdir/rispfx.json
f_Short ; echo -e "* AS Contact\n" ; jq -r '.data.owner_address[]' $tempdir/asn.json
echo '' ; jq -r '.data.email_contacts[]' $tempdir/asn.json
f_Short ; echo -e "* Traffic\n" ; echo -e "$ratio  $traffic"
echo -e "\n* Prefix Count (IPv4)\n" ; jq -r '.data.counts.v4' $tempdir/rispfx.json | tr -d '}",{' | sed 's/^ *//' | sed '/^$/d'
echo -e "\n* Prefix Count (IPv6)\n" ; jq -r '.data.counts.v6' $tempdir/rispfx.json | tr -d '}",{' | sed 's/^ *//' | sed '/^$/d'
if [ $option_as_details = "y" ] ; then
f_Long ; echo -e "[*] IX Memberships\n"
curl -s https://api.bgpview.io/asn/${asnum}/ixs | jq | sed -n '/data/,/@meta/{/data/!{/@meta/!p;}}' |
tr -d ',[{"}]' | sed 's/^ *//' | sed 's/name_full/full name/' | sed 's/country_code:/country:/'
f_Long ; echo -e "* Prefixes\n"
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS$asnum" > $tempdir/prefixes.json
echo -e "\n -- IPv6 --\n"
jq -r '.data.prefixes[] | .prefix' $tempdir/prefixes.json | grep -E "*.:.*" | sort -V | tr '[:space:]' ' ' | fmt -w 40 -s ; echo ''
echo -e "\n -- IPv4 --\n"
jq -r '.data.prefixes[] | .prefix' $tempdir/prefixes.json | grep -E -v "*.:.*" | sort -V | tr '[:space:]' ' ' | fmt -w 40 -s ; fi
}
function f_SIPcalc {
local s="$*"
if ! type sipcalc &> /dev/null; then
echo -e "${R}Please install sipcalc" ; else
echo '' ; sipcalc ${s} > $tempdir/scalc.txt
atype=`grep -s -w 'Address type' $tempdir/scalc.txt | cut -d '-' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//'`
exp=`grep -s -w 'Expanded Address' $tempdir/scalc.txt | cut -d '-' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//'`
compr=`grep -s -w 'Compressed address' $tempdir/scalc.txt | cut -d '-' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//'`
spref=`grep -s -w 'Subnet prefix' $tempdir/scalc.txt | cut -d '-' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//'`
echo "$s" > $tempdir/v6list
echo -e "Type         -  $atype" ; echo -e "Compressed   -  $compr"
echo -e "Expanded     -  $exp\n" ; echo -e "Sub. Prefix  -  $spref"
if [ $type_net = "false" ] ; then
echo -e "Net-Portion  -  $(/usr/bin/atk6-extract_networks6 $tempdir/v6list)"
echo -e "Host-Portion -  $(/usr/bin/atk6-extract_hosts6 $tempdir/v6list)"
echo -e "\n\n[+] Encoded MAC /IPv4\n" ; atk6-address6 ${s} ; fi ; fi
}
function f_netINFO {
local s="$*"
net=`echo "$s" | cut -d '/' -f 1` ; echo '' ; f_Long
if [[ ${net} =~ $REGEX_IP4 ]] ; then
if [ $type_net = "true" ] ; then
hosts=`ipcalc -b -n ${s} | grep -s -E "^Hosts/Net" | cut -d ':' -f 2 | sed 's/Class.*//' | tr -d ' '`
echo "NET | $s | $netn | $hosts Hosts" ; else
echo "NET | $netn | $nrange" ; fi ; fi
if ! [[ ${net} =~ $REGEX_IP4 ]] ; then
if [ $type_net = "false" ] ; then
inet6num=`grep -s -m 1 -E -i "^inet6num|^CIDR:|^i6:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
echo "NET | $inet6num  | $netn  |  $rir " ; else
echo "NET | $s  | $netn  | $rir  | AS $as" ; fi ; fi ; f_Long
echo "[@]: $abu" ; echo -e "____\n"
if [[ ${net} =~ $REGEX_IP4 ]] && [ $rir = "arin" ] ; then
echo -e "CIDR:        $cidr" ; fi
created=`grep -E -i -m 1 "^created:|RegDate:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
echo -e "NET:         $netn | $whois_cc | CREATED: $created" ; echo -e "\nORG:         $org"
f_PREFIX "${s}" ; echo ''
for a in $(cat $tempdir/asnums1.list | sort -u -g) ; do
f_AS_SUMMARY "${a}" ; done ; rm $tempdir/asnums1.list ; f_Short ; echo -e "* Network Contacts"
if [ $rir = "arin" ] ; then
grep -E "^OrgName:|^OrgId:|^Address:|^City:|Country:|^OrgAbuseName:|^OrgAbusePhone:|^OrgAbuseEmail:|^AbusePhone:|^AbuseName:|^AbuseEmail:|OrgTechName:|OrgTechPhone:|OrgTechEmail:|TechName:|TechPhone:|TechEmail:" $tempdir/whois.txt | sed '/OrgName/{x;p;x}' | sed '/OrgAbuseName:/{x;p;x;}' | sed '/OrgTechName:/{x;p;x;}'  | cut -d ':' -f 2- | sed 's/^ *//'
elif [ $rir = "lacnic" ] ; then
grep -s -E -m 1 -C 1 "^person:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' ; else
if [[ $(grep -s -w -c '^inetnum:' $tempdir/whois.txt ) -gt "0" ]] ; then
inet_p=`sed -n 'H; /^inetnum:/h; ${g;p;}' $tempdir/whois.txt | sed -n '/organisation:/,/source:/p'` ; else
inet_p=`sed -n 'H; /^inet6num:/h; ${g;p;}' $tempdir/whois.txt | sed -n '/organisation:/,/source:/p'` ; fi
if [[ $(echo "$inet_p" | grep -s -w -c '^descr:' ) -gt "0" ]] ; then
echo -e "\n* Description" ; echo "$inet_p" | grep "^descr:" | cut -d ':' -f 2- | sed 's/^ *//' ; fi
if [[ $(grep -s -w -c '^org-name:' $tempdir/whois.txt ) -gt "0" ]] ; then
echo -e "\n* Organisation" ; sed -e '/./{H;$!d;}' -e 'x;/organisation:/!d' $tempdir/whois.txt | grep -E -a -s "^org-name:|^address:|^e-mail:" |
sed '/org-name:/{x;p;x;}' | cut -d ':' -f 2- | sed 's/^ *//' ; fi
if [[ $(grep -s -w -c '^person:' $tempdir/whois.txt ) -gt "0" ]] ; then
echo -e "\n* Person" ; sed -e '/./{H;$!d;}' -e 'x;/person:/!d' $tempdir/whois.txt | grep -E -a -s "^person:|^e-mail:|^phone:|^address:|^nic-hdl" |
sed '/^$/d' | sed '/person:/{x;p;x;}' | cut -d ':' -f 2- | sed 's/^ *//' ; fi
if [[ $(grep -s -w -c '^person:' $tempdir/whois.txt ) -gt "0" ]] ; then
echo -e "\n* Role" ; sed -e '/./{H;$!d;}' -e 'x;/role:/!d' $tempdir/whois.txt | grep -E -a -s "^role:|^e-mail:|^phone:|^address:|^nic-hdl" |
sed '/^$/d' | sed '/role:/{x;p;x;}' | cut -d ':' -f 2- | sed 's/^ *//' ; fi
f_Shorter ; grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt | sort -u
grep -E "^organisation:|^mnt-by:" $tempdir/whois.txt | sed '/RIPE-NCC-*/d' | sed 's/organisation:/org:/' |  tr ':' ';'  | tr -d ' ' | sort -u -V
grep "^admin-c" $tempdir/whois.txt  | tr ':' ';' | tr -d ' ' | sort -u -V ; fi ; echo ''
}
function f_NETshort {
local s="$*" ; echo '' ; net=`echo "$s" | cut -d '/' -f 1`
curl -s https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${s} > $tempdir/ac.json
reg=`jq -r '.data.authorities[0]' $tempdir/ac.json`
whois -h whois.pwhois.org type=all $s > $tempdir/pwho
if [ $reg = "ripe" ] ; then
echo "$s" >> $tempdir/addresses_ripe.list
less_sp=`jq -r '.data.less_specifics[0]' $tempdir/ac.json | head -1` ; fi
netname=`grep -w "^Net-Name:" $tempdir/pwho | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//'`
if [ -n "$netname" ] ; then
orgname=`grep -w -m 1 "^Org-Name:" $tempdir/pwho | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//'`
netrange=`grep -w "^Net-Range:" $tempdir/pwho | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//'`
if [ "$netname" = "$orgname" ] ; then
organ=`grep "^AS-Org-Name:"  $tempdir/pwho | cut -d ' ' -f 2- | sed 's/^ *//' | tail -1` ; else
organ="$orgname" ; fi
created=`grep -w "^Create-Date:" $tempdir/pwho | cut -d ' ' -f 2- | cut -d ' ' -f -3 | sed 's/^ *//'`
whois_cc=`grep -w "^Country:" $tempdir/pwho | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tail -1` ; else
whois -h whois.$reg.net ${s} > $tempdir/whois
netrange=$(grep -E -m 1 "^inetnum:|^in:|^inet6num:|^i6:|^CIDR:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//')
netname=$(grep -E -i -m 1 "^netname:|^na:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//')
orgname=$(grep -i -E -m 1 "^organization:|^orgname:|^org-name:|^owner:|^descr:|^de:|^og:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//')
created=$(grep -E -i -m 1 "^created:|^cr:|RegDate:" $tempdir/whois | cut -d ':' -f 2- | cut -d '-' -f 1 | sed 's/^ *//' | sed 's/1970//')
whois_cc=`grep -E -i "^country:|^cy:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//'` ; fi
echo "$netrange" | grep -v '/'>> $tempdir/netranges.list
f_Long ; echo "NET | $netname:  $netrange" ; f_Long ; f_abxHEADER "${net}"
if [ $reg = "ripe" ] ; then
echo -e "NET:         $less_sp | $whois_cc | created: $created" ; else
echo -e "NET:         $netname | $whois_cc | created: $created" ; fi
echo -e "\nORG:         $organ"
f_PREFIX "${s}"
if [ $reg = "arin" ] || [ $reg = "lacnic" ] ; then
echo "$netrange" | grep '/' >> $tempdir/nets.list ; fi
if [ $reg = "ripe" ] && [[ ${net} =~ $REGEX_IP4 ]] ; then
echo "$less_sp" | grep '/' >> $tempdir/nets.list
ucelist=$(jq -r '.data.blocklist_info[] | .list' $tempdir/ac.json)
if [ -n "$ucelist" ] ; then
echo -e "\n\nuceprotect Listings\n____________________\n" ; jq -r '.data.blocklist_info[] | .list, .entries' $tempdir/ac.json ; fi ; fi
}
function f_ARIN_ORG {
local s="$*"
whois -h whois.arin.net -- "o + $s" > $tempdir/arin_org.txt
org_name=`cat $tempdir/arin_org.txt | grep -s -E "^OrgName:" | cut -d ':' -f 2- | sed 's/^ *//'`
org_id=`cat $tempdir/arin_org.txt | grep -s -E "^OrgID:" | cut -d ':' -f 2- | sed 's/^ *//'`
grep -s -E -m 2 "^OrgName:|OrgId:" $tempdir/arin_org.txt | cut -d ':' -f 2- | sed 's/^ *//' ; echo ''
grep -s -E "^Address:" $tempdir/arin_org.txt | cut -d ':' -f 2- | sed 's/^ *//'
arin_city=`grep -s -E  -m 1 "^City:" $tempdir/arin_org.txt | cut -d ':' -f 2- | sed 's/^ *//'`
arin_state=`grep -s -E  -m 1 "^StateProv:" $tempdir/arin_org.txt | cut -d ':' -f 2- | sed 's/^ *//'`
arin_zip=`grep -s -E  -m 1 "^PostalCode:" $tempdir/arin_org.txt | cut -d ':' -f 2- | sed 's/^ *//'`
arin_country=`grep -s -E  -m 1 "^Country:" $tempdir/arin_org.txt | cut -d ':' -f 2- | sed 's/^ *//'`
echo "$arin_state- $arin_zip" ; echo "$arin_city, $arin_country"
echo -e "\nRegDate: $(grep -s 'RegDate:' $tempdir/arin_org.txt  | cut -d ':' -f 2- | sed 's/^ *//')"
echo -e "Updated: $(grep -s -w -m 1 'Updated:' $tempdir/arin_org.txt  | cut -d ':' -f 2- | sed 's/^ *//')"
f_Shorter ; cat $tempdir/arin_org.txt |
grep -s -i -E "^AbuseName:|^AbusePhone:|^AbuseEmail:|^Org(AbuseName:|AbusePhone:|AbuseEmail:)" |
cut -d ':' -f 2- | sed 's/^ *//' ; echo ''
cat $tempdir/arin_org.txt |
grep -s -i -E "^TechName:|^TechPhone:|^TechEmail:|^Org(TechName:|TechPhone:|TechEmail:)" |
cut -d ':' -f 2- | sed 's/^ *//'
}
function f_whoisLOOKUP {
local s="$*" ; timeout 5 whois ${s} > $tempdir/whois_lookup.txt
cat $tempdir/whois_lookup.txt | sed '/^#/d' | sed '/^%/d' | sed '/icann.org/d' | sed '/NOTICE/d' |
sed '/reflect/d' | sed '/Fax:/d' |sed '/Fax Ext:/d' | sed '/unsolicited/d' | sed '/HKIRC-Accredited/d' |
sed '/how to/d' | sed '/queried/d' | sed '/Bundled/d' | sed '/Registry Domain ID:/d' | sed 's/^[ \t]*//' |
sed '/^$/d' > $tempdir/host-whois.txt
grep -s -w -i -A 1 -m 1 "domain name:" $tempdir/host-whois.txt> $tempdir/whois2.txt
grep -s -w -i "Domain:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i "Registry Domain ID:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -m 1 -A 1 "Registrar:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w "Nserver:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i -s "Status:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i -s "Domain Status:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i -s "Updated Date:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i -s "Creation Date:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -s "Changed:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w "Company Chinese name:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -m 1 "Registrar URL:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -m 1 "Registrar Abuse Contact"  $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w "Registry Creation Date:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -s "Last Modified:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -s -i "Expiry" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -m 1 "registrar:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -m 1 "e-mail:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -m 1 "website:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w -i -A 8 "nic-hdl:" $tempdir/host-whois.txt  >> $tempdir/whois2.txt
grep -s -s -w -i -m 1 "Organization:" $tempdir/host-whois.txt | sed '/Organization:/{x;p;x;}' >> $tempdir/whois2.txt
grep -s -s -w -i -m 1 "Registrant Name:" $tempdir/host-whois.txt | sed '/Registrant Name:/{x;p;x;}' >> $tempdir/whois2.txt
grep -s -s -w -i -m 1 "Country:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -s -w -i -m 1 "State/Province" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -s -w -i -m 1 "Address:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -s -w -i -m 1 "Registrant Street:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -s -w -i -m 1 "Registrant City:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -s -w -i -m 1 "Registrant Postal Code:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -s -w -i -m 1 "Registrant Phone:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -s -w -i -m 1 "Registrant Email:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -s -w -B 1 -A 16 "ADMINISTRATIVE" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -s -w "Registrant:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -s -w -i "Eligibility Type:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -w "Name Server:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -s -w -i "dnssec:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
grep -s -s -w -i -m 1 "source:" $tempdir/host-whois.txt >> $tempdir/whois2.txt
cat $tempdir/whois2.txt | sed '$!N; /^\(.*\)\n\1$/!P; D' | sed 's/nic-hdl:/\nnic-hdl:/' |
sed 's/Registrant:/\nRegistrant:/' | sed 's/Administrative/\nAdministrative/' |
sed 's/Technical/\nTechnical/' | fmt -w 80 -s > $tempdir/whois3.txt
}
function f_address_spaceWHOIS {
local s="$*" ; net=`echo "$s" | cut -d '/' -f 1`
if [[ ${net} =~ $REGEX_IP4 ]] ; then
reg=$(curl -s "https://stat.ripe.net/data/rir/data.json?resource=${s}" | jq -r '.data.rirs[0].rir' | cut -d ' ' -f 1 | tr -d ' ' | tr [:upper:] [:lower:])
else
curl -s https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${s} > $tempdir/ac.json
reg=`jq -r '.data.authorities[0]' $tempdir/ac.json` ; fi
if ! [ $reg = "arin" ] && ! [ $reg = "lacnic" ] ; then
whois -h whois.$reg.net -- "-r $s" > $tempdir/exact
cat $tempdir/exact |
grep -i -E "^inetnum:|^inet6num:|^cidr:|^netname:|^orgname:|^org-name:|^owner:|^descr:|^country:" | sed '/inetnum:/G' | sed '/inet6num:/G' |
cut -d ':' -f 2- | sed 's/^ *//' ; echo ''
whois -h whois.$reg.net -- "-r -F -M $s" | tr -d '%*' | sed 's/^ *//' > $tempdir/whois | grep -E -a  "^in:|^i6:|^na:" > $tempdir/whois
if [ $option_filter = "y" ] ; then
for f in $(cat $tempdir/filters) ; do
echo '' ; f_Short ; echo -e "More Specifcs | FILTER: $f" ; f_Short
cat $tempdir/whois | grep -E -a  "^in:|^i6:|^na:" |
grep -s -a -i -E -B 1 "${f}|*.${f}.*|${f}NET|*.-${f}.-*|${f}-.*|*-.${f}|${f}AS" > $tempdir/whois_filtered
cat $tempdir/whois_filtered | sed '/^$/d' | sed '/in:/{x;p;x;}' | sed '/i6:/{x;p;x;}' | sed '/--/d' | cut -d ' ' -f 2- | sed 's/^ *//'
f_Short ; echo -e "* CIDR\n"
grep -E -i "^i6:" $tempdir/whois_filtered | cut -d ' ' -f 2- | tr -d ' ' | fmt -s -w 20
for i in $(cat $tempdir/whois_filtered | grep "^in:" | grep -E "\-" | cut -d ' ' -f 2- | tr -d ' ') ; do
ipcalc ${i} | sed '/deaggregate/d' ; done ; echo '' ; done ; else
echo '' ; f_Short ; echo -e "More Specifcs" ; f_Short ; echo ''
cat $tempdir/whois | grep -E -a "^in:|^i6:|^na:|^de:|^og:|^or:|^rt:|^r6:|^ac:|^cy:" | sed '/in:/G' | sed '/i6:/G' | 
sed '/in:/i \___________________________________________________________\n' | sed '/i6:/i \___________________________________________________________\n' |
sed '/rt:/i \___________________________________________________________\n' | sed '/r6:/i \___________________________________________________________\n' | 
sed '/--/d' | cut -d ' ' -f 2- | sed 's/^ *//'
f_Short ; echo -e "* CIDR\n"
grep -E -i "^i6:" $tempdir/whois | cut -d ' ' -f 2- | tr -d ' ' | fmt -s -w 20
for i in $(cat $tempdir/whois| grep "^in:" | grep -E "\-" | cut -d ':' -f 2- | tr -d ' ') ; do
ipcalc "${i}" | sed '/deaggregate/d' | tail -1 ; done ; echo '' ; fi ; else 
echo -e "\nNO SUPPORT FOR ARIN & LACNIC FOR NOW\n" ; fi 
}
function f_whoisCONTACTS {
local s="$*" ; net=`echo $s | cut -d '/' -f 1`
whois -h whois.cymru.com -- "-v -t ${s}" > $tempdir/cymru.txt
if [[ ${net} =~ $REGEX_IP4 ]] ; then
regis=$(curl -s "https://stat.ripe.net/data/rir/data.json?resource=${s}" | jq -r '.data.rirs[0].rir' | cut -d ' ' -f 1 | tr -d ' ' | tr [:upper:] [:lower:])
else
regis=`tail -1 $tempdir/cymru.txt | awk -F'|' '{print $5}' $tempdir/cym | sed 's/ripencc/ripe/'` ; fi
if [ $regis = "arin" ] || [ $regis = "lacnic" ] ; then
whois -h whois.$regis.net ${s} > $tempdir/whois.txt ; else
whois -h whois.$regis.net -- "-B ${s}" > $tempdir/whois.txt ; fi
netn=`grep -s -i -E -m 1 "^netname:|^na:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
abu=`grep -s -E "^OrgAbuseEmail:|^abuse-c:|^% Abuse|^abuse-mailbox:" $tempdir/whois.txt | grep -s -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b"`
org=`grep -s -i -E -m 1 "^organization:|^org-name:|^owner:|^descr:|^og:|^de:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
whois_cc=`grep -E -i -m 1 "^country:|^cy:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//'`
f_Long ; echo -e "POCs | NET:  $netn, $whois_cc  |  $abu" ; f_Long
if [ $regis = "arin" ] ; then
echo -e "* Organisation"
cat $tempdir/whois.txt |
grep -E "^OrgName:|^OrgId:|^Address:|^City:|Country:|^OrgAbuseName:|^OrgAbusePhone:|^OrgAbuseEmail:|^AbusePhone:|^AbuseName:|^AbuseEmail:|OrgTechName:|OrgTechPhone:|OrgTechEmail:|TechName:|TechPhone:|TechEmail:" $tempdir/whois.txt | sed '/OrgName/{x;p;x}' | sed '/OrgAbuseName:/{x;p;x;}' | sed '/OrgTechName:/{x;p;x;}'  |
cut -d ':' -f 2- | sed 's/^ *//'
elif [ $regis = "lacnic" ] ; then
grep -s -E -m 1 -C 1 "^person:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' ; else
if [[ $(grep -s -w -c '^inetnum:' $tempdir/whois.txt ) -gt "0" ]] ; then
inet_p=`sed -n 'H; /^inetnum:/h; ${g;p;}' $tempdir/whois.txt | sed -n '/organisation:/,/source:/p'` ; else
inet_p=`sed -n 'H; /^inet6num:/h; ${g;p;}' $tempdir/whois.txt | sed -n '/organisation:/,/source:/p'` ; fi
if [[ $(echo "$inet_p" | grep -s -w -c '^descr:' ) -gt "0" ]] ; then
echo -e "* Description" ; echo "$inet_p" | grep "^descr:" | cut -d ':' -f 2- | sed 's/^ *//' ; echo '' ; fi
if [[ $(grep -s -w -c '^org-name:' $tempdir/whois.txt ) -gt "0" ]] ; then
echo -e "* Organisation"
sed -e '/./{H;$!d;}' -e 'x;/organisation:/!d' $tempdir/whois.txt | grep -E -a -s "^org-name:|^address:|^phone:|^e-mail:" |
sed '/org-name:/{x;p;x;}' | cut -d ':' -f 2- | sed 's/^ *//' ; echo '' ; fi
if [[ $(grep -s -w -c '^person:' $tempdir/whois.txt ) -gt "0" ]] ; then
echo -e "* Person" ; sed -e '/./{H;$!d;}' -e 'x;/person:/!d' $tempdir/whois.txt | grep -E -a -s "^person:|^e-mail:|^phone:|^address:|^nic-hdl" |
sed '/^$/d' | sed '/person:/{x;p;x;}' | cut -d ':' -f 2- | sed 's/^ *//' ; echo '' ; fi
if [[ $(grep -s -w -c '^role:' $tempdir/whois.txt ) -gt "0" ]] ; then
echo -e "* Role\n" ; role=`sed -n 'H; /^role:/h; ${g;p;}' $tempdir/whois.txt | sed -n '/role:/,/source:/p' | sed '/^$/d' | sed '/role:/{x;p;x;}'`
echo "$role" | grep -s -E "^role:|^address:" | cut -d ':' -f 2- | sed 's/^ *//' | sed 2q
r_phone=`echo "$role" | grep -s -E -m 1 "^phone:" | cut -d ':' -f 2- | sed 's/^ *//'`
r_mail=`echo "$role" | grep -s -E -m 1 "^e-mail:" | cut -d ':' -f 2- | sed 's/^ *//'`
echo "$role" | grep -s -E "^role:|address:" | sed '1,2d'  | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' '
echo '' ; echo "$r_phone" ; echo "$r_mail" ; fi ; f_Shorter
grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt | sort -u ; echo ''
grep "^admin-c" $tempdir/whois.txt  | tr ':' ';' | tr -d ' ' | sort -u -V ; fi
grep -E "^organisation:|^mnt-by:" $tempdir/whois.txt | sed '/RIPE-NCC-*/d' | sed 's/organisation:/org:/' |  tr ':' ';'  |
tr -d ' ' | sort -u -V | tr '[:space:]' ' ' ; echo ''
}
#******* pwhois.org *******
function f_whoisTABLE {
local s="$*" ; echo -e "begin\ntype=cymru" > $tempdir/addr.list ; cat ${s} >> $tempdir/addr.list ; echo "end" >> $tempdir/addr.list
netcat whois.pwhois.org 43 < $tempdir/addr.list > $tempdir/addr.txt
cat $tempdir/addr.txt  | sed '/Bulk mode; one IP/d' | sed '/ORG NAME/G' > $tempdir/whois_table.txt ; echo ''
}
function f_pwhoisBULK {
local s="$*" ; echo '' ; f_Long ; echo -e "begin" > $tempdir/addr.list
cat ${s} >> $tempdir/addr.list ; echo "end" >> $tempdir/addr.list
netcat whois.pwhois.org 43 < $tempdir/addr.list > $tempdir/addr.txt
cat $tempdir/addr.txt  | grep -E "^IP:|^Origin-AS:|^Prefix:|^AS-Org-Name:|^Org-Name:|^Net-Name:|^City:|^Geo-City:|^Country-Code:|^Geo-Country-Code:" |
sed '/IP:/i \_____________________\n'
}
function f_netBLOCKS {
local s="$*" ; f_Long; echo "[+] $s |  NETBLOCKS  [whois.pwhois.org]"; f_Long
echo -e "* v4 Netblocks  -         NetRange         |      Netname\n\n"
whois -h whois.pwhois.org "netblock org-id=${s}" | cut -d '|' -f 1,2 | grep -s -E "^\*>"
echo -e "\n\n* v6 Netblocks"
whois -h whois.pwhois.org "netblock6 org-id=${s}" | grep -s -E "^Net-(Range|Name|Handle|Org-ID)" |
sed '/Net-Range:/{x;p;x;}' | cut -d ':' -f 2- | sed 's/^ //g'
}
#*****************  WEBSITES & HOSTS *****************
function f_HEADERS {
local s="$*" ; f_Long ; echo -e "[+] $s | HTTP HEADERS | $(date)" ; f_Long ; echo ''
cat $tempdir/headers | sed 's/Content-Security-Policy:/Content-Security-Policy:\n/' | sed 's/content-security-policy:/content-security-policy:\n/' |
sed s'/default-src/\ndefault-src/' | sed 's/font-src/\nfont-src/' | sed 's/frame-src/\nframe-src/' | sed 's/img-src/\nimg-src/' | sed 's/style-src/\nstyle-src/' |
sed 's/^ *//' | fmt -w 120 -s ; echo ''
}
function f_linkDUMP {
local s="$*" ; echo '' > $tempdir/LINKS.${s}.txt; f_Long >> $tempdir/LINKS.${s}.txt
echo -e "[+] $s | LINK DUMP | $(date)" >> $tempdir/LINKS.${s}.txt ; f_Long >> $tempdir/LINKS.${s}.txt
if [ $option_source = "2" ] ; then
curl -s https://api.hackertarget.com/pagelinks/?q=${s}${api_key_ht} > $tempdir/linkdump.txt ; else
timeout 3 lynx -accept_all_cookies -dump -listonly -nonumbers www.${s} > $tempdir/linkdump_raw.txt
if [ -f $tempdir/${s}.html ] ; then
lynx -dump -listonly -nonumbers $tempdir/${s}.html | grep -E -v "^file/*" >> $tempdir/linkdump_raw.txt ; fi
cat $tempdir/linkdump_raw.txt | sort -f -u | sed '/Sichtbare Links:/d' | sed '/Versteckte Links:/d' |
sed '/[Vv]isible [Ll]inks:/d' | sed '/[Hh]idden [Ll]inks:/d' > $tempdir/linkdump.txt ; fi
cat $tempdir/linkdump.txt >> $tempdir/LINKS.${s}.txt
if [ $report = "true" ] ; then
cat $tempdir/LINKS.${s}.txt >> ${outdir}/LINK_DUMP.${s}.txt ; fi
}
function f_ROBOTS {
local s="$*" ; status_robots=$(curl -sLk --head -w %{http_code} $s/robots.txt -o /dev/null)
if [ $status_robots = "200" ] ; then
f_Long > ${outdir}/ROBOTS.${x}.txt ; echo -e "[+] ${s} | robots.txt | $(date)" >> ${outdir}/ROBOTS.${x}.txt
f_Long >> ${outdir}/ROBOTS.${x}.txt ; curl -sLk ${curl_ua} ${s}/robots.txt | fmt -s -w 120 >>  ${outdir}/ROBOTS.${x}.txt ; fi
status_humans=$(curl -sLk --head -w %{http_code} $s/humans.txt -o /dev/null)
if [ $status_humans = "200" ] ; then
f_Long > ${outdir}/HUMANS.${x}.txt; echo -e " ${s} humans.txt | $(date)" >> $outdir/HUMANS.${s}.txt
f_Long >> ${outdir}/HUMANS.${x}.txt ; curl -sLk ${curl_ua} ${s}/humans.txt | fmt -s -w 120 >> ${outdir}/HUMANS.${x}.txt ; fi
}
function f_GET_CENSYS {
local s="$*"
curl -s https://censys.io/ipv4/${s} |  sed -n '/<h4>Basic Information/,/<div id="map-canvas">/p' | sed -e :a -e 's/<[^>]*>//g;/</N;//ba' |
sed 's/^[ \t]*//' | sed '/Details/d' | sed '/\[\]/d' | sed '/^$/d' > $tempdir/censys
curl -s https://search.censys.io/hosts/${s}/data/table | sed -e :a -e 's/<[^>]*>//g;/</N;//ba' | sed 's/^ *//' | sed '/^$/d' > $tempdir/censyst
}
function f_STATUS {
local s="$*" ; effip=`grep -E "^IP:" $tempdir/response | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'`
status=`grep -s 'Status:' $tempdir/response | cut -d ':' -f 2- | cut -d '|' -f 1 | sed 's/^[ \t]*//;s/[ \t]*$//'`
effurl=`grep -E "^URL:" $tempdir/response | cut -d ':' -f 2- | tr -d ' '`
if ! type lynx &> /dev/null; then
title=`grep -E "<title>|</title>" $tempdir/${s}.html | sed -e :a -e 's/<[^>]*>//g;/</N;//ba' | sed 's/^[ \t]*//;s/[ \t]*$//'` ; else
title=$(lynx -crawl -dump $tempdir/${s}.html | grep -s TITLE | sed 's/THE_TITLE://' | sed 's/^[ \t]*//;s/[ \t]*$//') ; fi
verify=`grep -s -m 1 'SSL certificate verify' $tempdir/curl_trimmed | rev | cut -d ' ' -f 1 | rev | tr -d '.'`
doctype=$(grep -E -i "<\!doctype" $tempdir/src | grep -i -o -E "XHTML.[1-2]|HTML.[1-4]|<\!doctype html>" | tr [:lower:] [:upper:] | sed 's/<!DOCTYPE HTML>/HTML5/')
time_total=`grep -s 'Time Total:' $tempdir/response | cut -d ':' -f 2- | tr -d ' '`
redir=`grep -E "^Redirects:" $tempdir/response | cut -d '(' -f 2- | tr -d ')' | tr -d ' '`
ssl_hand=`grep "^SSL Handshake:" $tempdir/response | cut -d ':' -f 2- | tr -d ' '`
if [ $ssl_details = "false" ] ; then
google_a=`grep -s -a -oP "(UA-).*?(?=')" $tempdir/src`
jqu=`cat $tempdir/src | grep 'script' | grep -E -i -o -m 1 "jquery[0-9].[0-9]|jquery[0-9]|jquery"` ; fi
if [ $ww = "false" ] ; then
httpserver=$(grep -i "^Server:" $tempdir/headers  | cut -d ':' -f 2 | sed 's/^[ \t]*//;s/[ \t]*$//' | tail -1)
cat $tempdir/src_head > $tempdir/cms ; grep "text/css" $tempdir/src >> $tempdir/cms
grep '<script' $tempdir/src >> $tempdir/cms ; cat $tempdir/headers >> $tempdir/cms
if [ -f "$tempdir/robots.txt " ] ; then
cat $tempdir/robots.txt >> $tempdir/cms ; fi
cms=$(grep -s -E -i -o "wordpress|wp-content|wp-includes|wp-admin|typo3|typo3conf|typo3.conf|joomla|drupal|liferay|librecms|wix" $tempdir/cms |
sed 's/typo3conf/typo3/' | sed 's/typo3.conf/typo3/' | sed 's/wp-content/wordpress/' | sed 's/wp-includes/wordpress/' | sed 's/wp-admin/wordpress/' |
sed 's/^[ \t]*//;s/[ \t]*$//' | tr [:lower:] [:upper:] | sort -u -V | tail -1) ; else
httpserver=$(grep -s -oP '(HTTPServer\[).*?(?=,)' $tempdir/ww.txt | sed 's/HTTPServer\[//' | sed 's/^ *//' | tr -d ']' | tail -1)
cms=$(grep -s -E -i -o -m 1 "wordpress|typo3|joomla|drupal|liferay|librecms|wix" $tempdir/ww.txt | sort -u -V | tail -1) ; fi
if [ -n "$cms" ] ; then
cms_output="$cms" ; else
cms_output="none/unkown" ; fi
if [ $domain_enum = "true" ] ; then 
f_Long ; echo "DOMAIN HOST | $s | $effip | STATUS: $status | CERT: $verify" ; f_Long ; else 
f_Long ; echo "HOST | $s | $effip | STATUS: $status | CERT: $verify" ; f_Long ; fi 
echo -e "\nURL:          $effurl" ; echo -e "\nTitle:        $title"
if [ $ww = "true" ] ; then
echo -e "\nServer:       $httpserver | CMS: $cms_output" ; else
echo -e "\nCMS:          $cms_output" ; echo -e "\nServer:       $httpserver" ; fi
if [ $ssl_details = "false" ] ; then
echo -e "\nMarkup:       $doctype $jquery $(cat $tempdir/src | grep '<script' | grep -o -m 1 'bootstrap')"
if [ -n "$google_a" ] ; then
adsense=`grep -s -oP -m 1 '(ca-pub-).*?(?=\")' $tempdir/src | sed 's/ca-//'`
if [ -n "$adsense" ] ; then
echo -e "\nGoolge:       Analytics: $google_a | Adsense: $adsense" ;  else
echo -e "\nGoogle:       Analytics: $google_a" ; fi ; fi ; fi
f_DBL "${s}"
echo -e "\n\nResponse:     redirects: $redir,  SSL handshake: $ssl_hand,  total: $time_total"
echo -e "\nIPv4|IPv6:    $(echo $host4 |  tr '[:space:]' ' ' ; echo '')"
if [ -n "$host6" ] ; then
echo -e "\n              $(echo $host6 |  tr '[:space:]' ' ' ; echo '')" ; fi ; echo ''
}
function f_PAGE {
local s="$*"
if [ $domain_enum = "true" ] ; then 
f_Long; echo "$s | DOMAIN WEBPRESENCE"; f_Long ; else 
f_Long ; fi
if [ $option_connect = "9" ] ; then
httpserver=$(grep -s -oP '(HTTPServer\[).*?(?=,)' $tempdir/ww.txt | sed 's/HTTPServer\[//' | sed 's/^ *//' | tr -d ']' | tail -1)
jqu=$(grep -E -i -o -m 1 "jquery|jquery\[[0-9].[0-9].[0-9]\]" $tempdir/ww.txt)
cms=$(grep -s -E -i -o -m 1 "wordpress|typo3|joomla|drupal|liferay|librecms|wix" $tempdir/ww.txt | sort -u -V | tail -1)
title=`grep -s -oP '(Title\[).*?(?=\,)' $tempdir/ww.txt | tail -2 | sed 's/Title\[//' | tr -d '][' | sed 's/^ *//'`
echo -e "* Status\n" ; cut -d ']' -f 1  $tempdir/ww.txt | sed '/http/ s/$/]/' | sed '/^$/d' ; echo '' ; f_Short
grep -s -oP '(IP\[).*?(?=])' $tempdir/ww.txt  | tail -1  | sed 's/^ *//' | sed 's/IP\[/IP:         /' | tr -d ']['
echo -e "\nTITLE:      $title\n" ; echo -e "SERVER:     $httpserver" ; echo -e "\nCMS:        $cms"
f_DBL "${s}"; f_Short; grep -o -m 1 'HTML5'  $tempdir/ww.txt
grep -s -o -w 'Frame' $tempdir/ww.txt | tail -1 ; grep -s -o -w 'YouTube' $tempdir/ww.txt | tail -1
echo -e "$(grep -s -oP -m 1 '(Script\[).*?(?=\])' $tempdir/ww.txt | sed 's/Script\[//') $jq_vers"
grep -s -oP -m 1 '(Content-Language\[).*?(?=\])' $tempdir/ww.txt | sed 's/Content-Language\[/Lang: /' | tr -d ']'
grep -s -oP '(MetaGenerator\[).*?(?=,)' $tempdir/ww.txt | sort -u | sed 's/MetaGenerator\[/MetaGenerator: /' | tr -d '][' | sed 's/^ *//'
grep -s -oP '(PasswordField\[).*?(?=\])' $tempdir/ww.txt | sed 's/PasswordField\[/PasswordField:  /' | tr -d ']'
grep -s -oP '(WWW-Authenticate\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/\[/:  /' | tr -d ']['
grep -s -oP -m 1 '(OpenSearch\[).*?(?=\])' $tempdir/ww.txt | sed 's/OpenSearch\[/OpenSearch: /'
grep -s -oP '(Open-Graph-Protocol\[).*?(?=\])' $tempdir/ww.txt | sort -u  | sed 's/\[/: /' | tr -d ']'
grep -oP '(Meta-Author\[).*?(?=,)' $tempdir/ww.txt | sed 's/Meta-Author\[/Author: /' | tr -d '][' | sed 's/^ *//'
grep -s -oP '(Google-Analytics\[).*?(?=,)' $tempdir/ww.txt | sed 's/Google-Analytics\[/\nGoogle-Analytics:\n\[ /' |
tr -d '][' | sed 's/^ *//'
grep -s -oP '(Email\[).*?(?=])' $tempdir/ww.txt | tr -d '][' |  sed 's/Email/\n* E-Mail\n\n/' | sed 's/,/\n/g' | sed 's/^ *//'
f_Short ; echo -e "* Security Headers & Cookie Flags\n"
grep -s -oP '(Strict-Transport-Security\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/: /' | tr -d ']['
grep -s -oP '(X-Frame-Options\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/:  /' | tr -d ']['
grep -s -oP '(X-XSS-Protection\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/:  /' | tr -d ']['
grep -i -o 'content-security-policy' $tempdir/ww.txt | tail -1 ; grep -i -o 'x-content-type-options' $tempdir/ww.txt | tail -1
grep -s -oP '(HttpOnly\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/:  /' | tr -d ']['
grep -oP '(Cookies\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/:  /' | tr -d ']['  ; fi
if ! [ $option_connect = "9" ] ; then
doctype=$(grep -E -i "<\!doctype" $tempdir/src | grep -i -o -E "XHTML.[1-2]|HTML.[1-4]|<\!doctype html>" | tr [:lower:] [:upper:] | sed 's/<!DOCTYPE HTML>/HTML5/')
if [ $ww = "false" ] ; then
google_a=`grep -s -a -oP "(UA-).*?(?=')" $tempdir/src` ; else
jscript=`grep -s -oP -m 1 '(Script\[).*?(?=\])' $tempdir/ww.txt | sed 's/Script\[//' | sed 's/,/, /'`
jqu=`grep -E -i -o -m 1 "jquery|jquery\[[0-9].[0-9].[0-9]\]" $tempdir/ww.txt`
google_a=`grep -s -oP -m 1 '(Google-Analytics\[).*?(?=\,)' $tempdir/ww.txt` ; fi
if [ $ssl_details = "true" ] ; then
echo -e "* Markup, Scripts\n" ; echo "$doctype"
if [ $ww = "false" ] ; then
grep 'script type' $tempdir/src | cut -d '=' -f 2 | tr -d '>\"' | tr -d ' ' | sort -u -V
grep '<script' $tempdir/src | grep -o 'test/javascript'
cat $tempdir/src | grep 'script' | grep -E -i -o -m 1 "jquery[0-9].[0-9]|jquery[0-9]|jquery" ; else
echo "$jscript"
if [ -n "$jqu" ] ; then
echo "$jqu" | tr -d '][' ; fi ; fi
cat $tempdir/src | grep '<script' | grep -o -m 1 'bootstrap'
if [ -n "$google_a" ] ; then
adsense=`grep -s -oP -m 1 '(ca-pub-).*?(?=\")' $tempdir/src | sed 's/ca-//'`
echo -e "\nGoogle Analytics:  $google_a"
if [ -n "$adsense" ] ; then
echo "Adsense Client:    $adsense" ; fi ; fi
if [ $ww = "false" ] ; then
grep -s -oP '(name="author" content=").*?(?=")' $tempdir/src | cut -d '=' -f 3- | tr -d '\"' ; fi
if [ $ww = "true" ] ; then
grep -s -o -w 'Frame' $tempdir/ww.txt | tail -1 ; grep -s -o -w 'YouTube' $tempdir/ww.txt | tail -1
grep -s -oP -m 1 '(Content-Language\[).*?(?=\])' $tempdir/ww.txt | sed 's/Content-Language\[/Language: /' | tr -d ']'
grep -oP '(Meta-Author\[).*?(?=,)' $tempdir/ww.txt | sed 's/Meta-Author\[/Author: /' | tr -d '][' | sed 's/^ *//'
grep -s -oP '(Open-Graph-Protocol\[).*?(?=\])' $tempdir/ww.txt | sort -u  | sed 's/\[/: /' | tr -d ']'
grep -s -oP '(PasswordField\[).*?(?=\])' $tempdir/ww.txt | sed 's/PasswordField\[/PasswordField:  /' | tr -d ']'
grep -s -oP '(WWW-Authenticate\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/\[/:  /' | tr -d ']['
grep -s -oP -m 1 '(OpenSearch\[).*?(?=\])' $tempdir/ww.txt | sed 's/OpenSearch\[/OpenSearch: /'
grep -s -oP '(Modernizr\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/Modernizr\[/Modernizr:  /' | tr -d '][' ; fi ; fi
f_linkDUMP "${s}" ; curl -sLk ${curl_ua} ${s}/contact-us >> $tempdir/pages
curl -sLk ${curl_ua} ${s}/kontakt >> $tempdir/pages
if [ $ssl_details = "true" ] ; then
curl -sLk ${curl_ua} ${s}/jobs  >> $tempdir/pages ; curl -sLk ${curl_ua} ${s}/career >> $tempdir/pages; f_Short ; fi
grep -s -i -F -econtact -ediscord -ekontakt -efacebook -einstagram -elinkedin -epinterest -etwitter -exing -eyoutube $tempdir/linkdump.txt |
sed '/sport/d' | sed '/program/d' > $tempdir/social ; echo -e "* Website Description\n"
cat $tempdir/src_head | grep -s -w -A 1 "meta" | sed 's/^ *//' > $tempdir/meta
cat $tempdir/meta | tr -d '"' | tr -d '<' | tr -d '>' | tr -d '/' | sed '/meta name=description content=/!d' |
sed 's/meta/\nmeta/g' > $tempdir/content
cat $tempdir/content | sed '/meta name=description content=/!d' | sed 's/meta name=description content=//' |
sed 's/&#039;s/s/' | sed 's/link//' | sed 's/meta name=twitter:card//' | sed 's/rel=canonical//' | sed 's/href/\nhref/' |
sed 's/meta property=og:type//' | sed 's/\!--/\n\!--/' | sed '/\!--/d' | sed '$!N; /^\(.*\)\n\1$/!P; D' | sed 's/^ *//' |
sed 's/title/\ntitle/' | sed '/name=theme-color/d' | sed '/href=*/d' | sed 's/&amp;/\&/' | sed 's/rel=alternate//' | fmt -w 80 -s
cat $tempdir/linkdump.txt | grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" >> $tempdir/pagecontacts
grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/pages >> $tempdir/pagecontacts
grep -s -oP '(Email\[).*?(?=])' $tempdir/ww.txt | tr -d '][' |  sed 's/Email//' | sed 's/,/\n/' | sed 's/^ *//' >> $tempdir/pagecontacts
echo -e "\n\n* Social Media & Contacts\n"
cat $tempdir/social | sort -f -u | grep -E -v ".jpg|.png|.gif|.tiff|.ico" ; echo ''
grep -s -E -i "^tel:|^phone:|^call:|^telefon:" $tempdir/linkdump.txt | cut -d ':' -f 2- | tr -d ' ' | sort -u -V
cat $tempdir/pagecontacts | sort -f -u ; rm $tempdir/pagecontacts
f_Short ; echo -e "* Security Headers\n"
grep -s -E -i "^access-control-allow-origin:" $tempdir/headers | tail -1
grep -s -i "^cache-control:" $tempdir/headers | tail -1 ; grep -s -E -i "^referrer-policy:" $tempdir/headers | tail -1
grep -s -E -i "^Strict-Transport-Security:" $tempdir/headers | tail -1
grep -s -E -i "^X-Content-Type-Options:" $tempdir/headers | tail -1 ; grep -s -E -i "^X-Frame-Options:" $tempdir/headers | tail -1
grep -s -i "^x-proxy-cache:" $tempdir/headers | tail -1 ; grep -s -E -i "^X-Served-By" $tempdir/headers | tail -1
grep -s -E -i "^X-UA-Compatible:" $tempdir/headers | tail -1 ; grep -s -E -i "^X-WebKit-CSP:" $tempdir/headers | tail -1
grep -s -E -i "^X-Xss-Protection:" $tempdir/headers | tail -1
grep -s -E -i -o -m 1 "^P3P" $tempdir/headers | tail -1
grep -m 1 -i -o "^Content-Security-Policy" $tempdir/headers
grep -E -o "default-src|font-src|frame-src|img-src|style-src" $tempdir/headers  | sort -u | tr '[:space:]' ' ' ; echo ''
grep -s -E -i -o -m 1 "^expect-ct:" $tempdir/headers
grep -s -i "^set-cookie:" $tempdir/headers | sed 's/;/ ; /' |
grep -s -E -i -o -m 5 "path=.*|domain=*|samesite=|httponly|secure" | cut -d ' ' -f 1 | sort -f -u
if [ $ww = "false" ] ; then
grep -s -oP '(HttpOnly\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/:  /' | tr -d '][' ; fi
if [ $ssl_details = "true" ] ; then
f_Short ; echo -e "* Application Headers\n"
grep -E -i "^Via:|^X-Cache|^X-Squid|^X-Varnish:|^X-Server-Name:|^X-Server-Port:|^x-forwarded|^Forwarded" $tempdir/headers
grep -E -i "^X-Powered-By|^X-AspNet-Version|^X-Version|^Liferay-Portal|^X-TYPO3-.*|^X-OWA-Version|^X-Generator|X-Redirect-By|unix|debian|ubuntu|buster|stretch|jessie|squeeze|wheezy|lenny|SUSE|Red Hat|CentOS|win32|win64|X-Version" $tempdir/headers | sort -u -V
if [ $ww = "true" ] ; then
grep -s -oP '(MetaGenerator\[).*?(?=,)' $tempdir/ww.txt | sort -u -V | sed 's/MetaGenerator\[/MetaGenerator: /' | tr -d '][' | sed 's/^ *//' ; fi ; fi ; fi ; echo ''
}

function f_serverInfoHEADER {
local s="$*" ; serv='' ; dnsserv='' ; os=''
curl -s "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${s}" > $tempdir/ac.json
curl -s https://stat.ripe.net/data/reverse-dns-ip/data.json?resource=${s} > $tempdir/ptr.json
if [[ ${s} =~ $REGEX_IP4 ]] ; then
f_GET_CENSYS "${s}" ; f_abxHEADER "${s}"
protocols=$(grep -E -a "^\b[0-9]{1,5}+\/.[A-Za-z]{2,6}\b" $tempdir/censyst | sort -u -V | tr '[:space:]' ' ')
serv=$(sed -n '/^Server$/{n;p;}' $tempdir/censys | sed 's/linux/Linux/' | sort -u -V | tr '[:space:]' ' ')
echo -e "\nProtocols:   $protocols\n"
if [[ $(grep -s -w -c "53/DNS" $tempdir/censyst ) -gt "0" ]] ; then
dnsserv=$(sed -n '/53\/DNS/,/services.transport_protocol/p' $tempdir/censyst |  grep -E -A 1 "services.software.(vendor|product|version)" |
grep -E -v "services.software.(vendor|product|version)" | tr '[:space:]' ' ')
if [ -n "$dnsserv" ] ; then
echo -e "Server:      $dnsserv $serv\n" ; else
echo -e "Server:      not detected by censys.io\n" ; fi ; else
os=$(grep -E -A 1 "operating_system.(vendor|product|version)" $tempdir/censyst | grep -E -v "operating_system.(vendor|product|version)" |
sed 's/linux/Linux/' | tr '[:space:]' ' ')
serv=$(sed -n '/^Server$/{n;p;}' $tempdir/censys | sed 's/linux/Linux/' | sort -u -V | tr '[:space:]' ' ')
if [ -n "$os" ] ; then
echo -e "OS|Apps:     $os $serv\n" ; else
if [ -n "$serv" ] ; then
echo -e "Server:      $serv\n" ; fi ; fi ; fi ; fi
ptr=$(jq -r '.data.result[]?' $tempdir/ptr.json | sed 's/null/no ptr record/' | tr '[:space:]' ' ' ; echo '')
echo -e "rDNS:        $ptr\n"
}
function f_serverPROTOCOLS {
local s="$*" ; f_Long
curl -s https://search.censys.io/hosts/${s}/data/table | sed -e :a -e 's/<[^>]*>//g;/</N;//ba' | sed 's/^[ \t]*//' | sed '/Details/d' |  sed '/^$/d' >  $tempdir/censyst
curl -s https://censys.io/ipv4/${s}  | sed 's/^[ \t]*//' | sed '/^$/d' | sed -n '/<h4>Basic Information/,/<div id="map-canvas">/p' |
sed -e :a -e 's/<[^>]*>//g;/</N;//ba' | sed '/Details/d' | sed '/\[\]/d' | sed '/^$/d'  > $tempdir/censys
protocols=$(grep -E -a "^\b[0-9]{1,5}+\/.[A-Za-z]{2,6}\b" $tempdir/censyst | sort -u -V | tr '[:space:]' ' ')
ssl_subject=$(grep -m 1 -A 1 'services.tls.certificates.leaf_data.subject_dn' $tempdir/censyst | sed -n '/services.tls.certificates.leaf_data.subject_dn/{n;p;}')
os=$(grep -E -A 1 "operating_system.(vendor|product|version)" $tempdir/censyst | grep -E -v "operating_system.(vendor|product|version)" | tr '[:space:]' ' ')
if [[ $(grep -s -w -c "NTP" $tempdir/censyst ) -gt "0" ]] ; then
prec=$(sed -n '/services.ntp.get_time_header.precision/{n;p;}' $tempdir/censyst)
vers=$(sed -n '/services.ntp.get_time_header.version/{n;p;}' $tempdir/censyst)
stratum=$(sed -n '/services.ntp.get_time_header.stratum/{n;p;}' $tempdir/censyst)
leap=$(sed -n '/services.ntp.get_time_header.leap_indicator/{n;p;}' $tempdir/censyst)
poll=$(sed -n '/services.ntp.get_time_header.poll/{n;p;}' $tempdir/censyst) ; fi
sql_vers=$(sed -n '/^services.mysql.server_version/{n;p;}' $tempdir/censyst)
echo -e "PROTOCOLS:    $protocols\n"
if [[ $(grep -s -w -c "NTP" $tempdir/censyst ) -gt "0" ]] ; then
echo -e "NTP HEADER:   Version: $vers, stratum: $stratum, poll: $poll, precision: $prec, leap ind.: $leap\n" ; fi
sed -n '/^Server$/{n;p;}' $tempdir/censys | sort -u -V | tr '[:space:]' ' ' ; echo ''
if [ -n "$os" ] ; then
echo "$os" ; fi
if [[ $(grep -s -w -c "53/DNS" $tempdir/censys ) -gt "0" ]] ; then
ns_vers=$(sed -n '/53\/DNS/,/services.dns.server_type/p' $tempdir/censyst |  grep -E -A 1 "services.software.(vendor|product|version)" |
grep -E -v "services.software.(vendor|product|version)")
echo "$ns_vers" ; echo -e "Server Type: $server_type" ; fi
if [[ $(grep -s -w -c "HTTP" $tempdir/censys ) -gt "0" ]] ; then
grep -m 2 "CN=" $tempdir/censys ; grep -m 1 -A 1 'Browser Trusted' $tempdir/censys
sed -n '/TLS Handshake/,/Certificate Chain/p' $tempdir/censys  | grep -m 1 -C 1 "^Cipher Suite" | sed '/Cipher Suite/d'
grep -m 1 "^Heartbeat" $tempdir/censys ; fi
if [[ $(grep -s -w -c "SMTP" $tempdir/censyst ) -gt "0" ]] ; then
subj=`sed -n '/STARTTLS/,$p' $tempdir/censys | grep -m 2 "CN=" | head -1`
ca=`sed -n '/STARTTLS/,$p' $tempdir/censys | grep -m 2 "CN=" | tail -1`
ciphers=$(sed -n '/STARTTLS/,$p' $tempdir/censys | grep -m 1 -C 1 Cipher Suite | tr '[:space:]' ' ' ; echo '')
trusted=$(sed -n '/STARTTLS/,$p' $tempdir/censys | grep -m 1 -A 1 'Browser trusted' | tail -1)
exp=$(grep 'notAfter=' $tempdir/x509.txt | cut -s -d '=' -f 2- | head -1 | sed 's/^ *//')
echo -e "Trusted:      $verify" ; echo -e "\nSubject:     $subj"
echo -e "Issuer:      $ca" ; echo -e "\nCipher:      $ciphers\n" ; fi
if [[ $(grep -s -w -c "3306/MYSQL" $tempdir/censys ) -gt "0" ]] ; then
echo "$sql_vers" ; fi
}
function f_hostSUMMARY {
local s="$*" ; whois -h whois.pwhois.org type=all "$s" > $tempdir/pwho
hosting=`jq -r '.hosting' $tempdir/geo.json` ; mobile=`jq -r '.mobile' $tempdir/geo.json`
if cat $tempdir/pwho | grep -q -E "^Geo-"; then
city="Geo-City" ; cc="Geo-CC" ; else
city="City" ; cc="Country-Code" ; fi
pcity=$(cat $tempdir/pwho  | grep -m1 -E "^${city}" | cut -d ':' -f 2 | sed 's/^ //')
pcountry=$(cat $tempdir/pwho  | grep -m1 -E "^${cc}" | cut -d ':' -f 2 | sed 's/^ //')
if [[ ${s} =~ $REGEX_IP4 ]] ; then
tor_node=$(f_TOR "${s}") ; fi
echo -e "\nGEO:          $(jq -r '.city' $tempdir/geo.json), $(jq -r '.country' $tempdir/geo.json) | $pcity, $pcountry (pwhois.org)"
echo -e "\nORG:          $(jq -r '.org' $tempdir/geo.json) | ISP: $(jq -r '.isp' $tempdir/geo.json)\n"
if [[ ${s} =~ $REGEX_IP4 ]] ; then
if [ -f $tempdir/iscip.json ] ; then
cloudip=`jq -r '.ip.cloud' $tempdir/iscip.json`
echo -e "              Mobile:  $mobile  | Proxy: $(jq -r '.proxy' $tempdir/geo.json)"
echo -e "              Hosting: $hosting   | Cloud: $cloudip" ; else
echo -e "              Mobile: $mobile | Proxy: $(jq -r '.proxy' $tempdir/geo.json) | Hosting: $hosting" ; fi ; else
echo -e "              Proxy: $(jq -r '.proxy' $tempdir/geo.json) | Mobile: $mobile | Hosting: $hosting" ; fi
}
#*****************  CONNECTIVITY, PAGE LOADING-/RTT- & SERVER RESPONSE TIMES *****************
function f_HTTPing {
local s="$*"
httping -t 5 ${hping_array[@]} $s > $tempdir/http_ping
connects=`grep 'connects' $tempdir/http_ping | cut -d ' ' -f 3-`
avg=`grep 'round-trip' $tempdir/http_ping | cut -d '=' -f 2- | cut -d '/' -f 2`
echo -e "HTTPing:     $connects, avg: $avg ms\n"
}
function f_ICMPing {
local s="$*"
timeout 5 ping ${ping_array[@]} $s > $tempdir/iping
ping_stat=`sed -n '/---/{n;p;}' $tempdir/iping | sed 's/^ *//'`
avg_rtt=`cat $tempdir/iping | tail -1 | cut -d '/' -f 2,5`
echo -e "Ping[ICMP]:  $ping_stat; $avg_rtt ms\n"
}
function f_requestTIME {
local s="$*"
nmap ${request_array[@]} -R --resolve-all --dns-servers 1.1.1.1 --script http-chrono,http-server-header,http-title,https-redirect ${s} > $tempdir/chrono
f_Long ; echo "[+] $x | PAGE LOADING- & REFRESH-TIMES"
cat $tempdir/chrono | grep -E -i "Nmap scan report|rDNS|http-chrono:|http-date:|http-title:|http-server-header:|Requested resource" | tr -d '|_' | sed 's/^ *//' |
sed '/Nmap scan report/G' | sed 's/rDNS record for/rDNS:/' |  sed 's/http-chrono: //' | sed '/rDNS:/G' |
sed 's/Request times for /PAGE:           /' | sed 's/; avg/\nTIMES:          avg/' | sed 's/http-server-header:/SERVER:        /' |
sed 's/http-title:/TITLE:         /' | sed 's/Requested resource was/RESOURCE:      /' | sed '/RESOURCE:/G' | sed '/PAGE/G' | sed '/TIMES:/G' |
sed '/Nmap scan report/i \______________________________________________________________________________\n' |
sed 's/Nmap scan report for/*/' | sed 's/path-mtu:/\nPATH-MTU:        /' | sed '/PATH-MTU:/G'
}
function f_MTR {
local s="$*"
f_Long; echo -e "[+] $s | MTR (TCP, Port > $tport)" ; f_Long ; echo ' '
sudo mtr ${mtr_array[@]} -o "  L  S D  A BW  M" -P ${tport} ${s} | sed '/HOST:/G' > $tempdir/mtr.txt
cat $tempdir/mtr.txt; f_Shorter;  echo -e "Snt = packages sent; Wrst = worst RTT in ms; \nJavg = average jitter" ; echo ''
}
function f_DELEGATION_DIG {
echo -e "\n* DNS LOOKUP DELEGATION\n\n"
dig @1.1.1.1 ${t} +noall +answer +trace +noclass +nodnssec ${x} > $tempdir/trace.txt
cat $tempdir/trace.txt | grep ';; Received' | sed 's/;;//' | sed 's/^ *//' | sed '$d' | awk '{ print substr($0, index($0,$5)) }' |
sed 's/(/  (/' | sed G | sed 's/ in /\n>  /' ; echo '' ; cat $tempdir/trace.txt | grep -w -E "A|AAAA" ; echo -e "\n"
cat $tempdir/trace.txt | grep ';; Received' | sed 's/;;//' | sed 's/^ *//' | tail -1 | awk '{ print substr($0, index($0,$5)) }' |
sed 's/ in /\n>  /' | sed 's/(/  (/'
}
#*****************  DNS INFORMATION & BLOCKLISTS *****************
function f_systemDNS {
resolvectl status | sed -e '/./{H;$!d;}' -e 'x;/Current DNS Server:/!d;' | sed '/setting:/d' | sed '/Scopes:/d' | sed '/DNSSEC/d' |
sed 's/DNS Servers:/DNS Servers:\n/' | sed 's/^ *//' | sed '/^$/d' | sed '/Link/{x;p;x}'
}
function f_HOSTrevDNS {
local s="$*"
ip4_list=$(ipcalc -b -n ${s} 255.255.255.255 | grep -s 'Hostroute:' | cut -d ':' -f 2- | tr -d ' ')
for i in $ip4_list ; do
ptr=$(host $i ${nsserv} | grep -E "name pointer|not found:" | rev | cut -d ' ' -f 1 | rev | tr '[:space:]' ' ' ; echo '')
echo -e "$i\t=>\t$ptr" | sed '/3(NXDOMAIN)/d' ; done
}
function f_DIGrevDNS {
local s="$*"
ip4_list=`ipcalc -b -n ${s} 255.255.255.255 | grep -s 'Hostroute:' | cut -d ':' -f 2- | tr -d ' '`
for i in $ip4_list ; do
ptr=`dig ${dig4_array[@]} $i`
if ! [ -z $ptr ] ; then
echo -e "$i\t=>\t$ptr" ; fi ; done
}
function f_DNS {
local s="$*"
f_Long; echo "$s | DNS RECORDS"; f_Long; echo -e "\nHost A & AAAA\n_____________\n"
if [ $option_connect = "9" ] ; then
curl -s https://api.hackertarget.com/dnslookup/?q=${s} > $tempdir/dns.txt
echo '' >> $tempdir/dns.txt ; grep -E "^A|^AAAA" $tempdir/dns.txt | cut -d ':' -f 2- | sed 's/^ *//'
grep -e "^A" $tempdir/dns.txt | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tee $hostips > $tempdir/ips.list; else
hostA=`dig ${dig_array[@]} ${s}` ; echo "$hostA"
echo "$hostA" | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tee $hostips > $tempdir/ips.list
dig aaaa ${dig_array[@]} ${s} ; fi
echo -e "\n\nMail (MX) Servers\n_________________\n"
if [ $option_connect = "9" ] ; then
grep -E "^MX" $tempdir/dns.txt  | cut -d ':' -f 2- | sed 's/^ *//'
mx=`grep -E "^MX" $tempdir/dns.txt | rev | cut -d ' ' -f 1 | rev` ; echo '' ; else
dig mx ${dig_array[@]} ${s}  ; echo '' ; mx=`dig ${dig_array[@]} $(dig ${nssrv_dig} mx +short ${s})`
echo "$mx" ; dig aaaa ${dig_array[@]} $(dig ${nssrv_dig} mx +short ${s})
echo "$mx" | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tee $tempdir/mxips.list >> $tempdir/ips.list ; fi
echo -e "\n\nName Servers\n____________\n"
if [ $option_connect = "9" ] ; then
grep -E "^NS" $tempdir/dns.txt | cut -d ':' -f 2- | sed 's/^ *//'
ns=`grep NS $tempdir/dns.txt | rev | cut -d ' ' -f 1 | rev` ; else
dig ns ${dig_array[@]} ${s} ; echo '' ; ns=`dig ${dig_array[@]} $(dig ${nssrv_dig} ns +short ${s})`
echo "$ns" ; echo '' ; dig aaaa ${dig_array[@]} $(dig ${nssrv_dig} ns +short ${s})
echo "$ns" | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' >> $tempdir/ips.list ; fi
echo -e "\n\nStart of Authority \n___________________\n"
if [ $option_connect = "9" ] ; then
grep -E "^SOA" $tempdir/dns.txt  | cut -d ':' -f 2- | sed 's/^ *//' ; else
dig soa +noall +answer +noclass +ttlid ${s} ; dig soa +noall +answer +multiline ${s} > $tempdir/soa.txt
awk '{ print  $1 $2,   $3, $4, $5 }' $tempdir/soa.txt | sed '1,1d' | sed '$d' | sed '/serial/{x;p;x;}'; fi
echo -e "\n\nTXT Records \n____________"
if [ $option_connect = "9" ] ; then
echo '' ; grep -E "^TXT" $tempdir/dns.txt  | cut -d ':' -f 2- | sed 's/^ *//' ; else
txt_rec=`dig +short txt ${s}` ; echo "$txt_rec" | sed '/\"/{x;p;x;}' | fmt -w 80 -s
echo "$txt_rec" | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' >> $tempdir/ips.list
echo -e "\n\nSRV Records \n____________\n"
nmap -Pn -sn --script dns-srv-enum --script-args dns-srv-enum.domain=$x 2>/dev/null | grep '|' |
sed '/dns-srv-enum:/d' ; fi
if [ $option_dnsdetails = "y" ] ; then
f_Long ; f_whoisTABLE "$tempdir/ips.list" ; cat $tempdir/whois_table.txt | cut -d '|' -f -5
soa=`dig soa +short $x` ; soa_host=`echo "$soa" | cut -d ' ' -f 1`
if ! [ $option_connect = "9" ] ; then
f_Long ; echo "[+] RFC 1912 COMPLIANCE" ; f_Long
nmap -sn -Pn ${soa_host} --script dns-check-zone --script-args=dns-check-zone.domain=$x 2>/dev/null | grep '|' | tr -d '|_'  |
sed '/dns-check-zone:/d' | sed '/DNS check results for domain:/G' ; echo '' ; fi
if [ $option_connect = "9" ] ; then
for n in $ns ; do
curl -s http://ip-api.com/json/${n}?fields=54738911 > $tempdir/geo.json
ipv4=`jq -r '.query' $tempdir/geo.json` ; echo "$ipv4" >> $tempdir/ips.list
curl -s "https://stat.ripe.net/data/reverse-dns-ip/data.json?resource=${ipv4}" > $tempdir/ptr.json
ptr=`jq -r '.data.result[0]' $tempdir/ptr.json | sed 's/null/no ptr record/'`
f_Long ; echo "NS | $n | $ipv4" ; f_Long ; f_serverInfoHEADER "${ipv4}"
f_serverINFO "${ipv4}" ; done ; fi
if ! [ $option_connect = "9" ] ; then
for n in $(dig ns +short $s) ; do
curl -s http://ip-api.com/json/${n}?fields=54738911 > $tempdir/geo.json
ipv4=`jq -r '.query' $tempdir/geo.json`
ptr=$(host $ipv4 | cut -d ' ' -f 5 | sed 's/3(NXDOMAIN)/no record/' | head -1)
f_Long ; echo "NS | $n | $ipv4" ; f_Long ; f_serverInfoHEADER "${ipv4}"
echo -e "\nNSEC:        $(host -t nsec $n 1.1.1.1 | cut -d ' ' -f 3- | tail -1)"
echo -e "             $(host -t nsec3 $n 1.1.1.1 | cut -d ' ' -f 3- | tail -1)\n"
f_serverINFO "${ipv4}" ; done ; fi
if [ $option_connect = "9" ] ; then
for m in $mx ; do
curl -s http://ip-api.com/json/${m}?fields=54738911 > $tempdir/geo.json
ipv4=`jq -r '.query' $tempdir/geo.json` ; echo "$ipv4" >> $tempdir/ips.list
if [[ $ipv4 =~ $REGEX_IP4 ]] ; then
curl -s "https://stat.ripe.net/data/reverse-dns-ip/data.json?resource=${ipv4}" > $tempdir/ptr.json
ptr=`jq -r '.data.result[0]' $tempdir/ptr.json | sed 's/null/no ptr record/'`
f_Long ; echo "MX | $m | $ipv4" ; f_Long ; f_serverInfoHEADER "${ipv4}" ; f_serverINFO "${ipv4}"
if [ $option_zone = "1" ] || [ $option_zone = "3" ] ; then
f_Short ; f_BLOCKLISTS "$ipv4" ; echo '' ; fi
fi ; done ; fi
if ! [ $option_connect = "9" ] ; then
for a in $(cat $tempdir/mxips.list) ; do
if [[ $(echo $a | egrep -s -o -c '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}') -gt "0" ]] ; then
curl -s http://ip-api.com/json/${a}?fields=54738911 > $tempdir/geo.json
ptr=$(host $a | cut -d ' ' -f 5 | sed 's/3(NXDOMAIN)/no record/' | head -1)
f_Long ; echo "MX | $a | $ptr" ; f_Long ; f_serverInfoHEADER "${a}" ; f_serverINFO "${a}" ; f_certMX "${a}"
if [ $option_zone = "1" ] || [ $option_zone = "3" ] ; then
f_Short ; f_BLOCKLISTS "$a" ; echo '' ; fi ; fi ; done
if [ $option_ttl = "3" ] ; then
f_Long; echo "[+] $s | DNS RECORDS TTL [HUMAN READABLE]"; f_Long ; echo ''
dig ${nssrv} +noall +answer +noclass +ttlunits ${x}
dig ${nssrv} aaaa +noall +answer +noclass +ttlunits ${x} ; echo ''
dig ${nssrv} mx +noall +answer +noclass +ttlunits ${x} ; echo ''
dig ${nssrv} ns +noall +answer +noclass +ttlunits ${x} ;echo '' ; fi
f_Long ; echo -e "[+] $s | CHECKING FOR NON-MATCHING SOA ENTRIES..." ; f_Long ; echo ''
host -C $s | cut -d ' ' -f -7 | sed 's/Nameserver/Nserver/' ; echo '' ; fi ; fi 
}
function f_threatSUMMARY {
echo -e  "* INTERNET STORM CENTER (SANS) \n"
echo -e "Incidents:      $(jq -r '.ip.count' $tempdir/iscip.json)"
echo -e "Attacks:        $(jq -r '.ip.attacks' $tempdir/iscip.json)"
echo -e "Time:           $(jq -r '.ip.mindate' $tempdir/iscip.json) - $(jq -r '.ip.maxdate' $tempdir/iscip.json)"
echo -e "Updated:        $(jq -r '.ip.mindate' $tempdir/iscip.json)"
}
function f_BLOCKLISTS {
local s="$*"
echo -e "* BLOCKLISTS  [$s] \n\n"
reverse=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
for i in ${blocklists} ; do
in_list="$(dig @1.1.1.1 +short -t a ${reverse}.${i}.)"
if [[ $in_list ]]; then
echo -e "YES (${in_list}) | ${i}" ; else
echo -e "NO | ${i}" ; fi ; done
}
function f_projectHONEYPOT {
local s="$*" ; rev=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
echo -e "* PROJECT HONEYPOT \n"
response=$(dig +short ${honeykey}.${rev}.dnsbl.httpbl.org)
if [[ -z "$response" ]]; then
echo -e "No results for $s" ; else
last_seen=`echo "$response" | awk -F'.' '{print $2}'` ; score=`echo "$response" | awk -F'.' '{print $3}'`
category=`echo "$response" | awk -F'.' '{print $4}'`
if [ $category = "0" ] ; then
agent_cat="Category:       Search Engine"
elif [ $category = "1" ] ; then
agent_cat="Category:       Suspicious"
elif [ $category = "2" ] ; then
agent_cat="Category:       Harvester"
elif [ $category = "4" ] ; then
agent_cat="Category:       Comment Spammer"
elif [ $category = "5" ] ; then
agent_cat="Category:       Suspicious & Comment Spammer"
elif [ $category = "6" ] ; then
agent_cat="Category:       Harvester & Comment Spammer" ; fi
if [ $category = "0" ] ; then
if [ $score = "0" ]; then
third_octett="Agent:          Undocumented Searchengine"
elif [ $score = "2" ] ; then
third_octett="Agent:          ASK"
elif [ $score = "3" ] ; then
third_octett="Agent:          Baidu"
elif [ $score = "4" ] ; then
third_octett="Agent:          Excite"
elif [ $score = "5" ] ; then
third_octett="Agent:          Google"
elif [ $score = "8" ] ; then
third_octett="Agent:          MSN"
elif [[ $score = "9" ]] ; then
third_octett="Agent:          Yahoo" ; else
third_octett="Agent:          Searchengine (Miscellaneous)" ; fi ; fi
if ! [ $category = "0" ] ; then
third_octett="Threat Score:   $score" ; fi
echo "$agent_cat" ; echo "$third_octett" ; echo -e "Last Seen:      $last_seen  day(s) ago\n" ; fi
}
function f_forumSPAM {
local s="$*"
curl -s "http://api.stopforumspam.org/api?ip=${s}&json&badtorexit" > $tempdir/forum.json
last_seen=$(jq -r '.ip.lastseen' $tempdir/forum.json)
echo -e "* STOP FORUM SPAM\n"
if [ $last_seen != "null" ] ; then
echo -e "Last Seen:   $(jq -r '.ip.lastseen' $tempdir/forum.json)"; echo -e "Frequency:   $(jq -r '.ip.frequency' $tempdir/forum.json)"
echo -e "Appears:     $(jq -r '.ip.appears' $tempdir/forum.json)"; echo -e "Country:     $(jq -r '.ip.country' $tempdir/forum.json)"
echo -e "Torexit:     $(jq -r '.ip.torexit' $tempdir/forum.json)"
echo -e "Confidence:  $(jq -r '.ip.confidence' $tempdir/forum.json)" ; else
echo -e "No results for $s" ; fi
}
function f_THREAT_ENUM {
local s="$*" ; echo '' ; f_Long; echo "[+] $s | BLOCKLISTS & THREATFEEDS"; f_Long
echo -e "* UCEprotect (IP & Network)\n"; jq -r '.data.blocklist_info[] | .list, .entries' $tempdir/ac.json
f_Short ; f_projectHONEYPOT "${s}" ; echo -e "\n" ; f_forumSPAM "${s}" ; f_Short ; f_threatSUMMARY
curl -s "https://isc.sans.edu/api/ipdetails/${s}?json" > $tempdir/ipdetails.json
echo -e "\n\n* Recent Incidents (Times, Ports)\n"
jq -r '.[] | { Date: .date, Time: .time, SourcePort: .sourceport, TargetPort: .targetport, Protocol: .protocol, Flags: .flags}' $tempdir/ipdetails.json |
tr -d '},\"{' | sed 's/^ *//' | sed '/^$/d' | sed 's/Date:/Date:       /' | sed 's/Time:/Time:       /' | sed 's/Protocol:/Protocol:   /' |
sed '/Flags:/G' | sed 's/Flags:/Flags:      /' | sed 's/SourcePort:/SourcePort: /' | sed 's/TargetPort:/TargetPort: /' > $tempdir/attacks
tail -56 $tempdir/attacks ; f_Short ; f_BLOCKLISTS "${s}" ; echo ''
}
#*********** API calls *************
function f_RevDNS {
local s="$*"
curl -s https://api.hackertarget.com/reversedns/?q=${s}${api_key_ht} | sed 's/no records found/no_records/' > $tempdir/out_revdns.txt
cat $tempdir/out_revdns.txt | sed 's/ / => /'  | awk '{print $1 "\t" $2 "\t" $3}' > $tempdir/revdns.txt
echo ' ' >>  $tempdir/revdns.txt
if [[ $(wc -w $tempdir/revdns.txt  | cut -d ' ' -f 1 | tr -d ' ') -lt "2" ]] ; then
cat $tempdir/revdns.txt | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' ; else
echo '' ; cat $tempdir/revdns.txt ; fi
}
function f_RevIP {
local s="$*"
curl -s https://api.hackertarget.com/reverseiplookup/?q=${s}${api_key_ht} | sed 's/No DNS A records found/no_records/' ; echo ''
}
function f_VHOSTS {
local s="$*" ; f_Long ; echo -e "[+] ${s} Virtual Hosts" ; f_Long
curl -s https://api.hackertarget.com/reverseiplookup/?q=${s}${api_key_ht} ; echo ''
}
function f_BANNERS2 {
local s="$*" ; curl -s https://api.hackertarget.com/bannerlookup/?q=${s}${api_key_ht} > $tempdir/banners.json
jq -r '.' $tempdir/banners.json  | tr -d '{""}' | tr -d ',[]' | sed 's/^ *//' | sed "/^[[:space:]]*$/d" |
sed '/ip:/i \\n___\n' > $tempdir/banners.txt ; echo '' >> $tempdir/banners.txt
cat $tempdir/banners.txt
}
function f_BANNERS {
local s="$*" ; curl -s https://api.hackertarget.com/bannerlookup/?q=${s}${api_key_ht} > $tempdir/b.json
jq -r '{ip: .ip, cn: .https443.cn, http80: .http.server, https443: .https443.server, apps: .https443.apps[0], apps2: .https443.apps[1], ssh: .ssh,ftp: .ftp}' $tempdir/b.json |
sed '/null/d' | tr -d '}\",{' | sed 's/apps: //' | sed 's/apps2: //' | sed 's/^ *//' | sed '/^$/d' | sed '/ip:/i \___\n' > $tempdir/banners.txt; cat $tempdir/banners.txt
}
function f_NETGEO {
local s="$*"
echo -e "* $s | Geographic Distribution\n"
local s="$*" ; curl -s https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${s} > $tempdir/netloc.json
locations=`jq -r '.data.located_resources[].locations | .[]' $tempdir/netloc.json`
echo "$locations" | jq -r '{Country: .country, City: .city, Net: .resources[], Lat: .latitude, Lon: .longitude}' |
tr -d '},"{' | sed '/^$/d' | sed 's/^ *//' | sed '/Country:/i -----------'
jq -r '.data.located_resources[].locations | .[] | .resources[]' $tempdir/netloc.json | sort -u -V > $tempdir/nets_geo.list
}
function f_DNS_CHAIN {
local s="$*" ; echo -e "* PTR & Authoritative Nameservers\n"
curl -s "https://stat.ripe.net/data/dns-chain/data.json?resource=${s}" > $tempdir/chain.json
jq -r '.data.forward_nodes' $tempdir/chain.json | tr -d '{}]/":[}' | sed '/^$/d' | sed 's/^[ \t]*//' | head -1
echo '-' ; jq -r '.data.authoritative_nameservers[]' $tempdir/chain.json
}
function f_DELEGATION {
local s="$*" ; curl -s "https://stat.ripe.net/data/reverse-dns/data.json?resource=${s}" > $tempdir/revd.json
echo -e "* $s Rev. DNS Delegation \n"
jq -r '.data.delegations[]' $tempdir/revd.json | grep -s -A1 'domain\|descr\|nserver' | tr -d '\":,' |
grep -s 'value' | sed 's/value//' | sed 's/^ *//'
}
function f_ROUTE_CONS {
local s="$*" ; echo -e "* Prefix Routing Consistency\n"
curl -s "https://stat.ripe.net/data/prefix-routing-consistency/data.json?resource=${s}" > $tempdir/rc.json
jq -r '.data.routes[] | {Pfx: .prefix, Origin: .origin, in_BGP:  .in_bgp, in_Whois: .in_whois}' $tempdir/rc.json | tr -d '{",}' |
sed '/^$/d' | sed '/Pfx:/{x;p;x;G;}' | sed 's/Pfx:/*> /' | sed 's/in_Whois:/in Whois: /' | sed 's/in_BGP:/in BGP:   /' |
sed 's/Origin:/Origin:   /' | sed 's/^ *//' ; f_Shorter; echo -e "ASNs:\n"
jq '[.data.routes[] | { AS: .origin, Name: .asn_name}]' $tempdir/rc.json | jq unique | jq -r '.[] | .AS, .Name' | sed 'n;G'
jq -r '.data.routes[] | .prefix' $tempdir/rc.json | sort -V > $tempdir/nets_cons.list
}
function f_BGPviewPREFIXES {
curl -s https://api.bgpview.io/asn/${asnum}/prefixes  > $tempdir/prefixes.json
echo -e "\nIPv6 Prefixes\n______________\n"
jq -r '.data.ipv6_prefixes[] | {pfx: .prefix, net: .name, org: .description, roa: .roa_status, loc: .country_code}' $tempdir/prefixes.json |
tr -d '}/",{' | sed 's/^ *//' | sed '/^$/d' | sed 's/pfx:/\n*>  /' | sed 's/net:/\n net: /' | sed 's/org:/ org: /' | sed 's/roa:/ roa: /' |
sed 's/loc:/ loc: /' ; echo -e "\n\nIPv4 Prefixes\n______________\n"
jq -r '.data.ipv4_prefixes[] | {pfx: .prefix, net: .name, org: .description, roa: .roa_status, loc: .country_code}' $tempdir/prefixes.json |
tr -d '}/",{' | sed 's/^ *//' | sed '/^$/d' | sed 's/pfx:/\n*> /' | sed 's/net:/\nnet:/'
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
function f_AS_ROUTING_Cons {
local s="$*" ; curl -s "https://stat.ripe.net/data/as-routing-consistency/data.json?resource=as${s}" > $tempdir/ascons
if [ $option_as_route = "1" ] || [ $option_as_route = "3" ] ; then
echo -e "\n * Prefixes" ; echo -e "_____________\n"
jq -r '.data.prefixes[] | {pfx: .prefix, inBGP: .in_bgp, inWHOIS: .in_whois}' $tempdir/ascons | tr -d '}\",{' | sed 's/^ *//' |
sed 's/pfx:/*>/' | sed '/inBGP/{x;p;x;}' ; fi
if [ $option_as_route = "2" ] || [ $option_as_route = "3" ] ; then
echo -e "* Exports" ; echo -e "_____________\n"
jq -r '.data.exports[] | {pfx: .peer, inBGP: .in_bgp, inWHOIS: .in_whois}' $tempdir/ascons | tr -d '}\",{' | sed 's/^ *//' |
sed 's/pfx:/*/' ; echo -e "* Imports" ; echo -e "___________\n"
jq -r '.data.imports[] | {pfx: .peer, inBGP: .in_bgp, inWHOIS: .in_whois}' $tempdir/ascons | tr -d '}\",{' | sed 's/^ *//' |
sed 's/pfx:/*/' ; fi
}
function f_cSPOTTER {
local s="$*" ; f_Long ; echo -e "[+] $s | DOMAIN CERT. ISSUANCES [api.certspotter.com] | $(date)" ; f_Long
jq -r '.[] | {Subject: .dns_names[], Expires: .not_after, CA: .issuer.name, CertSHA256: .cert.sha256}' $tempdir/certs.json | tr -d '}"{,' |
sed 's/^ *//' | sed '/^$/d' | sed 's/CertSHA256:/CertSHA-256:/' |
sed '/CertSHA-256:/a\______________________________________________________________________________\n'
}
#*****************  SUBMENUS *****************
function f_options_NSSERVERS {
echo -e "\n ${B}22)${D}  DNS Records"
echo -e " ${B}23)${D}  dig Batch Mode (Bulk Lookup)"
echo -e " ${B}24)${D}  Shared Name Servers"
echo -e " ${B}25)${D}  Zone Walk & Zone Transfer"
}
function f_optionsWhois {
echo -e "\n ${B}31)${D}  Domain whois Status"
echo -e " ${B}32)${D}  Bulk whois Lookup (pwhois.org)"
echo -e " ${B}33)${D}  Inverse Lookup & Object Search (RIPE, APNIC, AFRINIC)"
echo -e " ${B}34)${D}  Prefix Address Space Enumeration"
echo -e " ${B}35)${D}  ARIN Network & PoC Search"
echo -e " ${B}36)${D}  Org & NetBlock Searches (pwhois.org)"
echo -e " ${B}37)${D}  AS Information, BGP Prefixes, Peering & Transit"
echo -e " ${B}38)${D}  IX Information"
}
function f_optionsIPV4 {
echo -e "\n ${B}44)${D}  IPv4 Hosts > Whois Geolocation, Blocklists, Banners, VHost"
echo -e " ${B}45)${D}  IPv4 Nets  > Whois, Geolocation, Routing Consistency"
echo -e " ${B}46)${D}  IPv4 Nets  > Reverse DNS, VHosts & Banners"
echo -e " ${B}47)${D}  IPv4 Nets  > Network Blocklists Check"
echo -e " ${B}p4)${D}  IPv4 Nets  > NMAP Ping Sweep"
}
function f_optionsIPV6 {
echo -e "\n ${B}66)${D}  IPv6 Hosts > Whois, Geolocation, DNS Delegation"
echo -e " ${B}67)${D}  IPv6 Nets  > Whois, Geolocation, DNS Delegation"
echo -e " ${B}68)${D}  IPv6 Nets  > Reverse DNS Lookup"
echo -e " ${B}69)${D}  Subdomain Bruteforcing (IPv4 & IPv6)"
echo -e " ${B}p6)${D}  thc-atk6 ICMPv6 Packets Builder"
echo -e " ${B}t6)${D}  thc-atk6 IPv6 Traceroute (MTU- & Tunnel Discovery) & RPKI Validation"
}
function f_optionsWEB {
echo -e "\n ${B}77)${D}  Webserver Information & Diagnostics (Connectivity- & SSL-Issues, Vulnerabilities)"
echo -e " ${B}78)${D}  Dump Certificates, Hyperlinks, HTTP Headers, robots.txt"
}
function f_options_T {
echo -e "\n ${B}t1)${D}  Path MTU Discovery (Nmap, ICMP/TCP)"
echo -e " ${B}t2)${D}  Tracepath (IPv4 & v6, MTU Discovery, ICMP only, non-root)"
echo -e " ${B}t3)${D}  MTR (Traceroute, RT-Times, Packet Loss; IPv4, IPv6, TCP,UDP,ICMP)"
echo -e " ${B}t4)${D}  NMAP Geo Traceroute (ICMP, TCP)"
echo -e " ${B}t5)${D}  Dublin Traceroute (NAT-aware, Multipath Tracerouting, ICMP only)"
echo -e " ${B}t6)${D}  atk-trace6 ICMPv6 Traceroute (MTU- & Tunnel-Discovery)"
echo -e " ${B}[*]${D}  Additional Option: 53), 54), 56)${D} RPKI Validation, ISP, Contact, Geolocation & whois Summary for each Hop"
}
function f_options_P {
echo -e "\n ${B}p1)${D}  NMAP Port-, Version- & Vulnerability Scans"
echo -e " ${B}p2)${D}  NMAP Port Scan (hackertarget.com API, IPv4) "
echo -e " ${B}p3)${D}  NPING (hackertarget.com API, IPv4)"
echo -e " ${B}p4)${D}  NMAP Ping Sweep (IPv4)"
echo -e " ${B}p5)${D}  NMAP Firewalk & Alternative Scanflags"
echo -e " ${B}p6)${D}  thc-atk6 ICMP6 Packets Builder"
}

#***************************** main program loop *****************************
while true
do
echo -e -n "\n  ${B}?${D}  " ; read choice
case $choice in
m)
f_startMenu
;;
o) f_Menu ;;
c | clear)
clear
f_Menu
;;
p) f_options_P ;;
t) f_options_T ;;
s | r)
#************** ADD Permanent Folder  *******************
f_makeNewDir ; f_Long ; f_REPORT ; f_Menu
;;
a)
f_Long ; echo -e "\n ${B}Main Menu${D}"
echo -e "\n  a)  SHOW ALL OPTIONS"
echo "  c)  CLEAR SCREEN"
echo "  i)  MANAGE TARGET INTERACTION"
echo "  o)  OPTIONS"
echo "  s)  SAVE RESULTS"
echo "  q)  QUIT"
echo -e "\n\n${B}OPTIONS MENU & SUBMENUS ${D}\n"
echo -e "  ${B}1)${D}  Domain Enumeration           ${B} 7)${D}  Webservers"
echo -e "  ${B}2)${D}  DNS                          ${B} p)${D}  Port Scans & Ping"
echo -e "  ${B}3)${D}  whois                        ${B} t)${D}  Traceroute"
echo -e "  ${B}4)${D}  IPv4                         ${B} i)${D}  Manage target interaction"
echo -e "  ${B}5)${D}  Rev_GoogleAnalytics Search   ${B} m)${D}  MAIN MENU"
echo -e "  ${B}6)${D}  IPv6"
echo -e "\n${B} 1) Domain Enumeration${D}\n"
echo -e "    Domain Webhost, DNS Records, SSL Info & Certificates, Subdomains, Networks, Prefixes, Owners, Contacts"
echo -e "\n${B} 2) Name Server & DNS Lookup Options ${D}" ; f_options_NSSERVERS
echo -e "\n${B} 3) Whois & BGP Related Options ${D}"
f_optionsWhois
echo -e "\n      LACNIC Whois Lookups are supported in Options ${B}44), 45), 66), 67)${D}"
echo -e "      Use Options ${B}33)-35)${D} to search for address ranges & network owner contacts"
echo -e "\n${B} 4) IPv4 Hosts & Networks ${D}" ; f_optionsIPV4 
echo -e "\n${B} 5) Reverse GoogleAnalytics Search${D}"
echo -e "\n${B} 6) IPv6 Addresses & Networks ${D}" ; f_optionsIPV6 
echo -e "\n${B} 7) Webservers ${D}"; f_optionsWEB
echo -e "\n${B} i) Manage target interaction${D}\n"
echo -e "    Allow direct target interaction (default) or \n    avoid revealing your IP address by working with whois Lookups & API calls only"
echo -e "\n${B} p) Port Scans & Ping${D}" ; f_options_P
echo -e "\n${B} t) Tracerouting, MTU Discovery, RPKI Validation${D}" ; f_options_T ; f_Long
echo -e "${B}Sources (APIs und whois Servers ${D}\n\n"
echo -e "abusix.com, bgpview.io, censys.io, certspotter.com, crt.sh, hackertarget.com, ip-api.com, ripeSTAT Data API, sublister.com, \nwhois.cymru.com, whois.pwhois.org, RIR whois Servers"
echo -e "\n\n${B}Dependencies ${D}"
echo -e "\nEssential: curl, dnsutils (installs dig & host), jq, lynx, nmap, openssl, whois"
echo -e "\nRecommended: dublin-traceroute, mtr, testssl, thc-ipv6, tracepath, wfuzz, whatweb\n"
;;
i)
f_Long ; echo -e "\n ${B}Option > Target Connect > ${D}"
echo -e "\n ${B}>${D} Send packets from your system to target systems ?"
echo -e -n "\n ${B}>${D} ${GREEN}[1]${B} yes | ${R}[9]${B} no, use APIs & 3rd party sources only  ?${D}  " ; read option_connect
if [ $option_connect = "1" ] ; then
conn="${GREEN}true${D}" ; else
conn="${R}false${D}" ; fi
f_Menu
;;
1)
f_makeNewDir ; f_Long ; option_dnsdetails="y" ; domain_enum="true" ; option_source="1"
type_net="false" ; ssl_details="true" ; ww="true" ; type_hop="false" ; blocklists="$blocklists_small"
echo -e -n "\n${B}Target  > [1]${D} Set target Domain ${B}| [2]${D} Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE ${B}>>${D}  " ; read input
targets="${input}" ; else
echo -e -n "\n${B}Target  > ${D}Domain  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list
targets="$tempdir/targets.list" ; fi
echo -e "\n${B}Option  > whois > ${D} Look up searchable object handles & details for domain networks?"
echo -e -n "\n${B}Option  > whois > ${B}[y] | [n]  ?${D}  " ; read option_whois
if  [ $option_connect = "9" ] ; then
echo -e "\n${B}Options > Subdomains >\n"
echo -e "${B} [1]${D} Subdomains (IPv4)"
echo -e "${B} [9]${D} SKIP" ; echo -e -n "\n${B}  ?${D}  "  ; read option_subs
echo -e "\n${B}Options  > MX, NS > ${D}\n"
echo -e "${B} [1]${D} Check SPAM Blocklists" ; echo -e "${B} [2]${D} Check for unauthorized zonetransfers"
echo -e "${B} [3]${D} BOTH" ; echo -e "${B} [9]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_zone ; else
declare -a dig_array=() ; declare -a dig4_array=() ; declare -a curl_array=() ; curl_array+=(-sLk4v)
echo -e "\n${B}Options > Subdomains >\n"
echo -e "${B} [1]${D} Subdomains (IPv4)" ; echo -e "${B} [2]${D} Subdomains (IPv4, IPv6)"
echo -e "${B} [9]${D} SKIP" ; echo -e -n "\n${B}  ?${D}  "  ; read option_subs
echo -e "\n${B}Nameservers (System Defaults)${D}\n" ; f_systemDNS
echo -e "\n\n${B}Options > Nameservers ${B}>\n"
echo -e "${B} [1]${D} Use system defaults" ; echo -e "${B} [2]${D} 9.9.9.9"
echo -e "${B} [3]${D} 1.1.1.1" ; echo -e "${B} [4]${D} Set custom NS" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ns
if [ $option_ns = "2" ] ; then
dig_array+=(@9.9.9.9); nssrv="@9.9.9.9"
elif [ $option_ns = "3" ] ; then
dig_array+=(@1.1.1.1) ;  nssrv="@1.1.1.1"
elif [ $option_ns = "4" ] ; then
echo -e -n "\n${B}Set     >${D} Nameserver  ${B} >>${D}   " ; read ns_input
dig_array+=(@nssrv) ;  dig_array+=(@nssrv) ; nssrv="@${ns_input}" ; else
nssrv="" ; fi
dig_array+=(+noall +answer +noclass)
echo -e "\n${B}Options > DNS Lookup >\n"
echo -e "${B} [1]${D} TTL values (ms)" ; echo -e "${B} [2]${D} TTL values (human readable)"
echo -e "${B} [3]${D} BOTH" ; echo -e "${B} [9]${D} Do not show TTL values" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ttl
if [ $option_ttl = "1" ] || [ $option_ttl = "3" ] ; then
dig_array+=(+ttlid)
elif [ $option_ttl = "2" ] ; then
dig_array+=(+ttlunits) ; else
dig_array+=(+nottlid) ; fi
echo -e "\n${B}Options  > MX, NS > ${D}\n"
echo -e "${B} [1]${D} Check SPAM Blocklists" ; echo -e "${B} [2]${D} Check for unauthorized zonetransfers"
echo -e "${B} [3]${D} BOTH" ; echo -e "${B} [9]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_zone
echo -e "\n${B}Option > curl > ${D} User Agent String\n"
echo -e "${B} [1]${D} default" ; echo -e "${B} [2]${D} $ua_moz" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ua
echo -e -n "\n${B}Option  > HTTPing >${D} Ping domain host(s) ${B}[y] | [n] ?${D}  " ; read option_ping
echo -e "\n${B}Options > SSL/TLS SECURITY > TESTSSL > \n"
echo -e "${B} [1]${D} Verification (Chain of trust), OSCP & Revocation Lists Check"
echo -e "${B} [2]${D} TESTSSL (Verification & Vulnerabilities)"
echo -e "${B} [3]${D} TESTSSL (Full, including Client Simulations)"
echo -e "${B} [9]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_testSSL ; fi
for x in $(cat $targets) ; do
out="$outdir/${x}.txt" ; f_textfileBanner >> ${out}
echo '' | tee -a ${out}; f_Long | tee -a ${out} ; echo -e "[+] $x | WHOIS" | tee -a ${out} ; f_Long | tee -a ${out}
f_whoisLOOKUP "${x}"; cat $tempdir/whois3.txt | tee -a ${out}; echo '' | tee -a ${out}
f_Long >>  $outdir/WHOIS.${x}.txt ; echo -e "$x | WHOIS" >> $outdir/WHOIS.${x}.txt ; f_Long >> $outdir/WHOIS.${x}.txt
cat $tempdir/whois3.txt >> $outdir/WHOIS.${x}.txt
if [ $option_connect = "9" ] ; then
curl -s https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht} > $tempdir/ww.txt
ip4=$(cat $tempdir/ww.txt | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tail -1)
curl -s http://ip-api.com/json/${ip4}?fields=16985627  > $tempdir/geo.json
curl -s https://stat.ripe.net/data/reverse-dns-ip/data.json?resource=${ip4} > $tempdir/ptr.json
ptr=`jq -r '.data.result[0]' $tempdir/ptr.json | sed 's/null/no ptr record/'`
f_PAGE "${x}" | tee -a ${out}
hosting=`jq -r '.hosting' $tempdir/geo.json` ; geo_c=`jq -r '.countryCode' $tempdir/geo.json`
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] $x | $ip4 | $geo_c | Hosting: $hosting" | tee -a ${out}; f_Long | tee -a ${out}
f_serverInfoHEADER "${ip4}" | tee -a ${out}; f_serverINFO "${ip4}" | tee -a ${out}
f_Long | tee -a ${out}; echo -e "[+] $x | CERTIFICATE STATUS" | tee -a ${out}; f_Long | tee -a ${out}
curl -s  "https://api.certspotter.com/v1/issuances?domain=${x}&expand=dns_names&expand=issuer&expand=cert" > $tempdir/hostcert.json
jq -r '.[] | {Subject: .dns_names[], Expires: .not_after, Issuer: .issuer.name, CertSHA256: .cert.sha256}' $tempdir/hostcert.json | tr -d '}"{,' |
sed 's/^ *//' | sed '/^$/d' | sed 's/CertSHA256:/CertSHA-256:/' | sed '/Subject:/{x;p;x;}' | sed '/CertSHA-256:/{x;p;x;}' | tee -a ${out}; else 
declare -a curl_array=() ; curl_array+=(-sLk4v) ; error_code=6 ; curl -s -f -L -k ${x} > /dev/null
if [ $? = ${error_code} ]; then
echo -e "\n${R} $x WEBSITE CONNECTION: FAILURE${D}\n\n"
echo -e "\n $x WEBSITE CONNECTION: FAILURE\n" >> ${out} ; exit 1 ; else
curl -s https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht} > $tempdir/ww.txt
f_writeOUT "${x}" ; f_HEADERS "$x" > ${outdir}/HEADERS.${x}.txt ; f_ROBOTS "${x}" ; fi
test_url=`grep "URL:" $tempdir/response | cut -d ':' -f 2- |  cut -d '/' -f 3 | sed 's/^[ \t]*//;s/[ \t]*$//'`
curl -s -f -L -k ${test_url} > /dev/null
if [ $? = ${error_code} ]; then
target_url=`echo $x` ; else
target_url=`echo $test_url` ; fi
domain1=$(grep 'Connected to' $tempdir/curl_trimmed | cut -d ' ' -f 3 | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '/' -f 4- |
cut -d '.' -f 1,2 | rev | head -1)
domain2=$(grep 'Connected to' $tempdir/curl_trimmed | cut -d ' ' -f 3 | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1  | rev | cut -d '/' -f 4- |
cut -d '.' -f 1,2 | rev | tail -1)
host4=$(dig +short $x) ; host6=$(dig aaaa +short $x)
f_STATUS "${x}" | tee -a ${out} ; declare -a  hping_array=() ; hping_array+=(-c 4)
for a in $host4 ; do
curl -s http://ip-api.com/json/${a}?fields=16985627  > $tempdir/geo.json
hosting=`jq -r '.hosting' $tempdir/geo.json` ; geo_c=`jq -r '.countryCode' $tempdir/geo.json`
echo '' ; f_Long; echo "[+] $a | $geo_c | Hosting: $hosting" ; f_Long ; f_serverInfoHEADER "${a}"
f_DRWHO "${a}" ; cat $tempdir/revwhois_temp.txt >> $outdir/WHOIS.${x}.txt
if [ $option_ping = "y" ] ; then
f_HTTPing "${a}" ; fi ; f_serverINFO "${a}" ; done | tee -a ${out}
if [ -n "$host6" ] ; then
declare -a hping_array=() ; hping_array+=(-6 -c 4)
for z in $host6 ; do
curl -s http://ip-api.com/json/${z}?fields=16985627  > $tempdir/geo.json
hosting=`jq -r '.hosting' $tempdir/geo.json` ; geo_c=`jq -r '.countryCode' $tempdir/geo.json`
echo '' ; f_Long; echo "[+] $z | $geo_c | Hosting: $hosting" ; f_Long ; f_serverInfoHEADER "${z}"
f_DRWHO "${z}" ; cat $tempdir/revwhois_temp.txt >> $outdir/WHOIS.${x}.txt
if [ $option_ping = "y" ] ; then
f_HTTPing "${z}" ; fi ; f_serverINFO "${z}" ; done | tee -a ${out} ; fi
f_PAGE "${x}" | tee -a ${out} ; echo '' | tee -a ${out} ; fi 
f_DNS "${x}" | tee -a ${out}
if [ $option_zone = "2" ] || [ $option_zone = "3" ] ; then
f_Long | tee -a ${out} ; echo -e "[+] ZONE TRANSFER" | tee -a ${out} ; f_Long | tee -a ${out}
curl -s https://api.hackertarget.com/zonetransfer/?q=${x}${api_key_ht} > $tempdir/zone.txt
echo '' >> $tempdir/zone.txt ; cat $tempdir/zone.txt | tee -a ${out} ; fi
if ! [ $option_connect = "9" ] ; then
echo '' | tee -a ${out} ; f_certINFO "${domain1}" | tee -a ${out}
if [ $domain1 != $domain2 ] ; then
echo '' | tee -a ${out} ; f_certINFO "${domain2}" | tee -a ${out} ; fi
if ! [ $option_testSSL = "9" ] ; then
f_testSSL "${domain1}" | tee -a ${out}
if [ $domain1 != $domain2 ] ; then
echo '' | tee -a ${out} ; f_testSSL "${domain2}" | tee -a ${out} ; fi ; fi ; fi 
curl -s "https://api.certspotter.com/v1/issuances?domain=${x}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert" > $tempdir/certs.json
f_cSPOTTER >> ${outdir}/CERTIFICATE_ISSUANCES.${x}.txt
if [ $option_subs = "1" ] || [ $option_subs = "2" ]  ; then
f_Long | tee -a ${out} ; echo -e "[+] $x | SUBDOMAINS (IPv4)" | tee -a ${out} ; f_Long | tee -a ${out}
curl -s https://api.hackertarget.com/hostsearch/?q=${x}${api_key_ht} > $tempdir/subs.txt
sort -t ',' -k 2 -V  $tempdir/subs.txt | cut -d ',' -f 1 | tr -d ' ' > $tempdir/hostsnames.txt
sed 's/^[ \t]*//;s/[ \t]*$//' $tempdir/hostsnames.txt | sed '/^$/d' | sort -f -u $tempdir/hostsnames.txt > $tempdir/hosts_ip4.txt
sort -t ',' -k 2 -V  $tempdir/subs.txt | sed 's/,/ => /'  | awk '{print $3 "\t\t" $2 "\t" $1}' > $tempdir/subs_sorted.txt
cat $tempdir/subs_sorted.txt | tee -a ${out}
egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/subs_sorted.txt >> $tempdir/ips.list
echo -e "\nSource > hackertarget.com" | tee -a ${out}
if ! [ $option_connect = "9" ] ; then
f_Short | tee -a ${out}
nmap -Pn -sn $x --script hostmap-crtsh 2>/dev/null > $tempdir/crt_results
cat $tempdir/crt_results | sed '/subdomains:/d' | sed '/hostmap-crtsh:/d' | grep '|' | tr -d '|_' | sed 's/\\n/\n/g' | sed 's/^ *//g' |
sed 's/*.//g' | grep -v '@' | sed '/^$/d' | tr -d ' ' | sort -u > $tempdir/crt_hosts.txt
dig @1.1.1.1 +noall +answer +nottlid +noclass -f $tempdir/crt_hosts.txt | sed '/CNAME/d' | sed '/NS/d' > $tempdir/crt_resolved.txt
cat $tempdir/crt_resolved.txt | tr -d ' ' | sed 's/A/,/g' | sort -t ',' -k 2 -V  | sed 's/,/ => /g' | egrep -s '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
awk '{print $3 "\t\t" $2 "\t" $1}' | tee -a ${out} ; echo '' | tee -a ${out}
cat $tempdir/crt_results | grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | sort -u -V | tee -a ${out}
echo -e "\nSource > crt.sh" | tee -a ${out} ; f_Short | tee -a ${out}
curl -s "https://api.sublist3r.com/search.php?domain=$x" > $tempdir/sublist.json
jq -r '.[]' $tempdir/sublist.json | sort > $tempdir/sublister.list
dig @1.1.1.1 -t a +noall +answer +noclass +nottlid -f $tempdir/sublister.list > $tempdir/sublister_resolved.list
cat $tempdir/sublister_resolved.list | sed 's/A/,/' | sed '/NS/d' | sed '/CNAME/d' |
tr -d ' ' | sort -t ',' -k 2 -V  | sed 's/,/ => /' | egrep -s '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
awk '{print $3 "\t\t" $2 "\t" $1}' | tee $tempdir/sublister_subs.txt ; cat $tempdir/sublister_subs.txt >> ${out}
cat $tempdir/sublister.list > $tempdir/hostnames.txt
cat $tempdir/hostnames.txt | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | sort -f -u  >> $tempdir/hosts_ip4.txt
cat $tempdir/sublister_subs.txt | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -V >> $tempdir/ips.list
echo -e "\nSource > https://api.sublist3r.com\n" | tee -a ${out} ; fi ; fi 
sort -t . -k 1,1n -k 2,2n -k 3,3n -u $tempdir/ips.list > $tempdir/ips_sorted.list
f_Long | tee -a ${out}; echo "[+] $x | NETWORKS | ORGANISATIONS | AS" | tee -a ${out}; f_Long | tee -a ${out}; echo '' | tee -a ${out}
f_whoisTABLE "$tempdir/ips_sorted.list " ; cat $tempdir/whois_table.txt | cut -d '|' -f -5 | tee -a ${out}
cat $tempdir/whois_table.txt | sed '/Microsoft/d' | sed '/Cloudflare/d' | sed '/Amazon.com/d' | sed '/AMAZO-*/d' | sed '/Google LLC/d' |
sed '/MICROSOFT/d' | sed '/GOOGLE-CLOUD/d' | sed '/[Dd]igital[Oo]cean/d' | cut -d '|' -f 2 | sed '/IP/d' | sed '/^$/d' | tr -d ' ' > $tempdir/whois_table.list
sort -t . -k 1,1n -k 2,2n -k 3,3n -u $tempdir/whois_table.list > $tempdir/v4_addresses.list ; echo '' | tee -a ${out}
cut -d '|' -f 1 $tempdir/whois_table.txt | sed '/AS/d' | sed '/^$/d' | tr -d ' ' | sort -u -n >> $tempdir/asnums.list
address_count=$(cat $tempdir/v4_addresses.list | wc -w)
if [[ $address_count -gt 10 ]] ; then
cat $tempdir/v4_addresses.list | sort -t . -k 1,1n -k 2,2n -u > $tempdir/lookup.list ; else
cat $tempdir/v4_addresses.list > $tempdir/lookup.list ; fi
for l in $(cat $tempdir/lookup.list) ; do
f_NETshort "${l}" >> $tempdir/net_lookup.txt ; done
if [ -f "$tempdir/net6.list" ] ; then
for z in $(cat $tempdir/net6.list) ; do
echo '' ; f_NETshort "${z}" ; done | tee -a ${out} ; fi ; f_Long | tee -a ${out}
for n in $(cat $tempdir/netranges.list | cut -d '/' -f 1 | tr -d ' ') ; do
ipcalc "${n}" | sed '/deaggregate/d' >> $tempdir/nets.list ; done
echo -e "* Networks (CIDR)\n" | tee -a ${out} ; sort -u -V $tempdir/nets.list | tee -a ${out}
echo '' | tee -a ${out} ; asns=`cat $tempdir/asnums.list | sort -g -u`
for a in $asns ; do
f_AS_SUMMARY "${a}" ; done | tee -a ${out}
if [ $option_whois = "y" ] ; then
ips=$(cat $tempdir/whois_table.txt | sed '/NET NAME/d' | sort -t '|' -k 5 -u -V | cut -d '|' -f 2 | tr -d ' ' | sed '/^$/d')
echo '' | tee -a ${out}
for i in $ips ; do
echo '' ; f_whoisCONTACTS "${i}" ; done | tee -a ${out} ; fi ; echo '' | tee -a ${out}
cat $tempdir/net_lookup.txt | tee -a ${out}
if ! [ $option_connect = "9" ] ; then
if [ $domain1 != $domain2 ] ; then
f_Long | tee -a ${out} ; echo -e "[+] $domain2 |  WHOIS" | tee -a ${out} ; f_Long | tee -a ${out}
f_whoisLOOKUP "${domain2}"; cat $tempdir/whois3.txt | tee -a ${out}; echo '' | tee -a ${out}
f_Long >>  $outdir/WHOIS.${x}.txt ; echo -e "$x | WHOIS" >> $outdir/WHOIS.${x}.txt ; f_Long >> $outdir/WHOIS.${x}.txt
cat $tempdir/whois3.txt >> $outdir/WHOIS.${x}.txt
if [ $option_subs = "2" ] ; then
f_Long | tee -a ${out}; echo -e "[+] IPv6 Subdomains" | tee -a ${out}; f_Long | tee -a ${out}
dig @1.1.1.1 -t aaaa +noall +answer +noclass +nottlid -f $tempdir/hosts_ip4.txt | sed 's/AAAA/,/' | sed '/NS/d' > $tempdir/ipv6_hosts.txt
cat $tempdir/ipv6_hosts.txt | tr -d ' '  | cut -s -d ',' -f 2 - | sed '/CNAME/d'  | sort -f -u > $tempdir/ip6.txt
cat $tempdir/ipv6_hosts.txt | sed 's/,/\t\t/' | tee -a ${out}
f_Short | tee -a ${out} ;  echo -e "\n* IPv6 Network Portions\n\n" | tee -a ${out}
net_portions=$(/usr/bin/atk6-extract_networks6 $tempdir/ip6.txt | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -V -u)
echo "$net_portions" | tee -a ${out} ; fi ; fi ;  echo ''
cat $tempdir/LINKS.${x}.txt | tee -a ${out} ; fi ; done ; echo '' ; f_removeDir ; f_Menu
;;
2) f_options_NSSERVERS ;;
3) f_optionsWhois ;;
4) f_optionsIPV4 ;;
5)
f_makeNewDir ; f_Long
echo -e -n "${B}\nTarget > ${D} e.g. UA-123456 or pub-00123456789 ${B}>>${D}  " ; read gooid
out="$outdir/Rev_GoogleAnalytics.txt" ; f_Long | tee -a ${out}
echo -e " $gooid | REVERSE GOOGLE ANALYTICS LOOKUP" | tee -a  ${out} ; f_Long | tee -a ${out}
curl -s https://api.hackertarget.com/analyticslookup/?q=${gooid} | tee -a ${out}
echo -e "\nSource > hackertarget.com\n" | tee -a ${out} ; f_removeDir ; f_Menu
;;
6) f_optionsIPV6 ;;
7) f_optionsWEB ;;
22)
f_makeNewDir ; f_Long ; declare -a dig_array=() ; type_hop="false"
if [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Options >${D} Show additional server, geolocation & whois information? ${B}[y] | [n]  ?${D}  " ; read option_dnsdetails
echo -e "\n${B}Options  > MX, NS > ${D}\n"
echo -e "${B} [1]${D} Check SPAM Blocklists" ; echo -e "${B} [2]${D} Check for unauthorized zonetransfers"
echo -e "${B} [3]${D} BOTH" ; echo -e "${B} [9]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_zone ; else
echo -e -n "\n${B}Option  >${D} Customize Enumeration Options  ${B}[y] | [n]  ?${D}  " ; read option_lookup
if [ $option_lookup = "n" ] ; then
dig_array+=(+noall +answer +noclass +nottlid) ; option_dnsdetails="n"
option_zone="9"; option_nmap="9" ; option_ns="1" ; else
echo -e "\n${B}Nameservers (System Defaults)${D}\n" ; f_systemDNS
echo -e "\n\n${B}Options > Nameservers ${B}>\n"
echo -e "${B} [1]${D} Use system defaults" ; echo -e "${B} [2]${D} 9.9.9.9"
echo -e "${B} [3]${D} 1.1.1.1" ; echo -e "${B} [4]${D} Set custom NS" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ns
if [ $option_ns = "2" ] ; then
dig_array+=(@9.9.9.9) ; nssrv="@9.9.9.9"
elif [ $option_ns = "3" ] ; then
dig_array+=(@1.1.1.1) ; nssrv="@1.1.1.1"
elif [ $option_ns = "4" ] ; then
echo -e -n "\n${B}Set     >${D} Nameserver  ${B} >>${D}   " ; read ns_input
dig_array+=(@nssrv) ; nssrv="@${ns_input}" ; else
nssrv="" ; fi ; dig_array+=(+noall +answer +noclass)
echo -e -n "\n${B}Option > [1]${D} TTL values (ms) ${B}| [2]${D} TTL values (human readable) ${B}| [3]${D} BOTH ${B}| [9]${D} SKIP ${B}?${D}  " ; read option_ttl
if [ $option_ttl = "1" ] || [ $option_ttl = "3" ] ; then
dig_array+=(+ttlid)
elif [ $option_ttl = "2" ] ; then
dig_array+=(+ttlunits) ; else
dig_array+=(+nottlid) ; fi
echo -e -n "\n${B}Options >${D} Show additional server, geolocation & whois information? ${B}[y] | [n]  ?${D}  " ; read option_dnsdetails
echo -e "\n${B}Options  > MX, NS > ${D}\n"
echo -e "${B} [1]${D} Check SPAM Blocklists" ; echo -e "${B} [2]${D} Check for unauthorized zonetransfers"
echo -e "${B} [3]${D} BOTH" ; echo -e "${B} [9]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_zone ; fi ; fi
echo -e -n "\n${B}Target  > [1]${D} Set target Domain ${B}| [2]${D} Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE ${B}>>${D}  " ; read input
hosts="${input}" ; else
echo -e -n "\n${B}Target  > ${D}Domain  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/hosts.list ; hosts="$tempdir/hosts.list" ; fi
for x in $(cat $hosts) ; do
out="${outdir}/DNS.${x}.txt" ; f_Long | tee -a ${out}; echo "[+] $x DNS RECORDS" | tee -a ${out}; f_Long | tee -a ${out}
f_DNS "${x}" | tee -a ${out} ; done ; echo '' | tee -a ${out} ; f_removeDir ; f_Menu
;;
23)
f_makeNewDir ; f_Long
echo -e "\n${B}Options > dig >${D} Queries/ Record Types ${B}>\n "
echo -e "${B} [1]${D} A" ; echo -e "${B} [2]${D} AAAA"
echo -e "${B} [3]${D} SRV (input > Hostnames)" ; echo -e "${B} [4]${D} NSSEC (input > NS Hostnames)"
echo -e "${B} [5]${D} Lookup Delegation Tracing (input > Hostnames, IP Addresses)"
echo -e -n "\n${B}  ? ${D}  " ; read option_record
echo -e -n "\n${B}dig Batch Mode > Input >${D} PATH TO FILE  ${B}>>${D}  " ; read input
if [ $report = "true" ] ; then
echo -e -n "\n${B}dig Batch Mode > Output >${D} FILE NAME  ${B}>>${D}  " ; read output
out="${outdir}/${output}.txt" ; else
out="$tempdir/out25.txt" ; fi
echo -e "\n${B}Nameservers (System Defaults)${D}\n" ; f_systemDNS
echo -e "\n${B}Options > ${D} Nameservers ${B}>\n"
echo -e "${B} [1]${D} Use system defaults" ; echo -e "${B} [2]${D} 9.9.9.9"
echo -e "${B} [3]${D} 1.1.1.1" ; echo -e "${B} [4]${D} Set custom NS"
echo -e -n "\n${B}  ? ${D}  " ; read option_ns
if [ $option_ns = "2" ] ; then
dig_array+=(@9.9.9.9) ; nssrv_dig="@9.9.9.9"
elif [ $option_ns = "3" ] ; then
dig_array+=(@1.1.1.1) ; nssrv_dig="@1.1.1.1"
elif [ $option_ns = "4" ] ; then
echo -e -n "\n${B}Set     >${D} Nameserver  ${B} >>${D}   " ; read nssrv
dig_array+=(@nssrv) ; nssrv_dig="@${nssrv}" ; else
nssrv_dig="" ; fi
if [ $option_record = "1" ] ; then
record="A"
elif [ $option_record = "2" ] ; then
dig_array+=(aaaa) ; record="AAAA"
elif [ $option_record = "3" ] ; then
dig_array+=(srv) ; record="SRV"
elif [ $option_record = "4" ] ; then
dig_array+=(nsec) ; record="NSEC"
elif [ $option_record = "5" ] ; then
dig_array+=(trace) ; fi
if [ $option_record = "1" ] || [ $option_record = "2" ] ; then
echo -e -n "\n${B}Option > Output > [1]${D} Short Mode  ${B}| [2]${D} Record Type & Query Address / URL ${B}?${D}  " ; read option_short
if [ $option_short = "2" ] ; then
dig_array+=(+noall +answer +noclass +nottlid) ; else
dig_array+=(+short) ; fi ; fi
if [ $option_record = "6" ] ; then
echo -e -n "\n${B}Option > ${D} DNS Delegation Tracing  >  Show DNSSEC Records   ${B}[y] | [n] ?${D}  " ; read option_dnssec
if [ $option_dnssec = "y" ] ; then
record="A, DNSSEC, RRSIG, Delegation Tracing" ; dig_array+=(+nocmd +noall +answer +noclass +split=4) ; else
record="A, Delegation Tracing" ; dig_array+=(+nocmd +noall +answer +noclass +nodnssec) ; fi ; fi
f_Long | tee -a ${out} ; echo -e " [dig BATCH MODE] | RECORD TYPE: $record" | tee -a ${out}; f_Long | tee -a ${out}
dig ${dig_array[@]} -f ${input} | tee -a ${out} ; echo '' | tee -a ${out} ; f_removeDir ; f_Menu
;;
24)
#****** 24) DISCOVER DOMAINS SHARING A COMMON WEBSERVER ******
f_makeNewDir ; f_Long
echo -e "\n${B}Shared DNS Server (Source: hackertarget.com)${D}\n"
echo -e -n "\n${B}Target >${D} Nameserver ${B}>>${D}  " ; read targetNS ; echo ''
out="${outdir}/Domains_sharing_${targetNS}"
f_Long | tee -a ${out}; echo -e "[+] SHARED NAME SERVER $targetNS | DOMAINS, HOST IPv4, NETWORKS, ORGS" | tee -a ${out}
f_Long | tee -a ${out}; curl -s https://api.hackertarget.com/findshareddns/?q=${targetNS}${api_key_ht} > $tempdir/sharedns
echo -e "begin\ntype=cymru" > $tempdir/ip.list
dig +noall +answer +noclass +nottlid -f $tempdir/sharedns | tee $sharedns_hosts.txt
cat $sharedns_hosts.txt >> ${out} ; f_Long | tee -a ${out}
egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $sharedns_hosts.txt |
sort -t . -k 1,1n -k 2,2n -k 3,3n -u >> $tempdir/ip.list
echo "end" >> $tempdir/ip.list
netcat whois.pwhois.org 43 < $tempdir/ip.list  > $tempdir/whois_table.txt
echo -e "${B}pwhois.org Bulk Lookup${D}\n" ; echo -e "[+] pwhois Bulk Lookup\n" >> ${out}
cat $tempdir/whois_table.txt | cut -d '|' -f 1,2,3,4,6 | sed '/Bulk mode; one IP/d' |
sed '/ORG NAME/{x;p;x;G;}' | tee -a ${out}
echo '' | tee -a ${out} ; f_removeDir ; f_Menu
;;
25)
f_makeNewDir ; f_Long
if [ $option_connect = "9" ] ; then
option_zone="3" ; else
echo -e "\n${B}Options >\n"
echo -e "${B} [1]${D} Zonewalk"
echo -e "${B} [2]${D} Zonetransfer [dig]"
echo -e "${B} [3]${D} Zonetransfer [hackertarget.com API]"
echo -e -n "\n${B}  ? ${D}  " ; read option_zone ; fi
echo -e -n "\n${B}Target >${D} DOMAIN ${B}>>${D}  " ; read target
out="${outdir}/NS.$target.txt"
if [ $option_zone = "1" ] ; then
echo -e -n "\n${B}Target >${D} NAME SERVER ${B}>>${D}  " ; read target_ns
f_Long | tee -a ${out}; echo "[+] $target | ZONEWALK | NS: $target_ns | $(date)" | tee -a ${out} ; f_Long | tee -a ${out}
echo '' | tee -a ${out}
sudo nmap -sSU -p 53 --script dns-nsec-enum --script-args dns-nsec-enum.domains=$target $target_ns | tee -a ${out} ; fi
if [ $option_zone = "2" ] ; then
echo -e -n "\n${B}Server > [1]${D} All NS records ${B}| [2]${D} specific name server  ${B}?${D}  " ; read option_ns
if   [ $option_ns = "2" ] ; then
echo -e -n "\n${B}Target >${D} NAME SERVER ${B}>>${D}  " ; read target_ns ; echo ''
dig axfr @${target_ns} $target | tee -a $out ; else
dig ns +short $target | rev | cut -c  2- | rev > $tempdir/ns.txt
for i in $(cat $tempdir/ns.txt); do
dig axfr @${i} $target ; done | tee -a ${out} ; fi ; fi
if [ $option_zone = "3" ] ; then
f_Long | tee -a ${out}; echo "[+] $target | ZONE TRANSFER" | tee -a ${out}; f_Long | tee -a ${out}
curl -s https://api.hackertarget.com/zonetransfer/?q=${target}${api_key_ht}  | tee -a ${out}
echo '' | tee -a ${out} ; fi ; f_removeDir ; f_Menu
;;
31)
f_makeNewDir ; f_Long ; out="${outdir}/DOMAIN_WHOIS.txt"
echo -e -n "\n${B}Target > [1]${D}  Set Target Domain ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D} DOMAIN   ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; else
echo -e -n "\n${B}Target > ${D}PATH TO FILE  ${B}>>${D} " ; read input ; fi
for x in $(cat $targets) ; do
echo '' | tee -a ${out}; f_Long | tee -a ${out} ; echo -e "[+] $x |  WHOIS" | tee -a ${out} ; f_Long | tee -a ${out}
f_whoisLOOKUP "${x}" ; cat $tempdir/whois3.txt | tee -a ${out} ; done
echo '' ; f_removeDir ; f_Menu ; f_optionsWhois
;;
32)
f_makeNewDir ; f_Long
echo -e "\n${B}pwhois.org Bulk Lookup (IPv4/IPv6)\n"
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}   " ; read input
echo -e -n "\n${B}Set   > ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename
out="${outdir}/WHOIS/${filename}.txt"
echo -e "\n${B}Option > pwhois Output >\n"
echo -e "${B} [1]${D}  Default" ; echo -e "${B} [2]${D}  Type Cymru (Table Layout)"
echo -e "${B} [3]${D}  BOTH" ; echo -e -n "\n${B}  ?${D}  " ; read option_pwhois
if [ $option_pwhois = "1" ] || [ $option_pwhois = "3" ] ; then
f_pwhoisBULK "${input}" | tee -a ${out} ; fi
if [ $option_pwhois = "2" ] || [ $option_pwhois = "3" ] ; then
f_Long | tee -a ${out}; f_whoisTABLE  "${input}" ; cat $tempdir/whois_table.txt | tee -a ${out} ; fi ; echo '' ; f_removeDir ; f_Menu
;;
33)
f_makeNewDir ; f_Long ; out="$tempdir/out33.txt"
echo -e "\n${B}Options > Sources > whois Servers >\n"
echo -e "${B} [1]${D}  RIPE" ; echo -e "${B} [2]${D}  AFRINIC"
echo -e "${B} [3]${D}  APNIC" ; echo -e -n "\n${B}   ?${D}  " ; read rir
if [ $rir = "1" ] ; then
reg="RIPE" ; regserver="whois.ripe.net"
elif [ $rir = "2" ] ; then
reg="AFRINIC" ; regserver="whois.afrinic.net"
elif [ $rir = "3" ] ; then
reg="APNIC" ; regserver="whois.apnic.net" ; else
regserver="whois.pwhois.org" ; fi ; f_Short
echo -e "For ${B}inverse Lookups${D} use the following syntax:\n"
echo "ObjectType;SearchTerm  -  e.g.  admin-c;JohnDoeXY-RIPE" ; f_Short
echo -e -n "\n${B}Target  > [1]${D} Set target ${B}| [2]${D} Read from file  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE  ${B}>>${D}   " ; read input
targets="${input}" ; else
echo -e -n "\n${B}Target  > ${D}SEARCH TERM  ${B}>>${D} " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; fi
if [ $option_target = "2" ] && [ $report = "true" ] ; then
echo -e -n "\n${B}Set   > ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename ; fi
headl="$tempdir/headline"
echo -e "\n${R}Warning: ${D} Exzessive searches for contact details are considered abusive."
echo -e "\n${B}Options > PoC Details > \n"
echo -e "${B} [1]${D} Net-Ranges & Abuse Contacts only"
echo -e "${B} [2]${D} Net-Ranges & Full Contact Details"
echo -e -n "\n${B}   ?${D}  " ; read option_poc
echo -e "\n${B}Options > Output >\n${D}"
echo -e "${B} [1]${D} Summary" ; echo -e "${B} [2]${D} Summary & Object Details (inverse search only)"
echo -e "${B} [3]${D} Summary & Full Output"
echo -e -n "\n${B}   ?${D}  " ; read option_results
echo '' > ${headl}; f_Long | tee -a ${headl}; echo -e "WHOIS | OBJECT & INVERSE SEARCHES  [$regserver]" | tee -a ${headl}
f_Long | tee -a ${headl}; echo -e "Searching...\n" | tee -a ${headl} ; cat $targets | tee -a ${headl}
for x in $(cat $targets) ; do
if [[ "$x" == *';'* ]] ; then
iSearch="true" ; query_type=`echo "$x" | cut -d ';' -f 1` ; obj=`echo "$x" | cut -d ';' -f 2`
if [ $query_type = "org" ] ; then
echo "$obj" | tr -d ' ' >> $tempdir/orgs.list ; fi
if [ $option_target = "1" ] ; then
filename=`echo $x | cut -d ';' -f 2- | tr -d ' '` ; fi ; else
iSearch="false"
if [ $option_target = "1" ] ; then
filename=`echo $x | cut -d '/' -f 1 | tr -d ' '` ; fi ; fi
if [ $iSearch = "true" ] ; then
if [ $option_poc = "2" ] ; then
whois -h ${regserver} -- "-B -i ${query_type} ${obj}" | sed 's/% Information related/Information related/' | sed '/Source:/d' |
sed 's/% Abuse contact/Abuse contact/' | sed '/mnt-ref:/d' | sed '/remarks:/d' | sed '/fax:/d' | sed '/^#/d' | sed '/%/d' |
sed '/^$/d' | sed '/Abuse contact/G' | sed 's/Abuse contact for .*. is/\[@\] /' |
sed '/Information related/i \_________________________________________________________\n' | sed '/Information related to /G' |
sed 's/Information related to /* /'  >> $tempdir/who1.txt ; else
whois -h ${regserver} -- "-F -i ${query_type} ${obj}"  | tr -d '*' | sed 's/^ *//' | sed 's/% Information related/Information related/' |
sed 's/%Abuse contact/Abuse contact/' | sed '/lm:/d' | sed '/%/d' | sed '/st:/d' |  sed '/so:/d' | sed '/^$/d' |
sed '/Abuse contact/G' | sed '/Information related/i \_________________________________________________________\n' | sed '/Information related to/G' |
sed 's/Abuse contact for .*. is/\[@\] /' | sed 's/Information related to /* /' | tr -d "\'" >> $tempdir/who1.txt ; fi ; fi
if [ $iSearch = "false" ] ; then
if [ $option_poc = "2" ] ; then
whois -h ${regserver} -- "-B ${x}" | sed 's/% Information related to /Information related to /' | sed '/Source:/d' |
sed 's/% Abuse contact/Abuse contact/' | sed '/mnt-ref:/d' | sed '/remarks:/d' | sed '/fax:/d' | sed '/^#/d' | sed '/%/d' |
sed '/^$/d' | sed '/Abuse contact/{x;p;x;G;}' | sed 's/Abuse contact for .*. is/\[@\] /' |
sed '/Information related/i \_________________________________________________________\n' | sed '/Information related/G' |
sed 's/Information related to/* /' >> $tempdir/who1.txt ; else
whois -h ${regserver} -- "-F ${x}"  | tr -d '*' | sed 's/% Information related/Information related/' |
sed 's/% Abuse contact/Abuse contact/' | sed '/lm:/d' | sed '/%/d' | sed '/st:/d' | sed '/so:/d' | sed '/^$/d' |
sed '/Abuse contact/G' | sed '/Information related/i \_________________________________________________________\n' |
sed '/Information related to/G' | sed 's/Abuse contact for .*. is/\[@\]: /' |
sed 's/Information related to /* /' | tr -d "\'" >> $tempdir/who1.txt ; fi ; fi ; done
if [ $iSearch = "true" ] ; then
if [ $option_results = "2" ] ; then
cat $targets | cut -d ';' -f 2 | sort -u > $tempdir/objects.list
for o in $(cat $tempdir/objects.list) ; do
whois -h ${regserver} -- "-B ${o}" | sed 's/% Information related/Information related/' |
sed 's/% Abuse contact/Abuse contact/' | sed '/%/d' |  sed '/mnt-ref:/d' | sed '/source:/d' | sed '/remarks:/d' |  sed '/fax:/d' | sed '/^#/d' |
sed '/^%/d' | sed '/^$/d' | sed '/Information related/i \_________________________________________________________\n' > $tempdir/who2_raw.txt
cat $tempdir/who2_raw.txt | sed '/Abuse contact/G' | sed 's/Abuse contact for .*. is/\[@\]: /'  | sed 's/Information related to /* /' | tr -d "\'"  |
sed '/organisation:/{x;p;x;}' | sed '/person:/{x;p;x;}' | sed '/role:/{x;p;x;}' | sed '/route:/{x;p;x;}' | sed '/route6:/{x;p;x;}' |
sed '/inetnum:/{x;p;x;}' | sed '/inet6num/{x;p;x;}' | sed '/mntner:/{x;p;x;}' | sed '/as-set:/{x;p;x;}' | sed '/aut-num:/{x;p;x;}' |
sed '/domain:/{x;p;x;}' >> $tempdir/who2.txt ; done
cat $tempdir/who2.txt > $tempdir/full_output.txt ; fi ; fi
cat $tempdir/who1.txt >> $tempdir/full_output.txt
if [[ $(cat $tempdir/who1.txt | grep -s -E -c "^inet6num:|i6:") -gt "0" ]] ; then
echo -e "\n_____________________________________\n" | tee -a ${out} ; echo -e "[+] Network Ranges (IPv6)" | tee -a ${out}
grep -s -E -A 5 "^inet6num:|^i6:" $tempdir/who1.txt > $tempdir/i6nums
cat $tempdir/i6nums | grep -s -E -m 4 "^inet6num:|^netname:|^country:|^org-name:|^descr:|^i6:|^na:|^cy:|^og:|^de:" |
sed '/inet6num:/i \_____________________________________\n' | sed '/i6:/i \_____________________________________\n' |
cut -d ':' -f 2- | sed 's/^ *//' | tee -a ${out} ; fi
if [[ $(grep -s -E -c '^inetnum:|^in:' $tempdir/full_output.txt ) -gt "0" ]] ; then
echo -e "\n_____________________________________\n" | tee -a ${out} ; echo -e "[+] Network Ranges (IPv4)" | tee -a ${out}
grep -s -E -A 2 '^inetnum:|in:' $tempdir/full_output.txt > $tempdir/inetnums1
grep -s -E '^inetnum:|^in:' $tempdir/inetnums1  | cut -d ':' -f 2- | tr -d ' ' | cut -d '-' -f 1 > $tempdir/inetnums2
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u $tempdir/inetnums2 > $tempdir/inetnums_u4
grep -s -w '^inetnum:|^in:' $tempdir/inetnums1  | cut -d ':' -f 2- | tr -d ' ' | cut -d '-' -f 2 >> $tempdir/inetnums2
sort -t . -k 1,1n -k 2,2n -k 3,3n -u $tempdir/inetnums2 > $tempdir/inetnums_u3
for a in $(cat $tempdir/inetnums_u4) ; do
grep -s -m 1 -A 2 "${a}" $tempdir/inetnums1 >> $tempdir/netranges.txt
nrange=`grep -s -m 1 "${a}" $tempdir/inetnums1 | cut -d ':' -f 2- | tr -d ' '`
ipcalc ${nrange} | sed '/deaggregate/d' | tail -1 >> $tempdir/cidr ; done
cat $tempdir/netranges.txt | sed '/inetnum/i \_____________________________________\n' |
sed '/^in:/i \_____________________________________\n' | cut -d ':' -f 2- |
sed 's/^ *//' | tee -a ${out} ; rm $tempdir/netranges.txt
echo -e "_____________________________________\n\n* CIDR\n" | tee -a ${out}
cat $tempdir/cidr | tr -d ' '  | sort -u -V | tee -a ${out} ; fi
grep -s -E "^org:|^og:" $tempdir/full_output.txt > $tempdir/orgs.list
if [ -f "$tempdir/orgs.list" ] ; then
grep -s -E "^org:|^og:" $tempdir/full_output.txt | sed 's/og:/org:/' | tr ':' ';'  | tr -d ' ' | sort -uV > $tempdir/org_handles
orgids=`grep -s -E "^organisation:|^og:" $tempdir/full_output.txt | cut -d ':' -f 2- | sed 's/^ *//' |  tr ':' ';'  | tr -d ' ' | sort -uV`
for oid in $orgids ; do
echo '' ; f_netBLOCKS "${oid}" ; done | tee -a ${out} ; fi
if [ $option_poc = "1" ] ; then
f_Long | tee -a ${out} ; echo -e "[+] Abuse Contacts\n" | tee -a ${out}
cat $tempdir/full_output.txt | grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | sort -u | tee -a ${out} ; else
f_Long | tee -a ${out} ;  echo -e "[+] Points of Contact\n" | tee -a ${out}
grep -s -E "^role:|^person:" $tempdir/full_output.txt | cut -d ':' -f 2- | sed 's/^ *//' | sort -u | tee -a ${out}
echo '' | tee -a ${out}
grep -s "^nic-hdl:" $tempdir/full_output.txt | cut -d ':' -f 2- | sed 's/^ *//' | sort -u
echo '' | tee -a ${out}
grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/full_output.txt | sort -u | tee -a ${out} ; fi
echo -e "\n_________________________________________________________\n\n[+] $reg Object Handles\n" | tee -a ${out}
grep -s -E "^abuse-c:|^admin-c:|^mnt-by:|^org:|^tech-c:|^ac:|^tc:|^mb:|^og:" $tempdir/full_output.txt  |
sed 's/ac:/admin-c:/g' | sed 's/tc:/tech-c:/g' | sed 's/og:/org:/g' | sed 's/mb:/mnt-by:/g' | tr ':' ';' |
tr -d ' ' > $tempdir/handles.txt
sort -u $tempdir/handles.txt | tee -a ${out}
if cat $tempdir/full_output.txt | grep -q -E "^org-name:|^og:|^or:|^origin:"; then
echo -e "\n_________________________________________________________\n\n[+] Autonomous Systems & Organisations" | tee -a ${out}
echo -e "_________________________________________________________\n" | tee -a ${out}; echo -e "* ORGs\n" | tee -a ${out}
grep -s -E "^organisation:|^og:"  $tempdir/full_output.txt | sed 's/og:/org:/' | sed 's/organisation:/org:/' | tr ':' ';' |
tr -d ' '  | sort -u -V | tee -a ${out} ; fi
asns=$(grep -E "aut-num:|an:" $tempdir/full_output.txt | cut -d ':' -f 2- | sed 's/^ *//' | sort -u -V)
if [ -n "$asns" ] ; then
echo -e "\n\n* ASNs\n" | tee -a ${out}
for as in $asns ; do
dig +short $as.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' ; echo '' ; done | tee -a ${out} ; fi
if cat $tempdir/full_output.txt | grep -q -E "^ns:|^nserver:"; then
echo -e "\n\n* Name Servers\n" | tee -a ${out}
grep -s -E "^ns:|^nserver:" $tempdir/full_output.txt | cut -d ':' -f 2- | sed 's/^ *//' | sort -u -V  | tee -a ${out} ; fi
if [ $iSearch = "true" ] ; then
if ! [ $option_results = "1" ] ; then
echo -e "\n_________________________________________________________\n\n[+] Object Details" | tee -a ${out}
cat $tempdir/who2.txt | tee -a ${out} ; fi ; fi
if [ $option_results = "3" ] ; then
if [ $option_poc = "1" ] ; then
cat $tempdir/who1.txt | cut -d ':' -f 2- | sed 's/^ *//' | tr -d "\'" | tee -a ${out} ; else
cat $tempdir/who1.txt | sed 's/^ *//' | tr -d "\'" | sed '/organisation:/{x;p;x;}' | sed '/person:/{x;p;x;}' |
sed '/role:/{x;p;x;}' | sed '/route:/{x;p;x;}' | sed '/route6:/{x;p;x;}' | sed '/inetnum:/{x;p;x;}' | sed '/inet6num/{x;p;x;}' |
sed '/mntner/{x;p;x;}' | sed '/as-set/{x;p;x;}' | sed '/aut-num:/{x;p;x;}' | sed '/domain:/{x;p;x;}' | tee -a ${out} ; fi ; fi
cat $headl >> ${outdir}/WHOIS.${filename}.txt ; cat ${out} >> ${outdir}/WHOIS.${filename}.txt
cat $tempdir/who1.txt >> ${outdir}/WHOIS_full_out.txt ; f_removeDir ; f_Menu ; f_optionsWhois
;;
34)
f_makeNewDir ; f_Long ; type_net="true" ; out="$tempdir/out46.txt" 
echo -e -n "\n${B}Target  > [1]${D} Set target Network  ${B}|  [2]${D} Read from File  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e -n "\n${B}Target  > ${D}NETWORK ADDRESS (CIDR) ${B}  >>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; fi
if [ $report = "true" ] ; then
echo -e -n "\n${B}Set    > ${D}OUTPUT - FILE NAME ${B}>>${D}  " ; read filename
out="${outdir}/$filename.txt" ; fi
echo -e -n "\n${B}Options > ${D}Filter results ${B}[y] | [n]  ?${D}  " ; read option_filter
if [ $option_filter = "y" ] ; then
echo -e -n "\n${B}Filter  > ${D}Single Searchterm or csv - e.g. access,backbone,service  ${B}>>${D}  " ; read filter
echo "$filter" | tr -d ' ' | sed 's/,/\n/g' | tr -d ' ' > $tempdir/filters ; fi
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+] PREFIX ADDRESS SPACE" | tee -a ${out}; f_Long | tee -a ${out}
echo -e "\nSearching for ...\n" | tee -a ${out} ; cat $tempdir/filters | tee -a ${out}
echo -e "\nwithin\n" | tee -a ${out} ; cat $targets | tee -a ${out}
for x in $(cat "$targets") ; do
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+] $x | ADDRESS SPACE" | tee -a ${out}; f_Long | tee -a ${out}
f_address_spaceWHOIS "${x}" | tee -a ${out} ; done ; f_removeDir ; f_Menu
;;
35)
f_makeNewDir ; f_Long
echo -e -n "\n${B}Target > [1]${D} Set target ${B}| [2]${D} Read from file  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE  ${B}>>${D}   " ; read input
targets="${input}" ; else
echo -e -n "\n${B}Target  > ${D}SEARCH TERM ${B}>>${D} " ; read input
echo "$input" > $tempdir/targets.list
targets="$tempdir/targets.list" ; fi
for x in $(cat $targets) ; do
out="$outdir/WHOIS_arin.${x}.txt"
f_Long | tee -a ${out} ; echo -e "[+] $x (whois.arin.net)\n\n" | tee -a ${out}
f_ARIN_ORG "${x}" | tee -a ${out}
o_name=`cat $tempdir/arin_org.txt | grep -s -E "^OrgName:" | cut -d ':' -f 2- | sed 's/^ *//'`
f_Short | tee -a ${out}
whois -h whois.arin.net -- "z + > $x" > $tempdir/org_nets.txt
echo -e "[*] Networks | [source: whois.arin.net]\n\n" | tee -a ${out}
cat $tempdir/org_nets.txt | grep -s -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|^NetName:" | sed '/Ref:/d' |
sed '/NetName:/G' | cut -d ':' -f 2- | sed 's/^ *//' | tee -a ${out}
oid=`cat $tempdir/org_nets.txt | grep -s -E -m 1 "^OrgId:" | cut -d ':' -f 2- | sed 's/^ *//'`
f_Long | tee -a ${out} ; f_netBLOCKS "${oid}" | tee -a ${out}
f_Long | tee -a ${out} ; echo -e "[*] $x Points of Contact" | tee -a ${out}
m=`cat $tempdir/arin_org.txt | grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | grep -s -m1 'abuse' | sed 's/abuse//' | sed 's/^ *//'`
whois -h whois.arin.net -- "e + ${m}" | grep -s -E "^Name:|^Handle:|^Company:|^City:|^Country:|^Updated:|^Phone:|^Email:" |
sed 's/Name:/\n\nName:/' | tee -a ${out} ; done ; echo '' ; f_removeDir ; f_Menu ; f_optionsWhois
;;
36)
f_makeNewDir ; f_Long ; out="${outdir}/Netblocks.txt"
echo -e -n "\n${B}Target > [1]${D} Set target ${B}| [2]${D} Read from file  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE  ${B}>>${D}   " ; read input
targets="${input}" ; else
echo -e -n "\n${B}Target  > ${D}SEARCH TERM ${B}>>${D} " ; read input
echo "$input" > $tempdir/targets.list
targets="$tempdir/targets.list" ; fi
echo -e -n "\n${B}Options > ${D} Set country code to filter ORG-search results ${B}[y] | [n]  ?${D}  " ; read option_filter
if [ $option_filter = "y" ] ; then
echo -e -n "\n${B}Filter  > ${D}Country Code - e.g. de ${B}>>${D}  " ; read countrycode ; fi
filter=`echo $countrycode | tr [:lower:] [:upper:] | cut -d ' ' -f 1 | tr -d '.,' | tr -d ' '`
for oid in $(cat $targets) ; do
echo -e "\nSearching pwhois.org for $oid\n" | tee -a ${out}
whois -h whois.pwhois.org "registry org-name=${oid}" > $tempdir/pwhois_org
if [ $option_filter = "y" ] ; then
cat $tempdir/pwhois_org | grep -s -E -i -w "^Org-ID:|^Org-Name:|^Country:|^Geo-Country:" | sed 's/Org-Name://' |
sed 's/Country://' | sed 's/^ *//' | sed '/Org-ID/{x;p;x;}' | grep -E -w -B 2 "^${filter}" | sed '/--/d' | tee $tempdir/orgs_filtred
cat $tempdir/orgs_filtred >> ${out} ; else
cat $tempdir/pwhois_org | grep -s -E -i -w "^Org-ID:|^Org-Name:|^Country:|^Geo-Country:" | sed 's/Org-Name://' |
sed 's/Country://' | sed 's/^ *//' | sed '/Org-ID/{x;p;x;}' ; fi ; done | tee -a ${out}
for oid in $(cat $targets) ; do
f_netBLOCKS "${oid}" ; done | tee -a ${out} ; echo '' ; f_removeDir ; f_Menu ; f_optionsWhois
;;
37)
f_makeNewDir ; f_Long ; option_as_details="y"
echo -e -n "\n${B}Target > ${D} AS number -e.g. ${B}AS${D}36459 ${B}>> AS${D}" ; read asnum
out="${outdir}/AS.${asnum}" ; echo -e "${B}Options > \n"
echo -e " ${B}[1]${D} AS Overview"
echo -e " ${B}[2]${D} Announced Prefixes"
echo -e " ${B}[3]${D} AS Routing Consistency"
echo -e " ${B}[4]${D} AS Upstream Transit"
echo -e " ${B}[5]${D} Peers"
echo -e " ${B}[6]${D} AS Threatfeeds (SANS ISC)"
echo -e -n "\n  ${B}?${D}  " ; read option_as
if [ $option_as = "2" ] ; then
echo -e "\n${B}Options > List announced Prefixes > \n"
echo -e "${B} [1]${D} Prefixes only"
echo -e "${B} [2]${D} Prefixes, incl. Netname, Description & Country"
echo -e "${B} [9]${D} SKIP"
echo -e -n "\n${B}  ?${D}  " ; read option_prefix ; fi
echo '' ; dig +short AS${asnum}.asn.cymru.com TXT > $tempdir/cy_asn
as_name=`cat $tempdir/cy_asn | cut -d '|' -f 5 | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//'`
headline=`cat $tempdir/cy_asn | cut -d '|' -f -4 | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d'`
if [ $option_as = "1" ] ; then
f_Long | tee -a ${out}; echo -e "[+] AS $headline" | tee -a ${out}; f_Long | tee -a ${out}
f_asINFO | tee -a ${out} ; fi
if [ $option_as = "2" ] ; then
f_Long | tee -a ${out}; echo -e "[+] AS $headline  |  BGP PREFIXES" |  tee -a ${out}; f_Long | tee -a ${out}
if [ $option_prefix = "1" ] ; then
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS$asnum" > $tempdir/prefixes.json
echo -e "\n -- IPv6 --\n" | tee -a ${out}
jq -r '.data.prefixes[] | .prefix' $tempdir/prefixes.json | grep -E "*.:.*" | sort -V | tee -a ${out}
echo -e "\n -- IPv4 --\n" | tee -a ${out}
jq -r '.data.prefixes[] | .prefix' $tempdir/prefixes.json | grep -E -v "*.:.*" | sort -V | tee -a ${out} ; else
f_BGPviewPREFIXES | tee -a ${out} ; fi ; fi
if [ $option_as = "3" ] ; then
echo -e -n "\n${B}Options  > [1]${D} Prefixes ${B}| [2]${D} Im-/Exports ${B}| [3]${D} BOTH ${B}?${D}  " ; read option_as_route
f_Long | tee -a ${out}; echo -e "[+] AS $headline  |  AS ROUTING CONSISTENCY" | tee -a ${out}; f_Long | tee -a ${out}
f_AS_ROUTING_Cons "${asnum}" | tee -a ${out} ; fi
if [ $option_as = "4" ] ; then
f_Long | tee -a ${out}; echo -e "[+] AS $headline  |  UPSTREAM TRANSIT" | tee -a ${out}; f_Long | tee -a ${out}
curl -s https://api.bgpview.io/asn/${asnum}/upstreams > $tempdir/ups.json ; echo -e "\nUpstreams, v4\n_____________\n" | tee -a ${out}
jq -r '.data.ipv4_upstreams | .[] | .asn, .name, .description, .country_code' $tempdir/ups.json | sed 'n;n;n;G' | tee -a ${out}
echo -e "\nUpstreams, v6\n_____________\n" | tee -a ${out}
jq -r '.data.ipv6_upstreams | .[] | .asn, .name, .description, .country_code' $tempdir/ups.json | sed 'n;n;n;G' | tee -a ${out} ; fi
if [ $option_as = "5" ] ; then
curl -s https://api.bgpview.io/asn/${asnum}/peers > $tempdir/peers.json ; echo -e "\nPeers, v4\n__________\n" | tee -a ${out}
jq -r '.data.ipv4_peers | .[] | .asn, .name, .description, .country_code' $tempdir/peers.json | sed 'n;n;n;G' | tee -a ${out}
echo -e "\nPeers, v6\n__________\n" | tee -a ${out}
jq -r '.data.ipv6_peers | .[] | .asn, .name, .description, .country_code' $tempdir/peers.json | sed 'n;n;n;G' | tee -a ${out} ; fi
if [ $option_as = "6" ] ; then
f_Long | tee -a ${out}; echo -e "[+] AS $headline  | SANS ISC THREATFEEDS (max. Results: 30)" | tee -a ${out}
f_Long | tee -a ${out} ; curl -s "https://isc.sans.edu/api/asnum/30/${asnum}?json" > $tempdir/asfeed.json
jq -r '.[] | {IP: .ip, REPORTS:.reports, TARGETS: .targets, FIRST: .firstseen, LATEST: .lastseen}' asfeed.json | tr -d '},\"{' | sed '/^$/d' |
sed 's/^ *//' | sed 's/IP:/IP:     /' | sed 's/FIRST:/FIRST:  /' | sed 's/LATEST:/LATEST: /' |
sed '/LATEST:/a \\________________________\n' ; fi ; echo '' ; f_removeDir ; f_Menu ; f_optionsWhois
;;
38)
f_makeNewDir ; f_Long
echo -e -n "Target > ${D} IX ID - e.g. 25  ${B}>>${D}  " ; read ixid
out="${outdir}/IX.${ixid}.txt" ; curl -s "https://api.bgpview.io/ix/$ixid" > $tempdir/ix.json
f_Long | tee -a ${out}; echo -e " IX | IX-$ixid | $(jq -r '.data.name' $tempdir/ix.json)" | tee -a ${out}
f_Long | tee -a ${out} ; echo '' | tee -a ${out}
jq -r '.data | .name_full, .city, .country_code, .tech_email, .tech_phone, .website' $tempdir/ix.json | tee -a ${out}
echo -e "\nMembers:  $(jq -r '.data.members_count' $tempdir/ix.json)" | tee -a ${out}
echo -e -n "\nList all members  [y] [n]  ? " ; read option_members
if [ $option_members = "y" ] ; then
f_Short | tee -a ${out}; echo "[+] Members" | tee -a ${out};  jq -r '.data.members[]' $tempdir/ix.json | tr -d '{,\"}' |
sed 's/^ *//' | tee -a ${out} ; fi  ; echo '' ; f_removeDir ; f_Menu ; f_optionsWhois
;;
44)
f_makeNewDir ; f_Long ; touch $tempdir/targets.list ; type_net="false" ; domain_enum="false"
blocklists="$blocklists_regular" ; option_as_details="n"
echo -e "\n${B}Options > \n"
echo -e "${B} [1]${D} IPv4 Host Overview" ; echo -e "${B} [2]${D} IP Address & whois Details"
echo -e "${B} [3]${D} Virtual Hosts" ; echo -e "${B} [4]${D} Service Banners"
echo -e "${B} [5]${D} Blocklists & Threatfeeds" ; echo -e "${B} [6]${D} All"
echo -e -n "\n${B}  ?${D}   "  ; read option_enum
echo -e -n "\n${B}Target > [1]${D}  Set Target ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D}IPv4 ADDRESS ${B}|${D} HOSTNAME  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE  ${B}>>${D} " ; read input
targets="${input}" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
for x in $(cat "$targets") ; do
if [ $option_enum = "5" ] || [ $option_enum = "6" ] ; then
curl -s "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${x}" > $tempdir/ac.json
curl -s "https://isc.sans.edu/api/ip/${x}?json" > $tempdir/iscip.json
curl -s "https://isc.sans.edu/api/ipdetails/${x}?json" > $tempdir/ipdetails.json ; fi
if [ $option_enum = "6" ] ; then
out="${outdir}/ENUM_AND_THREAT_EVAL.${x}.txt" ; fi
if [ $option_enum = "1" ] ; then
curl -s "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${x}" > $tempdir/ac.json
out="$outdir/IPv4_SUMMARIES.txt"
elif [ $option_enum = "2" ] ; then
out="${outdir}/WHOIS.${x}.txt"
elif [ $option_enum = "3" ] ; then
out="${outdir}/VHOSTS.${x}.txt" ; else
out="${outdir}/ENUM.${x}.txt" ; fi
curl -s http://ip-api.com/json/${x}?fields=21180379 > $tempdir/geo.json
if [[ "$x" =~ $REGEX_IP4 ]] ; then
ip4=`echo $x` ; else
ip4=`jq -r '.query' $tempdir/geo.json` ; fi
f_BOGON "${ip4}" ; asno=`jq -r '.as' $tempdir/geo.json | cut -d ' ' -f 1 | sed 's/AS/AS /'`
echo '' ; f_Long | tee -a ${out} ; if [[ "$x" =~ $REGEX_IP4 ]] ; then
echo "$x | BOGON: $is_bogon $(f_TOR "${x}") | $(jq -r '.countryCode' $tempdir/geo.json) | $(date)" | tee -a ${out} ; else
echo "$x | IP: $ip4 | $(jq -r '.countryCode' $tempdir/geo.json) | $asno | $(date)" | tee -a ${out} ; fi
if [ $option_enum = "1" ] || [ $option_enum = "5" ] ; then
f_abxHEADER "${ip4}" | tee -a ${out} ; f_serverINFO "${ip4}" | tee -a ${out}
if [ $option_enum = "5" ] ; then
f_THREAT_ENUM "${ip4}" | tee -a ${out}; fi ; fi
if [ $option_enum = "2" ] || [ $option_enum = "6" ] ; then
f_Long | tee -a ${out} ; f_DRWHO "${ip4}" ;  f_hostSUMMARY "${ip4}" | tee -a ${out}; f_serverPROTOCOLS "${ip4}" | tee -a ${out}
if [ $option_enum = "6" ] ; then
f_BANNERS "${x}" | tee -a ${out}; f_THREAT_ENUM "${ip4}" | tee -a ${out}; fi
f_netINFO "${ip4}" | tee -a ${out} ; f_Long | tee -a ${out}; f_DNS_CHAIN "${ip4}" | tee -a ${out}
echo '' | tee -a ${out}; f_DELEGATION "${ip4}" | tee -a ${out}
if [ $option_enum = "6" ] ; then
f_Long | tee -a ${out}; echo -e "* Network Geographic Distribution\n" | tee -a ${out}
curl -s https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${x} > $tempdir/netloc.json
locations=`jq -r '.data.located_resources[].locations | .[]' $tempdir/netloc.json`
echo "$locations" | jq -r '{Country: .country, City: .city, Net: .resources[], Lat: .latitude, Lon: .longitude}' |
tr -d '},"{' | sed '/^$/d' | sed 's/^ *//' | tee -a ${out}
for i in $(cat $tempdir/netlist) ; do
f_Long ; f_ROUTE_CONS "${i}" ; done | tee -a ${out} ; rm $tempdir/netlist ; fi ; fi
if [ $option_enum = "3" ] ; then
f_Long | tee -a ${out} ; echo -e "[+] $x | BANNERS" | tee -a ${out} ; f_Long | tee -a ${out}
f_serverPROTOCOLS "${ip4}" | tee -a ${out} ; f_BANNERS "${x}" | tee -a ${out} ; fi
if [ $option_enum = "4" ] || [ $option_enum = "6" ] ; then
f_VHOSTS "${ip4}" | tee -a ${out} ; fi ; done ; f_removeDir ; f_Menu ; f_optionsIPV4
;;
45)
f_makeNewDir ; f_Long ; type_net="true" ; domain_enum="false"
echo -e "\n${B}Options >\n"
echo -e "${B}[1]${D} Network whois" ; echo -e "${B}[2]${D} Prefix Routing Consistency"
echo -e "${B}[3]${D} Geographic Distribution" ; echo -e "${B}[4]${D} ALL" ; echo -e -n "\n${B}  ?${D}  " ; read option_enum
echo -e -n "\n${B}Target > [1]${D}  Set Target ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D}NETWORK (CIDR) ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE  ${B}>>${D} " ; read input ; targets="${input}" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
for x in $(cat "$targets") ; do
net=`echo $x | cut -d '/' -f 1`
if [ $option_enum = "1" ] ; then
out="${outdir}/NET_WHOIS.${net}.txt"
elif [ $option_enum = "2" ] ; then
out="${outdir}/ROUTING_STATUS.${net}.txt"
elif [ $option_enum = "3" ] ; then
out="${outdir}/NET_GEO.${net}.txt" ; else
out="${outdir}/NET_ENUM.${net}.txt" ; fi
if [ $option_enum = "2" ] || [ $option_enum = "3" ] ; then
f_Long | tee -a ${out} ; echo -e "[+] $x" ; f_Long | tee -a ${out} ; fi
if [ $option_enum = "1" ] || [ $option_enum = "4" ] ; then
f_DRWHO "${x}" ; f_netINFO "${x}" | tee -a ${out} ; f_Short | tee -a ${out} ; f_ROUTE_CONS "${x}" | tee -a ${out} ; fi 
if [ $option_enum = "2" ] ; then
f_ROUTE_CONS "${x}" | tee -a ${out}; f_Short | tee -a ${out}; echo -e "* Networks\n"; cat $tempdir/nets_cons.list ; fi
if [ $option_enum = "3" ] || [ $option_enum = "4" ] ; then
if [ $option_enum = "4" ] ; then
f_Short | tee -a ${out} ; fi
f_NETGEO "${x}" | tee -a ${out}
f_Long | tee -a ${out} ; f_whoisTABLE "$tempdir/nets_geo.list"
cat $tempdir/whois_table.txt | cut -d '|' -f 1,2,3,5,6 | tee -a ${out}
f_Long | tee -a ${out}; echo -e "* Networks\n"; cat $tempdir/nets_geo.list | tee -a ${out} ; fi
done ; f_removeDir ; f_Menu
;;
46)
f_makeNewDir ; f_Long ; type_net="true"
out="$tempdir/out4.txt"
echo -e "\n${B}Options > IPv4 Networks > DNS > \n"
echo -e "${B} [1]${D} Reverse DNS" ; echo -e "${B} [2]${D} Virtual Hosts"
echo -e "${B} [3]${D} BOTH" ; echo -e "${B} [9]${D} SKIP"
echo -e -n "\n${B}  ?${D}  " ; read option_net_1
if ! [ $option_net_1 = "9" ] ; then
if ! [ $option_connect = "9" ] ; then
if [ $option_net_1 = "1" ] || [ $option_net_1 = "3" ] ; then
echo -e "\n${B}Nameservers (System Defaults)${D}\n" ; f_systemDNS
echo -e "\n${B}Options  >  Reverse DNS  >  Sources >\n"
echo -e "${B} [1]${D} hackertarget.com API (max. size /24)\n"
echo -e "${B} [2] tool >  ${D}host | default NS  (no max. size)"
echo -e "${B} [3] tool >  ${D}host | custom NS   (no max. size)"
echo -e -n "\n${B}  ?${D}  " ; read option_source
if [ $option_source = "3" ] ; then
echo -e -n "\n${B}Set     >${D} Nameserver  ${B} >>${D}   " ; read input
nsserv=`echo $input | tr -d ' '` ; fi
echo -e -n "\n${B}Option  >${D} Look up ${B}IPv6 Addresses${D} for IPv4 PTR records? ${B} [y] | [n]  ?${D}  " ; read option_ip ; fi ; fi ; fi
if [ $option_connect = "9" ] ; then
echo -e "\n${B}Options > IPv4 Networks > Banners > \n"
echo -e "${B} [1] API  >${D}  hackertarget.com API"
echo -e "${B} [9]${D} SKIP" ; else
echo -e "\n${B}Options > IPv4 Networks > Banners > \n"
echo -e "${B} [1] API  >${D}  hackertarget.com API"
echo -e "${B} [2] NMAP >${D}  Version Scan, ICMP Ping"
echo -e "${B} [3] NMAP >${D}  Version Scan, NO Ping"
echo -e "${B} [9]      >${D}  SKIP" ; fi
echo -e -n "\n${B}  ?${D}  " ; read option_net_2
echo -e -n "\n${B}Target  > [1]${D} Single target network ${B}| [2]${D} Target list ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target  > ${D}Network (CIDR)  ${B}>>${D}   " ; read input
echo "$input" > $tempdir/nets.list
nets="$tempdir/nets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE  ${B}>>${D}   " ; read input
nets="${input}" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
if [ $report = "true" ] ; then
echo -e -n "\n${B}Set   > ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename
out="$outdir/${filename}.txt" ; fi
if [ $option_net_1 = "1" ] ; then
headline=" REVERSE DNS"
elif [ $option_net_1 = "2" ] ; then
headline=" REVERSE IP (VHOSTS)" ; else
headline=" REVERSE DNS | REVERSE IP (VHOSTS)" ; fi
if ! [ $option_net_2 = "9" ] ; then
headline2="| BANNER GRAB" ; fi
f_Long | tee -a ${out} ; echo -e " NETWORK ENUMERATION | $headline $headline2" | tee -a  ${out} ; f_Long | tee -a ${out}
echo -e "\n[+] Target Networks\n" | tee -a ${out} ; cat ${nets} | tee -a ${out} ; echo '' | tee -a ${out}
for x in $(cat ${nets}) ; do
whois -h whois.pwhois.org ${x} > $tempdir/pwho
netn=`grep -s -E "^Net-Name:" $tempdir/pwho | cut -d ':' -f 2- | sed 's/^ *//'`
prfx=`grep -s 'Prefix:' $tempdir/pwho | cut -d ':' -f 2- | sed 's/^ *//'`
orgn=`grep -s -E "^Org-Name:" $tempdir/pwho | cut -d ':' -f 2- | sed 's/^ *//'`
asnum=`grep -s 'Origin-AS:' $tempdir/pwho | cut -d ':' -f 2- | sed 's/^ *//'`
hostnum=`ipcalc -b -n ${x} | grep -s -E "^Hosts/Net" | cut -d ':' -f 2 | sed 's/Class.*//' | tr -d ' '` ; echo '' | tee -a ${out}
f_Long | tee -a ${out}; echo -e "$x | $netn | AS $asnum | $hostnum hosts" | tee -a ${out}; f_Long | tee -a ${out}
if [ $option_net_1 = "1" ] || [ $option_net_1 = "3" ] ; then
echo -e "* Reverse DNS\n" | tee -a ${out}
if [ $option_source = "1" ] || [ $option_connect = "9" ] ; then
f_RevDNS "${x}" | tee $tempdir/ipv4_hosts.txt ; cat $tempdir/ipv4_hosts.txt >> ${out} ; else
if [ $option_ip = "y" ] ; then
f_HOSTrevDNS "${x}" | tee $tempdir/ipv4_hosts.txt ; cat $tempdir/ipv4_hosts.txt >> ${out} ; else
f_HOSTrevDNS "${x}" | tee -a ${out} ; fi ;fi
if [ $option_ip = "y" ] ; then
awk '{print $3}' $tempdir/ipv4_hosts.txt | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/hosts.txt
f_Short | tee -a ${out} ; echo -e "[+]  IPv6 Hosts \n" | tee -a ${out}
dig aaaa +noall +answer +noclass +nottlid -f $tempdir/hosts.txt | sed 's/AAAA/,/' | sed '/NS/d' | sed '/CNAME/d' | tr -d ' '  > $tempdir/ipv6_hosts.txt
sort -t ',' -k 2 -uV $tempdir/ipv6_hosts.txt | sed 's/,/ /'  | awk '{print $2 "\t\t" $1}' > $tempdir/rev6.txt
cat $tempdir/rev6.txt | tee -a ${out} ; fi ; fi
#Banners
if ! [ $option_net_2 = "9" ] ; then
if [ $option_net_2 = "1" ] ; then
f_Short | tee -a ${out}; echo -e "* $x Banners" | tee -a ${out}; f_BANNERS "${x}" > $tempdir/services.txt ; else
echo '' | tee -a ${out}
if [ $option_net_2 = "2" ] ; then
sudo nmap -n -sV --top-ports 25 --script banner,http-server-header,https-redirect,http-title,mysql-info,ms-sql-info ${x} > $tempdir/nmap.txt ; else
sudo nmap -n -sV -Pn --top-ports 25 --script banner,http-server-header,https-redirect,http-title,mysql-info,ms-sql-info ${x} > $tempdir/nmap.txt ; fi
cat $tempdir/nmap.txt | sed '/PORT/{x;p;x;}' | sed '/\/tcp /{x;p;x;}' | sed '/Nmap scan report/i ____\n' | sed '/Read data files/d' |
sed '/NSE/d' | sed '/Initiating/d' | sed '/Completed/d' | sed '/Discovered/d' | sed '/Uptime guess:/{x;p;x;}' | sed '/Network Distance:/{x;p;x;}' |
fmt -w 120 -s | tee $tempdir/services.txt ; fi
cat $tempdir/services.txt | tee -a ${out} ; cat $tempdir/services.txt >> ${outdir}/BANNERS.txt ; fi
#VHosts
if [ $option_net_1 = "2" ] || [ $option_net_1 = "3" ] ; then
if [ $option_net_1 = "3" ] ; then
f_Short | tee -a ${out} ; fi
echo -e "* $x VHosts\n" | tee -a ${out} ; f_RevIP "${x}" | tee -a ${out} ; fi
done
if [ $report = "true" ] ; then
f_Long ; f_OutFile "$out" ; fi
echo '' ; f_Menu ; f_optionsIPV4 ; f_removeDir
;;
47)
f_makeNewDir ; f_Long ; blocklists="$blocklists_small"
echo -e -n "\n${B}Target > ${D}IPv4 NETWORK  ${B}>>${D}  " ; read input
net=`echo $input | cut -d '/' -f 1` ; out="${outdir}/NET.$net.BLOCKLISTS.txt"
ipcalc -b -n ${input} 255.255.255.255 | grep -s 'Hostroute:' | cut -d ':' -f 2- | tr -d ' ' | grep -E -v "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0$" |
grep -E -v "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.255$" > $tempdir/targets.list
whois -h whois.pwhois.org ${input} > $tempdir/pwho
netn=`grep -s -E "^Net-Name:" $tempdir/pwho | cut -d ':' -f 2- | sed 's/^ *//'`
prfx=`grep -s 'Prefix:' $tempdir/pwho | cut -d ':' -f 2- | sed 's/^ *//'`
orgn=`grep -s -E "^Org-Name:" $tempdir/pwho | cut -d ':' -f 2- | sed 's/^ *//'`
asnum=`grep -s 'Origin-AS:' $tempdir/pwho | cut -d ':' -f 2- | sed 's/^ *//'`
hostnum=`ipcalc -b -n ${input} | grep -s -E "^Hosts/Net" | cut -d ':' -f 2 | sed 's/Class.*//' | tr -d ' '` ; echo '' | tee -a ${out}
f_Long | tee -a ${out} ; echo -e "$input | BLOCKLIST CHECK | $netn | AS $asnum | $hostnum hosts" | tee -a ${out}; f_Long | tee -a ${out}
net=`echo "$input" | cut -d '/' -f 1`
f_ABX "${net}" ; echo "[@]: $abx  |  DATE:  $(date)" | tee -a ${out}
for x in $(cat $tempdir/targets.list) ; do
f_Long ; echo -e "[+] $x \n\n"
f_projectHONEYPOT "${x}" ; f_Shorter ; f_forumSPAM "${x}"
f_Shorter;  f_BLOCKLISTS "${x}" ; done | tee -a ${out}
echo '' ; f_Menu ; f_optionsIPV4 ; f_removeDir
;;
66)
f_makeNewDir ; f_Long ; type_net="false" ; domain_enum="false"
touch $tempdir/targets.list
echo -e -n "\n${B}Target  >  [1]${D} Set target IPv6 Address  ${B}|  [2]${D} Read from File  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  >${D} PATH TO FILE  ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e -n "\n${B}Target > ${D} IPV6 ADDRESS ${B} >>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; fi
echo -e "\n${B}Options >${D} GLOBAL *cast addresses ${B} >\n"
echo -e "${B}[1]${D} Address Geolocation, Whois, Reverse DNS Delegation"
echo -e "${B}[2]${D} Option [1] and Prefix Details"
echo -e -n "\n${B}  ?${D}  " ; read option_details
for x in $(cat "$targets") ; do
out="$outdir/${x}.txt"
f_Long | tee -a ${out} ; echo " $x" | tee -a ${out} ; f_Long | tee -a ${out}
f_SIPcalc "${x}" | tee -a ${out}
if [[ $(grep -s -w 'Address type' $tempdir/scalc.txt | grep -s -c -i -w 'Global') -ge "1" ]] ; then
f_DRWHO "${x}" ; curl -s http://ip-api.com/json/${x}?fields=54738911 > $tempdir/geo.json
asno=`jq -r '.as' $tempdir/geo.json | cut -d ' ' -f 1 | sed 's/AS/AS /'`
f_Long | tee -a ${out}; echo " $x | $(jq -r '.countryCode' $tempdir/geo.json) | $asno" | tee -a ${out}; f_Long | tee -a ${out}
f_hostSUMMARY  "${x}" | tee -a ${out} ; echo '' | tee -a ${out}
f_netINFO  "${x}" | tee -a ${out} ; f_Short | tee -a ${out}
f_DNS_CHAIN "${x}" | tee -a ${out} ; echo -e "\n" | tee -a ${out}
f_DELEGATION "${x}" | tee -a ${out}
if [ $option_details = "2" ] ; then
f_Short | tee -a ${out} ; f_NETGEO "${prfx}" | tee -a ${out} ; f_Short | tee -a ${out}
f_ROUTE_CONS "${prfx}" | tee -a ${out} ; f_Short | tee -a ${out} ; f_DELEGATION "${prfx}" | tee -a ${out} ; fi
fi ; done ; echo '' ; f_removeDir ; f_Menu
;;
67)
f_makeNewDir ; f_Long ; type_net="true" ; domain_enum="false"
echo -e "\n${B}Options >\n"
echo -e "${B}[1]${D} Network whois & AS Info"
echo -e "${B}[2]${D} Reverse DNS Delegation"
echo -e "${B}[3]${D} Prefix Routing Consistency"
echo -e "${B}[4]${D} Geographic Distribution"
echo -e "${B}[5]${D} ALL"
echo -e -n "\n${B}  ?${D}  " ; read option_enum
echo -e -n "\n${B}Target  >  [1]${D} Set target IPv6 Network  ${B}|  [2]${D} Read from File  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  >${D} PATH TO FILE ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e -n "\n${B}Target  >${D} IPv6 NETWORK ADDRESS (CIDR) ${B}  >>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; fi
if [ $report = "true" ] && [ $option_target = "2" ] ; then
echo -e -n "\n${B}Set   > ${D}OUTPUT - FILE NAME ${B}>>${D}  " ; read filename
out="${outdir}/$filename.txt" ; fi
for x in $(cat "$targets") ; do
net=`echo "$x" | cut -d '/' -f 1`
if [ $option_target = "1" ] ; then
out="$outdir/${net}.txt" ; else
out="$out" ; fi
if [ $option_enum = "1" ] || [ $option_enum = "5" ] ; then
f_DRWHO "${x}" ; echo '' | tee -a ${out} ;  f_netINFO "${x}" | tee -a ${out}
f_Short | tee -a ${out}
f_DELEGATION "${x}" | tee -a ${out} ; else
whois -h whois.cymru.com -- "-v -f ${x}" > $tempdir/cym
asnum=`awk -F'|' '{print $1}' $tempdir/cym | tr -d ' '` ; netrir=`awk -F'|' '{print $5}' $tempdir/cym | tr -d ' '`
reg_cc=`awk -F'|' '{print $4}' $tempdir/cym | tr -d ' '` ; bgp_prfx=`awk -F'|' '{print $3}' $tempdir/cym | tr -d ' '`
asname=`awk -F'|' '{print $7}' $tempdir/cym | tr -d ' '`
f_Long | tee -a ${out} ; echo -e " $x | $reg_cc | AS $asnum $asname \n\n BGP Prefix: $bgp_prfx | $netrir" | tee -a ${out}
f_Long | tee -a ${out} ; echo '' | tee -a ${out} ; fi
if [ $option_enum = "2" ] ; then
f_DELEGATION "${x}" | tee -a ${out} ; fi
if [ $option_enum = "3" ] || [ $option_enum = "5" ] ; then
if [ $option_enum = "5" ] ; then
f_Short | tee -a ${out} ; fi
f_ROUTE_CONS "${x}" | tee -a ${out} ; fi
if [ $option_enum = "4" ] || [ $option_enum = "5" ] ; then
if [ $option_enum = "5" ] ; then
f_Short | tee -a ${out} ; fi
f_NETGEO "${x}" | tee -a ${out} ; f_Short | tee -a ${out}
jq -r '.data.located_resources[].locations | .[] | .resources[] ' $tempdir/netloc.json > $tempdir/v6geo.list
echo '' | tee -a ${out} ; cat $tempdir/v6geo.list | sort -u -V | tee -a ${out} ; fi ; done; echo '' ; f_removeDir ; f_Menu
;;
68)
f_makeNewDir ; f_Long
if ! [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Target > ${D}IPv6 NETWORK ${B}|${D} REVERSE DOMAIN ADDRESS  ${B}>>${D}  " ; read target
f_Short ; f_DELEGATION "${target}"
echo -e -n "\n\n${B}Target > ${D}NAME SERVER ${B}>>${D}  " ; read target_ns
echo -e -n "\n${B}Option > [1] ${D} UDP  ${B} | [2] ${D} TCP  ${B}?${D}  " ; read input_protocol
if [ $input_protocol = "2" ] ; then
protocol="-t" ; else
protocol="" ; fi
net=`echo $target | rev | cut -d '/' -f 2- | rev` ; out="$outdir/REVERSE_DNS.${net}.txt"
f_Long | tee -a ${out}; echo " $address | REVERSE DNS" | tee -a ${out}; f_Long | tee -a ${out}; echo '' | tee -a ${out}
sudo atk6-dnsrevenum6 ${protocol} ${target_ns} ${target} | tee -a ${out} ;  else
f_WARNING ; fi ; echo '' ; f_Menu ; f_optionsIPV6 ; f_removeDir
;;
69)
f_makeNewDir ; f_Long
if ! [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Target > ${D}DOMAIN  ${B}>>${D}  " ; read target
out="$outdir/SUBSv6.${target}.txt" ; echo '' >> ${out}
f_Long | tee -a ${out}; echo -e "${x} | SUBDOMAINS (IPv6) | $(date)" | tee -a ${out}; f_Long | tee -a ${out}
atk6-dnsdict6 -d -l ${target} | sed '/Estimated time/G' | tee -a ${out} ; cat $tempdir/v6subs.txt >> $tempdir/subs.txt
cut -s -d '>' -f 2- $tempdir/v6subs.txt | tr -d ' ' > $tempdir/v6addresses.txt
f_Shorter | tee -a $tempdir/subs.txt ; echo -e "[+] Networks \n\n" | tee -a $tempdir/subs.txt
/usr/bin/atk6-extract_networks6 $tempdir/v6addresses.txt | sort -u | tee -a $tempdir/subs.txt
f_Shorter | tee -a $tempdir/subs.txt ; cat $tempdir/subs.txt >> ${out} ; else
f_WARNING ; fi ; echo '' ; f_removeDir ; f_Menu ; f_optionsIPV6
;;
77)
f_makeNewDir ; f_Long ; type_hop="false" ; domain_enum="false"
if ! [ $option_connect = "9" ] ; then
echo -e "\n${B}Options > Web Servers >\n"
echo -e "${B} [1]${D} Status & Overview"; echo -e "${B} [2]${D} Server Connectivity (Summary)"
echo -e "${B} [3]${D} Server Connectivity (Details)"; echo -e "${B} [4]${D} SSL Diagnostics"; echo -e "${B} [5]${D} Vulnerabilities"
echo -e -n "\n${B}  ?${D}  "  ; read option_enum
if [ $option_enum = "4" ] || [ $option_enum = "5" ] ; then
ssl_details="true" ; else
ssl_details="false" ; fi
echo -e "\n${B}Option >  curl > ${D} User Agent\n"
echo -e "${B} [1]${D} default" ; echo -e "${B} [2]${D} $ua_moz" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ua
if [ $option_ua = "2" ] ; then
curl_ua="-A $ua_moz" ; else
curl_ua="" ; fi
if [ $option_enum = "5" ] ; then
echo -e -n "\n${B}Options >${D} WhatWeb ${B}> [1]${D} Local App ${B}| [2]${D} hackertarget.com API  ${B}| [9]${D} SKIP  ${B}?${D}  " ; read ww_source
if [ $ww_source = "1" ] || [ $ww_source = "2" ] ; then
ww="true" ; else
ww="false" ; fi ; else 
ww_source="0" ; fi
if [ $option_enum = "1" ] || [ $option_enum = "5" ] ; then
echo -e -n "\n${B}Options > [1]${D} Dump & show hyperlinks & HTTP headers${B}| [2]${D} quietly dump stuff ${B}?${D}  " ; read option_dump ; fi 
if [ $option_enum = "3" ] ; then
echo -e -n "\n${B}Options > MTR > ${D} Target TCP Port ${B}> [1]${D} 80 ${B}| [2]${D} set port ${B}| [9] SKIP MTR ${B}?${D}  " ; read option_mtr
if ! [ $option_mtr = "9" ] ; then
if [ $option_mtr = "2" ] ; then
echo -e -n "\n${B}Set       >${D}  Target Port - e.g. 8080  ${B}>>${D}  " ; read tport ; else
tport="80" ; fi
echo -e "\n${B}Active Network Interfaces${D}\n"
ip -6 addr show | grep -s 'state UP' | cut -d ':' -f 2 | sed 's/^ *//'
echo -e -n "\n${B}Option atk6-trace6  >  ${D}Network Interface -e.g. eth0  ${B}>>${D}  " ; read interface ; fi ; fi 
if [ $option_enum = "4" ] ; then
option_testSSL="3"
elif [ $option_enum = "5" ] ; then
echo -e "\n${B}Options > SSL/TLS SECURITY > TESTSSL > \n"
echo -e "${B} [1]${D} Verification (Chain of trust), OSCP & Revocation Lists Check"
echo -e "${B} [2]${D} TESTSSL (Verification & Vulnerabilities)"
echo -e "${B} [3]${D} TESTSSL (Full, including Client Simulations)"
echo -e "${B} [9]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_testSSL ; else 
option_testSSL="9" ; fi 
if [ $option_enum = "5" ] ; then
echo -e "\n${B}Options > Nmap >\n"
echo -e "${B} [1]${D} Safe Mode" ; echo -e "${B} [2]${D} Intrusive Mode"
echo -e "${B} [9]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_nmap
if ! [ $option_nmap = "9" ] ; then
nmap_array+=(-Pn -sV --version-intensity 5 -O --osscan-limit -T3)
echo -e "\n${B}Ports   > Current target ports > ${D}\n"
echo -e "\n${B}Options > \n"
echo -e "${B} [1]${D} $web_ports"
echo -e "${B} [2]${D} $web_ports_xl"
echo -e "${B} [3]${D} customize ports"
echo -e -n "\n${B}  ? ${D}  " ; read option_ports
if [ $option_ports = "1" ] ; then
port_array+=(${web_ports})
elif [ $option_ports = "2" ] ; then
port_array+=(${web_ports_xl}) ; else
echo -e -n "\n${B}Set     > Ports  ${D}- e.g. 636,989-995  ${B}>>${D} " ; read add_ports
port_array+=(${add_ports}) ; fi
if [ $option_nmap = "2" ] ; then
script_array+=(${nmap_web})
script_args="--script-args http-methods.test-all,vulners.mincvss=7" ; else
script_array+=(${nmap_http_safe}) ; script_args="vulners.mincvss=7" ; fi ; fi 
echo -e "\n${B}Options > WFUZZ > \n"
echo -e "${B} [1]${D} robots.txt Enumeration" ; echo -e "${B} [2]${D} Server Directories Bruteforcing"
echo -e "${B} [3]${D} BOTH" ; echo -e "${B} [9]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_web1
echo -e "\n${B}Options > Other > \n"
echo -e "${B} [1]${D} Display HTML Comments"
echo -e "${B} [9]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_web2 ; fi ; fi 
echo -e -n "\n${B}Target > [1]${D} Set target host ${B}| [2]${D} Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}  " ; read input
targets="${input}" ; else
echo -e -n "\n${B}Target > ${D}Domain ${B}|${D} Hostname ${B}|${D} IP ADDRESS ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; fi
for x in $(cat "$targets") ; do
out="$outdir/WEB.$x.txt"
if [ $option_connect = "9" ] ; then
option_source="2" ; curl -s https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht} > $tempdir/ww.txt
ip4=$(cat $tempdir/ww.txt | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tail -1)
curl -s "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${ip4}" > $tempdir/ac.json
curl -s https://stat.ripe.net/data/reverse-dns-ip/data.json?resource=${ip4} > $tempdir/ptr.json
ptr=`jq -r '.data.result[0]' $tempdir/ptr.json | sed 's/null/no ptr record/'`
curl -s http://ip-api.com/json/$ip4?fields=21113371 > $tempdir/geo.json; f_PAGE "${x}" | tee -a ${out}
f_Long | tee -a ${out}; echo "[+] $x | $ipv4 | rDNS: $ptr" | tee -a ${out}; f_Long | tee -a ${out}
f_serverINFO "${ip4}" | tee -a ${out}; echo '' | tee -a ${out}; f_Short | tee -a ${out}; f_serverPROTOCOLS "${ip4}" | tee -a ${out}
f_Long | tee -a ${out}; echo -e "[+] $x | CERTIFICATE STATUS" | tee -a ${out}; f_Long | tee -a ${out}
curl -s  "https://api.certspotter.com/v1/issuances?domain=${x}&expand=dns_names&expand=issuer&expand=cert" > $tempdir/hostcert.json
jq -r '.[] | {Subject: .dns_names[], Expires: .not_after, Issuer: .issuer.name, CertSHA256: .cert.sha256}' $tempdir/hostcert.json | tr -d '}"{,' |
sed 's/^ *//' | sed '/^$/d' | sed 's/CertSHA256:/CertSHA-256:/' | sed '/Subject:/{x;p;x;}' | sed '/CertSHA-256:/{x;p;x;}' ; fi
if ! [ $option_connect = "5" ] ; then
ww="false" ; ww_source="9" ; fi 
if ! [ $option_connect = "9" ] ; then
if [ $ww_source = "1" ] ; then
whatweb --no-errors --color=never ${x} > $tempdir/ww.txt
elif [ $ww_source = "2" ] ; then
curl -s https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht} > $tempdir/ww.txt ; else
: ; fi
option_source="1"; declare -a curl_array=() ; curl_array+=(-sLk4v); error_code=6 ; curl -s -f -L -k ${x} > /dev/null
if [ $? = ${error_code} ]; then
echo -e "\n${R} $x WEBSITE CONNECTION: FAILURE${D}\n\n"
echo -e "\n $x WEBSITE CONNECTION: FAILURE\n" >> ${out} ; exit 1 ; else
echo -e "\n${B}${x} STATUS: ${GREEN}ONLINE${D}\n" ; fi
f_writeOUT "${x}" ; ip4=`grep -s "IP:" $tempdir/response | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'`
test_url=`grep "URL:" $tempdir/response | cut -d ':' -f 2- |  cut -d '/' -f 3 | sed 's/^[ \t]*//;s/[ \t]*$//'`
curl -s -f -L -k ${test_url} > /dev/null
if [ $? = ${error_code} ]; then
target_url=`echo $x` ; else
target_url=`echo $test_url` ; fi
if ! [ $option_enum = "2" ] ; then 
f_ROBOTS "${x}" ; fi
host4=$(dig +short $x) ; host6=$(dig aaaa +short $x) ; f_STATUS "${x}" | tee -a ${out}
if [ $option_enum = "1" ] ; then
f_Long | tee -a ${out}; f_PAGE "${x}" | tee -a ${out} ; f_certINFO "${x}" | tee -a ${out}
declare -a hping_array=(); hping_array+=(-c 4)
for a in $host4 ; do
ptr=$(host $a | grep -E "name pointer|not found:" | rev | cut -d ' ' -f 1 | rev | tr '[:space:]' ' ' | sed 's/3(NXDOMAIN)/no PTR record/' ; echo '')
curl -s "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${a}" > $tempdir/ac.json
curl -s http://ip-api.com/json/${a}?fields=16985627  > $tempdir/geo.json
country_c=`jq -r '.countryCode' $tempdir/geo.json` ; hosting=`jq -r '.hosting' $tempdir/geo.json`
f_Long | tee -a ${out}; echo "$a | $country_c | Hosting: $hosting" tee -a ${out} ; f_Long | tee -a ${out}
f_abxHEADER "${a}"| tee -a ${out} ; echo -e "rDNS:        $ptr\n" | tee -a ${out} ; f_HTTPing ${a} | tee -a ${out}
f_serverINFO "${a}" | tee -a ${out} ; done
if [ -n "$host6" ] ; then
declare -a hping_array=() ; hping_array+=(-6 -c 4) ; declare -a ping_array=() ; ping_array+=(-6 -c 4)
for z in $host6 ; do
ptr=$(host $z | grep -E "name pointer|not found:" | rev | cut -d ' ' -f 1 | rev | tr '[:space:]' ' ' | sed 's/3(NXDOMAIN)/no PTR record/' ; echo '')
curl -s "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${z}" > $tempdir/ac.json
curl -s http://ip-api.com/json/${z}?fields=16985627  > $tempdir/geo.json
country_c=`jq -r '.countryCode' $tempdir/geo.json` ; hosting=`jq -r '.hosting' $tempdir/geo.json`
f_Long | tee -a ${out}; echo "$z | $country_c | Hosting: $hosting" | tee -a ${out}; f_Long | tee -a ${out}
f_abxHEADER "${z}" | tee -a ${out} ; echo -e "rDNS:        $ptr\n" | tee -a ${out} ; f_HTTPing ${z} | tee -a ${out}
f_serverINFO "${z}" | tee -a ${out} ; done ; fi ; fi 
if ! [ $option_enum = "1" ] || ! [ $option_enum = "5" ] ; then
f_certINFO "${x}" | tee -a ${out} ; fi
if [ $option_enum = "2" ] || [ $option_enum = "3" ] ; then
f_Long | tee -a ${out}
declare -a hping_array=(); hping_array+=(-c 4); declare -a ping_array=(); ping_array+=(-c 4)
for a in $host4 ; do
ptr=$(host $a | grep -E "name pointer|not found:" | rev | cut -d ' ' -f 1 | rev | tr '[:space:]' ' ' | sed 's/3(NXDOMAIN)/no PTR record/' ; echo '')
sudo nmap -sS -p 80 --script path-mtu 2>/dev/null $a | grep 'path-mtu:' | cut -d ':' -f 2- | sed 's/^ *//' > $tempdir/pmtu
echo -e "\n* $a \n\n" | tee -a ${out} 
echo -e "rDNS:        $ptr\n" | tee -a ${out}
echo -e "MTU:         $(cat $tempdir/pmtu)\n" | tee -a ${out}; f_HTTPing "${a}" | tee -a ${out};
f_ICMPing "${a}" | tee -a ${out} ; echo '' | tee -a ${out} ; done 
if [ -n "$host6" ] ; then
declare -a hping_array=() ; hping_array+=(-6 -c 4) ; declare -a ping_array=() ; ping_array+=(-6 -c 4)
for z in $host6 ; do
ptr=$(host $z | grep -E "name pointer|not found:" | rev | cut -d ' ' -f 1 | rev | tr '[:space:]' ' ' | sed 's/3(NXDOMAIN)/no PTR record/' ; echo '')
echo -e "\n* $z \n\n" | tee -a ${out} ; echo -e "rDNS:        $ptr\n" | tee -a ${out}; f_HTTPing "${z}" | tee -a ${out};
f_ICMPing "${z}" | tee -a ${out} ; echo '' | tee -a ${out} ; done ; fi 
declare -a request_array=() ; request_array+=(-sT -PA -p 443) ; f_requestTIME "${target_url}" | tee -a ${out}
f_Long | tee -a ${out} ; f_DELEGATION_DIG "${x}" | tee -a ${out}
if [ -n "$host6" ]; then
t='aaaa' ; f_Long | tee -a ${out} ; f_DELEGATION_DIG "${x}" | tee -a ${out}  ; t='' ; fi ; fi 
if [ $option_enum = "3" ] ; then
if ! [ $option_mtr = "9" ] ; then
declare -a mtr_array=() ; mtr_array+=(--tcp -4 -c5 -w -b -z)
for a in $host4 ; do
f_MTR "${a}" ; done | tee -a ${out}
if [ -n "$host6" ] ; then
declare -a mtr_array=() ; mtr_array+=(--tcp -6 -c5 -w -b -z)
for z in $host6 ; do
f_MTR "${z}"; echo ''; f_Long; echo -e "[+] ${z} [atk6-trace6]"; f_Long; echo ''; sudo atk6-trace6 -t -d ${interface} ${z} > $tempdir/trace6
cat $tempdir/trace6 | sed '/Trace6 for/G'; echo '' ; done | tee -a ${out}; fi ; fi ; fi 
if [ $option_enum = "3" ] || [ $option_enum = "4" ] ; then
f_Long | tee -a ${out}; echo -e "[+] ${x} | SERVER RESONSE TIMES - DETAILS" | tee -a ${out} ; f_Long | tee -a ${out}
cat $tempdir/response | tee -a ${out} ; f_curlHandshake | tee -a ${out} ; echo '' | tee -a ${out} ; fi
if [ $option_enum = "4" ] ; then
f_testSSL "${x}" | tee -a ${out} ; fi
if [ $option_enum = "5" ] ; then
domain_enum="false" ; f_PAGE "${x}" | tee -a ${out}
for a in $host4 ; do
curl -s https://stat.ripe.net/data/reverse-dns-ip/data.json?resource=${a} > $tempdir/ptr.json
curl -s "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${a}" > $tempdir/ac.json
ptr=`jq -r '.data.result[0]' $tempdir/ptr.json | sed 's/null/no ptr record/'`
curl -s "https://isc.sans.edu/api/ip/${a}?json" > $tempdir/iscip.json
curl -s "https://isc.sans.edu/api/ipdetails/${a}?json" > $tempdir/ipdetails.json
echo '' ; f_Long; echo "$a | rDNS: $ptr" ; f_Long
f_abxHEADER "${a}" ; f_serverINFO "${a}" ; f_serverPROTOCOLS "${a}" ; f_BANNERS "${a}"
f_THREAT_ENUM "${a}" ; done | tee -a ${out}
if ! [ $option_nmap = "9" ] ; then
echo -e "\n" | tee -a ${out}; f_Long | tee -a ${out} ; echo -e "[+] $x | NMAP VULNERABILITY SCAN" | tee -a ${out}; f_Long | tee -a ${out}
sudo nmap ${nmap_array[@]} -p ${port_array[@]} $x -oA ${outdir}/WEB.${x} --script ${script_array[@]} ${script_args} > $tempdir/nmap.txt
cat $tempdir/nmap.txt | sed '/PORT/{x;p;x;G;}' | sed '/Starting Nmap/d' | sed '/Read data files/d' | sed '/NSE/d' | sed '/Initiating/d' |
sed '/Completed/d' | sed '/Discovered/d' | sed '/Service detection/d' | sed '/\/tcp /G' | fmt -s -w 120 |
sed '/vulners:/i \\n\----------------------------------------------------------\n' |
sed '/syn-ack ttl/i \----------------------------------------------------------\n' |
sed '/reset ttl/i \----------------------------------------------------------\n' | grep -E -v "SF:|SF-.*|fingerprint at|service unrecognized" |
sed '/Aggressive OS guesses:/i \\n\----------------------------------------------------------\n' | tee -a ${out} ; fi
f_certINFO "${x}" | tee -a ${out}
if ! [ $option_testSSL = "9" ] ; then
f_testSSL "${x}" | tee -a ${out} ; fi
if [ $option_web1 = "1" ] || [ $option_web1 = "3" ] ; then
if ! type wfuzz &> /dev/null; then
echo "Please install WFUZZ" ; else
echo '' | tee -a ${out} ; f_Long | tee -a ${out} ; echo -e "[+] ${x} [WFUZZ] | robots.txt" | tee -a ${out} ; f_Long | tee -a ${out}
echo '' | tee -a ${out} ; wfuzz --script=robots -z list,robots.txt -f $tempdir/fuzz $target_url/FUZZ ; echo '' | tee -a ${out}
cat $tempdir/fuzz >> ${out} ; rm $tempdir/fuzz ; fi ; fi
if [ $option_web1 = "2" ] || [ $option_web1 = "3" ] ; then
if ! type wfuzz &> /dev/null; then
echo "Please install WFUZZ" ; else
echo '' | tee -a ${out} ; f_Long | tee -a ${out} ; echo -e "[+] ${x} [WFUZZ] | DIRECTORIES" | tee -a ${out} ; f_Long | tee -a ${out}
wfuzz -w /usr/share/wfuzz/wordlist/general/medium.txt --hc 404,403 -f $tempdir/fuzz $target_url/FUZZ ; echo '' | tee -a ${out}
cat $tempdir/fuzz >> ${out} ; rm $tempdir/fuzz ; fi ; fi ; f_linkDUMP "${x}"
if [ $option_dump = "1" ] ; then
cat $tempdir/LINKS.${x}.txt | tee -a ${out}
f_HEADERS "${x}" | tee $tempdir/HEADERS ; cat $tempdir/HEADERS | tee -a ${out} > ${outdir}/HEADERS.${x}.txt ; else
f_HEADERS "${x}" > ${outdir}/HEADERS.${x}.txt ; fi
if [ $option_web2 = "1" ] ; then
f_Long | tee -a ${out} ; echo -e "[+] ${x} [NMAP] | HTML COMMENTS" | tee -a ${out}  ; f_Long | tee -a ${out}
nmap -Pn -sT -p 80,443 --script http-exif-spider,http-comments-displayer ${target_url} | sed '/PORT/{x;p;x;}' | sed '/Starting Nmap/d' | sed '/Read data files/d' |
sed '/NSE/d' | sed '/Nmap scan report/{x;p;x;}' | sed '/Initiating/d' | sed '/Completed/d' | sed '/\/tcp /{x;p;x;G;}' | tee -a ${out} ; fi ; fi 
fi ; done  ; echo '' ; f_removeDir ; f_Menu
;;
78)
f_makeNewDir ; f_Long ; echo -e "\n${B}Options  >  ${D}\n"
if [ $option_connect = "9" ] ; then
echo -e "${B} [1]${D} HTTP headers"; echo -e "${B} [2]${D} Link dump" ; echo -e "${B} [9]${D} CANCEL" ; else
echo -e "${B} [1]${D} HTTP headers"; echo -e "${B} [2]${D} Link dump"
echo -e "${B} [3]${D} robots.txt / humans.txt"; echo -e "${B} [4]${D} openSSL filedump & certificate status info"
echo -e "${B} [5]${D} openSSL filedump (quiet)"; echo -e "${B} [6]${D} ALL" ; echo -e "${B} [9]${D} CANCEL" ; fi
echo -e -n "\n${B}  ? ${D}  " ; read option_dump
if [ $option_connect = "9" ] ; then
echo -e -n "\n${B}Target  > [1]${D} Set target Host | IPv4 Address  ${B}|  [2]${D} Read from File  ${B}?${D}  " ; read option_target; else
echo -e -n "\n${B}Target  > [1]${D} Set target Host | IPv4/IPv6 Address  ${B}|  [2]${D} Read from File  ${B}?${D}  " ; read option_target ; fi
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Set     > ${D} TARGET  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; else
echo -e -n "\n${B}Enter  > ${D}PATH TO FILE  ${B}>>${D} " ; read input
targets="${input}" ; fi
if [ $option_connect = "9" ] ; then
option_source="2" ; else
echo -e -n "\n${B}Source  > ${D} HTTP Headers/ Link Dump ${B} > [1]${D} curl/ lynx  ${B}| [2]${D} hackertarget.com API   ${B}?${D}  " ; read option_source
if [ $option_source = "1" ] ; then
echo -e "\n${B}Option >  curl > ${D} User Agent\n"
echo -e "${B} [1]${D} default" ; echo -e "${B} [2]${D} $ua_moz" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ua
if [ $option_ua = "2" ] ; then
curl_ua="-A $ua_moz" ; else
curl_ua="" ; fi ; fi ; fi
for x in $(cat $targets) ; do
if [ $option_dump = "1" ] || [ $option_dump = "6" ] ; then
if [ $option_source = "1" ] ; then
curl -sILk --max-time 3 ${x} > $tempdir/headers ; else
curl -s https://api.hackertarget.com/httpheaders/?q=${x}${api_key_ht} > $tempdir/headers ; fi
f_HEADERS "${x}"  | tee -a ${outdir}/HEADERS.${x}.txt ; fi
if [ $option_dump = "2" ] || [ $option_dump = "6" ] ; then
f_linkDUMP "${x}" ; cat $tempdir/LINKS.${x}.txt ; fi
if [ $option_dump = "1" ] || [ $option_dump = "6" ] ; then
f_ROBOTS "${x}" ; fi
if [ $option_dump = "4" ] || [ $option_dump = "6" ] ; then
f_certINFO "${x}" | tee -a ${outdir}/CERT_INFO.${x}.txt ; fi
if [ $option_dump = "5" ] ; then
quiet_dump="true" ; f_certINFO "${x}" ; fi ; quiet_dump="false" ; done ; f_removeDir ; f_Menu
;;
t1)
f_makeNewDir ; f_Long ; out="${outdir}/PATH-MTU.txt"
echo -e "\n${B}NMAP Path MTU Discovery (TCP)${D}"
echo -e -n "\n${B}Target  > [1]${D} Set target (hostname, IPv4 ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e -n "\n${B} Set    >  TARGET  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; fi
echo -e -n "\n${B}Port  > ${D} e.g. 25  ${B}>>${D}  " ; read ports
for x in $(cat "$targets") ; do
f_Long | tee -a ${out} ; echo -e "[+] $target | PATH MTU | $(date)" | tee -a ${out} ; f_Long | tee -a ${out}
echo '' ; sudo nmap -sS -Pn -p ${ports} --script path-mtu $x | tee -a ${out} ; done
echo '' ; f_removeDir ; f_Menu; f_options_T
;;
t2)
f_makeNewDir ; f_Long
echo -e -n "\n ${B}Hostname | URL | IP >>  " ; read target
out="${outdir}ROUTES.$target.txt"
echo -e -n "\n${B}Options > [4]${D} IPv4 Mode  ${B}| [6]${D} IPv6 Mode | ${B}[b]${D} both ${B}?${D} " ; read IPvChoice
echo -e -n "\n${B}Set     >${D} Max. amount of hops (default: 30) ${B} >>${D}  " ; read hops
if [ $IPvChoice = "4" ] ||  [ $IPvChoice = "b" ] ; then
path_array+=(-4 -b)
echo -e "[+] $target Tracepath Results | IPv4- Mode\n\n"  | tee -a ${out}
tracepath  ${path_array[@]} -m ${hops} $target | tee -a ${out} ; fi
if [ $IPvChoice = "6" ] ||  [ $IPvChoice = "b" ] ; then
path_array+=(-6 -b)
echo -e "[+] $target Tracepath Results | IPv6- Mode\n\n"  | tee -a ${out}
tracepath  ${path_array[@]} -m ${hops} $target | tee -a ${out} ; fi
echo '' ; f_removeDir ; f_Menu; f_options_T
;;
t3)
f_makeNewDir ; f_Long
echo -e -n "\n${B}MTR > Source > [1] ${D}App (local inst.) ${B}| [2] ${D} hackertarget.com API  ${B}?${D}  " ; read option_source
if [ $option_source = "2" ] ; then
echo -e -n "\n${B}Target  >  ${D}HOSTNAME ${B}|${D} IPv4 ADDRESS ${B}>>${D}  " ; read target
out="${outdir}/ROUTES.${target}.txt" ; f_Long | tee -a ${out}; echo -e "[MTR] | $target | $(date)" | tee -a ${out}
f_Long | tee -a ${out} ; curl -s https://api.hackertarget.com/mtr/?q=${address}${api_key_ht}  | tee -a ${out}
echo -e "\n Source > hackertarget.com" | tee -a ${out} ; else
echo -e -n "\n${B}Target  > [1]${D} Set target (hostname, IPv4 or IPv6) ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target ; fi
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e -n "\n${B} Set    >   TARGET ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; fi
declare -a mtr_array=()
echo -e -n "\n${B}Options > [1]${D} IPV4 MODE  ${B}| [2]]${D}  IPV6 MODE ${B}| [9]${D}  AUTO (DEFAULT)  ${B}?${D}  " ; read IPvChoice
if  [ $IPvChoice = "1" ] ; then
mtr_array+=(-4 -w -b -z)
elif  [ $IPvChoice = "2" ] ; then
mtr_array+=(-6 -w -z -n) ; else
: ; fi
if  [ $IPvChoice = "1" ] ; then
echo -e -n "\n${B}Option > Hops >${D} Look up Organisation, Prefix & RPKI ${B} [y] | [n]  ?${D}  " ; read hop_details ; else
hop_details="n" ; fi
echo -e -n "\n${B}Set     >${D}  Max. hops (default 30): ${B}max hops  >>${D}  " ; read hops
mtr_array+=(-m ${hops})
echo -e -n "\n${B}Option  >${D}  No of pings - e.g. 5  ${B}>>${D}  " ; read pingcount
mtr_array+=(-c ${pingcount})
echo -e -n "\n${B}Options > Protocols > [1]${D}  TCP  ${B}| [2]${D}  UDP  ${B}| [3]${D}  ICMP  ${B}?${D}  " ; read protocol_input
if  [ $protocol_input = "1" ] ; then
mtr_array+=(--tcp) ; mtr_protocol="TCP"
echo -e -n "\n${B}Port    >${D}  Target Port - e.g. 25  ${B}>>${D}  " ; read tport
elif [ $protocol_input = "2" ] ; then
mtr_array+=(--udp) ; mtr_protocol="UDP" ; else
mtr_protocol="ICMP" ; fi
for x in $(cat "$targets") ; do
out="${outdir}/ROUTES.${x}.txt" ; f_MTR "${x}"
if [ $hop_details = "y" ] ; then
type_hop="true" ; domain_enum="false" ; echo '' | tee -a ${out}
hoplist=`cat $tempdir/mtr.txt | grep -E "[0-9]." | awk -F' ' '{print $3 $4}' | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sed '1,2d' | sed '/???/d'`
for i in $hoplist ; do
f_serverINFO "${i}" ; done | tee -a ${out} ; fi ; done
echo '' ; f_removeDir ; f_Menu ; f_options_T
;;
t4)
f_makeNewDir ; f_Long ; type_hop="true" ; domain_enum="false"
echo -e "\n${B}NMAP NSE Geo Traceroute${D}"
echo -e -n "\n${B}Target > ${D}HOSTNAME(s)${B} | ${D}IP(s)${B}  >>${D}   " ; read target
out="${outdir}/ROUTES.${target}.txt"
echo '' ; f_Long | tee -a ${out} ; echo " [NMAP]  GEO TRACEROUTE | $target" | tee -a ${out} ; f_Long | tee -a ${out}; echo '' | tee -a ${out}
sudo nmap -sn -Pn --traceroute --script traceroute-geolocation $target > $tempdir/geotrace
cat $tempdir/geotrace | sed '/^|/!d' | sed '1,1d' | sed '/HOP/{x;p;x;G}' | sed 's/|//' | tee -a ${out}; echo ''  | tee -a ${out}
hoplist=`cat $tempdir/geotrace | sed '/^|/!d' | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sed '1,1d'`
for i in $hoplist ; do
f_serverINFO "${i}" ; done | tee -a ${out}
echo '' ; f_removeDir ; f_Menu ; f_options_T
;;
t5)
f_makeNewDir ; f_Long
echo -e -n "\n${B}Dublin Traceroute > Options > [1]${D} Set target Host | IP Address  ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D}Hostname ${B}|${D}  URL ${B}|${D}  IP  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE  ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
for x in $(cat "$targets") ; do
out="$outdir/ROUTES.${x}.txt"
echo '' ; f_Long | tee -a ${out} ; echo " [Dublin Traceroute] | $x  " | tee -a ${out} ; f_Long | tee -a ${out}
echo '' ; sudo dublin-traceroute -n 12 $x | sed '/Flow ID/{x;p;x;G;}' | tee -a ${out} ; done
f_removeDir ; f_Menu ; f_options_T
;;
t6)
f_makeNewDir ; f_Long ; type_hop="true" ; domain_enum="false"
echo -e -n "\n${B}Target > [1]${D} Set target IPv6 Address  ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D} IPv6 Address   ${B}>>${D}   " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE  ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
echo -e "\n${B}Active Network Interfaces${D}\n"
ip -6 addr show | grep -s 'state UP' | cut -d ':' -f 2 | sed 's/^ *//'
echo -e -n "\n${B}Set  >  ${D}Network Interface -e.g. eth0  ${B}>>${D}  " ; read interface
for x in $(cat "$targets") ; do
out="${outdir}/ROUTES.${x}.txt" ; echo '' | tee -a ${out}
f_Long | tee -a ${out} ; echo -e "[+] ${x} [atk6-trace6] | $(date)" | tee -a ${out} ; f_Long | tee -a ${out}; echo '' | tee -a ${out}
sudo atk6-trace6 -t -d ${interface} ${x} > $tempdir/trace6
cat $tempdir/trace6 | sed '/Trace6 for/G' | tee -a ${out}
hops=`awk -F' ' '{print $2}' $tempdir/trace6 | sed '1,1d' | sed '/!!!/d' | sed '/???/d' | sed 's/^ *//' | sed '/^$/d'` 
for i in $hops ; do
f_serverINFO "${i}" ; done | tee -a ${out} ; done  ; f_removeDir ; f_Menu; f_options_T
;;
p1)
f_makeNewDir ; f_Long
echo -e "\n${B}Nmap Firewall Enumeration"
if ! [ $option_connect = "9" ] ; then
declare -a nmap_array=()  ; declare -a port_array=() 
echo -e "\n${B}Options >\n"
echo -e "${B} [1]${D} TCP Connect Scan (non-root)" ; echo -e "${B} [2]${D} Basic SYN Scan"
echo -e "${B} [3]${D} Service Version Scan (optional: vulners)" ; echo -e "${B} [4]${D} Service- & OS- Version Scan (optional: vulners)"
echo -e -n "\n${B}  ?${D}  " ; read scan_type
echo -e -n "\n${B}Mode    >  [1]${D}  IPv4   ${B}|  [2]${D}  IPv6  ${B}?${D}  " ; read option_ipv
echo -e -n "\n${B}Target  >  [1]${D} Set new target  ${B}| [2]${D} Read targets from list ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target >  ${D}PATH TO FILE ${B}>>${D}  " ; read input ; target="-iL ${input}" ; else
if [ $option_ipv = "2" ] ; then
nmap_array+=(-6); echo -e -n "\n${B}Target  >  ${D}Hostname(s)   ${B}|${D} IPv6 Address(es)  ${B}>>${D}  " ; read target ; else
echo -e -n "\n${B}Target  >  ${D}Hostname(s)   ${B}|${D} IPv4 Address(es)  ${B}|${D}  Network(s)  ${B}>>${D}  " ; read target ; fi ; fi
echo -e "\n\n${B}Target Ports  >\n"
echo -e "${B} [1]${D} nmap Top 100 Ports" ; echo -e "${B} [2]${D} nmap Top 500 Ports" ; echo -e "${B} [3]${D} nmap Top 1000 Ports"
echo -e "${B} [4]${D} $web_ports" ; echo -e "${B} [5]${D} $ports_net_services" ; echo -e "${B} [6]${D} Custom Port List"
echo -e -n "\n${B}  ?${D}  " ; read portChoice
if   [ $portChoice = "1" ] ; then
port_array+=(--top-ports 100)
elif [ $portChoice = "2" ] ; then
port_array+=(--top-ports 500)
elif [ $portChoice = "3" ] ; then
port_array+=(--top-ports 1000)
elif [ $portChoice = "4" ] ; then
port_array+=(-p ${web_ports})
elif [ $portChoice = "5" ] ; then
port_array+=(-p ${ports_net_services}) ; else 
echo -e -n "\n${B}Ports  > ${D} e.g. 636,989-995  ${B}>>${D}  " ; read ports
port_array+=(-p ${ports}) ; fi
if   [ $scan_type = "1" ] ; then
nmap_array+=(-sT) ; scripts_1="banner,ajp-headers,http-server-header,ms-sql-info,mysql-info"
elif [ $scan_type = "2" ] ; then
nmap_array+=(-sS) 
elif [ $scan_type = "3" ] ; then
nmap_array+=(-sV) ; scripts_1="banner,ajp-headers,http-server-header,ms-sql-info,mysql-info"
elif [ $scan_type = "4" ] ; then
nmap_array+=(-sV -O)
scripts_1="banner,ajp-headers,http-server-header,ms-sql-info,mysql-info,smb-protocols,smb-os-discovery,vmware-version" ; fi 
if ! [ $scan_type = "3" ] || [ $scan_type = "4" ] ; then
echo -e -n "\n${B}Option  > [1]${D} Scan for CVE Vulners  ${B}| [2]${D} CVE Vulners & empty mySQL/MS-SQL root passwords  ${B}| [9] SKIP  ${B}?${D}  "
read option_vulners
if   [ $option_vulners = "1" ] ; then
scripts_2="http-malware-host,smtp-strangeport,vulners"
elif   [ $option_vulners = "2" ] ; then
scripts_2="mysql-empty-password,ms-sql-empty-password,ms-sql-ntlm-info,http-malware-host,smtp-strangeport,vulners,ftp-anon" ; else 
: ; fi ; fi
if [ $scan_type = "1" ] ; then
nmap ${nmap_array[@]} -oA ${out}/${filename} ${port_array[@]} ${target} --script ${scripts_1} > $tempdir/nmap.txt
elif [ $scan_type = "2" ] ; then
sudo nmap ${nmap_array[@]} -oA ${out}/${filename} ${port_array[@]} ${target} > $tempdir/nmap.txt ; else 
if ! [ $option_vulners = "9" ] ; then
sudo nmap ${nmap_array[@]} ${port_array[@]} ${target} -oA ${outdir}/${scan_target} --script ${scripts_1},${scripts_2} > $tempdir/nmap.txt ; else
sudo nmap ${nmap_array[@]} ${port_array[@]} ${target} -oA ${outdir}/${scan_target} --script ${scripts_1} > $tempdir/nmap.txt ; fi ; fi 
f_Long | tee -a ${out}; echo "NMAP | $target | $(date)" | tee -a ${out}; f_Long | tee -a ${out}
cat $tempdir/nmap.txt | sed '/PORT/{x;p;x;G}' | sed '/Starting Nmap/d' | sed '/Read data files/d' | sed '/NSE/d' | sed '/Initiating/d' |
sed '/Completed/d' | sed '/Service detection/d' | sed '/\/tcp /G' |
sed '/Nmap scan report for /i \______________________________________________________________________________\n' |
sed 's/Nmap scan report for/*/' | sed '/Host is/{x;p;x;}' | sed 's/Aggressive OS guesses:/\nAggressive OS guesses:\n' |
sed '/Network Distance:/{x;p;x;}' | fmt -s -w 120 | tee -a ${out} ; else 
f_WARNING ; fi ; f_removeDir ; f_Menu ; f_options_P
;;
p2)
f_makeNewDir ; f_Long ; echo -e -n "\n${B}Nmap > Target >${D} IPv4 ADDRESS  >>${D}  " ; read target
out="${outdir}/PORTSCAN.${target}.txt" ; f_Long | tee -a ${out}
echo -e " [NMAP] PORT SCAN | $target | $(date) | Source: hackertarget.com" | tee -a ${out}
f_Long | tee -a ${out}; echo '' | tee -a ${out}; curl -s https://api.hackertarget.com/nmap/?q=${target}${api_key_ht} | tee -a ${out}
f_removeDir ; f_Menu ; f_options_P
;;
p3)
f_makeNewDir ; f_Long ; out="${outdir}/NPING.txt"
echo -e -n "\n${B}Nping > Target >${D} IPv4 Address ${B}>>${D}  " ; read scan_target
f_Long | tee -a ${out}; echo -e " [NPING] | $scan_target | Source: hackertarget.com API)\n" | tee -a ${out}
echo '' ; curl -s https://api.hackertarget.com/nping/?q=${scan_target}${api_key_ht}  | tee -a ${out}
f_removeDir ; f_Menu ; f_options_P
;;
49 | p4)
f_makeNewDir ; f_Long
echo -e "\n${B}Options > IPv4 Ping Sweep > Types >\n"
echo -e "${B} [1]${D} ICMP Echo"
echo -e "${B} [2]${D} TCP SYN Ping"
echo -e "${B} [3]${D} UDP Ping"
echo -e -n "\n${B}  ?${D}  " ; read pingType
echo -e "\n${B}Option > Target >\n"
echo -e "${B} [1]${D} Set target IPv4 Network (CIDR)"
echo -e "${B} [2]${D} Read Networks from File"
echo -e -n "\n${B}  ?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target >  ${D}PATH TO FILE ${B}>>${D}  " ; read input
target="-iL ${input}" ; scan_target="LIST" ; else
echo -e -n "\n${B}Target >  NETWORK (CIDR)  >>${D}  " ; read target
scan_target=`echo $target | cut -d '/' -f 1` ; fi
if [ $option_target = "1" ] ; then
out="${outdir}/PINGSWEEP.$scan_target.txt"
f_Long | tee -a ${out} ; echo " [NMAP] PING SWEEP | $target" | tee -a ${out} ; f_Long | tee -a ${out} ; else
out="${outdir}/NMAP_PING.txt" ;  f_Long | tee -a ${out} ; echo -e " [NMAP] PING | $target \n" | tee -a ${out} ; fi ; echo ''
if [ $pingType = "1" ] ; then
sudo nmap -sn -PE $target | tee -a ${out}
elif [ $pingType = "2" ] ; then
sudo nmap -sn -PS ${ports} $target | tee -a ${out}
elif [ $pingType = "3" ] ; then
sudo nmap -sn -PA ${ports} $target | tee -a ${out}
elif [ $pingType = "4" ] ; then
sudo nmap -sn -PU ${ports} $target | tee -a ${out}
elif [ $pingType = "5" ] ; then
sudo nmap -sn -PM $target | tee -a ${out} ;  fi ; f_removeDir ; f_Menu
;;
p5)
f_makeNewDir ; f_Long ; scripts=''
echo -e "\n${B}Nmap Firewall Enumeration"
if ! [ $option_connect = "9" ] ; then
declare -a nmap_array=() ; nmap_array+=(--reason) ; declare -a port_array=() 
echo -e "\n${B}Options >\n"
echo -e "${B} [1]${D} Alternative Scan Flags (ACK,FIN etc.)" ; echo -e "${B} [2]${D} Firewalk"
echo -e "${B} [3]${D} BOTH" ; echo -e -n "\n${B}  ?${D}  " ; read scan_type
echo -e -n "\n${B}Mode    >  [1]${D}  IPv4   ${B}|  [2]${D}  IPv6  ${B}?${D}  " ; read option_ipv
echo -e -n "\n${B}Target  >  [1]${D} Set new target  ${B}| [2]${D} Read targets from list ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target >  ${D}PATH TO FILE ${B}>>${D}  " ; read input ; target="-iL ${input}" ; else
if [ $option_ipv = "2" ] ; then
nmap_array+=(-6); echo -e -n "\n${B}Target  >  ${D}Hostname(s)   ${B}|${D} IPv6 Address(es)  ${B}>>${D}  " ; read target ; else
echo -e -n "\n${B}Target  >  ${D}Hostname(s)   ${B}|${D} IPv4 Address(es)  ${B}|${D}  Network(s)  ${B}>>${D}  " ; read target ; fi ; fi
scan_target=`echo $target | cut -d '/' -f 1` 
echo -e "\n\n${B}Target Ports  >\n"
echo -e "${B} [1]${D} nmap Top 100 Ports" ; echo -e "${B} [2]${D} nmap Top 500 Ports"
echo -e "${B} [3]${D} nmap Top 1000 Ports" ; echo -e "${B} [4]${D} $web_ports"
echo -e "${B} [5]${D} $ports_net_services" ; echo -e "${B} [6]${D} Custom Port List"
echo -e -n "\n${B}  ?${D}  " ; read portChoice
if   [ $portChoice = "1" ] ; then
port_array+=(--top-ports 100)
elif [ $portChoice = "2" ] ; then
port_array+=(--top-ports 500)
elif [ $portChoice = "3" ] ; then
port_array+=(--top-ports 1000)
elif [ $portChoice = "4" ] ; then
port_array+=(-p ${web_ports})
elif [ $portChoice = "5" ] ; then
port_array+=(-p ${ports_net_services}) ; else 
echo -e -n "\n${B}Ports  > ${D} e.g. 636,989-995  ${B}>>${D}  " ; read ports
port_array+=(-p ${ports}) ; fi
if [ $scan_type = "1" ] ; then
echo -e -n "\n${B}Option  >${D}  Send ping to check host status  ${B} [y] | [n]  ?${D}  " ; read option_ping
if [ $option_ping = "n" ] ; then
nmap_array+=(-Pn); fi ; fi 
if [ $scan_type = "2" ] || [ $scan_type = "3" ] ; then
echo -e "\n\n${B}Number of filtered ports to probe >\n"
echo -e "${B} [1]${D} All" ; echo -e "${B} [2]${D} Set number" ; echo -e -n "\n${B}  ?${D}  " ; read option_probe
if   [ $option_probe = "1" ] ; then
probes="-1" ; else 
echo -e -n "\n${B}Set   > Num of probed ports ${D} e.g. 5 ${B}>>${D}  " ; read probes ; fi
scripts="--script=firewalk --traceroute --script-args=firewalk.max-probed-ports=${probes}" ; fi
if [ $scan_type = "1" ] || [ $scan_type = "3" ] ; then
echo -e -n "\n\n${B}Flags   >  [1]${D} ACK ${B}| [2]${D} FIN ${B}| [3]${D} FIN & ACK ${B}| [4]${D} WINDOW SCAN  ${B}?${D}  " ; read scan_flag
if [ $scan_flag = "1" ] ; then
flag="ACK SCAN" ; nmap_array+=(-sA)
elif [ $scan_flag = "2" ] ; then
flag="FIN SCAN" ; nmap_array+=(-sF)
elif [ $scan_flag = "3" ] ; then
flag="FIN SCAN" ; nmap_array+=(-sF) ; nmap2_array+=(--reason -sA)
elif [ $scan_flag = "4" ] ; then
flag="WINDOW SCAN" ; nmap_array+=(-sW) ; else
flag="VERSION SCAN" ; nmap_array+=(-sV) ; fi
echo -e -n "\n\n${B}Options >  [1]${D} Packet Fragmentation ${B}| [2]${D} Source Port Spoofing ${B}| [3]${D} BOTH ${B}| [9]${D} IGNORE ${B}?${D}  " ; read option_extra
if   [ $option_extra = "1" ] ; then
nmap_array+=(-f)
if [ $scan_flag = "3" ] ; then
nmap2_array+=(-f) ; fi
elif [ $option_extra = "2" ] ; then
echo -e -n "\n\n${B}Set     >${D}  Source Port${B}>>${D}  " ; read source_port
nmap_array+=(-g ${source_port})
if [ $scan_flag = "3" ] ; then
nmap2_array+=(-g ${source_port}) ; fi
elif [ $option_extra = "3" ] ; then
echo -e -n "\n\n${B}Set     >${D}  Source Port${B}>>${D}  " ; read source_port
nmap_array+=(-f -g ${source_port})
if [ $scan_flag = "3" ] ; then
nmap2_array+=(-f -g ${source_port}) ; fi ; fi ; fi 
if [ $report = "true" ] ; then
if [ $option_target = "2" ] ; then 
echo -e -n "\n${B}Set     > ${D} OUTPUT-FILE NAME  ${B}>>${D}  " ; read filename ; else 
filename="$scan_target" ; fi ; else 
filename="p7" ; fi ; out="${outdir}/$filename.txt" 
sudo nmap ${nmap_array[@]} -oA ${outdir}/${filename} ${port_array[@]} ${scripts} ${target}  > $tempdir/nmap.txt
if [ $scan_type = "1" ] || [ $scan_type = "3" ] ; then
if [ $scan_flag = "3" ] ; then
sudo nmap ${nmap2_array[@]} -oA ${outdir}/2.${filename} ${port_array[@]} ${target} > $tempdir/nmap2.txt ; fi ; fi 
if [ $scan_type = "2" ] ; then
f_Long | tee -a ${out}; echo "NMAP | $target | $(date)" | tee -a ${out}; f_Long | tee -a ${out} ; else
f_Long | tee -a ${out}; echo "NMAP | $target | $flag | $(date)" | tee -a ${out}; f_Long | tee -a ${out} ; fi  
cat $tempdir/nmap.txt | sed '/PORT/{x;p;x;G}' | sed '/Starting Nmap/d' | sed '/Read data files/d' | sed '/NSE/d' | sed '/Initiating/d' |
sed '/Completed/d' | sed '/Service detection/d' | sed '/\/tcp /G' | sed 's/Nmap scan report for/*/' | sed '/Host is/{x;p;x;}' | fmt -s -w 120 | tee -a ${out}
if [ -f $tempdir/nmap2.txt ] ; then
f_Long | tee -a ${out}; echo "NMAP | $target | ACK SCAN | $(date)" | tee -a ${out}; f_Long | tee -a ${out}
cat $tempdir/nmap2.txt | sed '/PORT/{x;p;x;G}' | sed '/Starting Nmap/d' | sed '/Read data files/d' | sed '/NSE/d' | sed '/Initiating/d' |
sed '/Completed/d' | sed '/Service detection/d' | sed '/\/tcp /G' | sed 's/Nmap scan report for/*/' | sed '/Host is/{x;p;x;}' | fmt -s -w 120 | tee -a ${out} ; fi ; else
f_WARNING ; fi ; f_removeDir ; f_Menu
;;
p6)
f_makeNewDir ; f_Long
if ! [ $option_connect = "9" ] ; then
touch $tempdir/targets.list ; output="$out/ICMPv6.txt"
echo -e -n "\n${B}Target > [1]${D} Set target IPv6 Address  ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D} IPv6 Address   ${B}>>${D}   " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE  ${B}>>${D}  " ; read input ; targets="$input" ; else
echo -e "${R}ERROR!${D}" ; exit 0 ; fi
echo -e "\n${B}Active Network Interfaces${D}\n" ; ip -6 addr show | grep -s -w 'state UP' | cut -d ' ' -f 2 | tr -d ':'
echo -e -n "\n${B}Set >${D} Network interface (e.g. eth0)  ${B}>>${D} "; read n_interface
declare -a v6_array=() ; v6_array+=(${n_interface})
echo -e -n "\n${B}Set >${D} Number of packets (default:1)  ${B}>>${D} "; read packets
echo -e -n "\n${B}Option >${D} Set custom ICMPv6 type (default: 128 = ping) ${B} [y] | [n] ? ${D} " ; read answer
if  [ $answer = "y" ] ; then
echo -e -n "\n${B}Set >${D} ICMPv6 type ${B}>>${D} "; read option_type ; v6_array+=(-T ${option_type}) ; fi
echo -e -n "\n${B}Option >${D} Set custom ICMPv6 code (default: 0) ${B} [y] | [n] ? ${D} " ; read answer
if  [ $answer = "y" ] ; then
echo -e -n "\n${B}Set >${D} ICMPv6 code  ${B}>>${D} "; read option_code ; v6_array+=(-C ${option_code}) ; fi
for x in $(cat "$targets") ; do
f_Short | tee -a ${out} ; echo -e "\n[+] ${x} ICMPv6\n" | tee -a ${out} ; echo '' | tee -a ${out}
sudo atk6-thcping6 ${v6_array[@]} ${x} | sed '/packet sent/{x;p;x;G;}' | tee -a ${out}
echo ' ' | tee -a ${out} ; done ; else
f_WARNING ; fi ; f_removeDir ; f_Menu
;;
q)
echo -e "\n${B}----------------------------------- Done -------------------------------------\n"
echo -e "                       ${BDim}Author - Thomas Wy, July 2021${D}\n\n" ; f_removeDir
break
;;
esac
done 
